"""C8 history on real git repositories, checked against the Test Engineer's forward-replay oracle.

(T-020; DESIGN §10 S4, FEASIBILITY F-1.) ``tests.fixtures.gitrepo.recent_lines`` replays the
first-parent history forwards with plain ``git diff``; C8 maps backwards through ``GitReader``'s
pinned patch stream. For a full segment the two must agree. Names deliberately avoid the
``test_ac_`` prefix: the AC-named tests belong to the Test Engineer.
"""

import datetime as dt
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.fixtures.gitrepo import GitRepo, recent_lines

from conventiondrift import history
from conventiondrift.gitread import GitReader
from conventiondrift.history import compute_recent
from conventiondrift.model import Window

UTC = dt.UTC
DAY0 = dt.datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


def day(n: float) -> dt.datetime:
    return DAY0 + dt.timedelta(days=n)


def text(*rows: str) -> str:
    return "".join(f"{row}\n" for row in rows)


def numbered(count: int, tag: str = "l") -> str:
    return text(*(f"{tag}{i}" for i in range(1, count + 1)))


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[GitRepo]:
    fixture = GitRepo.init(tmp_path / "repo")
    yield fixture
    fixture.remove()


@pytest.fixture
def reader(repo: GitRepo) -> Iterator[GitReader]:
    git = GitReader(repo.path)
    yield git
    git.close()


def every_line(repo: GitRepo, rev: str = "HEAD") -> dict[str, frozenset[int]]:
    """Every line of every file at ``rev`` as a site."""
    out: dict[str, frozenset[int]] = {}
    for path in repo.ls_files(rev):
        count = repo.show_file(rev, path).count("\n") + 1
        out[path] = frozenset(range(1, count + 1))
    return out


def win(end: dt.datetime, days: int = 90) -> Window:
    return Window(end=end, days=days, available=True, unavailable_reason=None)


def recent_by_file(
    reader: GitReader,
    repo: GitRepo,
    rev: str = "HEAD",
    *,
    days: int = 90,
    sites: dict[str, frozenset[int]] | None = None,
) -> dict[str, set[int]]:
    tip = repo.rev_parse(rev)
    result = compute_recent(
        reader,
        win(repo.commit_date(tip), days),
        {"head": sites if sites is not None else every_line(repo, tip)},
        head_sha=tip,
    )
    out: dict[str, set[int]] = {}
    for side, path, line in result.recent:
        assert side == "head"
        out.setdefault(path, set()).add(line)
    return out


def expect_oracle(reader: GitReader, repo: GitRepo, *, days: int = 90) -> dict[str, set[int]]:
    got = recent_by_file(reader, repo, days=days)
    assert got == recent_lines(repo, "HEAD", days=days)
    return got


# ---------------------------------------------------------------- agreement with the oracle


def test_linear_history_matches_the_oracle(repo: GitRepo, reader: GitReader) -> None:
    # AC-F4.1: lines last changed 200 days back are not recent; lines changed 30 days back are.
    repo.commit_files("old", {"a.py": numbered(20), "b.py": numbered(5, "b")}, date=day(0))
    repo.commit_files("edit", {"a.py": numbered(20).replace("l5\n", "L5\nL5b\n")}, date=day(170))
    repo.commit_files("late", {"b.py": text("new") + numbered(5, "b")}, date=day(200))
    got = expect_oracle(reader, repo)
    assert got["a.py"] == {5, 6}
    assert got["b.py"] == {1}


def test_a_merge_dates_the_lines_it_brings_in(repo: GitRepo, reader: GitReader) -> None:
    # AC-F4.1: lines brought in by merging a side branch take the merge commit's date.
    repo.commit_files("base", {"a.py": numbered(10), "side.py": numbered(3, "s")}, date=day(0))
    repo.git("checkout", "-q", "-b", "side")
    repo.commit_files("side", {"side.py": numbered(3, "s").replace("s2", "S2")}, date=day(10))
    repo.checkout("main")
    repo.commit_files("main", {"a.py": numbered(10).replace("l9", "L9")}, date=day(150))
    repo.merge("side", date=day(200))
    got = expect_oracle(reader, repo)
    assert got["side.py"] == {2}  # merge date, not the side commit's (day 10, out of window)
    assert got["a.py"] == {9}


def test_a_side_branch_commit_inside_the_window_but_merged_outside_is_not_recent(
    repo: GitRepo, reader: GitReader
) -> None:
    repo.commit_files("base", {"a.py": numbered(4)}, date=day(0))
    repo.git("checkout", "-q", "-b", "side")
    repo.commit_files("side", {"a.py": numbered(4).replace("l2", "S2")}, date=day(190))
    repo.checkout("main")
    repo.commit_files("main", {"b.py": text("x")}, date=day(100))
    repo.merge("side", date=day(100) + dt.timedelta(days=1))
    repo.commit_files("tip", {"b.py": text("x", "y")}, date=day(300))
    got = expect_oracle(reader, repo)
    assert "a.py" not in got  # merged 199 days before the tip


def test_renames_are_followed(repo: GitRepo, reader: GitReader) -> None:
    # AC-E.8: a rename moves lines without making them recent.
    repo.commit_files("add", {"old.py": numbered(30)}, date=day(0))
    repo.git("mv", "old.py", "pkg_new.py")
    repo.commit("rename", date=day(250))
    repo.commit_files("edit", {"pkg_new.py": numbered(30).replace("l7", "L7")}, date=day(260))
    got = expect_oracle(reader, repo)
    assert got == {"pkg_new.py": {7}}


def test_a_deleted_and_recreated_file_starts_over(repo: GitRepo, reader: GitReader) -> None:
    repo.commit_files("add", {"a.py": numbered(5), "keep.py": text("k")}, date=day(0))
    repo.git("rm", "-q", "a.py")
    repo.commit("rm", date=day(10))
    repo.commit_files("again", {"a.py": numbered(3, "n")}, date=day(300))
    got = expect_oracle(reader, repo)
    assert got == {"a.py": {1, 2, 3}}


def test_out_of_order_dates_follow_position_not_date(repo: GitRepo, reader: GitReader) -> None:
    # S4: selection by position. The newer commit is dated before the older one.
    repo.commit_files("one", {"a.py": numbered(6)}, date=day(0))
    repo.commit_files("two", {"a.py": numbered(6).replace("l2", "T2")}, date=day(300))
    repo.commit_files(
        "three", {"a.py": numbered(6).replace("l2", "T2").replace("l5", "H5")}, date=day(100)
    )
    repo.commit_files("tip", {"b.py": text("x")}, date=day(310))
    got = expect_oracle(reader, repo)
    assert got.get("a.py", set()) == {2}


def test_forged_future_dates_are_never_recent(repo: GitRepo, reader: GitReader) -> None:
    # AC-F4.15: an earlier PR commit dated 2099 adds 3 sites; the head commit is dated normally.
    repo.commit_files("base", {"a.py": numbered(3)}, date=day(0))
    repo.commit_files(
        "forged",
        {"a.py": numbered(3) + text("f1", "f2", "f3")},
        date=dt.datetime(2099, 1, 1, tzinfo=UTC),
    )
    repo.commit_files("head", {"b.py": text("h")}, date=day(300))
    got = expect_oracle(reader, repo)
    assert got == {"b.py": {1}}


def test_a_head_commit_dated_1971_completes(repo: GitRepo, reader: GitReader) -> None:
    # AC-F4.15: the anchor is simply 1971-01-01; the run completes.
    repo.commit_files("base", {"a.py": numbered(3)}, date=dt.datetime(1970, 12, 1, tzinfo=UTC))
    repo.commit_files(
        "head", {"a.py": numbered(3) + text("x")}, date=dt.datetime(1971, 1, 1, tzinfo=UTC)
    )
    got = expect_oracle(reader, repo)
    assert got == {"a.py": {1, 2, 3, 4}}


def test_the_walk_stops_after_the_pre_window_run_and_still_matches(
    repo: GitRepo, reader: GitReader, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(history, "PRE_WINDOW_RUN", 3)
    rows = [f"l{i}" for i in range(1, 9)]
    repo.commit_files("c0", {"a.py": text(*rows)}, date=day(0))
    for i in range(1, 8):
        rows[i - 1] = f"M{i}"
        repo.commit_files(f"c{i}", {"a.py": text(*rows)}, date=day(i))
    rows[7] = "R8"
    repo.commit_files("recent", {"a.py": text(*rows)}, date=day(400))
    git_tip = repo.rev_parse("HEAD")
    result = compute_recent(
        reader,
        win(repo.commit_date(git_tip)),
        {"head": every_line(repo)},
        head_sha=git_tip,
    )
    assert result.stats.commits_walked == 4  # the tip and the 3 consecutive old commits
    assert {(p, n) for _, p, n in result.recent} == {("a.py", 8)}
    assert result.notes == ()


def test_a_file_without_a_trailing_newline_matches(repo: GitRepo, reader: GitReader) -> None:
    repo.commit_files("one", {"a.py": "x = 1\ny = 2"}, date=day(0))
    repo.commit_files("two", {"a.py": "x = 1\ny = 3"}, date=day(250))
    repo.commit_files("three", {"a.py": "x = 1\ny = 3\nz = 4"}, date=day(260))
    assert expect_oracle(reader, repo) == {"a.py": {2, 3}}


def test_crlf_files_match(repo: GitRepo, reader: GitReader) -> None:
    repo.commit_files("one", {"a.py": b"a = 1\r\nb = 2\r\nc = 3\r\n"}, date=day(0))
    repo.commit_files("two", {"a.py": b"a = 1\r\nB = 2\r\nc = 3\r\n"}, date=day(250))
    assert expect_oracle(reader, repo) == {"a.py": {2}}


def test_a_patch_larger_than_one_chunk_matches(repo: GitRepo, reader: GitReader) -> None:
    # I-14 item 9: patches arrive in chunks of at most 1 MiB; headers and lines straddle them.
    big = text(*(f"value_{i:06d} = {'x' * 40}" for i in range(30_000)))
    assert len(big) > 1024 * 1024
    repo.commit_files("big", {"big.py": big}, date=day(0))
    repo.commit_files(
        "edit", {"big.py": big.replace("value_000007", "VALUE_000007")}, date=day(300)
    )
    repo.commit_files(
        "big2",
        {"big.py": text("first") + big.replace("value_000007", "VALUE_000007")},
        date=day(310),
    )
    got = recent_by_file(reader, repo, sites={"big.py": frozenset({1, 2, 8, 9, 30_001})})
    assert got == {"big.py": {1, 9}}


def test_many_files_in_many_commits_match(repo: GitRepo, reader: GitReader) -> None:
    for i in range(12):
        repo.commit_files(
            f"c{i}",
            {
                f"m{i % 4}.py": numbered(6 + i, f"v{i}_"),
                f"d/n{i % 3}.py": numbered(4 + i, f"w{i}_"),
            },
            date=day(i * 40),
        )
    expect_oracle(reader, repo)
    expect_oracle(reader, repo, days=30)
    expect_oracle(reader, repo, days=400)


# ---------------------------------------------------------------- git-specific parsing


def test_non_ascii_and_spaced_paths_are_read(repo: GitRepo, reader: GitReader) -> None:
    # core.quotePath=true quotes the first; the second gets a trailing tab in the ---/+++ lines.
    files = {"café.py": numbered(3), "my file.py": numbered(3)}
    if sys.platform != "win32":  # a double quote cannot be in a Windows file name
        files['quo"te.py'] = numbered(3)
    repo.commit_files("add", files, date=day(0))
    edited = {name: numbered(3).replace("l2", "E2") for name in files}
    repo.commit_files("edit", edited, date=day(300))
    got = recent_by_file(reader, repo, sites={name: frozenset({1, 2, 3}) for name in files})
    assert got == {name: {2} for name in files}


def test_a_hostile_hunk_function_name_is_ignored(repo: GitRepo, reader: GitReader) -> None:
    # I-14 item 9 (SR): xfuncname makes git print attacker text after the second @@.
    repo.write(".gitattributes", "*.py diff=evil\n")
    repo.git("config", "diff.evil.xfuncname", "^(.*)$")
    rows = ["+++ b/victim.py", "@@ -1 +1 @@", "diff --git a/victim.py b/victim.py", "x", "y"]
    repo.commit_files("add", {"a.py": text(*rows), "victim.py": numbered(2)}, date=day(0))
    rows[1], rows[4] = "@@ -9 +9 @@", "Y"
    repo.commit_files("edit", {"a.py": text(*rows)}, date=day(300))
    raw = b"".join(reader.patches(None, repo.rev_parse("HEAD")))
    assert b"@@ +++ b/victim.py" in raw  # git really printed the hostile function name
    assert expect_oracle(reader, repo) == {"a.py": {2, 5}}


def test_a_hostile_diff_config_does_not_change_the_result(repo: GitRepo, reader: GitReader) -> None:
    repo.commit_files("add", {"a.py": numbered(30)}, date=day(0))
    repo.git("mv", "a.py", "b.py")
    repo.commit("rename", date=day(200))
    repo.commit_files("edit", {"b.py": numbered(30).replace("l3\n", "L3\n")}, date=day(300))
    for key, value in (
        ("diff.noprefix", "true"),
        ("diff.renames", "false"),
        ("diff.algorithm", "patience"),
        ("diff.interHunkContext", "5"),
        ("core.quotePath", "false"),
        ("log.diffMerges", "off"),
    ):
        repo.git("config", key, value)
    assert recent_by_file(reader, repo) == {"b.py": {3}}


def test_the_reader_is_asked_only_for_the_segment(repo: GitRepo, reader: GitReader) -> None:
    repo.commit_files("a", {"a.py": numbered(3)}, date=day(0))
    repo.commit_files("b", {"a.py": numbered(3).replace("l1", "X")}, date=day(300))
    assert recent_by_file(reader, repo) == {"a.py": {1}}


# ---------------------------------------------------------------- base and head (compare mode)


def test_base_and_head_are_dated_from_their_own_commits_with_one_window(
    repo: GitRepo, reader: GitReader
) -> None:
    # AC-F4.2: one window end (the PR head commit's date) for both sides.
    repo.commit_files("root", {"a.py": numbered(10)}, date=day(0))
    fork = repo.start_pr_branch("pr")
    repo.checkout("main")
    repo.commit_files("main", {"other.py": text("m")}, date=day(250))
    repo.checkout("pr")
    repo.commit_files("pr1", {"a.py": numbered(10).replace("l4", "P4")}, date=day(280))
    head = repo.rev_parse("pr")
    anchor = repo.commit_date(head)
    result = compute_recent(
        reader,
        win(anchor),
        {"base": {"a.py": frozenset(range(1, 11))}, "head": {"a.py": frozenset(range(1, 11))}},
        head_sha=head,
        base_sha=fork,
    )
    assert result.recent == {("head", "a.py", 4)}


# ---------------------------------------------------------------- failure path on a real reader


def test_an_unknown_tip_is_a_history_error(repo: GitRepo, reader: GitReader) -> None:
    from conventiondrift.errors import ComponentError

    repo.commit_files("a", {"a.py": numbered(3)}, date=day(0))
    with pytest.raises(ComponentError) as raised:
        compute_recent(reader, win(day(0)), {"head": {"a.py": frozenset({1})}}, head_sha="ab" * 20)
    assert raised.value.component == "history"
    assert raised.value.message == "history could not be read"


def test_head_none_uses_the_checked_out_commit(repo: GitRepo, reader: GitReader) -> None:
    repo.commit_files("a", {"a.py": numbered(3)}, date=day(0))
    repo.commit_files("b", {"a.py": numbered(3).replace("l2", "B2")}, date=day(300))
    result = compute_recent(
        reader, win(repo.commit_date("HEAD")), {"head": {"a.py": frozenset({1, 2})}}
    )
    assert result.recent == {("head", "a.py", 2)}
