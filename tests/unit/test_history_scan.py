"""Unit tests for C8 scan-mode dating (T-020; DESIGN §12 A-3, INTERFACES I-4 S3, I-12 counters).

Tracked files are compared with their ``HEAD`` blob in Python: untracked and changed lines are
recent, unchanged lines are dated through ``HEAD``'s history. Names deliberately avoid the
``test_ac_`` prefix: the AC-named tests belong to the Test Engineer.
"""

import datetime as dt
import hashlib
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

import pytest
from history_support import FakeGit, file_diff, hunk, marker, sha, when, window
from tests.fixtures.gitrepo import GitRepo

from conventiondrift import history
from conventiondrift.components import TreeEntry
from conventiondrift.gitread import GitReader
from conventiondrift.history import HistoryResult, compute_recent
from conventiondrift.model import PyFile, Window

TIP = sha(5)


def blob_id(data: bytes, family: str = "sha1") -> str:
    digest = hashlib.new(family, b"blob %d\x00" % len(data) + data)
    return digest.hexdigest()


def entry(path: str, data: bytes, mode: str = "100644", family: str = "sha1") -> TreeEntry:
    return (mode, blob_id(data, family), len(data), path)


def rows(*items: str) -> bytes:
    return "".join(f"{item}\n" for item in items).encode()


def scan(
    git: FakeGit,
    sites: Mapping[str, Sequence[int]],
    files: Mapping[str, bytes],
) -> HistoryResult:
    return compute_recent(
        git,
        window(),
        {"head": {path: frozenset(lines) for path, lines in sites.items()}},
        [PyFile(path, data) for path, data in files.items()],
        head_sha=TIP,
    )


def recent_lines(result: HistoryResult, path: str) -> set[int]:
    return {line for (_, file, line) in result.recent if file == path}


def test_untracked_files_are_all_recent_without_walking_history() -> None:
    # A-3: all lines of an untracked file are recent. Nothing needs dating, so git is not asked.
    git = FakeGit([(TIP, when(1000))], [])
    result = scan(git, {"new.py": [1, 2, 3]}, {"new.py": rows("a", "b", "c")})
    assert result.recent == {("head", "new.py", n) for n in (1, 2, 3)}
    assert git.chain_calls == [] and git.blob_calls == []


def test_an_unchanged_tracked_file_is_dated_by_history() -> None:
    data = rows("a", "b", "c")
    git = FakeGit(
        [(TIP, when(1))],
        [marker(TIP) + file_diff(b"a.py", hunk(2, 1, 2, 1))],
        tree=[entry("a.py", data)],
    )
    result = scan(git, {"a.py": [1, 2, 3]}, {"a.py": data})
    assert recent_lines(result, "a.py") == {2}
    assert git.blob_calls == []  # equal hashes: the blob is never read


def test_changed_lines_are_recent_and_unchanged_lines_map_back_to_head() -> None:
    head_data = rows("a", "b", "c", "d")
    work_data = rows("a", "X", "b", "c", "d")  # a line inserted at 2
    git = FakeGit(
        [(TIP, when(1))],
        [marker(TIP) + file_diff(b"a.py", hunk(2, 1, 2, 1))],  # HEAD line 2 ("b") is recent
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    result = scan(git, {"a.py": [1, 2, 3, 4, 5]}, {"a.py": work_data})
    # Working line 2 is new; working line 3 is HEAD line 2 (recent in history); others are old.
    assert recent_lines(result, "a.py") == {2, 3}
    assert git.blob_calls == [(blob_id(head_data), len(head_data))]
    assert result.stats.scan_diff_work == 4 * 5


def test_replaced_lines_are_recent() -> None:
    head_data = rows("a", "b", "c")
    work_data = rows("a", "B", "c")
    git = FakeGit(
        [(TIP, when(1000))],
        [marker(TIP) + file_diff(b"a.py", hunk(1, 0, 1, 3))],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    assert recent_lines(scan(git, {"a.py": [1, 2, 3]}, {"a.py": work_data}), "a.py") == {2}


def test_a_changed_file_with_no_matching_line_is_all_recent_without_a_walk() -> None:
    head_data = rows("a", "b")
    git = FakeGit(
        [(TIP, when(1))], [], tree=[entry("a.py", head_data)], blobs={blob_id(head_data): head_data}
    )
    result = scan(git, {"a.py": [1, 2]}, {"a.py": rows("x", "y")})
    assert recent_lines(result, "a.py") == {1, 2}
    assert git.chain_calls == []


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_a_head_entry_that_is_not_a_regular_file_counts_as_untracked(mode: str) -> None:
    data = rows("a")
    git = FakeGit([(TIP, when(1000))], [], tree=[(mode, blob_id(data), None, "a.py")])
    assert recent_lines(scan(git, {"a.py": [1]}, {"a.py": data}), "a.py") == {1}
    assert git.blob_calls == []


def test_files_not_in_scan_files_use_plain_history() -> None:
    git = FakeGit([(TIP, when(1))], [marker(TIP) + file_diff(b"a.py", hunk(1, 0, 1, 1))])
    result = scan(git, {"a.py": [1]}, {"other.py": rows("x")})
    assert recent_lines(result, "a.py") == {1}
    assert git.tree_calls == []  # no scan file had sites


def test_the_head_tree_is_read_once_for_all_scan_files() -> None:
    one, two = rows("a"), rows("b")
    git = FakeGit([(TIP, when(1000))], [], tree=[entry("a.py", one), entry("b.py", two)])
    scan(git, {"a.py": [1], "b.py": [1]}, {"a.py": one, "b.py": two})
    assert git.tree_calls == [TIP]


def test_a_tracked_file_may_be_changed_in_a_sha256_repository() -> None:
    head_data, work_data = rows("a", "b"), rows("a", "c")
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", head_data, family="sha256")],
        blobs={blob_id(head_data, "sha256"): head_data},
    )
    assert recent_lines(scan(git, {"a.py": [1, 2]}, {"a.py": work_data}), "a.py") == {2}
    unchanged = FakeGit(
        [(TIP, when(1))],
        [marker(TIP) + file_diff(b"a.py", hunk(1, 0, 1, 1))],
        tree=[entry("a.py", head_data, family="sha256")],
    )
    assert recent_lines(scan(unchanged, {"a.py": [1, 2]}, {"a.py": head_data}), "a.py") == {1}
    assert unchanged.blob_calls == []


def test_an_entry_without_a_size_reads_the_blob_up_to_the_working_size() -> None:
    head_data, work_data = rows("a"), rows("b")
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[("100644", blob_id(head_data), None, "a.py")],
        blobs={blob_id(head_data): head_data},
    )
    scan(git, {"a.py": [1]}, {"a.py": work_data})
    assert git.blob_calls == [(blob_id(head_data), len(work_data))]


def test_a_binary_looking_file_without_newlines_is_one_line() -> None:
    head_data, work_data = b"one line", b"other line"
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    assert recent_lines(scan(git, {"a.py": [1]}, {"a.py": work_data}), "a.py") == {1}


def test_empty_files_diff_at_no_cost() -> None:
    git = FakeGit([(TIP, when(1000))], [], tree=[entry("a.py", b"")], blobs={blob_id(b""): b""})
    result = scan(git, {"a.py": [1]}, {"a.py": rows("x")})
    assert recent_lines(result, "a.py") == {1}
    assert result.stats.scan_diff_work == 0


def test_the_line_diff_does_not_junk_popular_lines() -> None:
    # A-3: difflib.SequenceMatcher(autojunk=False). With autojunk on, 300 equal lines would be
    # ignored as "popular" and every one of them would look rewritten.
    head_data = rows(*(["x"] * 300), "end")
    work_data = rows("end", *(["x"] * 300))
    git = FakeGit(
        [(TIP, when(1000))],
        [marker(TIP) + file_diff(b"a.py", hunk(1, 0, 1, 301))],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    result = scan(git, {"a.py": range(1, 302)}, {"a.py": work_data})
    assert recent_lines(result, "a.py") == {1}


# ---------------------------------------------------------------- limits (A-3 condition 5)


def test_a_working_file_over_the_line_limit_is_all_recent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history, "SCAN_LINE_LIMIT", 3)
    head_data = rows("a", "b")
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    result = scan(git, {"a.py": [1, 2]}, {"a.py": rows("a", "b", "c", "d")})
    assert recent_lines(result, "a.py") == {1, 2}
    assert result.stats.scan_all_recent_line_limit == 1
    assert result.stats.scan_diff_work == 0
    assert git.blob_calls == []  # the HEAD blob is not even read
    assert result.notes == (history.SCAN_LINE_LIMIT_NOTE,)


def test_a_head_blob_over_the_line_limit_is_all_recent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history, "SCAN_LINE_LIMIT", 3)
    head_data = rows("a", "b", "c", "d")
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    result = scan(git, {"a.py": [1, 2]}, {"a.py": rows("a", "x")})
    assert recent_lines(result, "a.py") == {1, 2}
    assert result.stats.scan_all_recent_line_limit == 1
    assert len(git.blob_calls) == 1


def test_exactly_the_line_limit_is_still_diffed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history, "SCAN_LINE_LIMIT", 3)
    head_data = rows("a", "b", "c")
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    result = scan(git, {"a.py": [1, 2, 3]}, {"a.py": rows("a", "b", "x")})
    assert recent_lines(result, "a.py") == {3}
    assert result.stats.scan_all_recent_line_limit == 0
    assert result.notes == ()


def budget_git(contents: dict[str, tuple[bytes, bytes]]) -> tuple[FakeGit, dict[str, bytes]]:
    tree = [entry(path, head) for path, (head, _) in contents.items()]
    blobs = {blob_id(head): head for head, _ in contents.values()}
    return (
        FakeGit([(TIP, when(1000))], [], tree=tree, blobs=blobs),
        {path: work for path, (_, work) in contents.items()},
    )


def test_the_diff_budget_is_spent_in_path_order_and_stays_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 10)
    git, files = budget_git(
        {
            "z.py": (rows("1"), rows("2")),  # cost 1, but sorts last
            "m.py": (rows("a", "b", "c"), rows("a", "b", "x")),  # cost 9
            "a.py": (rows("a", "b"), rows("a", "y")),  # cost 4, diffed first
        }
    )
    sites = {path: list(range(1, len(work.splitlines()) + 1)) for path, work in files.items()}
    result = scan(git, sites, files)
    # a.py (4) is diffed; m.py (4 + 9 = 13 > 10) exhausts the budget; z.py would fit but stays
    # all recent.
    assert recent_lines(result, "a.py") == {2}
    assert recent_lines(result, "m.py") == {1, 2, 3}
    assert recent_lines(result, "z.py") == {1}
    assert result.stats.scan_diff_work == 4
    assert result.stats.scan_all_recent_diff_budget == 2
    assert result.notes == (history.SCAN_DIFF_BUDGET_NOTE,)
    assert len(git.blob_calls) == 2  # z.py's blob is never read once the budget is spent


def test_a_file_that_uses_exactly_the_remaining_budget_is_diffed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 9)
    git, files = budget_git({"a.py": (rows("a", "b", "c"), rows("a", "b", "x"))})
    result = scan(git, {"a.py": [1, 2, 3]}, files)
    assert recent_lines(result, "a.py") == {3}
    assert result.stats.scan_diff_work == 9
    assert result.stats.scan_all_recent_diff_budget == 0


def test_paths_are_ordered_by_their_utf8_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    # A-5: sorted by repo-relative path as UTF-8 bytes. "é" (0xC3 0xA9) sorts after "z".
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 1)
    git, files = budget_git({"é.py": (rows("c"), rows("b")), "z.py": (rows("a"), rows("b"))})
    result = scan(git, {"é.py": [1], "z.py": [1]}, files)
    assert result.stats.scan_diff_work == 1
    assert result.stats.scan_all_recent_diff_budget == 1
    assert [call[0] for call in git.blob_calls] == [blob_id(rows("a")), blob_id(rows("c"))]


def test_line_limit_files_do_not_spend_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history, "SCAN_LINE_LIMIT", 2)
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 4)
    git, files = budget_git(
        {
            "a.py": (rows("a"), rows("a", "b", "c")),  # over the limit
            "b.py": (rows("a", "b"), rows("a", "x")),  # cost 4, fits
        }
    )
    result = scan(git, {"a.py": [1, 2, 3], "b.py": [1, 2]}, files)
    assert result.stats.scan_all_recent_line_limit == 1
    assert result.stats.scan_all_recent_diff_budget == 0
    assert recent_lines(result, "b.py") == {2}


# ---------------------------------------------------------------- real git


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[GitRepo]:
    fixture = GitRepo.init(tmp_path / "repo")
    yield fixture
    fixture.remove()


def real_scan(repo: GitRepo, sites: dict[str, Sequence[int]]) -> set[tuple[str, int]]:
    reader = GitReader(repo.path)
    try:
        anchor = repo.commit_date("HEAD")
        files = [
            PyFile(path, (repo.path / path).read_bytes())
            for path in sites
            if (repo.path / path).exists()
        ]
        result = compute_recent(
            reader,
            Window(end=anchor, days=90, available=True, unavailable_reason=None),
            {"head": {path: frozenset(lines) for path, lines in sites.items()}},
            files,
        )
    finally:
        reader.close()
    return {(file, line) for (_, file, line) in result.recent}


def test_real_repository_scan_mixes_untracked_changed_and_unchanged(repo: GitRepo) -> None:
    # S3: the window is anchored at HEAD's committer date; uncommitted lines are recent.
    day0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    repo.commit_files("old", {"keep.py": "a\nb\nc\n", "edit.py": "p\nq\nr\ns\n"}, date=day0)
    repo.commit_files("recent", {"keep.py": "a\nB\nc\n"}, date=day0 + dt.timedelta(days=300))
    repo.write("edit.py", "p\nQ\nq\nr\nS\n")  # working tree: line 2 inserted, line 5 replaces "s"
    repo.write("untracked.py", "u1\nu2\n")
    got = real_scan(
        repo, {"keep.py": [1, 2, 3], "edit.py": [1, 2, 3, 4, 5], "untracked.py": [1, 2]}
    )
    assert got == {
        ("keep.py", 2),  # changed 0 days before HEAD
        ("edit.py", 2),
        ("edit.py", 5),
        ("untracked.py", 1),
        ("untracked.py", 2),
    }


def test_real_repository_scan_dates_unchanged_lines_through_head(repo: GitRepo) -> None:
    day0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    repo.commit_files("old", {"a.py": "a\nb\nc\nd\n"}, date=day0)
    repo.commit_files("recent", {"a.py": "a\nb\nC\nd\n"}, date=day0 + dt.timedelta(days=300))
    repo.write("a.py", "new\na\nb\nC\nd\n")  # one line added on top: HEAD line 3 is now line 4
    assert real_scan(repo, {"a.py": [1, 2, 3, 4, 5]}) == {("a.py", 1), ("a.py", 4)}
