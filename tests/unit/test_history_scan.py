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
from conventiondrift.discover.safefs import FILE_MAX_BYTES
from conventiondrift.errors import ComponentError
from conventiondrift.gitread import GitReader
from conventiondrift.history import GitHistory, compute_recent
from conventiondrift.model import HistoryResult, PyFile, TrackedState, Window

TIP = sha(1)  # FakeGit's HEAD: scan mode resolves it through the reader


def blob_id(data: bytes, family: str = "sha1") -> str:
    digest = hashlib.new(family, b"blob %d\x00" % len(data) + data)
    return digest.hexdigest()


def entry(path: str, data: bytes, mode: str = "100644", family: str = "sha1") -> TreeEntry:
    return (mode, blob_id(data, family), len(data), path)


def rows(*items: str) -> bytes:
    return "".join(f"{item}\n" for item in items).encode()


def tracked_from(git: FakeGit, files: Mapping[str, bytes]) -> dict[str, TrackedState]:
    """What C4 would pass: one entry per tracked file, ``unchanged`` from comparing blob ids."""
    return {
        path: TrackedState(oid, blob_id(files[path], "sha256" if len(oid) == 64 else "sha1") == oid)
        for _, oid, _, path in git.entries
        if path in files
    }


def scan(
    git: FakeGit,
    sites: Mapping[str, Sequence[int]],
    files: Mapping[str, bytes],
    tracked: Mapping[str, TrackedState] | None = None,
    max_file_bytes: int | None = None,
) -> HistoryResult:
    result = compute_recent(
        git,
        window(),
        {"head": {path: frozenset(lines) for path, lines in sites.items()}},
        scan_files=[PyFile(path, data) for path, data in files.items()],
        scan_tracked=tracked_from(git, files) if tracked is None else tracked,
        max_file_bytes=max_file_bytes,
    )
    assert git.tree_calls == []  # C8 never lists the tree (I-14 ruling 3)
    return result


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
    assert git.blob_calls == [(blob_id(head_data), FILE_MAX_BYTES)]
    assert result.stats["scan_diff_work"] == 4 * 5


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


def test_a_tracked_file_is_trusted_as_c4_reports_it_and_never_rehashed() -> None:
    # I-14 ruling 3: C4 owns the blob comparison. Contents that differ from the blob id are
    # still "unchanged" when C4 says so, so C8 did not hash them.
    git = FakeGit([(TIP, when(1))], [marker(TIP) + file_diff(b"a.py", hunk(2, 1, 2, 1))])
    tracked = {"a.py": TrackedState("c" * 40, True)}
    result = scan(git, {"a.py": [1, 2]}, {"a.py": rows("not", "the", "blob")}, tracked)
    assert recent_lines(result, "a.py") == {2}
    assert git.blob_calls == []


def test_a_file_without_a_tracked_entry_is_untracked_whatever_head_holds() -> None:
    data = rows("a")
    git = FakeGit([(TIP, when(1000))], [], tree=[entry("a.py", data)])
    result = scan(git, {"a.py": [1]}, {"a.py": data}, tracked={})
    assert recent_lines(result, "a.py") == {1}
    assert git.chain_calls == [] and git.blob_calls == []


def test_files_not_in_scan_files_use_plain_history() -> None:
    git = FakeGit([(TIP, when(1))], [marker(TIP) + file_diff(b"a.py", hunk(1, 0, 1, 1))])
    result = scan(git, {"a.py": [1]}, {"other.py": rows("x")})
    assert recent_lines(result, "a.py") == {1}


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


def head_blob_case(size: int) -> tuple[FakeGit, bytes]:
    head_data = b"h" * size  # one line, so only the byte limit can stop it
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    return git, b"w" * 10


def test_a_head_blob_over_the_py_size_limit_is_all_recent_and_never_read() -> None:
    # I-14 ruling 4: C4's per-file .py limit, checked by the reader before the body is read.
    git, work = head_blob_case(FILE_MAX_BYTES + 1)
    result = scan(git, {"a.py": [1]}, {"a.py": work})
    assert recent_lines(result, "a.py") == {1}
    assert result.stats["scan_all_recent_line_limit"] == 1
    assert result.stats["scan_all_recent_diff_budget"] == 0
    assert result.stats["scan_diff_work"] == 0
    assert result.notes == (history.SCAN_LINE_LIMIT_NOTE,)
    assert git.blob_calls == [(blob_id(b"h" * (FILE_MAX_BYTES + 1)), FILE_MAX_BYTES)]
    assert git.chain_calls == []


def test_a_head_blob_exactly_at_the_py_size_limit_is_diffed() -> None:
    git, work = head_blob_case(FILE_MAX_BYTES)
    result = scan(git, {"a.py": [1]}, {"a.py": work})
    assert recent_lines(result, "a.py") == {1}  # the one line changed
    assert result.stats["scan_all_recent_line_limit"] == 0
    assert result.stats["scan_diff_work"] == 1
    assert result.notes == ()


def test_max_file_bytes_none_uses_the_default_py_limit() -> None:
    git, work = head_blob_case(10)
    scan(git, {"a.py": [1]}, {"a.py": work}, max_file_bytes=None)
    assert git.blob_calls == [(blob_id(b"h" * 10), FILE_MAX_BYTES)]


def test_an_explicit_max_file_bytes_replaces_the_default() -> None:
    # I-14 C8 ruling 7: the value passed is the size limit for the HEAD blob.
    git, work = head_blob_case(10)
    scan(git, {"a.py": [1]}, {"a.py": work}, max_file_bytes=50)
    assert git.blob_calls == [(blob_id(b"h" * 10), 50)]


@pytest.mark.parametrize(("size", "over"), [(49, False), (50, False), (51, True)])
def test_the_explicit_limit_is_inclusive_at_the_boundary(size: int, over: bool) -> None:
    git, work = head_blob_case(size)
    result = scan(git, {"a.py": [1]}, {"a.py": work}, max_file_bytes=50)
    assert recent_lines(result, "a.py") == {1}  # the one line changed either way
    assert result.stats["scan_all_recent_line_limit"] == int(over)
    assert result.stats["scan_diff_work"] == int(not over)
    assert result.notes == ((history.SCAN_LINE_LIMIT_NOTE,) if over else ())


def test_a_zero_limit_is_a_limit_not_the_default() -> None:
    git, work = head_blob_case(1)
    result = scan(git, {"a.py": [1]}, {"a.py": work}, max_file_bytes=0)
    assert git.blob_calls == [(blob_id(b"h"), 0)]
    assert result.stats["scan_all_recent_line_limit"] == 1


def test_a_limit_above_the_default_is_used_as_given() -> None:
    git, work = head_blob_case(FILE_MAX_BYTES + 1)
    result = scan(git, {"a.py": [1]}, {"a.py": work}, max_file_bytes=FILE_MAX_BYTES + 1)
    assert result.stats["scan_all_recent_line_limit"] == 0
    assert result.stats["scan_diff_work"] == 1


def test_a_negative_limit_is_a_history_error() -> None:
    git, work = head_blob_case(10)
    with pytest.raises(ComponentError):
        scan(git, {"a.py": [1]}, {"a.py": work}, max_file_bytes=-1)


def test_git_history_passes_max_file_bytes_through() -> None:
    git, work = head_blob_case(10)
    result = GitHistory().recent(
        git,
        window(),
        {"head": {"a.py": frozenset({1})}},
        scan_files=[PyFile("a.py", work)],
        scan_tracked=tracked_from(git, {"a.py": work}),
        max_file_bytes=9,
    )
    assert result.stats["scan_all_recent_line_limit"] == 1


def test_several_oversize_blobs_each_count_once() -> None:
    big = b"h" * (FILE_MAX_BYTES + 1)
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", big), entry("b.py", big + b"x")],
        blobs={blob_id(big): big, blob_id(big + b"x"): big + b"x"},
    )
    result = scan(git, {"a.py": [1], "b.py": [1]}, {"a.py": b"1\n", "b.py": b"2\n"})
    assert result.stats["scan_all_recent_line_limit"] == 2
    assert result.notes == (history.SCAN_LINE_LIMIT_NOTE,)  # one note per run


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
    assert result.stats["scan_diff_work"] == 0


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
    assert result.stats["scan_all_recent_line_limit"] == 1
    assert result.stats["scan_diff_work"] == 0
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
    assert result.stats["scan_all_recent_line_limit"] == 1
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
    assert result.stats["scan_all_recent_line_limit"] == 0
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
    assert result.stats["scan_diff_work"] == 4
    assert result.stats["scan_all_recent_diff_budget"] == 2
    assert result.notes == (history.SCAN_DIFF_BUDGET_NOTE,)
    assert len(git.blob_calls) == 2  # z.py's blob is never read once the budget is spent


def test_a_file_that_uses_exactly_the_remaining_budget_is_diffed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 9)
    git, files = budget_git({"a.py": (rows("a", "b", "c"), rows("a", "b", "x"))})
    result = scan(git, {"a.py": [1, 2, 3]}, files)
    assert recent_lines(result, "a.py") == {3}
    assert result.stats["scan_diff_work"] == 9
    assert result.stats["scan_all_recent_diff_budget"] == 0


def test_paths_are_ordered_by_their_utf8_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    # A-5: sorted by repo-relative path as UTF-8 bytes. "é" (0xC3 0xA9) sorts after "z".
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 1)
    git, files = budget_git({"é.py": (rows("c"), rows("b")), "z.py": (rows("a"), rows("b"))})
    result = scan(git, {"é.py": [1], "z.py": [1]}, files)
    assert result.stats["scan_diff_work"] == 1
    assert result.stats["scan_all_recent_diff_budget"] == 1
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
    assert result.stats["scan_all_recent_line_limit"] == 1
    assert result.stats["scan_all_recent_diff_budget"] == 0
    assert recent_lines(result, "b.py") == {2}


def test_every_note_in_one_run_comes_in_a_fixed_order(monkeypatch: pytest.MonkeyPatch) -> None:
    # commit cap, then line limit, diff budget, and bare CR last.
    monkeypatch.setattr(history, "SCAN_LINE_LIMIT", 3)
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 1)
    contents = {
        "a.py": (rows("a"), rows("a", "b", "c", "d")),  # over the line limit
        "b.py": (rows("a"), b"b\rc\n"),  # costs 1, bare CR, fits the budget
        "c.py": (rows("a"), rows("b")),  # budget spent
        "u.py": (rows("a"), rows("b")),  # tracked below, also over budget
    }
    git, files = budget_git(contents)
    git.chain = [(sha(i), when(0.5)) for i in range(1, history.COMMIT_CAP + 2)]
    sites = {path: [1] for path in files} | {"keep.py": [1]}
    result = compute_recent(
        git,
        window(),
        {"head": {path: frozenset(lines) for path, lines in sites.items()}},
        scan_files=[PyFile(path, data) for path, data in files.items()],
        scan_tracked=tracked_from(git, files),
    )
    assert result.notes[:3] == (
        history.COMMIT_CAP_NOTE,
        history.SCAN_LINE_LIMIT_NOTE,
        history.SCAN_DIFF_BUDGET_NOTE,
    )
    assert result.notes[3:] == (history.bare_cr_note(1),)


def test_a_bare_cr_scan_file_is_noted_untracked_or_not_and_never_crashes() -> None:
    git = FakeGit([(TIP, when(1000))], [])
    files = {"a.py": b"x\ry\r", "b.py": b"p\nq\n", "c.py": b"u\r\nv\r\n"}
    result = scan(git, {"a.py": [1, 2], "b.py": [1], "c.py": [1]}, files, tracked={})
    assert result.notes == (history.bare_cr_note(1),)  # CRLF in c.py is not a bare CR
    assert recent_lines(result, "a.py") == {1, 2}


def test_a_bare_cr_file_without_site_lines_is_not_counted() -> None:
    git = FakeGit([(TIP, when(1000))], [])
    result = scan(git, {"b.py": [1]}, {"a.py": b"x\ry\r", "b.py": b"p\n"}, tracked={})
    assert result.notes == ()


def test_a_bare_cr_blob_changed_in_the_working_tree_is_diffed_without_a_crash() -> None:
    head_data, work_data = b"a\rb\n", b"a\rc\n"
    git = FakeGit(
        [(TIP, when(1000))],
        [],
        tree=[entry("a.py", head_data)],
        blobs={blob_id(head_data): head_data},
    )
    result = scan(git, {"a.py": [1]}, {"a.py": work_data})
    assert recent_lines(result, "a.py") == {1}
    assert result.notes == (history.bare_cr_note(1),)


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
        tracked: dict[str, TrackedState] = {}
        for file in files:  # what C4 computes: ls-tree id against the working-tree blob hash
            listed = repo.git("ls-tree", "HEAD", "--", file.path).split()
            if listed:
                tracked[file.path] = TrackedState(
                    listed[2], repo.git("hash-object", "--", file.path) == listed[2]
                )
        result = compute_recent(
            reader,
            Window(end=anchor, days=90, available=True, unavailable_reason=None),
            {"head": {path: frozenset(lines) for path, lines in sites.items()}},
            scan_files=files,
            scan_tracked=tracked,
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


def test_every_kind_of_scan_file_in_one_run_is_handled_and_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # One file of each kind, in path order, so no kind can end the run early, and two of
    # every counted kind, so each counter adds up.
    monkeypatch.setattr(history, "SCAN_LINE_LIMIT", 3)
    contents = {
        "bb.py": (rows("a", "b"), rows("a", "b")),  # unchanged: dated by history
        "c.py": (rows("a"), rows("a", "b", "c", "d")),  # working file over the line limit
        "d.py": (rows("a"), rows("a", "b", "c", "d")),  # and another
        "e.py": (rows("a", "b", "c", "d"), rows("a", "x")),  # HEAD blob over the line limit
        "f.py": (rows("a", "b", "c", "d"), rows("a", "x")),  # and another
        "g.py": (rows("a", "b"), b"a\nx\ry\n"),  # diffed (cost 4), bare CR
        "h.py": (rows("a", "b", "c"), rows("a", "z")),  # diffed (cost 6)
    }
    git, files = budget_git(contents)
    git.chain = [(TIP, when(1))]
    git.chunks = [marker(TIP) + file_diff(b"a.py", hunk(1, 0, 1, 1))]
    files["b.py"] = b"u\rv\n"  # untracked, bare CR
    sites = {"a.py": [1], "b.py": [1]} | {path: [1, 2] for path in contents}
    result = scan(git, sites, files)
    assert result.recent == {
        ("head", "a.py", 1),  # not a scan file: dated by history
        ("head", "b.py", 1),
        *(("head", f"{name}.py", line) for name in "cdef" for line in (1, 2)),
        ("head", "g.py", 2),
        ("head", "h.py", 2),
    }
    assert dict(result.stats) == {
        "scan_all_recent_line_limit": 4,
        "scan_all_recent_diff_budget": 0,
        "scan_diff_work": 4 + 6,
    }
    assert result.notes == (history.SCAN_LINE_LIMIT_NOTE, history.bare_cr_note(2))


def test_paths_that_are_not_utf8_sort_by_their_original_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # C4 keeps undecodable bytes with surrogateescape: b"\xff" sorts after b"\xee\x80\x80"
    # ("\ue000") as bytes, though "\udcff" sorts before "\ue000" as text.
    monkeypatch.setattr(history, "SCAN_DIFF_BUDGET", 1)
    raw, private = "\udcff.py", "\ue000.py"
    git, files = budget_git({raw: (rows("c"), rows("b")), private: (rows("a"), rows("b"))})
    result = scan(git, {raw: [1], private: [1]}, files)
    assert result.stats["scan_diff_work"] == 1
    assert result.stats["scan_all_recent_diff_budget"] == 1
    assert [call[0] for call in git.blob_calls] == [blob_id(rows("a")), blob_id(rows("c"))]
