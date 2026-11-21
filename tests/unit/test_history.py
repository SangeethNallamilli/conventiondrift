"""Unit tests for C8 history on in-memory stand-ins (T-020; DESIGN §10 S4, §12 A-5, I-14 item 9).

Names deliberately avoid the ``test_ac_`` prefix: the AC-named tests belong to the
Test Engineer. The AC or rule each case exercises is given in a comment instead.
"""

import dataclasses
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

import pytest
from history_support import END, FakeGit, file_diff, hunk, marker, sha, when, window

from conventiondrift import history
from conventiondrift.components import GitReaderProtocol, History, Side
from conventiondrift.errors import ComponentError, FileSkipped, GitUnavailable
from conventiondrift.history import (
    COMMIT_CAP,
    PATCH_MAX_BYTES,
    PRE_WINDOW_RUN,
    GitHistory,
    bare_cr_note,
    compute_recent,
)
from conventiondrift.model import HistoryResult, PyFile, TrackedState, Window

HEAD = sha(1)
NO_STATS = {
    "scan_all_recent_line_limit": 0,
    "scan_all_recent_diff_budget": 0,
    "scan_diff_work": 0,
}
Sites = dict[Side, dict[str, frozenset[int]]]


def lines(*numbers: int) -> frozenset[int]:
    return frozenset(numbers)


def recent_of(
    chain: Sequence[tuple[str, datetime]],
    patches: Sequence[bytes],
    sites: Sites,
    *,
    days: int = 90,
) -> frozenset[tuple[str, str, int]]:
    git = FakeGit(chain, patches)
    return compute_recent(git, window(days), sites, tips={"head": HEAD}).recent


def one_commit(
    days_before: float, *sections: bytes
) -> tuple[list[tuple[str, datetime]], list[bytes]]:
    return [(HEAD, when(days_before))], [marker(HEAD) + b"".join(sections)]


# ---------------------------------------------------------------- constants and seams


def test_caps_match_the_design_and_the_reader() -> None:
    # DESIGN S4 / A-3 / R2.6 numbers; COMMIT_CAP is the reader's --max-count (I-14 item 9).
    from conventiondrift import gitread

    assert COMMIT_CAP == 10_000 == gitread.MAX_COUNT_CAP
    assert PATCH_MAX_BYTES == 256 * 1024 * 1024
    assert PRE_WINDOW_RUN == 200
    assert history.SCAN_LINE_LIMIT == 5_000
    assert history.SCAN_DIFF_BUDGET == 200_000_000


def test_the_notes_use_the_pm_approved_wording() -> None:
    # D-PM-45: the numbers come from the cap constants.
    assert history.COMMIT_CAP_NOTE == (
        "History was limited to the newest 10,000 commits, so recent adherence may be incomplete."
    )
    assert history.PATCH_CAP_NOTE == (
        "History reading stopped at 256 MiB of patch text, so recent adherence may be incomplete."
    )
    assert history.SCAN_LINE_LIMIT_NOTE == (
        "Changed files over 5,000 lines were treated as entirely recent without a line diff, "
        "so recent adherence may be approximate."
    )
    assert history.SCAN_DIFF_BUDGET_NOTE == (
        "The line-diff budget ran out, so the remaining changed files were treated as entirely "
        "recent and recent adherence may be approximate."
    )


def test_the_bare_cr_note_gives_the_count() -> None:
    assert bare_cr_note(1) == (
        "1 file has bare carriage-return line endings, which git does not count as line breaks, "
        "so recent adherence may be approximate for it."
    )
    assert bare_cr_note(3) == (
        "3 files have bare carriage-return line endings, which git does not count as line breaks, "
        "so recent adherence may be approximate for them."
    )


def test_git_history_satisfies_the_history_protocol() -> None:
    component: History = GitHistory()
    got = component.recent(
        None, window(), {"head": {"a.py": lines(1)}}, scan_files=[PyFile("a.py", b"")]
    )
    assert got.recent == frozenset() and not got.available


def test_the_real_reader_type_is_accepted() -> None:
    git: GitReaderProtocol = FakeGit()
    assert compute_recent(git, window(), {}).recent == frozenset()


# ---------------------------------------------------------------- unavailable inputs


@pytest.mark.parametrize(
    "bad",
    [
        Window(end=None, days=90, available=False, unavailable_reason="no history"),
        Window(end=END, days=90, available=False, unavailable_reason="internal error"),
        Window(end=None, days=90, available=True, unavailable_reason=None),
    ],
)
def test_an_unavailable_window_is_empty_and_never_touches_git(bad: Window) -> None:
    git = FakeGit([(HEAD, END)], [marker(HEAD)])
    result = compute_recent(git, bad, {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert result == HistoryResult(frozenset(), False, (), NO_STATS)
    assert git.chain_calls == [] and git.patch_calls == []


def test_no_reader_means_recent_is_unavailable() -> None:
    # I-14 ruling 5: with no HEAD commit, available is False and the set is empty.
    result = compute_recent(None, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert result == HistoryResult(frozenset(), False, (), NO_STATS)


def test_an_available_result_says_so_and_carries_every_counter() -> None:
    chain, patches = one_commit(1, file_diff(b"a.py", hunk(1, 0, 1, 1)))
    result = compute_recent(
        FakeGit(chain, patches), window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD}
    )
    assert result.available and result.notes == () and dict(result.stats) == NO_STATS
    assert isinstance(result.stats, MappingProxyType)


def test_no_site_lines_means_no_git_calls() -> None:
    git = FakeGit([(HEAD, END)], [marker(HEAD)])
    sites: Sites = {"head": {}, "base": {"a.py": frozenset()}}
    assert compute_recent(git, window(), sites, tips={"head": HEAD}).recent == frozenset()
    assert git.chain_calls == []


@pytest.mark.parametrize(
    ("sites", "tips"),
    [
        ({"base": {"a.py": lines(1)}}, {"head": HEAD}),  # base sites, no base tip
        ({"head": {"a.py": lines(1)}}, {"base": HEAD}),  # head sites, no head tip
        ({"head": {"a.py": lines(1)}}, {}),  # no tips and no scan files: not scan mode
        ({"base": {"a.py": lines(1)}, "head": {"b.py": lines(1)}}, {"head": HEAD}),
    ],
)
def test_a_side_with_site_lines_and_no_tip_is_a_value_error(
    sites: Sites, tips: dict[Side, str]
) -> None:
    # I-14 ruling 1: a caller bug, raised before anything is read.
    git = FakeGit([(HEAD, END)], [marker(HEAD)])
    with pytest.raises(ValueError, match="no tip commit"):
        compute_recent(git, window(), sites, tips=tips)
    assert git.chain_calls == []


def test_a_missing_tip_is_a_value_error_even_when_recent_is_unavailable() -> None:
    bad = Window(end=None, days=90, available=False, unavailable_reason="no history")
    with pytest.raises(ValueError, match="no tip commit"):
        compute_recent(FakeGit(), bad, {"head": {"a.py": lines(1)}})


def test_a_side_with_no_site_lines_needs_no_tip() -> None:
    git = FakeGit([(HEAD, END)], [marker(HEAD)])
    sites: Sites = {"base": {"a.py": frozenset()}, "head": {}}
    assert compute_recent(git, window(), sites).available


def test_scan_mode_resolves_head_through_the_reader() -> None:
    # Scan mode (S3, I-14): no tips, scan files, and the reader's HEAD is the tip.
    git = FakeGit(
        [(sha(7), END)], [marker(sha(7)) + file_diff(b"a.py", hunk(1, 0, 1, 1))], head=sha(7)
    )
    tracked = {"a.py": TrackedState("c" * 40, True)}
    result = compute_recent(
        git,
        window(),
        {"head": {"a.py": lines(1)}},
        scan_files=[PyFile("a.py", b"x\n")],
        scan_tracked=tracked,
    )
    assert result.recent == {("head", "a.py", 1)}
    assert git.chain_calls == [(sha(7), COMMIT_CAP)]


def test_scan_mode_has_no_base_side() -> None:
    with pytest.raises(ValueError, match="no tip commit"):
        compute_recent(
            FakeGit([(HEAD, END)], [marker(HEAD)]),
            window(),
            {"base": {"a.py": lines(1)}},
            scan_files=[PyFile("a.py", b"x\n")],
        )


@pytest.mark.parametrize(
    "tips", [{"head": HEAD}, {"base": HEAD}, {"base": sha(2), "head": HEAD}], ids=str
)
@pytest.mark.parametrize("sites", [{"head": {"a.py": lines(1)}}, {}], ids=["sites", "no sites"])
def test_tips_and_scan_files_together_are_a_value_error(
    tips: dict[Side, str], sites: Sites
) -> None:
    # I-14 C8 ruling 7: a call is PR mode (tips) or scan mode (scan files), never both.
    git = FakeGit([(HEAD, END)], [marker(HEAD)])
    with pytest.raises(ValueError, match="different modes"):
        compute_recent(git, window(), sites, tips=tips, scan_files=[PyFile("a.py", b"x\n")])
    assert git.chain_calls == []


def test_tips_and_scan_files_are_a_value_error_even_when_recent_is_unavailable() -> None:
    bad = Window(end=None, days=90, available=False, unavailable_reason="no history")
    with pytest.raises(ValueError, match="different modes"):
        compute_recent(None, bad, {}, tips={"head": HEAD}, scan_files=[PyFile("a.py", b"x\n")])


def test_a_side_with_empty_site_lines_needs_no_tip_in_scan_mode() -> None:
    git = FakeGit([(HEAD, END)], [marker(HEAD)])
    sites: Sites = {"base": {"a.py": frozenset()}, "head": {}}
    result = compute_recent(git, window(), sites, scan_files=[PyFile("a.py", b"x\n")])
    assert result.available and git.chain_calls == []


# ---------------------------------------------------------------- classification


@pytest.mark.parametrize(
    ("days_before", "expected"),
    [
        (0, True),  # a commit at the window end is recent: start <= date <= end
        (89.999, True),
        (90, True),  # exactly at the window start is recent
        (90.001, False),
        (200, False),
        (-0.001, False),  # AC-F4.15: dated after the window end is never recent
        (-36500, False),  # forged 2099-style date
    ],
)
def test_classification_uses_closed_window_bounds(days_before: float, expected: bool) -> None:
    chain, patches = one_commit(days_before, file_diff(b"a.py", hunk(1, 0, 1, 1)))
    got = recent_of(chain, patches, {"head": {"a.py": lines(1)}})
    assert (got == {("head", "a.py", 1)}) is expected


def test_window_length_follows_history_days() -> None:
    # AC-F9.6: history-days 30 excludes a site changed 45 days before the head commit.
    chain, patches = one_commit(45, file_diff(b"a.py", hunk(1, 0, 1, 1)))
    sites: Sites = {"head": {"a.py": lines(1)}}
    assert recent_of(chain, patches, sites, days=30) == frozenset()
    assert recent_of(chain, patches, sites, days=90) == {("head", "a.py", 1)}


def test_a_window_end_before_the_year_one_does_not_overflow() -> None:
    early = datetime(1, 1, 2, tzinfo=UTC)
    chain = [(HEAD, early)]
    git = FakeGit(chain, [marker(HEAD) + file_diff(b"a.py", hunk(1, 0, 1, 1))])
    result = compute_recent(
        git, window(3650, early), {"head": {"a.py": lines(1)}}, tips={"head": HEAD}
    )
    assert result.recent == {("head", "a.py", 1)}


def test_a_forged_1971_anchor_completes() -> None:
    # AC-F4.15: a head commit dated 1971 only moves the window; nothing crashes.
    anchor = datetime(1971, 1, 1, tzinfo=UTC)
    git = FakeGit([(HEAD, anchor)], [marker(HEAD) + file_diff(b"a.py", hunk(1, 0, 1, 2))])
    got = compute_recent_with(git, window(90, anchor), {"head": {"a.py": lines(1, 2)}})
    assert got == {("head", "a.py", 1), ("head", "a.py", 2)}


def compute_recent_with(git: FakeGit, win: Window, sites: Sites) -> frozenset[tuple[str, str, int]]:
    return compute_recent(git, win, sites, tips={"head": HEAD}).recent


def test_only_lines_inside_the_plus_side_are_dated_by_a_commit() -> None:
    # S4: an untouched line is not recent, even in a recent commit.
    chain, patches = one_commit(1, file_diff(b"a.py", hunk(10, 0, 10, 2)))
    got = recent_of(chain, patches, {"head": {"a.py": lines(5, 9, 10, 11, 12, 20)}})
    assert got == {("head", "a.py", 10), ("head", "a.py", 11)}


def test_a_newer_commit_wins_over_an_older_one_for_the_same_line() -> None:
    # Newest first: the old, in-window commit never sees a line the newer, out-of-window one took.
    new_sha, old_sha = sha(1), sha(2)
    chain = [(new_sha, when(100)), (old_sha, when(10))]
    patches = [
        marker(new_sha) + file_diff(b"a.py", hunk(3, 1, 3, 1)),
        marker(old_sha) + file_diff(b"a.py", hunk(1, 0, 1, 5)),
    ]
    got = recent_of(chain, patches, {"head": {"a.py": lines(3, 4)}})
    assert got == {("head", "a.py", 4)}


def test_out_of_order_dates_cannot_make_an_older_commit_win() -> None:
    # S4: selection by position, not date. The newer commit carries an older date.
    new_sha, old_sha = sha(1), sha(2)
    chain = [(new_sha, when(300)), (old_sha, when(5))]
    patches = [
        marker(new_sha) + file_diff(b"a.py", hunk(1, 1, 1, 1)),
        marker(old_sha) + file_diff(b"a.py", hunk(1, 0, 1, 3)),
    ]
    got = recent_of(chain, patches, {"head": {"a.py": lines(1, 2, 3)}})
    assert got == {("head", "a.py", 2), ("head", "a.py", 3)}


def test_untracked_files_and_unknown_lines_are_not_recent() -> None:
    chain, patches = one_commit(1, file_diff(b"a.py", hunk(1, 0, 1, 1)))
    got = recent_of(chain, patches, {"head": {"other.py": lines(1), "a.py": lines(99)}})
    assert got == frozenset()


def test_each_side_is_dated_from_its_own_tip_with_one_window() -> None:
    # AC-F4.2: base and head share the window end; each reads its own commit's history.
    head_sha, base_sha = sha(1), sha(2)
    git = FakeGit(
        patches_for={
            head_sha: [marker(head_sha) + file_diff(b"a.py", hunk(1, 0, 1, 1))],
            base_sha: [marker(base_sha) + file_diff(b"a.py", hunk(1, 0, 1, 1))],
        },
        chains={head_sha: [(head_sha, when(10))], base_sha: [(base_sha, when(200))]},
    )
    result = compute_recent(
        git,
        window(),
        {"head": {"a.py": lines(1)}, "base": {"a.py": lines(1)}},
        tips={"head": head_sha, "base": base_sha},
    )
    assert result.recent == {("head", "a.py", 1)}
    assert [call[0] for call in git.chain_calls] == [base_sha, head_sha]


# ---------------------------------------------------------------- hunk arithmetic


def mapped(hunks: Sequence[bytes], site_lines: Sequence[int]) -> set[int]:
    chain = [(sha(1), when(1)), (sha(2), when(1000))]
    patches = [
        marker(sha(1)) + file_diff(b"a.py", *hunks),
        marker(sha(2)) + file_diff(b"a.py", hunk(1, 0, 1, 100)),
    ]
    got = recent_of(chain, patches, {"head": {"a.py": frozenset(site_lines)}})
    return {line for (_, _, line) in got}


@pytest.mark.parametrize(
    ("hunks", "expected"),
    [
        ([hunk(5, 0, 6, 2)], {6, 7}),  # insertion after old line 5
        ([hunk(5, 2, 4, 0)], set()),  # deletion: nothing is added
        ([hunk(5, 2, 5, 3)], {5, 6, 7}),  # replacement that grows
        ([hunk(5, 3, 5, 1)], {5}),  # replacement that shrinks
        ([hunk(1, 0, 1, 1), hunk(9, 0, 10, 1)], {1, 10}),  # two hunks
        ([hunk(1, 1, 1, 1)], {1}),  # one line replaced
        ([hunk(1, 1, 0, 0)], set()),  # the first line deleted
    ],
)
def test_hunks_date_exactly_their_plus_lines(hunks: Sequence[bytes], expected: set[int]) -> None:
    assert mapped(hunks, list(range(1, 15))) == expected


def test_lines_after_hunks_shift_back_before_older_commits_see_them() -> None:
    # An older, out-of-window commit added 100 lines; the newer commit inserted 2 lines at 6-7.
    # Old line 8 is now line 10, so site lines 10 and 11 map to old lines 8 and 9 (not recent).
    got = mapped([hunk(5, 0, 6, 2)], [5, 6, 7, 8, 10, 11])
    assert got == {6, 7}


def test_a_deletion_shifts_later_lines_up_before_older_commits_see_them() -> None:
    chain = [(sha(1), when(1000)), (sha(2), when(1))]
    patches = [
        marker(sha(1)) + file_diff(b"a.py", hunk(5, 2, 4, 0)),
        marker(sha(2)) + file_diff(b"a.py", hunk(7, 1, 7, 1)),
    ]
    # Site line 5 is old line 7 (two lines were deleted before it), which the recent commit
    # replaced; site line 6 is old line 8, which it did not touch.
    got = recent_of(chain, patches, {"head": {"a.py": lines(5, 6)}})
    assert got == {("head", "a.py", 5)}


def test_lines_are_dated_once_and_leave_the_walk() -> None:
    chain = [(sha(1), when(1)), (sha(2), when(2))]
    patches = [
        marker(sha(1)) + file_diff(b"a.py", hunk(2, 1, 2, 1)),
        marker(sha(2)) + file_diff(b"a.py", hunk(1, 0, 1, 3)),
    ]
    got = recent_of(chain, patches, {"head": {"a.py": lines(1, 2, 3)}})
    assert got == {("head", "a.py", n) for n in (1, 2, 3)}


# ---------------------------------------------------------------- renames and file lifecycle


def test_a_pure_rename_moves_the_tracked_lines_to_the_old_path() -> None:
    # AC-E.8 / F-1: a 100% rename has no hunks; the older commit's lines follow the rename.
    new_sha, old_sha = sha(1), sha(2)
    chain = [(new_sha, when(100)), (old_sha, when(1))]
    patches = [
        marker(new_sha) + file_diff(b"new.py", rename_from=b"old.py", old=b"old.py", new=b"new.py"),
        marker(old_sha) + file_diff(b"old.py", hunk(1, 0, 1, 2)),
    ]
    got = recent_of(chain, patches, {"head": {"new.py": lines(1, 2)}})
    assert got == {("head", "new.py", 1), ("head", "new.py", 2)}


def test_a_rename_with_edits_maps_through_its_hunks_and_the_rename() -> None:
    new_sha, old_sha = sha(1), sha(2)
    chain = [(new_sha, when(100)), (old_sha, when(1))]
    patches = [
        marker(new_sha)
        + file_diff(
            b"new.py", hunk(1, 0, 1, 1), rename_from=b"old.py", old=b"old.py", new=b"new.py"
        ),
        marker(old_sha) + file_diff(b"old.py", hunk(1, 0, 1, 3)),
    ]
    got = recent_of(chain, patches, {"head": {"new.py": lines(1, 2, 3)}})
    assert got == {("head", "new.py", 2), ("head", "new.py", 3)}


def test_a_file_created_in_a_commit_dates_all_its_lines_and_stops() -> None:
    chain = [(sha(1), when(1)), (sha(2), when(1))]
    created = file_diff(
        b"a.py", hunk(0, 0, 1, 3), old=b"/dev/null", header=b"new file mode 100644\n"
    )
    git = FakeGit(chain, [marker(sha(1)) + created + marker(sha(2)), b"never read"])
    got = compute_recent(git, window(), {"head": {"a.py": lines(1, 2, 3, 4)}}, tips={"head": HEAD})
    # Line 4 does not exist in the created file: it cannot be traced further, so the walk is over.
    assert got.recent == {("head", "a.py", n) for n in (1, 2, 3)}
    assert git.consumed == 1 and git.closed == 1


def test_a_deleted_then_recreated_path_does_not_leak_old_lines() -> None:
    recreated, deleted, original = sha(1), sha(2), sha(3)
    chain = [(recreated, when(500)), (deleted, when(5)), (original, when(1))]
    patches = [
        marker(recreated) + file_diff(b"a.py", hunk(0, 0, 1, 1), old=b"/dev/null"),
        marker(deleted) + file_diff(b"a.py", hunk(1, 1, 0, 0), new=b"/dev/null"),
        marker(original) + file_diff(b"a.py", hunk(0, 0, 1, 1), old=b"/dev/null"),
    ]
    got = recent_of(chain, patches, {"head": {"a.py": lines(1)}})
    assert got == frozenset()


def test_a_mode_change_moves_nothing() -> None:
    chain = [(sha(1), when(100)), (sha(2), when(1))]
    patches = [
        marker(sha(1)) + b"diff --git a/a.py b/a.py\nold mode 100644\nnew mode 100755\n",
        marker(sha(2)) + file_diff(b"a.py", hunk(1, 0, 1, 1)),
    ]
    assert recent_of(chain, patches, {"head": {"a.py": lines(1)}}) == {("head", "a.py", 1)}


def test_other_files_in_a_commit_are_ignored() -> None:
    chain = [(sha(1), when(1))]
    patches = [
        marker(sha(1))
        + file_diff(b"x.py", hunk(1, 5, 1, 5))
        + file_diff(b"a.py", hunk(2, 0, 2, 1))
        + file_diff(b"y.py", hunk(1, 5, 1, 5))
    ]
    assert recent_of(chain, patches, {"head": {"a.py": lines(1, 2)}}) == {("head", "a.py", 2)}


def test_a_rename_of_an_untracked_file_is_ignored() -> None:
    chain = [(sha(1), when(1))]
    patches = [
        marker(sha(1))
        + file_diff(b"new.py", rename_from=b"old.py", old=b"old.py", new=b"new.py")
        + file_diff(b"a.py", hunk(1, 0, 1, 1))
    ]
    assert recent_of(chain, patches, {"head": {"a.py": lines(1)}}) == {("head", "a.py", 1)}


def test_a_rename_onto_a_tracked_path_is_an_internal_error() -> None:
    # Two tip files can never share one path in a commit; stray patch text must not corrupt state.
    chain = [(sha(1), when(1))]
    patches = [
        marker(sha(1))
        + file_diff(b"a.py", hunk(1, 0, 1, 1), rename_from=b"b.py", old=b"b.py", new=b"a.py")
    ]
    with pytest.raises(ComponentError) as raised:
        compute_recent(
            FakeGit(chain, patches),
            window(),
            {"head": {"a.py": lines(2), "b.py": lines(1)}},
            tips={"head": HEAD},
        )
    assert raised.value.component == "history"


# ---------------------------------------------------------------- parser rules


def test_hunk_header_function_text_is_ignored() -> None:
    # I-14 item 9 (SR): xfuncname text after the second @@ is attacker-controlled.
    hostile = b" @@ -1,9 +1,9 @@ +++ b/evil.py\n+++ b/evil.py"
    chain, patches = one_commit(1, file_diff(b"a.py", hunk(1, 0, 1, 2, tail=hostile)))
    assert recent_of(chain, patches, {"head": {"a.py": lines(1, 2)}}) == {
        ("head", "a.py", 1),
        ("head", "a.py", 2),
    }


@pytest.mark.parametrize(
    "content",
    [
        b"+++ b/a.py",
        b"--- a/a.py",
        b"diff --git a/b.py b/b.py",
        b"\x00" + b"f" * 40,
        b"@@ -1 +1 @@",
        b"rename to evil.py",
        b"\\ not a marker",
    ],
)
def test_content_lines_that_look_like_headers_are_skipped_by_count(content: bytes) -> None:
    body = b"@@ -1,0 +1,2 @@\n+" + content + b"\n+second\n"
    chain = [(sha(1), when(1)), (sha(2), when(1000))]
    patches = [
        marker(sha(1)) + b"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n" + body,
        marker(sha(2)) + file_diff(b"a.py", hunk(1, 0, 1, 9)),
    ]
    got = recent_of(chain, patches, {"head": {"a.py": lines(1, 2, 3)}})
    assert got == {("head", "a.py", 1), ("head", "a.py", 2)}


def test_no_newline_markers_do_not_count_as_hunk_lines() -> None:
    body = (
        b"@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
        b"@@ -5,0 +6 @@\n+added\n"
    )
    chain = [(sha(1), when(1)), (sha(2), when(1000))]
    patches = [
        marker(sha(1)) + b"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n" + body,
        marker(sha(2)) + file_diff(b"a.py", hunk(1, 0, 1, 9)),
    ]
    got = recent_of(chain, patches, {"head": {"a.py": lines(1, 2, 6, 7)}})
    assert got == {("head", "a.py", 1), ("head", "a.py", 6)}


def test_a_content_line_after_a_no_newline_marker_is_still_content() -> None:
    body = b"@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+++ b/evil.py\n"
    chain = [(sha(1), when(1)), (sha(2), when(1000))]
    patches = [
        marker(sha(1)) + b"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n" + body,
        marker(sha(2)) + file_diff(b"a.py", hunk(1, 0, 1, 9)),
    ]
    assert recent_of(chain, patches, {"head": {"a.py": lines(1, 2)}}) == {("head", "a.py", 1)}


def split_every(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


@pytest.mark.parametrize("size", [1, 2, 3, 7, 64])
def test_markers_and_headers_split_across_chunks_parse_the_same(size: int) -> None:
    # I-14 item 9: T-020 must handle commit markers split across chunks.
    chain = [(sha(1), when(1)), (sha(2), when(1000))]
    text = (
        marker(sha(1))
        + file_diff(b"a.py", hunk(2, 1, 2, 2))
        + marker(sha(2))
        + file_diff(b"a.py", hunk(1, 0, 1, 9))
    )
    git = FakeGit(chain, split_every(text, size))
    got = compute_recent(git, window(), {"head": {"a.py": lines(1, 2, 3, 4)}}, tips={"head": HEAD})
    assert got.recent == {("head", "a.py", 2), ("head", "a.py", 3)}


def test_a_final_line_without_a_newline_is_read() -> None:
    chain = [(sha(1), when(1))]
    text = marker(sha(1)) + file_diff(b"a.py", hunk(1, 0, 1, 1)).rstrip(b"\n")
    got = compute_recent(
        FakeGit(chain, [text]), window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD}
    )
    assert got.recent == {("head", "a.py", 1)}


def test_the_commit_marker_may_be_a_sha256_object_name() -> None:
    big = "ab" * 32
    chain = [(big, when(1))]
    text = b"\x00" + big.encode() + b"\n" + file_diff(b"a.py", hunk(1, 0, 1, 1))
    got = compute_recent(
        FakeGit(chain, [text]), window(), {"head": {"a.py": lines(1)}}, tips={"head": big}
    )
    assert got.recent == {("head", "a.py", 1)}


def test_commits_with_no_diff_may_be_missing_from_the_stream() -> None:
    # An empty commit prints no section, and the stream may skip it entirely.
    chain = [(sha(1), when(1)), (sha(2), when(2)), (sha(3), when(3))]
    patches = [marker(sha(1)), marker(sha(3)) + file_diff(b"a.py", hunk(1, 0, 1, 1))]
    assert recent_of(chain, patches, {"head": {"a.py": lines(1)}}) == {("head", "a.py", 1)}


QUOTED = [
    (b'"a/caf\\303\\251.py"', "café.py"),
    (b'"a/tab\\there.py"', "tab\there.py"),
    (b'"a/quo\\"te\\\\.py"', 'quo"te\\.py'),
    (b'"a/\\a\\b\\n\\v\\f\\r.py"', "\a\b\n\v\f\r.py"),
    (b'"a/\\377.py"', "\udcff.py"),
    (b"a/plain name.py\t", "plain name.py"),
    (b'"a/ends\\t"', "ends\t"),
]


@pytest.mark.parametrize(("token", "path"), QUOTED)
def test_quoted_and_spaced_paths_are_read_back_exactly(token: bytes, path: str) -> None:
    # I-14 item 9: T-020 unquotes C-quoted paths (core.quotePath=true).
    plus = (
        token.replace(b'"a/', b'"b/', 1)
        if token.startswith(b'"')
        else token.replace(b"a/", b"b/", 1)
    )
    section = b"diff --git x y\n--- " + token + b"\n+++ " + plus + b"\n" + hunk(1, 0, 1, 1)
    chain = [(sha(1), when(1))]
    got = compute_recent(
        FakeGit(chain, [marker(sha(1)) + section]),
        window(),
        {"head": {path: lines(1)}},
        tips={"head": HEAD},
    )
    assert got.recent == {("head", path, 1)}


def test_quoted_rename_lines_are_unquoted() -> None:
    new_sha, old_sha = sha(1), sha(2)
    chain = [(new_sha, when(100)), (old_sha, when(1))]
    patches = [
        marker(new_sha)
        + b"diff --git x y\nsimilarity index 100%\n"
        + b'rename from "caf\\303\\251.py"\nrename to plain.py\n',
        marker(old_sha)
        + b'diff --git x y\n--- /dev/null\n+++ "b/caf\\303\\251.py"\n'
        + hunk(0, 0, 1, 1),
    ]
    got = recent_of(chain, patches, {"head": {"plain.py": lines(1)}})
    assert got == {("head", "plain.py", 1)}


@pytest.mark.parametrize(
    "broken",
    [
        b"diff --git x y\n--- a/a.py\n+++ c/a.py\n" + hunk(1, 0, 1, 1),  # wrong prefix
        b'diff --git x y\n--- a/a.py\n+++ "b/unterminated\n' + hunk(1, 0, 1, 1),
        b'diff --git x y\n--- a/a.py\n+++ "b/bad\\q.py"\n' + hunk(1, 0, 1, 1),
        b'diff --git x y\n--- a/a.py\n+++ "b/bad\\777.py"\n' + hunk(1, 0, 1, 1),
        b"diff --git x y\n--- a/a.py\n+++ b/a.py\n@@ nonsense @@\n",
        b"diff --git x y\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,99999999999999 @@\n+x\n",
    ],
)
def test_unreadable_patch_text_is_an_internal_error(broken: bytes) -> None:
    git = FakeGit([(sha(1), when(1))], [marker(sha(1)) + broken])
    with pytest.raises(ComponentError) as raised:
        compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert raised.value.component == "history"
    assert git.closed == 1


_AFTER_HUNK_VALUE = {b"--- ": b"a/b.py", b"+++ ": b"b/b.py"}


@pytest.mark.parametrize("prefix", history._SECTION_HEADERS)
def test_a_file_name_line_after_a_hunk_is_an_internal_error(prefix: bytes) -> None:
    # Git writes names before the first hunk; a later one would re-point mapped lines.
    late = prefix + _AFTER_HUNK_VALUE.get(prefix, b"b.py") + b"\n"
    git = FakeGit(
        [(sha(1), when(1))], [marker(sha(1)) + file_diff(b"a.py", hunk(1, 0, 1, 1)) + late]
    )
    with pytest.raises(ComponentError) as raised:
        compute_recent(git, window(), {"head": {"a.py": lines(1, 2)}}, tips={"head": HEAD})
    assert raised.value.component == "history"
    assert git.closed == 1


def test_a_no_newline_marker_after_the_last_hunk_is_not_a_file_name_line() -> None:
    section = file_diff(b"a.py", hunk(1, 0, 1, 1)) + b"\\ No newline at end of file\n"
    chain = [(sha(1), when(1))]
    assert recent_of(chain, [marker(sha(1)) + section], {"head": {"a.py": lines(1)}}) == {
        ("head", "a.py", 1)
    }


@pytest.mark.parametrize(
    "stream",
    [
        [b"\x00" + b"f" * 40 + b"\n"],  # a commit that is not in the chain
        [b"\x00nothex\n"],
        [marker(sha(1)) + marker(sha(1))],  # the same commit twice
        [marker(sha(2)) + marker(sha(1))],  # out of chain order
    ],
)
def test_commit_markers_must_follow_the_chain(stream: list[bytes]) -> None:
    git = FakeGit([(sha(1), when(1)), (sha(2), when(2))], stream)
    with pytest.raises(ComponentError):
        compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})


def test_a_stream_that_ends_inside_a_hunk_is_an_internal_error() -> None:
    git = FakeGit(
        [(sha(1), when(1))],
        [marker(sha(1)) + b"diff --git x y\n--- a/a.py\n+++ b/a.py\n@@ -1,0 +1,3 @@\n+one\n"],
    )
    with pytest.raises(ComponentError):
        compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})


def test_text_outside_any_section_is_ignored() -> None:
    chain = [(sha(1), when(1))]
    text = b"stray\n" + marker(sha(1)) + b"noise\nindex x\n" + file_diff(b"a.py", hunk(1, 0, 1, 1))
    assert recent_of(chain, [text], {"head": {"a.py": lines(1)}}) == {("head", "a.py", 1)}


def test_an_empty_chain_has_no_recent_lines() -> None:
    git = FakeGit([], [])
    assert (
        compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD}).recent
        == frozenset()
    )
    assert git.patch_calls == []


# ---------------------------------------------------------------- segment selection (S4)


def long_chain(count: int, date_for: Callable[[int], datetime]) -> list[tuple[str, datetime]]:
    return [(sha(i + 1), date_for(i)) for i in range(count)]


def test_the_walk_stops_after_200_consecutive_pre_window_commits() -> None:
    chain = long_chain(300, lambda i: when(0 if i == 0 else 100 + i))
    git = FakeGit(chain, [marker(HEAD)])
    result = compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    # Commit 0 is in the window; commits 1..200 are the 200 consecutive old ones.
    assert git.patch_calls == [(chain[201][0], HEAD)]
    assert result.notes == ()


def test_an_in_window_or_future_commit_resets_the_run() -> None:
    def date(i: int) -> datetime:
        if i == 150:
            return when(10)  # in the window
        if i == 340:
            return END + timedelta(days=5)  # future-dated: not "before the window start"
        return when(100 + i)

    chain = long_chain(600, date)
    git = FakeGit(chain, [])
    compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    # Runs: 0..149 (150), then 151..339 (189), then 341.. -> the 200th is index 540.
    assert git.patch_calls == [(chain[541][0], HEAD)]


def test_a_commit_dated_exactly_at_the_window_start_is_not_pre_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(history, "PRE_WINDOW_RUN", 2)
    dates = [when(0), when(100), when(90), when(100), when(100), when(100)]
    chain = [(sha(i + 1), date) for i, date in enumerate(dates)]
    git = FakeGit(chain, [])
    compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    # "Before the window start" is strict: the commit at day 90 resets the run.
    assert git.patch_calls == [(chain[5][0], HEAD)]


def test_199_old_commits_do_not_stop_the_walk() -> None:
    chain = long_chain(199, lambda i: when(100 + i))
    git = FakeGit(chain, [])
    compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert git.patch_calls == [(None, HEAD)]  # the segment reaches the root


def sites_a() -> Sites:
    return {"head": {"a.py": lines(1)}}


@pytest.mark.parametrize(
    ("count", "note"),
    [(COMMIT_CAP - 1, False), (COMMIT_CAP, False), (COMMIT_CAP + 1, True), (COMMIT_CAP + 5, True)],
)
def test_the_commit_cap_note_needs_a_commit_past_the_cap(count: int, note: bool) -> None:
    # I-14 ruling 6d: a chain of exactly 10,000 is not a cap hit; one more commit is.
    chain = long_chain(count, lambda i: when(i / 1000))
    git = FakeGit(chain, [])
    result = compute_recent(git, window(), sites_a(), tips={"head": HEAD})
    assert result.notes == ((history.COMMIT_CAP_NOTE,) if note else ())
    assert git.chain_calls[0] == (HEAD, COMMIT_CAP)  # never asks the reader for more than its cap
    assert max(limit for _, limit in git.chain_calls) <= COMMIT_CAP


def test_a_chain_of_exactly_the_cap_asks_for_the_commit_after_the_oldest() -> None:
    chain = long_chain(COMMIT_CAP, lambda i: when(i / 1000))
    git = FakeGit(chain, [])
    compute_recent(git, window(), sites_a(), tips={"head": HEAD})
    assert git.chain_calls == [(HEAD, COMMIT_CAP), (chain[-1][0], 2)]
    assert git.patch_calls == [(None, HEAD)]


def test_the_commit_cap_probe_is_not_made_when_every_line_was_dated() -> None:
    chain = long_chain(COMMIT_CAP + 1, lambda i: when(i / 1000))
    patches = [marker(HEAD) + file_diff(b"a.py", hunk(1, 0, 1, 1))]
    git = FakeGit(chain, patches)
    result = compute_recent(git, window(), sites_a(), tips={"head": HEAD})
    assert result.notes == () and result.recent == {("head", "a.py", 1)}
    assert git.chain_calls == [(HEAD, COMMIT_CAP)]


def test_a_chain_cut_at_the_cap_reads_the_first_10000_commits_only() -> None:
    chain = long_chain(COMMIT_CAP + 1, lambda i: when(i / 1000))
    git = FakeGit(chain, [])
    compute_recent(git, window(), sites_a(), tips={"head": HEAD})
    assert git.patch_calls == [(None, HEAD)]  # the reader's own --max-count bounds the stream


def test_a_failing_cap_probe_is_an_internal_error() -> None:
    class NoProbe(FakeGit):
        def first_parent_chain(self, sha: str, limit: int) -> Sequence[tuple[str, datetime]]:
            if limit == 2:
                raise GitUnavailable()
            return super().first_parent_chain(sha, limit)

    git = NoProbe(long_chain(COMMIT_CAP, lambda i: when(i / 1000)), [])
    with pytest.raises(ComponentError) as raised:
        compute_recent(git, window(), sites_a(), tips={"head": HEAD})
    assert raised.value.component == "history"


def test_no_commit_cap_note_when_every_line_was_dated() -> None:
    chain = long_chain(COMMIT_CAP + 1, lambda i: when(i / 1000))
    patches = [marker(HEAD) + file_diff(b"a.py", hunk(1, 0, 1, 1))]
    git = FakeGit(chain, patches)
    result = compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert result.notes == ()
    assert result.recent == {("head", "a.py", 1)}


def test_the_200_run_ending_exactly_at_the_cap_is_not_a_cap_hit() -> None:
    chain = long_chain(COMMIT_CAP, lambda i: when(100 + i) if i >= COMMIT_CAP - 200 else when(1))
    git = FakeGit(chain, [])
    result = compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert result.notes == ()


# ---------------------------------------------------------------- patch-byte cap (A-5)


def test_the_patch_cap_stops_reading_closes_the_stream_and_notes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A-5: newest commits first; lines not yet dated are not recent, with a note.
    monkeypatch.setattr(history, "PATCH_MAX_BYTES", 400)
    newest, oldest = sha(1), sha(2)
    chain = [(newest, when(1)), (oldest, when(2))]
    first = marker(newest) + file_diff(b"a.py", hunk(1, 0, 1, 1))
    second = (
        marker(oldest) + file_diff(b"a.py", hunk(1, 0, 1, 1)) + file_diff(b"b.py", hunk(1, 0, 1, 1))
    )
    git = FakeGit(chain, [first, marker(oldest) + b"x" * 400, second])
    got = compute_recent(
        git,
        window(),
        {"head": {"a.py": lines(1, 2), "b.py": lines(1)}},
        tips={"head": HEAD},
    )
    assert got.recent == {("head", "a.py", 1)}
    assert got.notes == (history.PATCH_CAP_NOTE,)
    assert git.consumed == 2 and git.closed == 1


def test_hunks_read_before_the_patch_cap_still_count(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hunk header is complete once read, so a section cut by the cap keeps what it already said.
    text = marker(sha(1)) + file_diff(b"a.py", hunk(1, 0, 1, 1), hunk(5, 0, 6, 1))
    cut_at = text.index(b"@@ -5")
    monkeypatch.setattr(history, "PATCH_MAX_BYTES", cut_at)
    git = FakeGit([(sha(1), when(1))], [text[:cut_at], text[cut_at:]])
    got = compute_recent(git, window(), {"head": {"a.py": lines(1, 6)}}, tips={"head": HEAD})
    assert got.recent == {("head", "a.py", 1)}
    assert got.notes == (history.PATCH_CAP_NOTE,)
    assert git.consumed == 1 and git.closed == 1


def test_a_hunk_header_cut_in_half_by_the_patch_cap_is_not_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = marker(sha(1)) + file_diff(b"a.py", hunk(1, 0, 1, 1))
    cut_at = text.index(b"@@ -1") + 5
    monkeypatch.setattr(history, "PATCH_MAX_BYTES", cut_at)
    git = FakeGit([(sha(1), when(1))], [text[:cut_at], text[cut_at:]])
    got = compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert got.recent == frozenset()
    assert got.notes == (history.PATCH_CAP_NOTE,)


def test_hunks_that_overlap_are_an_internal_error() -> None:
    git = FakeGit(
        [(sha(1), when(1))],
        [marker(sha(1)) + file_diff(b"a.py", hunk(1, 0, 1, 5), hunk(1, 1, 4, 1))],
    )
    with pytest.raises(ComponentError):
        compute_recent(git, window(), {"head": {"a.py": lines(1, 4)}}, tips={"head": HEAD})


def test_hunks_that_go_backwards_are_an_internal_error() -> None:
    git = FakeGit(
        [(sha(1), when(1))],
        [marker(sha(1)) + file_diff(b"a.py", hunk(9, 0, 10, 1), hunk(1, 0, 1, 1))],
    )
    with pytest.raises(ComponentError):
        compute_recent(git, window(), {"head": {"a.py": lines(1, 10)}}, tips={"head": HEAD})


def test_hitting_the_cap_with_nothing_left_to_date_has_no_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(history, "PATCH_MAX_BYTES", 10)
    chain = [(sha(1), when(1)), (sha(2), when(2))]
    first = marker(sha(1)) + file_diff(b"a.py", hunk(1, 0, 1, 1))
    git = FakeGit(chain, [first + marker(sha(2)), b"never read"])
    got = compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert got.notes == ()
    assert git.closed == 1


def test_reading_stops_as_soon_as_every_line_is_dated() -> None:
    chain = [(sha(1), when(1)), (sha(2), when(2))]
    chunks = [marker(sha(1)) + file_diff(b"a.py", hunk(1, 0, 1, 1)) + marker(sha(2)), b"more"]
    git = FakeGit(chain, chunks)
    got = compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert got.recent == {("head", "a.py", 1)}
    assert git.consumed == 1 and git.closed == 1


# ---------------------------------------------------------------- failure path


class _Raises(FakeGit):
    """A reader whose first_parent_chain raises ``error``."""

    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def first_parent_chain(self, sha: str, limit: int) -> Sequence[tuple[str, datetime]]:
        raise self.error


@pytest.mark.parametrize(
    "error",
    [
        ComponentError("gitread", "git log failed (exit 128)"),
        GitUnavailable("no git"),
        FileSkipped("size limit"),
        MemoryError(),
    ],
)
def test_reader_failures_become_a_history_component_error(error: BaseException) -> None:
    # I-11 C8 / DESIGN §4: a history failure shows recent as unavailable.
    with pytest.raises(ComponentError) as raised:
        compute_recent(_Raises(error), window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert raised.value.component == "history"
    assert raised.value.__cause__ is error
    assert "gitread" not in raised.value.message


def test_a_history_error_passes_through_unchanged() -> None:
    error = ComponentError("history", "x")
    with pytest.raises(ComponentError) as raised:
        compute_recent(_Raises(error), window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert raised.value is error


def test_other_errors_are_not_swallowed() -> None:
    with pytest.raises(KeyboardInterrupt):
        compute_recent(
            _Raises(KeyboardInterrupt()),
            window(),
            {"head": {"a.py": lines(1)}},
            tips={"head": HEAD},
        )


def test_the_patch_stream_is_closed_when_reading_fails_midway() -> None:
    class Failing(FakeGit):
        def _stream(self, chunks: Sequence[bytes]):  # type: ignore[no-untyped-def]
            try:
                yield marker(sha(1))
                raise ComponentError("gitread", "timed out")
            finally:
                self.closed += 1

    git = Failing([(sha(1), when(1))], [])
    with pytest.raises(ComponentError) as raised:
        compute_recent(git, window(), {"head": {"a.py": lines(1)}}, tips={"head": HEAD})
    assert raised.value.component == "history"
    assert git.closed == 1


# ---------------------------------------------------------------- GitHistory


def test_git_history_keeps_no_state_between_calls() -> None:
    component = GitHistory()
    chain = long_chain(COMMIT_CAP + 1, lambda i: when(i / 1000))
    first = component.recent(FakeGit(chain, []), window(), sites_a(), tips={"head": HEAD})
    second = component.recent(FakeGit(chain[:3], []), window(), sites_a(), tips={"head": HEAD})
    assert first.notes == (history.COMMIT_CAP_NOTE,) and second.notes == ()
    assert not hasattr(component, "notes") and not hasattr(component, "stats")
    assert vars(component) == {}


def test_git_history_takes_the_tips_in_the_call() -> None:
    head_sha, base_sha = sha(1), sha(2)
    git = FakeGit(
        patches_for={base_sha: [marker(base_sha) + file_diff(b"a.py", hunk(1, 0, 1, 1))]},
        chains={base_sha: [(base_sha, when(1))]},
    )
    got = GitHistory().recent(
        git, window(), {"base": {"a.py": lines(1)}}, tips={"head": head_sha, "base": base_sha}
    )
    assert got.recent == {("base", "a.py", 1)}


def test_results_are_immutable() -> None:
    result = HistoryResult(frozenset(), True, (), NO_STATS)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.notes = ("x",)  # type: ignore[misc]
    with pytest.raises(TypeError):
        result.stats["scan_diff_work"] = 1  # type: ignore[index]


# ---------------------------------------------------------------- bare CR (I-14 ruling 6c)


def cr_hunk(
    old_start: int, old_count: int, new_start: int, new_count: int, content: bytes
) -> bytes:
    """A hunk whose ``+`` lines are ``content`` (each line without its newline)."""
    head = hunk(old_start, old_count, new_start, new_count).split(b"\n", 1)[0]
    return (
        head
        + b"\n"
        + b"".join(b"-old line\n" for _ in range(old_count))
        + (b"".join(b"+" + row + b"\n" for row in content.split(b"\n")[:new_count]))
    )


def test_a_bare_cr_in_a_tracked_files_hunks_is_noted_once_with_the_count() -> None:
    sections = (
        file_diff(b"a.py", cr_hunk(1, 0, 1, 2, b"x\ry\nz")),  # bare CR inside a line
        file_diff(b"b.py", cr_hunk(1, 0, 1, 2, b"x\r\nz\r\r\nq")),  # CRLF endings and a CR CR LF
        file_diff(b"c.py", cr_hunk(1, 0, 1, 1, b"plain")),
        file_diff(b"untracked.py", cr_hunk(1, 0, 1, 1, b"u\rv")),  # nothing tracked: not read
    )
    git = FakeGit([(HEAD, when(1))], [marker(HEAD) + b"".join(sections)])
    sites: Sites = {"head": {"a.py": lines(1, 2), "b.py": lines(1, 2), "c.py": lines(1)}}
    result = compute_recent(git, window(), sites, tips={"head": HEAD})
    assert result.notes == (bare_cr_note(2),)  # a.py and b.py ("z\r\r" has a bare CR)
    assert ("head", "a.py", 1) in result.recent  # dated by its newlines, no crash


def test_a_file_with_only_crlf_endings_is_not_noted() -> None:
    chain, patches = one_commit(1, file_diff(b"a.py", cr_hunk(1, 0, 1, 2, b"x\r\ny\r")))
    result = compute_recent(FakeGit(chain, patches), window(), sites_a(), tips={"head": HEAD})
    assert result.notes == ()


def test_one_bare_cr_file_read_on_both_sides_counts_once() -> None:
    both = marker(sha(1)) + file_diff(b"a.py", cr_hunk(1, 0, 1, 1, b"x\ry"))
    git = FakeGit(
        patches_for={sha(1): [both], sha(2): [both.replace(sha(1).encode(), sha(2).encode())]},
        chains={sha(1): [(sha(1), when(1))], sha(2): [(sha(2), when(1))]},
    )
    result = compute_recent(
        git,
        window(),
        {"head": {"a.py": lines(1)}, "base": {"a.py": lines(1)}},
        tips={"head": sha(1), "base": sha(2)},
    )
    assert result.notes == (bare_cr_note(1),)
