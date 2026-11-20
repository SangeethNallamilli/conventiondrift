"""Unit tests for the rule start column that C6 extraction records (T-015, I-13 rule ids).

The column is 1-based, counted in characters of the line as written (a tab is one),
and is where the rule's first character is, including after an I-7 marker.
"""

import pytest

from conventiondrift.rules.extract import MARKER, Candidate, extract_file, segment


def _columns(text: str, path: str = "AGENTS.md") -> list[tuple[int, int]]:
    return [(r.line, r.column) for r in extract_file(path, text.encode()).rules]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Use a.\n", [(1, 1)]),
        ("  Use a.\n", [(1, 3)]),
        ("- Use a.\n", [(1, 3)]),
        ("-   Use a.\n", [(1, 5)]),
        ("  * Use a.\n", [(1, 5)]),
        ("12. Use a.\n", [(1, 5)]),
        ("\tUse a.\n", [(1, 2)]),
        ("Use a. Use b.\n", [(1, 1), (1, 8)]),
        ("- Use a.   Never b.\n", [(1, 3), (1, 12)]),
        ("Hello there. Use a.\n", [(1, 14)]),
        ("Use a\nand more. Use b.\n", [(1, 1), (2, 11)]),
        ("Use a\n  continued. Never b.\n", [(1, 1), (2, 14)]),
        ("Intro\n\nUse a.\n", [(3, 1)]),
        ("é Use a. Use b.\n", [(1, 10)]),
    ],
)
def test_column_is_the_one_based_character_column(
    text: str, expected: list[tuple[int, int]]
) -> None:
    assert _columns(text) == expected


def test_column_after_a_trailing_marker_is_unchanged() -> None:
    assert _columns(f"- Use a. {MARKER}\n") == [(1, 3)]


def test_column_counts_the_marker_before_the_rule_in_the_line_as_written() -> None:
    # The marker is replaced by one space for splitting, but the column is in the original line.
    text = f"{MARKER} Use a.\n"
    assert _columns(text) == [(1, len(MARKER) + 2)]


def test_column_after_two_markers_counts_both() -> None:
    text = f"{MARKER}{MARKER}Use a. Use b.\n"
    start = 2 * len(MARKER)
    assert _columns(text) == [(1, start + 1), (1, start + 8)]


def test_column_after_three_markers_counts_all_three() -> None:
    text = f"{MARKER}{MARKER}{MARKER}Use a. Use b.\n"
    start = 3 * len(MARKER)
    assert _columns(text) == [(1, start + 1), (1, start + 8)]


def test_column_counts_only_the_markers_before_the_rule() -> None:
    text = f"{MARKER}Use a. {MARKER}{MARKER} Use b.\n"
    first = len(MARKER) + 1
    second = first + len("Use a. ") + 2 * len(MARKER) + 1
    assert _columns(text) == [(1, first), (1, second)]


def test_column_between_a_marker_and_a_later_sentence() -> None:
    text = f"Use a. {MARKER} Use b.\n"
    assert _columns(text) == [(1, 1), (1, 8 + len(MARKER) + 1)]


def test_candidates_carry_the_column_but_compare_without_it() -> None:
    candidates = list(segment("AGENTS.md", "x\n- Use a. Never b.\n"))
    assert [(c.line, c.column) for c in candidates] == [(1, 1), (2, 3), (2, 10)]

    assert candidates[1] == Candidate(line=2, text="Use a.")
    assert Candidate(line=2, text="Use a.").column == 0


def test_the_column_counts_characters_not_bytes() -> None:
    # "é" is two UTF-8 bytes and U+1F600 four, but each is one column.
    assert _columns("é\U0001f600 x. Use a. Never b.\n") == [(1, 7), (1, 14)]
    assert _columns("\U0001f600\U0001f600 x. Use a.\n") == [(1, 7)]
