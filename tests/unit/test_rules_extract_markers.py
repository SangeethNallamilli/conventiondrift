"""Unit tests for the ignore-marker column lookup in rules/extract.py (CON-68).

Each line's marker positions are found once (``_marks``) and every sentence's column is a
bisect over them (``_raw_index``). The old per-sentence search is kept below as a reference,
and the new lookup must give exactly what it gave: the same columns, the same rules and the
same ignored and unattached markers. Inputs are built from the module's own ``MARKER``.
"""

from collections.abc import Iterator

import pytest
from checker_support import assert_linear
from hypothesis import given, settings
from hypothesis import strategies as st

from conventiondrift.rules import extract
from conventiondrift.rules.extract import MARKER, Candidate, extract_file, segment

WIDTH = len(MARKER) - 1
"""How much wider the line is than its content for each marker."""


def _old_raw_index(raw: str, index: int) -> int:
    """The lookup as it was before CON-68 (01de241), kept as the reference."""
    shift = 0
    position = raw.find(MARKER)
    while position >= 0 and position - shift < index:
        shift += len(MARKER) - 1
        position = raw.find(MARKER, position + len(MARKER))
    return index + shift


def _new(raw: str, index: int) -> int:
    return extract._raw_index(extract._marks(raw), index)


def _old_segment(monkeypatch: pytest.MonkeyPatch, path: str, text: str) -> list[Candidate]:
    """``segment`` with the old lookup: each line carries itself, searched per sentence."""
    with monkeypatch.context() as patched:
        patched.setattr(extract, "_marks", lambda raw: raw)
        patched.setattr(extract, "_raw_index", _old_raw_index)
        return list(segment(path, text))


PIECES = [MARKER, "a", ". ", " ", "-", "<!--", "-->", "- ", "Use x.", "\n", "\t", "é"]
# Near misses of the marker, built from it: none of them is a marker.
NEAR_MISSES = [
    MARKER.upper(),
    MARKER[:-1],
    MARKER[1:],
    MARKER.replace(" ", "  "),
    MARKER.replace(" ", "\t"),
    MARKER[: len(MARKER) // 2],
]
texts = st.lists(st.sampled_from(PIECES + NEAR_MISSES), max_size=40).map("".join)


# --- (c) the same answer as before -------------------------------------------------------


@settings(max_examples=400)
@given(texts.filter(lambda t: "\n" not in t))
def test_lookup_equals_the_old_search_at_every_index(raw: str) -> None:
    content = raw.replace(MARKER, " ")
    for index in range(len(content) + 2):
        assert _new(raw, index) == _old_raw_index(raw, index)


@settings(max_examples=300)
@given(texts)
def test_segment_equals_the_old_segment(text: str) -> None:
    with pytest.MonkeyPatch.context() as monkeypatch:
        for path in ("AGENTS.md", "rules.mdc"):
            assert list(segment(path, text)) == _old_segment(monkeypatch, path, text)


@settings(max_examples=200)
@given(texts)
def test_extracted_rules_and_ignores_equal_the_old_ones(text: str) -> None:
    new = extract_file("AGENTS.md", text.encode())
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(extract, "_marks", lambda raw: raw)
        monkeypatch.setattr(extract, "_raw_index", _old_raw_index)
        old = extract_file("AGENTS.md", text.encode())
    assert new == old


@pytest.mark.parametrize(
    "text",
    [
        f"Use a. {MARKER} Use b. Never c.\n",
        f"Use a.{MARKER}Use b.\n",
        f"{MARKER}Use a. {MARKER}{MARKER} Use b. {MARKER}\n",
        f"- Use a. {MARKER} Never b.\n",
        f"Use a.\n{MARKER}\nUse b. {MARKER} Use c.\n",
        f"Use a\n{MARKER} and more. Use b.\n",
    ],
    ids=["mid-line", "glued", "start-and-adjacent", "bullet", "alone-then-mid", "continued"],
)
def test_a_marker_in_the_middle_of_a_line_is_handled_as_before(
    monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    assert list(segment("AGENTS.md", text)) == _old_segment(monkeypatch, "AGENTS.md", text)
    new = extract_file("AGENTS.md", text.encode())
    monkeypatch.setattr(extract, "_marks", lambda raw: raw)
    monkeypatch.setattr(extract, "_raw_index", _old_raw_index)
    assert extract_file("AGENTS.md", text.encode()) == new


def test_mid_line_marker_columns_and_ignores() -> None:
    result = extract_file("AGENTS.md", f"Use a. {MARKER} Use b. Never c.\n".encode())
    assert [(r.line, r.column) for r in result.rules] == [
        (1, 1),
        (1, 8 + len(MARKER) + 1),
        (1, 8 + len(MARKER) + 8),
    ]
    assert [r.ignored for r in result.rules] == [True, True, True]


# --- the positions found once per line --------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", ()),
        ("Use a.", ()),
        (MARKER, (0,)),
        (MARKER + MARKER, (0, 1)),
        ("ab" + MARKER + "c" + MARKER, (2, 4)),
        (MARKER[:-1] + MARKER, (len(MARKER) - 1,)),
    ],
)
def test_marks_are_content_positions(raw: str, expected: tuple[int, ...]) -> None:
    assert extract._marks(raw) == expected
    content = raw.replace(MARKER, " ")
    assert all(content[m] == " " for m in expected)


@pytest.mark.parametrize("near", NEAR_MISSES)
def test_a_near_miss_is_not_a_marker(near: str) -> None:
    raw = f"Use a. {near} Use b."
    assert extract._marks(raw) == ()
    assert all(_new(raw, i) == i for i in range(len(raw) + 1))


# --- bisect edge cases (CR) --------------------------------------------------------------


MARKS = (3, 10, 11)


def test_a_sentence_at_the_start_of_the_line_is_not_shifted() -> None:
    assert extract._raw_index(MARKS, 0) == 0
    assert extract._raw_index((0,), 0) == 0
    (first,) = segment("AGENTS.md", "Use a.\n")
    assert first.column == 1


def test_a_sentence_at_the_end_of_the_line_counts_every_marker() -> None:
    assert extract._raw_index(MARKS, 12) == 12 + 3 * WIDTH
    assert extract._raw_index(MARKS, 100) == 100 + 3 * WIDTH
    *_, last = segment("AGENTS.md", f"{MARKER}Use a. {MARKER}Use b.{MARKER}\n")
    assert (last.text, last.column) == ("Use b.", len("Use a. ") + 2 * len(MARKER) + 1)


@pytest.mark.parametrize("mark", MARKS)
def test_an_index_exactly_on_a_marker_is_not_shifted_by_that_marker(mark: int) -> None:
    before = MARKS.index(mark)
    assert extract._raw_index(MARKS, mark) == mark + before * WIDTH
    assert extract._raw_index(MARKS, mark + 1) == mark + 1 + (before + 1) * WIDTH
    raw = "abc" + MARKER + "defghi" + MARKER + MARKER + "j"
    assert extract._marks(raw) == MARKS
    assert _new(raw, mark) == _old_raw_index(raw, mark)


def test_a_sentence_right_after_a_marker_starts_after_it() -> None:
    _, second = segment("AGENTS.md", f"Use a.{MARKER}Use b.\n")
    assert second.text == "Use b."
    assert second.column == len("Use a.") + len(MARKER) + 1


# --- (b) speed on one long line ----------------------------------------------------------


def _segmented(text: str) -> Iterator[Candidate]:
    return iter(list(segment("AGENTS.md", text)))


@pytest.mark.parametrize(
    "unit",
    ["a. ", ". ", "a. " * 50 + MARKER],
    ids=["short-sentences", "bare-periods", "with-markers"],
)
def test_one_long_line_of_short_sentences_is_linear(unit: str) -> None:
    # Up to a single 1 MiB line, within 1 s + 4 s/MiB (checker_support.assert_linear).
    assert_linear(lambda n: unit * (n // len(unit)), _segmented, label=unit[:8])
