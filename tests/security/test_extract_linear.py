"""SEC-T09 / R2.6: rule extraction stays linear on one long instruction line (CON-68, M-63-1).

SECURITY-RULES R2 treats every instruction file as hostile, and R2.6 requires bounded work.
An instruction file may be up to 1 MiB (R2.3) and may be a single physical line. These tests
time ``extract_file`` (segmenting, normalizing, recognizing, the R2.6 caps and I-7 marker
attachment) on one line of up to 1 MiB made of very short sentences, with and without I-7
markers, CRLF line ends and bare CRs inside the line, using the repo's shared
``assert_linear`` (1.0 s + 4.0 s/MiB absolute budget at each size, best of three, and the
doubling-ratio check once a step takes over 1 s).

The shapes are the ones that split into many candidate sentences, so the per-sentence cost is
what gets measured (``tests/unit/test_rules_extract_vs.py`` uses shapes that never end a
sentence, so it yields one candidate). The expected verdict comes from R2.6, not from the code.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from conventiondrift.model import FileRules
from conventiondrift.rules.extract import MARKER, extract_file, segment
from unit.checker_support import LINEAR_SIZES, MIB, assert_linear

# The I-7 marker as written in INTERFACES.md; pinned so a changed constant can't shrink the input.
I7_MARKER = "<!-- conventiondrift: ignore -->"
assert MARKER == I7_MARKER
assert max(LINEAR_SIZES) == MIB  # up to the R2.3 instruction-file cap


def _line(n: int, unit: str, *, head: str = "", tail: str = "\n") -> str:
    """One physical line of at most ``n`` characters: ``head``, ``unit`` repeated, ``tail``."""
    count = (n - len(head) - len(tail)) // len(unit)
    return head + unit * count + tail


def _marker_mid(n: int) -> str:
    half = _line(n // 2, "a. ", tail="")
    return half + I7_MARKER + " " + _line(n - len(half) - len(I7_MARKER) - 1, "a. ")


# Each maker returns one physical line of at most n characters (all ASCII, so also n bytes).
SHAPES: dict[str, Callable[[int], str]] = {
    # The SR / KT-ARCHITECT §5.1 shapes.
    "dot-space": lambda n: _line(n, ". "),
    "a-dot": lambda n: _line(n, "a. "),
    "vs-dot-dot": lambda n: _line(n, "vs.. "),
    "xvs-dot": lambda n: _line(n, "xvs. "),
    "bullet": lambda n: _line(n, "a. ", head="- "),
    "rule-sentences": lambda n: _line(n, "Use a. "),
    # I-7 markers on the line.
    "marker-at-start": lambda n: _line(n, "a. ", head=I7_MARKER + " "),
    "marker-mid-line": _marker_mid,
    "marker-at-end": lambda n: _line(n, "Use a. ", tail=I7_MARKER + "\n"),
    "many-markers": lambda n: _line(n, "a. " + I7_MARKER + " "),
    "marker-glued-to-each-rule": lambda n: _line(n, I7_MARKER + "Use a. "),
    "bullet-many-markers": lambda n: _line(n, "Use a. " + I7_MARKER + " ", head="- "),
    # CR: a CRLF line end, and bare CRs inside the line (only LF and CRLF end a line).
    "a-dot-crlf": lambda n: _line(n, "a. ", tail="\r\n"),
    "marker-at-end-crlf": lambda n: _line(n, "Use a. ", tail=I7_MARKER + "\r\n"),
    "many-markers-crlf": lambda n: _line(n, "a. " + I7_MARKER + " ", tail="\r\n"),
    "bare-cr-separated": lambda n: _line(n, "a.\r", tail="\r\n"),
    "bare-cr-many-markers": lambda n: _line(n, "a.\r" + I7_MARKER + "\r", tail="\r\n"),
}


def _extract(data: bytes) -> FileRules:
    return extract_file("AGENTS.md", data)


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_sec_t09_shapes_are_one_line_of_many_sentences(shape: str) -> None:
    # Guards the timing test's inputs: one physical line, at most n characters, splitting
    # into many candidate sentences, so a slow per-sentence path is what gets measured.
    n = 1 << 14
    text = SHAPES[shape](n)
    assert len(text) <= n
    assert text.count("\n") == 1 and text.endswith("\n")  # one physical line (LF or CRLF end)
    assert sum(1 for _ in segment("AGENTS.md", text)) >= n // 64


@pytest.mark.timing
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_sec_t09_single_line_extraction_is_linear(shape: str) -> None:
    make = SHAPES[shape]
    assert_linear(lambda n: make(n).encode(), _extract, label=shape)
