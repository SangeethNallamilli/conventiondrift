"""I-7 inline ignore marker: which rules a marker ignores (CON-68 regression, AC-F9.10).

Pins the I-7 [stable] attachment rule before the CON-68 (M-63-1) rework of marker positions in
``rules/extract.py``. Every expected value is written out by hand from INTERFACES.md I-7:

- The marker is exactly ``<!-- conventiondrift: ignore -->``, case-sensitive, single spaces.
- It applies to a rule when it is on the **same line as the start of the rule** (anywhere on that
  line: start, middle or end), or **alone on the line directly above** it.
- It is never part of the rule text. A marker anywhere else does nothing and is listed as
  unattached (by its 1-based line).

and from INTERFACES I-13 C6 item 5 (a rule's column is 1-based and counts characters, i.e.
Unicode code points, of the line as written, markers included). Line numbers are git's, so a
CRLF file gives the same answer as its LF twin; every case runs with both line endings.

Expected columns are computed from the input line itself (``line.index(anchor) + 1``), the
I-13 definition, never from the code. Normalized texts follow DESIGN §7 step 2 (lowercase,
whitespace collapsed, I-7 marker dropped).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from conventiondrift.model import FileRules
from conventiondrift.rules.extract import MARKER, extract_file

M = "<!-- conventiondrift: ignore -->"  # INTERFACES I-7, written out
assert MARKER == M


@dataclass(frozen=True)
class Want:
    line: int
    anchor: str  # the rule's first characters as written; its first occurrence on the line
    normalized: str
    ignored: bool


@dataclass(frozen=True)
class Case:
    lines: tuple[str, ...]
    rules: tuple[Want, ...]
    unattached: tuple[int, ...] = ()


CASES: dict[str, Case] = {
    # --- marker on the rule's start line -------------------------------------------------
    "i7-example-marker-at-line-end": Case(
        (f"- Use requests for HTTP calls {M}",),
        (Want(1, "Use requests", "use requests for http calls", True),),
    ),
    "marker-at-line-start-then-space": Case(
        (f"{M} Use a.",),
        (Want(1, "Use a.", "use a.", True),),
    ),
    "marker-glued-to-rule-start": Case(
        (f"{M}Use a.",),
        (Want(1, "Use a.", "use a.", True),),
    ),
    "marker-at-end-after-terminator-glued": Case(
        (f"Use a.{M}",),
        (Want(1, "Use a.", "use a.", True),),
    ),
    "marker-mid-sentence-is-dropped-from-text": Case(
        (f"Always set a timeout {M} on requests.",),
        (Want(1, "Always", "always set a timeout on requests.", True),),
    ),
    "marker-mid-line-between-sentences-ignores-both": Case(
        (f"Use a. {M} Never b.",),
        (Want(1, "Use a.", "use a.", True), Want(1, "Never b.", "never b.", True)),
    ),
    "marker-glued-after-a-terminator": Case(
        (f"Use a.{M} Never b.",),
        (Want(1, "Use a.", "use a.", True), Want(1, "Never b.", "never b.", True)),
    ),
    "marker-glued-before-the-next-sentence": Case(
        (f"Use a. {M}Never b.",),
        (Want(1, "Use a.", "use a.", True), Want(1, "Never b.", "never b.", True)),
    ),
    "marker-at-end-of-a-two-rule-line-ignores-both": Case(
        (f"- Use a. Never b. {M}",),
        (Want(1, "Use a.", "use a.", True), Want(1, "Never b.", "never b.", True)),
    ),
    # D-TL-57 (I-7 clarification, TL as Architect, 2026-11-20): with no whitespace around the
    # marker, the line still splits into two sentences and every rule on it is ignored.
    "d-tl-57-marker-glued-between-two-sentences": Case(
        (f"Use a.{M}Never b.", "Avoid c."),
        (
            Want(1, "Use a.", "use a.", True),
            Want(1, "Never b.", "never b.", True),
            Want(2, "Avoid c.", "avoid c.", False),
        ),
    ),
    "many-markers-on-one-line": Case(
        (f"{M} Use a. {M}{M} Never b. {M}",),
        (Want(1, "Use a.", "use a.", True), Want(1, "Never b.", "never b.", True)),
    ),
    "marker-only-on-the-line-of-a-later-rule": Case(
        ("Use a.", f"Never b. {M}", "Avoid c."),
        (
            Want(1, "Use a.", "use a.", False),
            Want(2, "Never b.", "never b.", True),
            Want(3, "Avoid c.", "avoid c.", False),
        ),
    ),
    "rule-starting-mid-continuation-line-with-marker": Case(
        ("Use a", f"and more. Never b. {M}"),
        (Want(1, "Use a", "use a and more.", False), Want(2, "Never b.", "never b.", True)),
    ),
    # --- marker alone on the line directly above ----------------------------------------
    "alone-above-a-bullet": Case(
        (M, "- Use a.", "- Never b."),
        (Want(2, "Use a.", "use a.", True), Want(3, "Never b.", "never b.", False)),
    ),
    "alone-above-with-surrounding-whitespace": Case(
        (f"  {M}\t ", "Use a."),
        (Want(2, "Use a.", "use a.", True),),
    ),
    "alone-between-two-rules-ignores-only-the-lower": Case(
        ("Use a.", M, "Never b."),
        (Want(1, "Use a.", "use a.", False), Want(3, "Never b.", "never b.", True)),
    ),
    "alone-above-a-line-holding-two-rules-ignores-both": Case(
        (M, "Use a. Never b."),
        (Want(2, "Use a.", "use a.", True), Want(2, "Never b.", "never b.", True)),
    ),
    "alone-above-and-on-the-same-line": Case(
        (M, f"Use a. {M}"),
        (Want(2, "Use a.", "use a.", True),),
    ),
    # --- markers that apply to nothing --------------------------------------------------
    "alone-as-the-last-line": Case(
        ("Use a.", M),
        (Want(1, "Use a.", "use a.", False),),
        (2,),
    ),
    "alone-two-lines-above": Case(
        (M, "", "Use a."),
        (Want(3, "Use a.", "use a.", False),),
        (1,),
    ),
    "alone-above-a-heading": Case(
        (M, "# Heading", "Use a."),
        (Want(3, "Use a.", "use a.", False),),
        (1,),
    ),
    "not-alone-on-the-line-above": Case(
        (f"Prose here. {M}", "Use a."),
        (Want(2, "Use a.", "use a.", False),),
        (1,),
    ),
    "on-a-continuation-line-of-the-rule": Case(
        ("- Use httpx", f"  for calls. {M}"),
        (Want(1, "Use httpx", "use httpx for calls.", False),),
        (2,),
    ),
    "on-a-prose-only-line": Case(
        ("Use a.", f"Just prose. {M}"),
        (Want(1, "Use a.", "use a.", False),),
        (2,),
    ),
    "inside-a-code-fence": Case(
        ("```", f"Use x. {M}", M, "```", "Use y."),
        (Want(5, "Use y.", "use y.", False),),
        (2, 3),
    ),
    # --- unicode ------------------------------------------------------------------------
    "unicode-before-the-marker-and-the-rule": Case(
        (f"\u00e9\U0001f600 x. {M} Use caf\u00e9 \u65e5\u672c\u8a9e.",),
        (Want(1, "Use caf", "use caf\u00e9 \u65e5\u672c\u8a9e.", True),),
    ),
    "unicode-rules-marker-mid-line": Case(
        (f"- Use na\u00efve \u2713 code. {M} Never \U0001f600 emoji.",),
        (
            Want(1, "Use na", "use na\u00efve \u2713 code.", True),
            Want(1, "Never", "never \U0001f600 emoji.", True),
        ),
    ),
    "unicode-alone-above": Case(
        (M, "- Prefer \u00fcber over caf\u00e9."),
        (Want(2, "Prefer", "prefer \u00fcber over caf\u00e9.", True),),
    ),
}

# Not the I-7 marker: case, spacing, punctuation and look-alike characters (I-7: exact match).
NEAR_MISSES = (
    "<!-- Conventiondrift: ignore -->",
    "<!-- conventiondrift: IGNORE -->",
    "<!--  conventiondrift: ignore -->",
    "<!-- conventiondrift:  ignore -->",
    "<!-- conventiondrift:ignore -->",
    "<!--conventiondrift: ignore-->",
    "<!-- conventiondrift: ignore --!>",
    "<!-- conventiondrift; ignore -->",
    "<!--\u00a0conventiondrift: ignore -->",  # no-break space
    "<!-- conventiondrift\uff1a ignore -->",  # fullwidth colon
    "<!\u2014 conventiondrift: ignore \u2014>",  # em dashes
    "<!-- conventiondrift: ignore\u200b -->",  # zero-width space
)

EOLS = {"lf": "\n", "crlf": "\r\n"}


def _extract(lines: tuple[str, ...], eol: str) -> FileRules:
    return extract_file("AGENTS.md", "".join(line + eol for line in lines).encode())


@pytest.mark.parametrize("eol", sorted(EOLS))
@pytest.mark.parametrize("name", list(CASES))
def test_i7_marker_attachment(name: str, eol: str) -> None:
    case = CASES[name]
    result = _extract(case.lines, EOLS[eol])
    got = [(r.line, r.column, r.normalized_text, r.ignored) for r in result.rules]
    want = [
        (w.line, case.lines[w.line - 1].index(w.anchor) + 1, w.normalized, w.ignored)
        for w in case.rules
    ]
    assert got == want
    assert result.unattached_markers == case.unattached
    for rule in result.rules:  # I-7: never part of the rule text
        assert M not in rule.text and M not in rule.normalized_text


@pytest.mark.parametrize("eol", sorted(EOLS))
def test_i7_marker_glued_between_two_sentences_ignores_every_rule_on_the_line(eol: str) -> None:
    # D-TL-57: "Use a.<marker>Never b." (no whitespace around the marker) is two sentences,
    # and every rule starting on the marker's line is ignored; the marker is attached.
    result = _extract((f"Use a.{M}Never b.", "Avoid c."), EOLS[eol])
    assert [(r.line, r.text, r.ignored) for r in result.rules] == [
        (1, "Use a.", True),
        (1, "Never b.", True),
        (2, "Avoid c.", False),
    ]
    assert result.unattached_markers == ()


@pytest.mark.parametrize("eol", sorted(EOLS))
@pytest.mark.parametrize("variant", NEAR_MISSES)
def test_i7_near_miss_is_not_a_marker(variant: str, eol: str) -> None:
    assert variant != M
    # On the rule's own line, and alone on the line directly above a rule.
    result = _extract((f"Use a. {variant}", "", variant, "- Never b."), EOLS[eol])
    assert [(r.line, r.ignored) for r in result.rules] == [(1, False), (4, False)]
    assert result.unattached_markers == ()


def test_i7_crlf_and_lf_give_the_same_rules() -> None:
    # One file holding every case above, separated by blank lines: CRLF must match LF exactly.
    lines: list[str] = []
    for case in CASES.values():
        lines += [*case.lines, ""]
    lf = _extract(tuple(lines), "\n")
    crlf = _extract(tuple(lines), "\r\n")
    assert lf.rules and lf.unattached_markers
    assert crlf == lf
