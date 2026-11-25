"""T-023 / T-024 unit and property tests for render/escape.py (critical module).

Covers DESIGN §3a, SECURITY-RULES R3.1, I-14, the unit halves of
AC-N3.10, AC-N3.13 and AC-E.17, and the md_codeblock contract (CON-26
option A, SC-2.58 / AC-F6.7). Spec tests named ``test_ac_*`` belong to
the Test Engineer. This file does not use that prefix.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

import conventiondrift.render.escape as esc
from conventiondrift.render.escape import (
    md,
    md_cell,
    md_codeblock,
    output_heredoc,
    sarif_text,
    sarif_uri,
    text_field,
    workflow_cmd,
    workflow_prop,
)

# The AC-N3.10 hostile rule text and causing path (SPEC.md AC-N3.10).
HOSTILE_RULE = (
    "Use requests, ping @someone <img src=x onerror=alert(1)> "
    "[link](https://evil.example) **bold** #123 ```python"
)
HOSTILE_PATH = "src/@someone/<b>x</b>.py"
# The AC-N3.13 injection strings.
INJECT_RULE = (
    "Use requests\n::warning file=x::injected ::add-mask::secret "
    "::stop-commands::tok %0A::error::x %0D"
)
INJECT_PATH = "src/::warning::%0A.py"
# AC-N3.13 / SC-2.52: the causing path also contains a ',' and a lone '%'.
INJECT_PATH_SC252 = "src/::warning::%0A,b%.py"

# One representative per character class the mappings care about.
C0_NUL = "\x00"
C0_TAB = "\t"
C0_LF = "\n"
C0_CR = "\r"
C0_US = "\x1f"
DEL = "\x7f"
C1_PAD = "\x80"
C1_NEL = "\x85"
C1_APC = "\x9f"
CF_BIDI = "\u202e"  # RIGHT-TO-LEFT OVERRIDE
CF_RLI = "\u2067"
CF_ZWSP = "\u200b"
CF_ZWJ = "\u200d"
CF_BOM = "\ufeff"
CF_ALM = "\u061c"
CF_SHY = "\xad"  # SOFT HYPHEN: Cf, not in the illustrative list
ZL = "\u2028"
ZP = "\u2029"
CS_LOW = "\ud800"
CS_HIGH = "\udfff"
# ZWJ emoji (R3 accepted cost: the joiner becomes a visible label).
ZWJ_EMOJI = "👨‍👩‍👧‍👦"  # U+1F468 U+200D U+1F469 U+200D U+1F467 U+200D U+1F466
ZWJ_EMOJI_VISIBLE = "👨U+200D👩U+200D👧U+200D👦"

_HIDDEN = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def unspan(s: str) -> str:
    """Parse one CommonMark inline code span back to its literal content."""
    m = re.fullmatch(r"(`+)(.*?)\1", s, re.DOTALL)
    assert m, f"not a single code span: {s!r}"
    fence, body = m.group(1), m.group(2)
    # no backtick run inside may equal the fence length (it would close the span early)
    assert all(len(r) != len(fence) for r in re.findall(r"`+", body))
    if body.startswith(" ") and body.endswith(" ") and body.strip(" "):
        body = body[1:-1]
    return body


def visible(text: str) -> str:
    """Independent expected I-14 visible form (Control Pictures / U+XXXX)."""
    parts: list[str] = []
    for char in text:
        code = ord(char)
        if code < 32:
            parts.append(chr(0x2400 + code))
        elif code == 127:
            parts.append("\u2421")
        elif unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp", "Cs"}:
            parts.append("U+" + format(code, "04X"))
        else:
            parts.append(char)
    return "".join(parts)


_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
# RFC 3986 relative-ref path with no scheme, query or fragment: pchar / "/" only.
_URI_REFERENCE = re.compile(r"(?:[A-Za-z0-9\-._~/]|%[0-9A-F]{2})*")


def pct(text: str) -> str:
    """Independent RFC 3986 percent-encoding: unreserved and ``/`` kept, rest UTF-8 %XX."""
    parts: list[str] = []
    for char in text:
        if char in _UNRESERVED or char == "/":
            parts.append(char)
        else:
            parts.append("".join(f"%{byte:02X}" for byte in char.encode("utf-8")))
    return "".join(parts)


def hidden_chars(text: str) -> list[str]:
    return [char for char in text if unicodedata.category(char) in _HIDDEN]


# CON-26 / I-14 md_codeblock helpers, independent of the implementation.
_MAX_CODEBLOCK_LINE = 1000
_CUT_MARKER = " […{n} more chars]"
_INFO_OK = re.compile(r"^[a-z0-9-]*$")
# Every separator str.splitlines() recognizes (Python 3.11+ docs), as raw chars.
_SPLITLINES_SEPARATORS = (
    "\n",
    "\r",
    "\r\n",
    "\v",
    "\f",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
)
# Inner lines of the AC-F6.7 approved snapshot (SC-2.58, drafts/pm/ac_f6_7.approved.md).
_AC_F67_LINES = (
    '\u26a0\ufe0f AGENTS.md line 9: "Use requests for HTTP calls"',
    "   Before this PR: 3 of 40 call sites used requests",
    "   After this PR:  0 of 40 (removed in src/api/client.py)",
    "   Agents treat this file as an instruction and will likely",
    "   reintroduce requests in future changes.",
    "",
    "   Suggested fix:",
    "   - Use requests for HTTP calls",
    "   + Use httpx for HTTP calls",
)
_AC_F67_APPROVED = (
    "\U0001f9ed conventiondrift: this PR makes 1 agent rule stale\n"
    "\n"
    "```\n" + "\n".join(_AC_F67_LINES) + "\n```\n"
    "\n"
    "1 rule changed status \u00b7 8 unchanged \u00b7 details in the job summary\n"
)


def prepared_line(text: str) -> str:
    """I-14 mapping, then the CON-26 1000-character cut and visible marker."""
    mapped = visible(text)
    if len(mapped) <= _MAX_CODEBLOCK_LINE:
        return mapped
    extra = len(mapped) - _MAX_CODEBLOCK_LINE
    return mapped[:_MAX_CODEBLOCK_LINE] + _CUT_MARKER.format(n=extra)


def parse_codeblock(out: str) -> tuple[str, str, list[str]]:
    """Parse ``fence + info + newline + joined body + newline + fence`` (no trailing newline)."""
    match = re.match(r"(`{3,})", out)
    assert match is not None, f"missing opening fence: {out!r}"
    fence = match.group(1)
    rest = out[len(fence) :]
    assert "\n" in rest, f"no newline after opening fence: {out!r}"
    info, _, tail = rest.partition("\n")
    closing = "\n" + fence
    assert tail.endswith(closing), f"missing closing fence: {out!r}"
    assert not out.endswith("\n"), f"trailing newline after closing fence: {out!r}"
    body = tail[: -len(closing)]
    return fence, info, body.split("\n")


def codeblock_body(out: str) -> list[str]:
    _fence, _info, body = parse_codeblock(out)
    return body


def hidden_chars_except_structural_newlines(out: str) -> list[str]:
    """The contract formula uses LF between fences; those are the only Cc allowed."""
    return hidden_chars(out.replace("\n", ""))


def _unescaped_pipe_count(row: str) -> int:
    return sum(
        1
        for index, char in enumerate(row)
        if char == "|" and (index == 0 or row[index - 1] != "\\")
    )


# ---- md() ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", [HOSTILE_RULE, HOSTILE_PATH])
def test_md_hostile_rule_and_path_are_one_literal_code_span(text: str) -> None:
    out = md(text)
    assert "\n" not in out and "\r" not in out
    assert unspan(out) == text  # visible text is the original, verbatim


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Use httpx", "`Use httpx`"),
        ("a`b", "``a`b``"),
        ("``x", "``` ``x ```"),
        ("x`", "`` x` ``"),
        (" lead", "`  lead `"),
        ("trail ", "` trail  `"),
        ("   ", "`   `"),  # all spaces: no padding (CommonMark does not strip)
        ("a ``` b", "````a ``` b````"),
        ("", ""),
        ("line1\nline2", "`line1\u240aline2`"),
        ("cr\r\nlf", "`cr\u240d\u240alf`"),
        ("nul\x00del\x7f", "`nul\u2400del\u2421`"),
        ("tab\there", "`tab\u2409here`"),
        ("@someone #123", "`@someone #123`"),
        ("keep :: and %0A", "`keep :: and %0A`"),
    ],
)
def test_md_exact(text: str, expected: str) -> None:
    assert md(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Interior "a" / "X" / NBSP are just unmapped content, not a special alphabet.
        (" a ", "`  a  `"),
        (" X ", "`  X  `"),
        (" \u00a0 ", "`  \u00a0  `"),
    ],
    ids=["letter", "x", "nbsp"],
)
def test_md_pads_a_body_that_starts_and_ends_with_a_space(text: str, expected: str) -> None:
    """Pin CommonMark padding for a verbatim inline code span.

    INTERFACES.md names ``md`` a "Markdown inline code span". AC-N3.10 requires
    the visible rendered text to be the original (unmapped) string verbatim;
    I-14 / SC-2.51 keep every character that is not in the mapped categories
    unchanged, including U+00A0 (NBSP). CommonMark strips exactly one U+0020
    from each end of a span that starts and ends with a space and is not all
    spaces, so the emitter must pad exactly one U+0020 on each side. NBSP is
    not a CommonMark space, so a U+0020-NBSP-U+0020 body is not all spaces.
    """
    assert md(text) == expected
    assert unspan(md(text)) == visible(text)


def test_md_blank_line_cannot_break_out() -> None:
    out = md("ok\n\n# heading\n\n<script>x</script>")
    assert "\n" not in out
    assert unspan(out) == "ok\u240a\u240a# heading\u240a\u240a<script>x</script>"


def test_md_long_fence_never_opens_a_code_block() -> None:
    # A line starting with >=3 backticks only opens a fence if its info string has no
    # backtick; md() only emits a >=3 fence when the content has backticks.
    for text in ["```", "``` python", "x``y", "````"]:
        out = md(text)
        fence = re.match(r"`+", out)
        assert fence
        if len(fence.group()) >= 3:
            assert "`" in out[len(fence.group()) :]


def test_md_printable_unicode_and_sc251_strings_stay_verbatim() -> None:
    s = "ünïcode ファイル :: %0A"
    assert unspan(md(s)) == s


@settings(max_examples=500, derandomize=True)
@given(st.text())
def test_md_roundtrip_property(text: str) -> None:
    out = md(text)
    if not text:
        assert out == ""
        return
    assert "\n" not in out and "\r" not in out
    assert unspan(out) == visible(text)
    assert hidden_chars(out) == []


# ---- md_cell() ----------------------------------------------------------------------


def test_md_cell_is_md_plus_escaped_pipes() -> None:
    assert md_cell("plain") == md("plain") == "`plain`"
    assert md_cell("a|b") == "`a\\|b`"
    assert md_cell("|both|") == r"`\|both\|`"
    assert md_cell("") == ""
    # backticks and pipes together: fence from md(), pipes then escaped
    assert md_cell("a`b|c") == "``a`b\\|c``"


def test_md_cell_keeps_gfm_table_column_count() -> None:
    left, right = md_cell("a|b"), md_cell("c")
    row = f"| {left} | {right} |"
    assert left == "`a\\|b`"
    assert right == "`c`"
    assert row == "| `a\\|b` | `c` |"
    assert _unescaped_pipe_count(row) == 3  # start, mid, end => two cells


def test_md_cell_without_pipe_escape_would_split_the_row() -> None:
    raw = f"| {md('a|b')} | {md('c')} |"
    assert _unescaped_pipe_count(raw) == 4  # the unescaped content pipe adds a column


def _gfm_row_cells(row: str) -> list[str]:
    """Split a GFM table row on ``|`` not preceded by an odd number of backslashes."""
    cells: list[str] = []
    start = 0
    for index, char in enumerate(row):
        if char != "|":
            continue
        count = 0
        pos = index - 1
        while pos >= start and row[pos] == "\\":
            count += 1
            pos -= 1
        if count % 2 == 0:
            cells.append(row[start:index])
            start = index + 1
    cells.append(row[start:])
    if cells and cells[0] == "":
        cells = cells[1:]
    if cells and cells[-1] == "":
        cells = cells[:-1]
    return cells


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a\\|b", "`a\\\\\\|b`"),
        ("trail\\", "`trail\\\\`"),
        ("\\", "`\\\\`"),
        ("\\\\|", "`\\\\\\\\\\|`"),
        ("|", "`\\|`"),
        ("a|b|c", "`a\\|b\\|c`"),
    ],
    ids=[
        "a-backslash-pipe-b",
        "trailing-backslash",
        "lone-backslash",
        "two-backslashes-pipe",
        "pipe",
        "a-pipe-b-pipe-c",
    ],
)
def test_md_cell_backslash_before_pipe_stays_one_cell(text: str, expected: str) -> None:
    out = md_cell(text)
    assert out == expected
    row = f"| x | {out} | y |"
    assert _gfm_row_cells(row) == [" x ", f" {out} ", " y "]


@settings(max_examples=400, derandomize=True)
@given(st.text())
def test_md_cell_roundtrip_property(text: str) -> None:
    out = md_cell(text)
    if not text:
        assert out == ""
        return
    assert out == md(text).replace("\\", "\\\\").replace("|", "\\|")
    assert hidden_chars(out) == []


# ---- per-class mapping, applied to each affected function ---------------------------


# (label, sample, expected visible form with CR/LF also mapped)
_CLASS_CASES: list[tuple[str, str, str]] = [
    ("Cc C0 NUL", f"A{C0_NUL}B", "A\u2400B"),
    ("Cc C0 TAB", f"A{C0_TAB}B", "A\u2409B"),
    ("Cc C0 US", f"A{C0_US}B", "A\u241fB"),
    ("Cc C0 LF", f"A{C0_LF}B", "A\u240aB"),
    ("Cc C0 CR", f"A{C0_CR}B", "A\u240dB"),
    ("DEL", f"A{DEL}B", "A\u2421B"),
    ("C1 PAD", f"A{C1_PAD}B", "AU+0080B"),
    ("C1 NEL", f"A{C1_NEL}B", "AU+0085B"),
    ("C1 APC", f"A{C1_APC}B", "AU+009FB"),
    ("Cf bidi RLO", f"A{CF_BIDI}B", "AU+202EB"),
    ("Cf bidi RLI", f"A{CF_RLI}B", "AU+2067B"),
    ("Cf bidi ALM", f"A{CF_ALM}B", "AU+061CB"),
    ("Cf zero-width ZWSP", f"A{CF_ZWSP}B", "AU+200BB"),
    ("Cf zero-width ZWJ", f"A{CF_ZWJ}B", "AU+200DB"),
    ("Cf zero-width BOM", f"A{CF_BOM}B", "AU+FEFFB"),
    ("Cf soft hyphen (by category, not a list)", f"A{CF_SHY}B", "AU+00ADB"),
    ("Zl", f"A{ZL}B", "AU+2028B"),
    ("Zp", f"A{ZP}B", "AU+2029B"),
    ("Cs low", f"A{CS_LOW}B", "AU+D800B"),
    ("Cs high", f"A{CS_HIGH}B", "AU+DFFFB"),
]

_CLASS_IDS = [label for label, _sample, _mapped in _CLASS_CASES]


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_md_per_character_class(label: str, sample: str, mapped: str) -> None:
    out = md(sample)
    assert "\n" not in out and "\r" not in out
    assert unspan(out) == mapped
    assert hidden_chars(out) == []


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_md_cell_per_character_class(label: str, sample: str, mapped: str) -> None:
    out = md_cell(sample)
    assert unspan(out.replace("\\|", "|")) == mapped
    assert hidden_chars(out) == []


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_workflow_cmd_per_character_class(label: str, sample: str, mapped: str) -> None:
    # Mapping runs first, so CR/LF are already pictures; then % is encoded.
    out = workflow_cmd(sample)
    assert out == mapped.replace("%", "%25")
    assert "\n" not in out and "\r" not in out
    assert hidden_chars(out) == []
    if C0_LF in sample:
        assert "\u240a" in out and "%0A" not in out
    if C0_CR in sample:
        assert "\u240d" in out and "%0D" not in out


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_workflow_prop_per_character_class(label: str, sample: str, mapped: str) -> None:
    out = workflow_prop(sample)
    expected = mapped.replace("%", "%25").replace(":", "%3A").replace(",", "%2C")
    assert out == expected
    assert hidden_chars(out) == []
    assert ":" not in out and "," not in out and "\n" not in out and "\r" not in out


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_sarif_text_per_character_class(label: str, sample: str, mapped: str) -> None:
    out = sarif_text(sample)
    assert sarif_unescape(out) == mapped
    assert hidden_chars(out) == []


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_sarif_uri_per_character_class(label: str, sample: str, mapped: str) -> None:
    """R3 / D-TL-97: the I-14 mapping first, then RFC 3986 percent-encoding of the result."""
    assert any(unicodedata.category(char) in esc._LABEL_CATEGORIES for char in sample)
    out = sarif_uri(sample)
    assert out == pct(mapped)
    assert out.isascii() and _URI_REFERENCE.fullmatch(out)
    assert hidden_chars(out) == []


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_output_heredoc_per_character_class(label: str, sample: str, mapped: str) -> None:
    entry = output_heredoc("report-path", sample)
    delivered = parse_output_file(entry)["report-path"]
    assert delivered == mapped
    assert hidden_chars(delivered) == []


@pytest.mark.parametrize(("label", "sample", "_mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_text_field_per_character_class(label: str, sample: str, _mapped: str) -> None:
    """R3: bidi, zero-width, format, surrogate and other labelled classes use repr()."""
    assert any(unicodedata.category(char) in esc._LABEL_CATEGORIES for char in sample)
    out = text_field(sample)
    assert out == repr(sample)
    # repr() is a single Python literal, so a raw newline or :: starter cannot begin a line.
    assert "\n" not in out
    assert not out.startswith("::")


def test_text_field_reprs_backslash_and_command_prefix() -> None:
    assert text_field(r"foo\bar.md") == repr(r"foo\bar.md")
    assert text_field("::warning::x.md") == repr("::warning::x.md")
    assert text_field("AGENTS.md") == "AGENTS.md"
    assert text_field("a rule", quoted=True) == '"a rule"'
    # A quoted field that also needs repr stays a repr, not a second wrap.
    assert text_field("::warning::x", quoted=True) == repr("::warning::x")


def test_label_format_is_uppercase_at_least_four_digits() -> None:
    # The I-14 spelling is still open; this pins the current helper's format.
    assert unspan(md(CF_BIDI)) == "U+202E"
    assert unspan(md(CF_SHY)) == "U+00AD"
    assert unspan(md(CS_LOW)) == "U+D800"
    assert "u+" not in md(CF_BIDI)
    assert "U+202e" not in md(CF_BIDI)
    # I-14's own example, and a tag character that needs more than four digits.
    begin_beam = "\U0001d173"
    tag_space = "\U000e0020"
    assert unicodedata.category(begin_beam) == "Cf"
    assert unicodedata.category(tag_space) == "Cf"
    assert unspan(md(begin_beam)) == "U+1D173"
    assert unspan(md(tag_space)) == "U+E0020"


def test_zwj_emoji_shows_joiners_as_labels() -> None:
    assert unspan(md(ZWJ_EMOJI)) == ZWJ_EMOJI_VISIBLE
    assert unspan(md_cell(ZWJ_EMOJI)) == ZWJ_EMOJI_VISIBLE
    assert workflow_cmd(ZWJ_EMOJI) == ZWJ_EMOJI_VISIBLE
    assert workflow_prop(ZWJ_EMOJI) == ZWJ_EMOJI_VISIBLE
    assert sarif_text(ZWJ_EMOJI) == ZWJ_EMOJI_VISIBLE
    assert codeblock_body(md_codeblock([ZWJ_EMOJI])) == [ZWJ_EMOJI_VISIBLE]


def test_lone_surrogates_do_not_crash() -> None:
    for sample in (CS_LOW, CS_HIGH, f"ok{CS_LOW}{CS_HIGH}ok", CS_LOW * 3):
        assert unspan(md(sample)) == visible(sample)
        assert md_cell(sample) == md(sample)
        assert workflow_cmd(sample) == visible(sample)
        assert workflow_prop(sample) == visible(sample)
        assert sarif_text(sample) == visible(sample)
        assert sarif_uri(sample) == pct(visible(sample))
        assert output_heredoc("report-path", sample).endswith("\n")
        assert codeblock_body(md_codeblock([sample])) == [visible(sample)]


def test_control_picture_boundaries() -> None:
    # Space (U+0020) and U+00A0 stay; U+001F / U+007F / U+0080 / U+009F map.
    assert unspan(md("A B")) == "A B"
    assert unspan(md("A\u00a0B")) == "A\u00a0B"
    assert unspan(md("\x1f")) == "\u241f"
    assert unspan(md("\x7f")) == "\u2421"
    assert unspan(md("\x80")) == "U+0080"
    assert unspan(md("\x9f")) == "U+009F"
    assert unspan(md("\xa0")) == "\xa0"


# ---- workflow_cmd() / workflow_prop() -----------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", "plain"),
        ("100%", "100%25"),
        ("%0A", "%250A"),  # printable %0A stays, then % is encoded
        ("a\nb", "a\u240ab"),
        ("a\rb", "a\u240db"),
        ("a\r\nb", "a\u240d\u240ab"),
        ("a:b,c", "a:b,c"),  # data keeps ':' and ','
        ("::warning::x", "::warning::x"),
        ("%%\n", "%25%25\u240a"),
        ("tab\there", "tab\u2409here"),
        ("nul\x00del\x7f", "nul\u2400del\u2421"),
    ],
)
def test_workflow_cmd_exact(text: str, expected: str) -> None:
    assert workflow_cmd(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("src/a.py", "src/a.py"),
        ("a:b", "a%3Ab"),
        ("a,b", "a%2Cb"),
        ("100%", "100%25"),
        ("x\ny", "x\u240ay"),
        ("x\ry", "x\u240dy"),
        ("%3A", "%253A"),
        (INJECT_PATH, "src/%3A%3Awarning%3A%3A%250A.py"),
    ],
)
def test_workflow_prop_exact(text: str, expected: str) -> None:
    assert workflow_prop(text) == expected


def runner_unescape_data(s: str) -> str:
    return s.replace("%0D", "\r").replace("%0A", "\n").replace("%25", "%")


def runner_unescape_prop(s: str) -> str:
    return runner_unescape_data(s.replace("%3A", ":").replace("%2C", ","))


@pytest.mark.parametrize(
    "path",
    [INJECT_PATH, INJECT_PATH_SC252],
    ids=["inject-path", "sc252-comma-and-lone-percent"],
)
def test_injected_rule_and_path_form_one_annotation_line(path: str) -> None:
    # Gap 7 / SC-2.52: the combined annotation line must also survive ',' and a lone '%'.
    line = f"::warning file={workflow_prop(path)},line=9::{workflow_cmd(INJECT_RULE)}"
    assert "\n" not in line and "\r" not in line
    m = re.fullmatch(r"::warning file=([^,:]*),line=9::(.*)", line)
    assert m, "properties must not be split by injected ':' or ','"
    assert runner_unescape_prop(m.group(1)) == visible(path)
    assert runner_unescape_data(m.group(2)) == visible(INJECT_RULE)
    if path == INJECT_PATH_SC252:
        assert "," in path
        # A lone '%' remains after the '%0A' sequence is removed.
        assert path.replace("%0A", "").count("%") >= 1
        assert "%2C" in line  # comma is encoded, not a new property separator
        assert "%25" in workflow_prop(path)  # lone '%' is encoded


@settings(max_examples=500, derandomize=True)
@given(st.text())
def test_workflow_escapes_stay_on_one_line_and_hide_specials(text: str) -> None:
    data, prop = workflow_cmd(text), workflow_prop(text)
    for out in (data, prop):
        assert "\n" not in out and "\r" not in out
        assert hidden_chars(out) == []
    assert ":" not in prop and "," not in prop
    assert runner_unescape_data(data) == visible(text)
    assert runner_unescape_prop(prop) == visible(text)


@settings(max_examples=400, derandomize=True)
@given(st.text())
def test_no_hidden_categories_in_md_cell_or_workflow_outputs(text: str) -> None:
    # Protocol percent-encodings are ASCII, so they are not an exception in
    # the output itself; the check is simply "none of these categories remain".
    for out in (md(text), md_cell(text), workflow_cmd(text), workflow_prop(text), sarif_text(text)):
        assert hidden_chars(out) == []
    delivered = parse_output_file(output_heredoc("report-path", text))["report-path"]
    assert hidden_chars(delivered) == []


_RESIDUAL_MESSAGE = r"^residual control character after mapping$"
_RESIDUALS = ["\r", "\n", "\x00", "\x7f", "\x85", "\u202e", "\u2028", "\u2029", "\ud800"]
_RESIDUAL_IDS = ["CR", "LF", "NUL", "DEL", "C1", "Cf bidi", "Zl", "Zp", "Cs"]


# Written independently from INTERFACES.md I-14 (L493), not read from the code.
_I14_LABELLED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def test_guarded_categories_match_i14() -> None:
    """The code's category set must equal I-14's written list, so they can't drift together."""
    assert esc._LABEL_CATEGORIES == _I14_LABELLED_CATEGORIES


def test_residual_cases_cover_every_guarded_category() -> None:
    """D-TL-25: the residual cases must span exactly the categories the guard rejects."""
    assert {unicodedata.category(c) for c in _RESIDUALS} == set(esc._LABEL_CATEGORIES)


@pytest.mark.parametrize("func", [workflow_cmd, workflow_prop], ids=lambda f: f.__name__)
@pytest.mark.parametrize("residual", _RESIDUALS, ids=_RESIDUAL_IDS)
def test_workflow_fails_closed_if_mapping_is_bypassed(
    monkeypatch: pytest.MonkeyPatch,
    func: Callable[[str], str],
    residual: str,
) -> None:
    monkeypatch.setattr(esc, "_visible_text", lambda text: text)
    with pytest.raises(ValueError, match=_RESIDUAL_MESSAGE) as caught:
        func("pre" + residual + "post")
    message = str(caught.value)
    assert residual not in message
    assert "pre" not in message
    assert "post" not in message


def test_workflow_guard_is_silent_when_mapping_ran() -> None:
    hostile = "a\nb\rc" + "".join(_RESIDUALS)
    assert workflow_cmd(hostile)
    assert workflow_prop(hostile)


# ---- output_heredoc() ---------------------------------------------------------------


def parse_output_file(content: str) -> dict[str, str]:
    """Parse GITHUB_OUTPUT the way the runner does (heredoc form only)."""
    out: dict[str, str] = {}
    lines = content.split("\n")
    i = 0
    while i < len(lines) and lines[i]:
        name, delim = lines[i].split("<<", 1)
        j = lines.index(delim, i + 1)
        out[name] = "\n".join(lines[i + 1 : j])
        i = j + 1
    return out


@pytest.mark.parametrize(
    "value",
    ["3", "", "RUNNER_TEMP/conventiondrift/report.json", INJECT_RULE, "a\nb\n", "x<<y\nEOF"],
)
def test_output_heredoc_roundtrip(value: str) -> None:
    entry = output_heredoc("report-path", value)
    assert entry.endswith("\n")
    assert parse_output_file(entry) == {"report-path": visible(value)}


def test_four_outputs_exact_even_with_injection() -> None:
    hostile = "1\nghadelimiter_x\nsarif-path<<EOF\nevil\nEOF\n"
    content = (
        output_heredoc("stale-count", "3")
        + output_heredoc("new-stale-count", "1")
        + output_heredoc("report-path", hostile)
        + output_heredoc("sarif-path", "")
    )
    assert parse_output_file(content) == {
        "stale-count": "3",
        "new-stale-count": "1",
        "report-path": visible(hostile),
        "sarif-path": "",
    }


def test_output_heredoc_shape_and_fresh_delimiter() -> None:
    a, b = output_heredoc("stale-count", "3"), output_heredoc("stale-count", "3")
    m = re.fullmatch(r"stale-count<<(ghadelimiter_[0-9a-f]{32})\n3\n\1\n", a)
    assert m
    assert a != b, "delimiter must be fresh per call"
    assert m.group(1) not in "3"


def _value_block(entry: str) -> tuple[str, str]:
    """Return (delimiter, value) from one heredoc entry."""
    header, newline, rest = entry.partition("\n")
    assert newline == "\n"
    delimiter = header.split("<<", 1)[1]
    assert rest.endswith(delimiter + "\n")
    value = rest[: -(len(delimiter) + 1)]
    assert value.endswith("\n")
    return delimiter, value[:-1]


def test_output_heredoc_delimiter_never_appears_in_the_value_block() -> None:
    for value in ("3", "has ghadelimiter_ prefix only", INJECT_RULE, "a\nb", ""):
        entry = output_heredoc("report-path", value)
        delimiter, delivered = _value_block(entry)
        assert delimiter.startswith("ghadelimiter_")
        assert len(delimiter) == len("ghadelimiter_") + 32
        assert delimiter not in delivered
        assert parse_output_file(entry) == {"report-path": visible(value)}


def test_output_heredoc_regenerates_when_delimiter_in_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokens = iter(["aa", "aa", "bb"])
    seen: list[int] = []

    def fake(n: int) -> str:
        seen.append(n)
        return next(tokens)

    monkeypatch.setattr(esc, "_token", fake)
    entry = output_heredoc("report-path", "has ghadelimiter_aa inside")
    assert entry == "report-path<<ghadelimiter_bb\nhas ghadelimiter_aa inside\nghadelimiter_bb\n"
    assert seen == [16, 16, 16]
    delimiter, delivered = _value_block(entry)
    assert delimiter == "ghadelimiter_bb"
    assert delimiter not in delivered


@pytest.mark.parametrize(
    "value",
    [
        "before\nghadelimiter_aa\nafter",
        "before\r\nghadelimiter_aa\r\nafter",
        "before\nghadelimiter_aa  \nafter",
        "before\nghadelimiter_aa\t\nafter",
        "before\nghadelimiter_aa",
    ],
    ids=[
        "own-line",
        "own-line-crlf",
        "own-line-trailing-spaces",
        "own-line-trailing-tabs",
        "at-end",
    ],
)
def test_output_heredoc_regenerates_on_line_oriented_collision(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    tokens = iter(["aa", "bb"])
    monkeypatch.setattr(esc, "_token", lambda n: next(tokens))
    forced, chosen = "ghadelimiter_aa", "ghadelimiter_bb"
    mapped = visible(value)
    assert forced in mapped
    entry = output_heredoc("report-path", value)
    delimiter, delivered = _value_block(entry)
    assert delimiter == chosen
    assert chosen not in delivered
    assert delivered == mapped
    assert parse_output_file(entry) == {"report-path": mapped}
    lines = entry.split("\n")
    assert entry.endswith("\n")
    assert lines[0] == f"report-path<<{chosen}"
    assert lines[-1] == ""
    assert lines[-2] == chosen
    opening = [i for i, line in enumerate(lines) if line.startswith("report-path<<")]
    closing = [i for i, line in enumerate(lines) if line == chosen]
    assert opening == [0], "exactly one opening line"
    assert closing == [len(lines) - 2], "exactly one closing line"


def test_output_heredoc_gives_up_after_bounded_tries(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake(n: int) -> str:
        calls.append(n)
        return "zz"

    monkeypatch.setattr(esc, "_token", fake)
    with pytest.raises(ValueError, match=r"^no heredoc delimiter absent from the value$"):
        output_heredoc("report-path", "ghadelimiter_zz")
    assert len(calls) == 8


def test_output_heredoc_last_try_can_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    tokens = iter(["zz"] * 7 + ["ok"])
    monkeypatch.setattr(esc, "_token", lambda n: next(tokens))
    assert output_heredoc("x", "ghadelimiter_zz").startswith("x<<ghadelimiter_ok\n")


def test_output_heredoc_default_token_is_secrets() -> None:
    import secrets

    assert esc._token is secrets.token_hex


@pytest.mark.parametrize(
    "name",
    [
        "",
        "Stale",
        "1x",
        "-x",
        "a b",
        "a\nb",
        "a<<b",
        "a=b",
        "x" * 65,
        "stale-count\n",
        "GITHUB_ENV",
    ],
)
def test_output_heredoc_rejects_bad_names(name: str) -> None:
    with pytest.raises(ValueError, match=r"^invalid output name$"):
        output_heredoc(name, "1")


@pytest.mark.parametrize("name", ["a", "stale-count", "new-stale-count", "sarif-path", "x" * 64])
def test_output_heredoc_accepts_names(name: str) -> None:
    assert output_heredoc(name, "1").startswith(f"{name}<<ghadelimiter_")


@settings(max_examples=300, derandomize=True)
@given(st.text())
def test_output_heredoc_roundtrip_property(value: str) -> None:
    delivered = parse_output_file(output_heredoc("report-path", value))["report-path"]
    assert delivered == visible(value)
    assert hidden_chars(delivered) == []


# ---- sarif_text() -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", "plain"),
        ("[link](1)", "\\[link\\](1)"),
        ("a\\b", "a\\\\b"),
        ("\\[", "\\\\\\["),
        ("**bold** <b>x</b> @someone #123", "**bold** <b>x</b> @someone #123"),
        ("line\nbreak", "line\u240abreak"),
        ("keep :: and %0A", "keep :: and %0A"),
    ],
)
def test_sarif_text_exact(text: str, expected: str) -> None:
    assert sarif_text(text) == expected


def sarif_unescape(s: str) -> str:
    return re.sub(r"\\([\\\[\]])", r"\1", s)


@settings(max_examples=500, derandomize=True)
@given(st.text())
def test_sarif_text_no_embedded_link_and_roundtrip(text: str) -> None:
    out = sarif_text(text)
    assert sarif_unescape(out) == visible(text)
    assert hidden_chars(out) == []
    # every '[' / ']' in the output is preceded by an odd number of backslashes
    for m in re.finditer(r"[\[\]]", out):
        run = len(out[: m.start()]) - len(out[: m.start()].rstrip("\\"))
        assert run % 2 == 1


def test_sarif_text_hostile_rule_visible_verbatim() -> None:
    assert sarif_unescape(sarif_text(HOSTILE_RULE)) == HOSTILE_RULE


def test_sarif_text_json_roundtrips_every_mapped_class() -> None:
    sample = (
        f"plain {C0_NUL}{C0_TAB}{C0_LF}{C0_CR}{C0_US}{DEL}"
        f"{C1_PAD}{C1_NEL}{C1_APC}{CF_BIDI}{CF_ZWSP}{CF_ZWJ}{ZL}{ZP}{CS_LOW}"
        " [link] slash\\ end"
    )
    encoded = sarif_text(sample)
    assert hidden_chars(encoded) == []
    payload = {"message": {"text": encoded}}
    assert json.loads(json.dumps(payload, ensure_ascii=False)) == payload


# ---- sarif_uri() (D-TL-97) ------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("AGENTS.md", "AGENTS.md"),
        (".github/copilot-instructions.md", ".github/copilot-instructions.md"),
        ("a-b_c~d/e.f", "a-b_c~d/e.f"),
        ("docs/my rules/AGENTS.md", "docs/my%20rules/AGENTS.md"),
        ("100%.md", "100%25.md"),
        ("a#b.md", "a%23b.md"),
        ("a?b=c.md", "a%3Fb%3Dc.md"),
        ("c:x.md", "c%3Ax.md"),
        ("a\\b.md", "a%5Cb.md"),
        ("[x]@y!$&'()*+,;=.md", "%5Bx%5D%40y%21%24%26%27%28%29%2A%2B%2C%3B%3D.md"),
        ("caf\u00e9/\u65e5\u672c.md", "caf%C3%A9/%E6%97%A5%E6%9C%AC.md"),
        ("\U0001f600.md", "%F0%9F%98%80.md"),
        ("/abs.md", "%2Fabs.md"),
        ("//host/x.md", "%2F%2Fhost/x.md"),
        ("a//b/", "a//b/"),
        ("", ""),
    ],
)
def test_sarif_uri_exact(path: str, expected: str) -> None:
    out = sarif_uri(path)
    assert out == expected
    assert out.isascii() and _URI_REFERENCE.fullmatch(out)
    assert not out.startswith("/")


def test_sarif_uri_maps_invisible_classes_before_encoding() -> None:
    sample = (
        f"d{C0_NUL}{C0_TAB}{C0_LF}{C0_CR}{DEL}{C1_NEL}{CF_BIDI}{CF_ZWSP}{CF_BOM}"
        f"{ZL}{ZP}{CS_LOW}{CS_HIGH}/x.md"
    )
    out = sarif_uri(sample)
    assert out == pct(visible(sample))
    assert "U%2B202E" in out and "U%2BD800" in out and "%E2%90%8A" in out
    assert out.isascii() and "\n" not in out and "\r" not in out


def test_sarif_uri_hostile_path_is_one_ascii_reference() -> None:
    out = sarif_uri(INJECT_PATH)
    assert out == "src/%3A%3Awarning%3A%3A%250A.py"
    assert _URI_REFERENCE.fullmatch(sarif_uri(HOSTILE_PATH))


@given(st.text(max_size=60))
@settings(max_examples=300, deadline=None)
@example(CS_LOW + "/" + CS_HIGH)
@example("//" + CF_BIDI)
def test_sarif_uri_property(text: str) -> None:
    out = sarif_uri(text)
    assert out.isascii() and _URI_REFERENCE.fullmatch(out)
    assert not out.startswith("/")
    assert out.count("/") == visible(text).count("/") - (len(text) - len(text.lstrip("/")))
    assert out == pct(visible(text)) or out.startswith("%2F")


# ---- md_codeblock() ------------------------------------------------------------------


def test_md_codeblock_empty_input_matches_contract_formula() -> None:
    # fence + info + "\n" + "\n".join([]) + "\n" + fence, and no trailing newline.
    assert md_codeblock([]) == "```\n\n```"
    assert md_codeblock([], "") == "```\n\n```"
    assert not md_codeblock([]).endswith("\n")


def test_md_codeblock_one_empty_line_matches_empty_input() -> None:
    # The contract formula yields the same bytes for no lines and one empty line.
    assert md_codeblock([""]) == md_codeblock([]) == "```\n\n```"


def test_md_codeblock_single_line_structure() -> None:
    out = md_codeblock(["hello"])
    assert out == "```\nhello\n```"
    fence, info, body = parse_codeblock(out)
    assert fence == "```" and info == "" and body == ["hello"]


def test_md_codeblock_multiline_structure() -> None:
    out = md_codeblock(["alpha", "beta", "gamma"])
    assert out == "```\nalpha\nbeta\ngamma\n```"
    assert parse_codeblock(out) == ("```", "", ["alpha", "beta", "gamma"])


def test_md_codeblock_accepts_a_tuple_of_lines() -> None:
    assert md_codeblock(("a", "b")) == md_codeblock(["a", "b"])


@pytest.mark.parametrize(
    ("lines", "fence_len"),
    [
        (["no ticks"], 3),
        (["a`b"], 3),  # run of 1 -> max(3, 2) = 3
        (["a``b"], 3),  # run of 2 -> max(3, 3) = 3
        (["```"], 4),
        (["````"], 5),
        (["`" * 4], 5),
        (["`" * 10], 11),
        (["```x"], 4),  # run at start
        (["x```"], 4),  # run at end
        (["x```y"], 4),  # run in the middle
        (["    ```"], 4),  # indented fence-looking line still escalates
        (["` ```` ``"], 5),  # longest run on the line (4), not the first
        (["a`b", "```", "x``y"], 4),  # longest across lines; runs do not merge
        (["``", "``"], 3),  # two run-of-2 lines stay 3; they must not be joined
    ],
    ids=[
        "none",
        "run-1",
        "run-2",
        "run-3",
        "run-4-literal",
        "run-4",
        "run-10",
        "start",
        "end",
        "middle",
        "indented-run-3",
        "longest-of-several",
        "across-lines",
        "runs-do-not-merge-across-lines",
    ],
)
def test_md_codeblock_fence_escalates_with_backtick_runs(lines: list[str], fence_len: int) -> None:
    out = md_codeblock(lines)
    fence, info, body = parse_codeblock(out)
    assert info == ""
    assert len(fence) == fence_len
    assert fence == "`" * fence_len
    assert body == [prepared_line(line) for line in lines]
    for line in body:
        for run in re.findall(r"`+", line):
            assert len(run) < len(fence)


def test_md_codeblock_tildes_do_not_affect_the_fence() -> None:
    out = md_codeblock(["~~~", "~~~~ python", "  ~~~"])
    fence, info, body = parse_codeblock(out)
    assert fence == "```" and info == ""
    assert body == ["~~~", "~~~~ python", "  ~~~"]


def test_md_codeblock_markdown_payloads_are_left_literal() -> None:
    lines = ["@user", "<img src=x>", "[x](y)", "#1"]
    out = md_codeblock(lines)
    assert parse_codeblock(out) == ("```", "", lines)
    # GFM would act on these outside a fence; inside they must be unchanged.
    assert "@user" in out and "<img src=x>" in out and "[x](y)" in out and "#1" in out


def test_md_codeblock_lf_cr_and_u2028_stay_one_output_line() -> None:
    lines = ["has\nlf", "has\rcr", "has\u2028sep"]
    out = md_codeblock(lines)
    fence, info, body = parse_codeblock(out)
    assert fence == "```" and info == ""
    assert body == ["has\u240alf", "has\u240dcr", "hasU+2028sep"]
    assert len(out.splitlines()) == len(lines) + 2


# SR conditions 1 and 2: each listed character, plus the splitlines invariant.
_SR_INVISIBLE: list[tuple[str, str, str]] = [
    ("VT", "\v", "\u240b"),
    ("FF", "\f", "\u240c"),
    ("ESC", "\x1b", "\u241b"),
    ("FS", "\x1c", "\u241c"),
    ("GS", "\x1d", "\u241d"),
    ("RS", "\x1e", "\u241e"),
    ("NEL", "\x85", "U+0085"),
    ("LSEP", "\u2028", "U+2028"),
    ("PSEP", "\u2029", "U+2029"),
    ("LRE", "\u202a", "U+202A"),
    ("RLE", "\u202b", "U+202B"),
    ("PDF", "\u202c", "U+202C"),
    ("LRO", "\u202d", "U+202D"),
    ("RLO", "\u202e", "U+202E"),
    ("LRI", "\u2066", "U+2066"),
    ("RLI", "\u2067", "U+2067"),
    ("FSI", "\u2068", "U+2068"),
    ("PDI", "\u2069", "U+2069"),
    ("ZWSP", "\u200b", "U+200B"),
    ("ZWNJ", "\u200c", "U+200C"),
    ("ZWJ", "\u200d", "U+200D"),
    ("LRM", "\u200e", "U+200E"),
    ("RLM", "\u200f", "U+200F"),
    ("BOM", "\ufeff", "U+FEFF"),
]


@pytest.mark.parametrize(
    ("label", "sample", "mapped"),
    _SR_INVISIBLE,
    ids=[label for label, _sample, _mapped in _SR_INVISIBLE],
)
def test_md_codeblock_sr_invisible_chars_are_mapped(label: str, sample: str, mapped: str) -> None:
    out = md_codeblock([f"A{sample}B"])
    assert codeblock_body(out) == [f"A{mapped}B"]
    assert hidden_chars_except_structural_newlines(out) == []


def test_md_codeblock_splitlines_count_with_every_separator() -> None:
    lines = [f"pre{sep}post" for sep in _SPLITLINES_SEPARATORS]
    out = md_codeblock(lines)
    assert len(out.splitlines()) == len(lines) + 2
    assert codeblock_body(out) == [prepared_line(line) for line in lines]
    assert hidden_chars_except_structural_newlines(out) == []


@pytest.mark.parametrize(("label", "sample", "mapped"), _CLASS_CASES, ids=_CLASS_IDS)
def test_md_codeblock_per_character_class(label: str, sample: str, mapped: str) -> None:
    out = md_codeblock([sample])
    assert codeblock_body(out) == [mapped]
    assert hidden_chars_except_structural_newlines(out) == []


def test_md_codeblock_printable_and_injection_tokens_stay_verbatim() -> None:
    lines = ["ünïcode ファイル :: %0A", "keep :: and %0A"]
    assert codeblock_body(md_codeblock(lines)) == lines


@pytest.mark.parametrize(
    ("info", "lines"),
    [
        ("", ["plain"]),
        ("python", ["x = 1"]),
        ("diff", ["- a", "+ b"]),
        ("markdown", ["# heading"]),
        ("a-z0-9-", ["ok"]),
        ("a" * 32, ["max"]),
        ("-", ["hyphen-only"]),
        ("0", ["digit-only"]),
    ],
)
def test_md_codeblock_valid_info_is_echoed_only_on_the_opening_fence(
    info: str, lines: list[str]
) -> None:
    out = md_codeblock(lines, info)
    fence, got_info, body = parse_codeblock(out)
    assert fence == "```"
    assert got_info == info
    assert body == lines
    assert out.startswith(fence + info + "\n")
    assert out.endswith("\n" + fence)
    if info:
        assert not out.endswith(fence + info)


@pytest.mark.parametrize(
    "info",
    [
        "Python",
        "c++",
        "foo_bar",
        "foo bar",
        "foo\tbar",
        "foo\nbar",
        "foo\rbar",
        "foo`bar",
        "foo.bar",
        " ",
        "python ",
        " python",
        "a" * 33,
        "a" * 32 + "-",
        "~",
        "text/plain",
        "x" * 100,
    ],
    ids=[
        "uppercase",
        "plus",
        "underscore",
        "space",
        "tab",
        "newline",
        "cr",
        "backtick",
        "dot",
        "space-only",
        "trailing-space",
        "leading-space",
        "33-chars",
        "33-chars-hyphen",
        "tilde",
        "slash",
        "100-chars",
    ],
)
def test_md_codeblock_rejects_bad_info(info: str) -> None:
    with pytest.raises(ValueError):
        md_codeblock(["ok"], info)


def test_md_codeblock_line_of_1000_chars_is_kept() -> None:
    line = "a" * 1000
    out = md_codeblock([line])
    assert codeblock_body(out) == [line]
    assert "\u2026" not in out
    assert "more chars" not in out


def test_md_codeblock_line_of_1001_chars_is_cut_with_marker() -> None:
    line = "b" * 1001
    out = md_codeblock([line])
    expected = "b" * 1000 + _CUT_MARKER.format(n=1)
    assert codeblock_body(out) == [expected]
    assert expected.endswith(" [\u20261 more chars]")
    assert "b" * 1001 not in out


def test_md_codeblock_60000_backtick_line_fence_is_at_most_1001() -> None:
    line = "`" * 60_000
    out = md_codeblock([line])
    fence, info, body = parse_codeblock(out)
    assert info == ""
    assert len(fence) == 1001
    assert body == ["`" * 1000 + _CUT_MARKER.format(n=59_000)]
    assert len(out.splitlines()) == 3  # opening, one body line, closing


def test_md_codeblock_fence_is_computed_after_the_cut() -> None:
    # 999 printable chars plus 50 backticks: a pre-cut fence would be 51 long.
    line = "a" * 999 + "`" * 50
    out = md_codeblock([line])
    fence, _info, body = parse_codeblock(out)
    assert body == ["a" * 999 + "`" + _CUT_MARKER.format(n=49)]
    assert len(fence) == 3


def test_md_codeblock_cut_happens_after_mapping() -> None:
    # 200 * U+2028 -> 200 * "U+2028" = 1200 characters; the cut may split a label.
    line = "\u2028" * 200
    mapped = visible(line)
    assert len(mapped) == 1200
    out = md_codeblock([line])
    assert codeblock_body(out) == [mapped[:1000] + _CUT_MARKER.format(n=200)]
    # A cut-before-map implementation would keep 200 labels (1000 mapped chars
    # would require ~167 original characters, not 200).
    assert "U+2028" * 200 not in out


def test_md_codeblock_each_long_line_is_cut_independently() -> None:
    lines = ["x" * 1001, "ok", "y" * 1500]
    out = md_codeblock(lines)
    assert codeblock_body(out) == [prepared_line(line) for line in lines]


def test_md_codeblock_ac_f67_fixture_block_is_byte_identical() -> None:
    block = md_codeblock(list(_AC_F67_LINES))
    assert block == "```\n" + "\n".join(_AC_F67_LINES) + "\n```"
    snapshot = (
        "\U0001f9ed conventiondrift: this PR makes 1 agent rule stale\n\n"
        + block
        + "\n\n"
        + "1 rule changed status \u00b7 8 unchanged \u00b7 details in the job summary\n"
    )
    assert snapshot == _AC_F67_APPROVED
    assert snapshot.encode("utf-8") == _AC_F67_APPROVED.encode("utf-8")


@settings(max_examples=300, derandomize=True)
@example([], "")
@example(["hello"], "")
@example(["```", "x`y"], "python")
@example(["`" * 10], "diff")
@example(["`" * 1001], "")
@example(["a\n", "b\u2028c"], "")
@given(
    lines=st.lists(st.text(max_size=2000), max_size=8),
    info=st.from_regex(r"^[a-z0-9-]{0,32}$", fullmatch=True),
)
def test_md_codeblock_roundtrip_property(lines: list[str], info: str) -> None:
    out = md_codeblock(lines, info)
    fence, got_info, _body = parse_codeblock(out)
    prepared = [prepared_line(line) for line in lines]
    longest = 0
    for line in prepared:
        for run in re.findall(r"`+", line):
            longest = max(longest, len(run))
    assert got_info == info
    assert _INFO_OK.fullmatch(got_info)
    assert len(got_info) <= 32
    assert fence == "`" * max(3, longest + 1)
    assert 3 <= len(fence) <= 1001
    assert out == fence + info + "\n" + "\n".join(prepared) + "\n" + fence
    assert hidden_chars_except_structural_newlines(out) == []
    if lines:
        assert len(out.splitlines()) == len(lines) + 2
    else:
        assert len(out.splitlines()) == 3


# ---- module surface -------------------------------------------------------------------


def test_public_surface_is_exactly_one_function_per_sink() -> None:
    assert sorted(esc.__all__) == [
        "md",
        "md_cell",
        "md_codeblock",
        "output_heredoc",
        "sarif_text",
        "sarif_uri",
        "text_field",
        "workflow_cmd",
        "workflow_prop",
    ]
    assert esc.MAX_CODEBLOCK_LINE == 1000
