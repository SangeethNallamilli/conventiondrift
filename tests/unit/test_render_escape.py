"""T-023 unit and property tests for render/escape.py (critical module).

Covers DESIGN §3a, SECURITY-RULES R3.1, I-14, and the unit halves of
AC-N3.10, AC-N3.13 and AC-E.17. Spec tests named ``test_ac_*`` belong to
the Test Engineer. This file does not use that prefix.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import conventiondrift.render.escape as esc
from conventiondrift.render.escape import (
    md,
    md_cell,
    output_heredoc,
    sarif_text,
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


def hidden_chars(text: str) -> list[str]:
    return [char for char in text if unicodedata.category(char) in _HIDDEN]


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


@settings(max_examples=400, derandomize=True)
@given(st.text())
def test_md_cell_roundtrip_property(text: str) -> None:
    out = md_cell(text)
    if not text:
        assert out == ""
        return
    assert out == md(text).replace("|", "\\|")
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
def test_output_heredoc_per_character_class(label: str, sample: str, mapped: str) -> None:
    entry = output_heredoc("report-path", sample)
    delivered = parse_output_file(entry)["report-path"]
    assert delivered == mapped
    assert hidden_chars(delivered) == []


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


def test_lone_surrogates_do_not_crash() -> None:
    for sample in (CS_LOW, CS_HIGH, f"ok{CS_LOW}{CS_HIGH}ok", CS_LOW * 3):
        assert unspan(md(sample)) == visible(sample)
        assert md_cell(sample) == md(sample)
        assert workflow_cmd(sample) == visible(sample)
        assert workflow_prop(sample) == visible(sample)
        assert sarif_text(sample) == visible(sample)
        assert output_heredoc("report-path", sample).endswith("\n")


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


def test_injected_rule_and_path_form_one_annotation_line() -> None:
    line = f"::warning file={workflow_prop(INJECT_PATH)},line=9::{workflow_cmd(INJECT_RULE)}"
    assert "\n" not in line and "\r" not in line
    m = re.fullmatch(r"::warning file=([^,:]*),line=9::(.*)", line)
    assert m, "properties must not be split by injected ':' or ','"
    assert runner_unescape_prop(m.group(1)) == visible(INJECT_PATH)
    assert runner_unescape_data(m.group(2)) == visible(INJECT_RULE)


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


@pytest.mark.parametrize("func", [workflow_cmd, workflow_prop], ids=lambda f: f.__name__)
@pytest.mark.parametrize(
    "residual",
    ["\r", "\n", "\x00", "\x7f", "\x85", "\u202e", "\u2028", "\ud800"],
    ids=["CR", "LF", "NUL", "DEL", "C1", "Cf bidi", "Zl", "Cs"],
)
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
    hostile = "a\nb\rc" + "\x00\x7f\x85\u202e\u2028\ud800"
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


# ---- module surface -------------------------------------------------------------------


def test_public_surface_is_exactly_one_function_per_sink() -> None:
    assert sorted(esc.__all__) == [
        "md",
        "md_cell",
        "output_heredoc",
        "sarif_text",
        "workflow_cmd",
        "workflow_prop",
    ]
