"""T-023 unit and property tests for render/escape.py (critical module).

Covers DESIGN §3a, SECURITY-RULES R3.1, and the unit halves of AC-N3.10,
AC-N3.13 and AC-E.17. Spec tests named ``test_ac_*`` belong to the Test Engineer.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import conventiondrift.render.escape as esc
from conventiondrift.render.escape import (
    md,
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
    """What md() must show: the text with C0/DEL as Control Pictures."""
    return "".join(
        chr(0x2400 + ord(c)) if ord(c) < 0x20 else ("\u2421" if c == "\x7f" else c) for c in text
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


def test_md_does_not_mutate_unicode() -> None:
    s = "ünïcode ファイル \u202e bidi \u2028 sep"
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


# ---- workflow_cmd() / workflow_prop() -----------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", "plain"),
        ("100%", "100%25"),
        ("%0A", "%250A"),
        ("a\nb", "a%0Ab"),
        ("a\rb", "a%0Db"),
        ("a\r\nb", "a%0D%0Ab"),
        ("a:b,c", "a:b,c"),  # data keeps ':' and ','
        ("::warning::x", "::warning::x"),
        ("%%\n", "%25%25%0A"),
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
        ("x\ny", "x%0Ay"),
        ("x\ry", "x%0Dy"),
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
    assert runner_unescape_prop(m.group(1)) == INJECT_PATH
    assert runner_unescape_data(m.group(2)) == INJECT_RULE


@settings(max_examples=500, derandomize=True)
@given(st.text())
def test_workflow_escapes_roundtrip_and_stay_on_one_line(text: str) -> None:
    data, prop = workflow_cmd(text), workflow_prop(text)
    for out in (data, prop):
        assert "\n" not in out and "\r" not in out
    assert ":" not in prop and "," not in prop
    assert runner_unescape_data(data) == text
    assert runner_unescape_prop(prop) == text


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
    assert parse_output_file(entry) == {"report-path": value}


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
        "report-path": hostile,
        "sarif-path": "",
    }


def test_output_heredoc_shape_and_fresh_delimiter() -> None:
    a, b = output_heredoc("stale-count", "3"), output_heredoc("stale-count", "3")
    m = re.fullmatch(r"stale-count<<(ghadelimiter_[0-9a-f]{32})\n3\n\1\n", a)
    assert m
    assert a != b, "delimiter must be fresh per call"


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
@given(st.text(alphabet=st.characters(blacklist_characters="\r")))
def test_output_heredoc_roundtrip_property(value: str) -> None:
    assert parse_output_file(output_heredoc("report-path", value)) == {"report-path": value}


# ---- sarif_text() -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", "plain"),
        ("[link](1)", "\\[link\\](1)"),
        ("a\\b", "a\\\\b"),
        ("\\[", "\\\\\\["),
        ("**bold** <b>x</b> @someone #123", "**bold** <b>x</b> @someone #123"),
        ("line\nbreak", "line\nbreak"),
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
    assert sarif_unescape(out) == text
    # every '[' / ']' in the output is preceded by an odd number of backslashes
    for m in re.finditer(r"[\[\]]", out):
        run = len(out[: m.start()]) - len(out[: m.start()].rstrip("\\"))
        assert run % 2 == 1


def test_sarif_text_hostile_rule_visible_verbatim() -> None:
    assert sarif_unescape(sarif_text(HOSTILE_RULE)) == HOSTILE_RULE


# ---- module surface -------------------------------------------------------------------


def test_public_surface_is_exactly_one_function_per_sink() -> None:
    assert sorted(esc.__all__) == [
        "md",
        "output_heredoc",
        "sarif_text",
        "workflow_cmd",
        "workflow_prop",
    ]
