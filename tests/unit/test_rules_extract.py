"""Unit tests for C6 rule extraction, conventiondrift.rules.extract (T-013).

Expected answers come from SPEC (AC-F2.3, F2.4, F2.5, F2.7, F2.8, AC-E.2),
DESIGN §7 steps 1-3, DESIGN §10 S4 (R2.6 caps), DESIGN §12 A-5 (cap order) and
INTERFACES I-7 (markers), written out by hand, never computed by the code under
test (D-TL-25). Negative and cap tests take their parameters from the module's
own table and constants and also pin those to the spec values.
"""

import ast
import inspect
import re
import time
from collections.abc import Callable
from functools import partial

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conventiondrift.rules import extract as ex
from conventiondrift.rules.extract import (
    MARKER,
    Candidate,
    Marker,
    attach_markers,
    extract_file,
    find_markers,
    normalize,
    recognize,
    segment,
)

# DESIGN §7 step 3, in its order: the fixed table of imperative shapes.
SPEC_SHAPES = (
    "use X",
    "prefer X over Y",
    "always X",
    "never X",
    "do not / don't X",
    "X, not Y",
    "avoid X",
    "store / keep / represent X as Y",
)

# Positive examples per shape, written from DESIGN §7 and the SPEC ACs.
POSITIVES: dict[str, tuple[str, ...]] = {
    "use X": ("Use httpx for HTTP calls.", "Use uv for dependencies."),
    "prefer X over Y": ("Prefer pytest over unittest.",),
    "always X": ("Always use f-strings.", "Always keep functions small"),
    "never X": ("Never use print().",),
    "do not / don't X": (
        "Do not use bare except.",
        "Don't use bare except.",
        "Don\u2019t use bare except.",
    ),
    "X, not Y": ("Logging, not print.",),
    "avoid X": ("Avoid print in library code.",),
    "store / keep / represent X as Y": (
        "Store money as integer cents.",
        "Keep money as integer cents.",
        "Represent money as integer cents.",
    ),
}

AC_F2_5_LINES = (
    "Use logging, not print.",
    "Use httpx for HTTP calls.",
    "Use pytest, not unittest.",
    "Store money as integer cents.",
    "Use f-strings for string formatting.",
    "Do not use bare except.",
    "Always use type hints.",
    "Use uv for dependencies.",
)


def _rules(text: str, path: str = "AGENTS.md") -> list[tuple[int, str]]:
    return [(r.line, r.text) for r in extract_file(path, text.encode()).rules]


def _lines(text: str, path: str = "AGENTS.md") -> list[int]:
    return [r.line for r in extract_file(path, text.encode()).rules]


# --- pattern table -------------------------------------------------------------------


def test_shape_table_is_the_design_table_in_order() -> None:
    assert tuple(shape.name for shape in ex.SHAPES) == SPEC_SHAPES


def test_positive_examples_cover_every_shape() -> None:
    assert set(POSITIVES) == {shape.name for shape in ex.SHAPES}


@pytest.mark.parametrize(
    ("shape", "sentence"),
    [(shape, s) for shape, sentences in POSITIVES.items() for s in sentences],
)
def test_each_shape_is_recognized(shape: str, sentence: str) -> None:
    assert recognize(normalize(sentence)) == shape


def _bare_word(shape_name: str) -> list[str]:
    # The leading words of a shape with nothing after them: no X, so no rule.
    return {
        "use X": ["use", "use "],
        "prefer X over Y": ["prefer pytest", "prefer over y", "prefer pytest over"],
        "always X": ["always"],
        "never X": ["never"],
        "do not / don't X": ["do not", "don't", "don\u2019t"],
        "X, not Y": [", not y", "logging, not", "logging not print"],
        "avoid X": ["avoid"],
        "store / keep / represent X as Y": ["store money", "keep x as", "represent as y"],
    }[shape_name]


@pytest.mark.parametrize("shape", ex.SHAPES, ids=lambda s: s.name)
def test_each_shape_rejects_incomplete_sentences(shape: ex.Shape) -> None:
    for text in _bare_word(shape.name):
        assert shape.pattern.search(text) is None, text
        assert recognize(text) is None, text


@pytest.mark.parametrize("shape", ex.SHAPES, ids=lambda s: s.name)
def test_each_shape_is_anchored_at_sentence_start(shape: ex.Shape) -> None:
    # A shape later in a prose sentence is not an imperative (I-13 C6 ruling T-013-2).
    for sentence in POSITIVES[shape.name]:
        prose = "our team says " + normalize(sentence).replace(",", "")
        assert shape.pattern.search(prose) is None, prose


def test_prose_without_a_shape_is_not_a_rule() -> None:
    for text in (
        "Our services talk to each other over HTTP.",
        "We use Django.",
        "This repository is a demo.",
        "Users never log in twice.",
    ):
        assert recognize(normalize(text)) is None, text


def test_first_matching_shape_names_the_rule() -> None:
    # "Use httpx, not requests." has both "use X" and "X, not Y"; table order wins.
    assert recognize("use httpx, not requests.") == "use X"


# --- SPEC acceptance shapes ------------------------------------------------------------


def test_five_bullet_shapes_at_lines_1_to_5() -> None:
    text = (
        "- Use httpx, not requests.\n"
        "- Prefer pytest over unittest.\n"
        "- Always use f-strings.\n"
        "- Never use print().\n"
        "- Do not use bare except.\n"
    )
    assert _rules(text) == [
        (1, "Use httpx, not requests."),
        (2, "Prefer pytest over unittest."),
        (3, "Always use f-strings."),
        (4, "Never use print()."),
        (5, "Do not use bare except."),
    ]


def test_paragraph_sentence_rule_at_line_3() -> None:
    text = (
        "# Conventions\n"
        "\n"
        "Our services talk to each other over HTTP. Use httpx, not requests, for those calls.\n"
    )
    assert _rules(text) == [(3, "Use httpx, not requests, for those calls.")]


def test_eight_canonical_sentences_at_lines_1_to_8() -> None:
    text = "".join(line + "\n" for line in AC_F2_5_LINES)
    assert _rules(text) == list(enumerate(AC_F2_5_LINES, start=1))


def test_unmappable_rule_is_still_a_rule() -> None:
    # AC-F2.7's rule must reach mapping, which then gives Not verifiable.
    assert _rules("Always keep functions small\n") == [(1, "Always keep functions small")]


def test_rules_on_lines_4_9_17() -> None:
    lines = ["# Title", "", "Some prose here.", "- Use httpx for HTTP calls."]
    lines += ["", "More prose.", "", "Still prose, nothing to check."]
    lines += ["- Never use print()."]
    lines += ["", "prose"] * 3 + [""]
    lines += ["Always use type hints."]
    text = "\n".join(lines) + "\n"
    assert _lines(text) == [4, 9, 17]


def test_prose_only_file_has_zero_rules() -> None:
    text = "# About\n\nThis project analyzes code. It is written in Python.\n\nSee the docs.\n"
    result = extract_file("AGENTS.md", text.encode())
    assert result.rules == ()
    assert result.unattached_markers == ()


def test_extraction_is_identical_over_10_runs() -> None:
    text = "".join(line + "\n" for line in AC_F2_5_LINES) + f"{MARKER}\n- Use pip.\n"
    first = extract_file("AGENTS.md", text.encode())
    assert all(extract_file("AGENTS.md", text.encode()) == first for _ in range(9))


# --- segmenting ------------------------------------------------------------------------


def test_bullet_kinds_each_start_a_rule() -> None:
    text = "- Use a.\n* Use b.\n+ Use c.\n1. Use d.\n2) Use e.\n  - Use f.\n"
    assert _rules(text) == [
        (1, "Use a."),
        (2, "Use b."),
        (3, "Use c."),
        (4, "Use d."),
        (5, "Use e."),
        (6, "Use f."),
    ]


def test_bullet_continuation_lines_join_the_bullet() -> None:
    text = "- Use httpx\n  for HTTP calls.\n- Never use\nprint().\n"
    assert _rules(text) == [(1, "Use httpx for HTTP calls."), (3, "Never use print().")]


def test_sentence_start_line_inside_a_wrapped_paragraph() -> None:
    text = (
        "Intro line one\ncontinues here. Use httpx\n"
        "for calls. And more\nprose. Never use print().\n"
    )
    assert _rules(text) == [(2, "Use httpx for calls."), (4, "Never use print().")]


def test_blank_line_heading_and_break_end_a_paragraph() -> None:
    text = "Some prose\n\nUse a\n## Head\nUse b\n---\nUse c\n***\nUse d\n"
    assert _rules(text) == [(3, "Use a"), (5, "Use b"), (7, "Use c"), (9, "Use d")]


def test_two_break_chars_or_a_bullet_char_without_space_continue_the_paragraph() -> None:
    # A thematic break needs three marks, and a bullet needs whitespace after it.
    text = "Use a\n__\n-b, not c.\n*Never* x\n1.5 and\nmore.\n"
    assert list(segment("AGENTS.md", text)) == [
        Candidate(line=1, text="Use a __ -b, not c."),
        Candidate(line=4, text="*Never* x 1.5 and more."),
    ]


def test_heading_text_is_not_a_candidate() -> None:
    assert _rules("# Use httpx\n## Never use print\n") == []


def test_sentence_terminators() -> None:
    text = "Use a! Use b? Use python 3.11. Use e.g.x now.\n"
    assert _rules(text) == [
        (1, "Use a!"),
        (1, "Use b?"),
        (1, "Use python 3.11."),
        (1, "Use e.g.x now."),
    ]


def test_crlf_bom_and_unicode_line_separators() -> None:
    data = "\ufeffUse a.\r\n\r\nUse b\u2028still line 3.\r\n- Use c.\r\n".encode()
    result = extract_file("AGENTS.md", data)
    assert [(r.line, r.text) for r in result.rules] == [
        (1, "Use a."),
        (3, "Use b still line 3."),
        (4, "Use c."),
    ]


def test_undecodable_bytes_do_not_raise() -> None:
    result = extract_file("AGENTS.md", b"Use \xff\xfe a.\n")
    assert [r.line for r in result.rules] == [1]


def test_segment_yields_prose_candidates_too() -> None:
    assert list(segment("AGENTS.md", "Hello there. Use a.\n")) == [
        Candidate(line=1, text="Hello there."),
        Candidate(line=1, text="Use a."),
    ]


# --- code fences -----------------------------------------------------------------------


@pytest.mark.parametrize("fence", ["```", "~~~", "````", "```python", "~~~ text", "   ```"])
def test_code_fence_content_is_ignored(fence: str) -> None:
    close = fence.strip().split(" ")[0].rstrip("python")
    text = f"- Use a.\n{fence}\n- Use x.\nNever use y.\n{close}\n- Use b.\n"
    assert _rules(text) == [(1, "Use a."), (6, "Use b.")]


def test_shorter_or_other_fence_does_not_close() -> None:
    text = "````\nUse x.\n```\n~~~~\nUse y.\n````\nUse b.\n"
    assert _rules(text) == [(7, "Use b.")]


def test_closing_fence_may_be_longer() -> None:
    assert _rules("```\nUse x.\n``````\nUse b.\n") == [(4, "Use b.")]


def test_unclosed_fence_runs_to_end_of_file() -> None:
    assert _rules("Use a.\n```\nUse x.\n\nNever use y.\n") == [(1, "Use a.")]


def test_backtick_info_string_with_backtick_is_not_a_fence() -> None:
    # CommonMark: "```a`b" is inline code, not a fence opener.
    assert _rules("```a`b\n\nUse b.\n") == [(3, "Use b.")]


def test_fence_text_after_closing_chars_does_not_close() -> None:
    assert _rules("```\n``` not a close\nUse x.\n```\nUse b.\n") == [(5, "Use b.")]


def test_fence_ends_the_open_paragraph() -> None:
    assert _rules("Use a\n```\ncode\n```\nUse b\n") == [(1, "Use a"), (5, "Use b")]


# --- .mdc front matter -----------------------------------------------------------------


def test_mdc_front_matter_is_skipped_and_lines_kept() -> None:
    text = "---\ndescription: Use httpx.\nglobs: '*.py'\n---\n- Use httpx.\n"
    assert _rules(text, ".cursor/rules/http.mdc") == [(5, "Use httpx.")]


def test_front_matter_only_in_mdc_files() -> None:
    text = "---\nUse a.\n---\n- Use b.\n"
    assert _rules(text, "AGENTS.md") == [(2, "Use a."), (4, "Use b.")]


def test_front_matter_must_start_on_line_1() -> None:
    text = "\n---\nUse a.\n---\n"
    assert _rules(text, "x.mdc") == [(3, "Use a.")]


def test_unclosed_mdc_front_matter_is_not_front_matter() -> None:
    # I-13 C6 ruling (T-013-1): read as CommonMark does, so the rule is kept.
    assert _rules("---\nUse a.\n", "x.mdc") == [(2, "Use a.")]


def test_mdc_front_matter_with_trailing_spaces() -> None:
    assert _rules("--- \nUse a.\n---  \nUse b.\n", "x.mdc") == [(4, "Use b.")]


# --- normalizing -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Use  HTTPX\tfor   calls.", "use httpx for calls."),
        ("**Never** use `print()`.", "never use print()."),
        ("*Always* use __type hints__.", "always use type hints."),
        ("_Use_ httpx.", "use httpx."),
        ("Store money as integer_cents.", "store money as integer_cents."),
        ("Use x_ and _y.", "use x and y."),
        (f"Use requests for HTTP calls {MARKER}", "use requests for http calls"),
        ("", ""),
        ("___", ""),
    ],
)
def test_normalize(raw: str, expected: str) -> None:
    assert normalize(raw) == expected


def test_rule_text_keeps_markdown_but_drops_the_marker() -> None:
    (rule,) = extract_file("AGENTS.md", f"- Use **httpx**  for calls {MARKER}\n".encode()).rules
    assert rule.text == "Use **httpx** for calls"
    assert rule.normalized_text == "use httpx for calls"


# --- I-7 markers -----------------------------------------------------------------------


def test_marker_constant_is_i7_text() -> None:
    assert MARKER == "<!-- conventiondrift: ignore -->"


def test_marker_on_the_same_line_ignores_the_rule() -> None:
    result = extract_file("AGENTS.md", f"- Use requests for HTTP calls {MARKER}\n".encode())
    assert [(r.line, r.ignored) for r in result.rules] == [(1, True)]
    assert result.unattached_markers == ()


def test_marker_alone_on_the_line_above_ignores_the_rule() -> None:
    text = f"- Use a.\n  {MARKER}  \n- Use b.\n- Use c.\n"
    result = extract_file("AGENTS.md", text.encode())
    assert [(r.line, r.ignored) for r in result.rules] == [(1, False), (3, True), (4, False)]
    assert result.unattached_markers == ()


def test_marker_two_lines_above_is_unattached() -> None:
    result = extract_file("AGENTS.md", f"{MARKER}\n\n- Use b.\n".encode())
    assert [r.ignored for r in result.rules] == [False]
    assert result.unattached_markers == (1,)


def test_marker_not_alone_on_line_above_is_unattached() -> None:
    result = extract_file("AGENTS.md", f"Some prose {MARKER}\n- Use b.\n".encode())
    assert [r.ignored for r in result.rules] == [False]
    assert result.unattached_markers == (1,)


def test_marker_on_continuation_line_is_unattached() -> None:
    result = extract_file("AGENTS.md", f"- Use httpx\n  for calls. {MARKER}\n".encode())
    assert [r.ignored for r in result.rules] == [False]
    assert result.unattached_markers == (2,)


@pytest.mark.parametrize(
    "variant",
    [
        "<!-- Conventiondrift: ignore -->",
        "<!--conventiondrift: ignore-->",
        "<!-- conventiondrift:  ignore -->",
        "<!-- conventiondrift: IGNORE -->",
    ],
)
def test_marker_match_is_exact(variant: str) -> None:
    result = extract_file("AGENTS.md", f"- Use a. {variant}\n".encode())
    assert [r.ignored for r in result.rules] == [False]
    assert result.unattached_markers == ()


def test_marker_on_a_line_with_two_rule_starts_ignores_both() -> None:
    result = extract_file("AGENTS.md", f"Use a. Use b. {MARKER}\n".encode())
    assert [(r.line, r.ignored) for r in result.rules] == [(1, True), (1, True)]


def test_marker_line_alone_ends_the_paragraph() -> None:
    text = f"Some prose\n{MARKER}\nUse b.\n"
    result = extract_file("AGENTS.md", text.encode())
    assert [(r.line, r.text, r.ignored) for r in result.rules] == [(3, "Use b.", True)]


def test_marker_in_code_fence_or_on_prose_is_unattached() -> None:
    text = f"```\n{MARKER}\nUse x.\n```\nProse only. {MARKER}\n"
    result = extract_file("AGENTS.md", text.encode())
    assert result.rules == ()
    assert result.unattached_markers == (2, 5)


def test_one_entry_per_marker_line() -> None:
    assert find_markers(f"a {MARKER} {MARKER}\n{MARKER}\n") == (
        Marker(line=1, alone=False),
        Marker(line=2, alone=True),
    )


def test_policy_side_markers_override_the_files_own() -> None:
    text = f"- Use a.\n- Use b. {MARKER}\n"
    result = extract_file("AGENTS.md", text.encode(), markers=(Marker(line=1, alone=False),))
    assert [(r.line, r.ignored) for r in result.rules] == [(1, True), (2, False)]
    result = extract_file("AGENTS.md", text.encode(), markers=())
    assert [r.ignored for r in result.rules] == [False, False]


def test_policy_markers_pairs_are_accepted_as_is() -> None:
    # I-13 Policy.markers holds plain (line, alone_on_line) pairs; they pass straight through.
    text = "- Use a.\n- Use b.\n"
    pairs: tuple[tuple[int, bool], ...] = ((1, True), (2, False))
    result = extract_file("AGENTS.md", text.encode(), markers=pairs)
    assert [(r.line, r.ignored) for r in result.rules] == [(1, False), (2, True)]
    assert Marker(4, True) == (4, True)


def test_attach_markers_directly() -> None:
    markers = (Marker(3, True), Marker(5, False), Marker(9, True), Marker(10, False))
    assert attach_markers({4, 5, 7}, markers) == (frozenset({4, 5}), (9, 10))


# --- R2.6 caps -------------------------------------------------------------------------


def test_cap_constants_are_the_r2_6_values() -> None:
    assert ex.MAX_RULES_PER_FILE == 500
    assert ex.MAX_CANDIDATES_PER_FILE == 5_000


@pytest.mark.parametrize("delta", [-1, 0, 1, 7])
def test_rule_cap_keeps_the_first_n_in_file_order(delta: int) -> None:
    cap = ex.MAX_RULES_PER_FILE
    count = cap + delta
    text = "".join(f"- Use opt{i}.\n" for i in range(count))
    result = extract_file("AGENTS.md", text.encode())
    kept = min(count, cap)
    assert [r.line for r in result.rules] == list(range(1, kept + 1))
    assert result.rules[-1].text == f"Use opt{kept - 1}."
    assert result.rules_dropped == count - kept
    assert result.candidates_dropped == 0


@pytest.mark.parametrize("delta", [-1, 0, 1, 7])
def test_candidate_cap_keeps_the_first_n_in_file_order(delta: int) -> None:
    cap = ex.MAX_CANDIDATES_PER_FILE
    count = cap + delta
    # Prose candidates fill the cap; the rule sits right after them.
    text = "Prose here. " * (count - 1) + "Use httpx.\n"
    result = extract_file("AGENTS.md", text.encode())
    if count <= cap:
        assert [r.text for r in result.rules] == ["Use httpx."]
        assert result.candidates_dropped == 0
    else:
        assert result.rules == ()
        assert result.candidates_dropped == count - cap


def test_candidate_cap_counts_in_column_order_on_one_line() -> None:
    cap = ex.MAX_CANDIDATES_PER_FILE
    text = "Use a. " + "Prose. " * (cap - 2) + "Use b. Use c.\n"
    result = extract_file("AGENTS.md", text.encode())
    assert [r.text for r in result.rules] == ["Use a.", "Use b."]
    assert result.candidates_dropped == 1


def test_both_caps_together() -> None:
    cap_c, cap_r = ex.MAX_CANDIDATES_PER_FILE, ex.MAX_RULES_PER_FILE
    text = "".join(f"- Use o{i}.\n" for i in range(cap_c + 3))
    result = extract_file("AGENTS.md", text.encode())
    assert len(result.rules) == cap_r
    assert result.rules_dropped == cap_c - cap_r
    assert result.candidates_dropped == 3


def test_marker_on_a_capped_rule_is_unattached() -> None:
    cap = ex.MAX_RULES_PER_FILE
    text = "".join(f"- Use o{i}.\n" for i in range(cap)) + f"- Use extra. {MARKER}\n"
    result = extract_file("AGENTS.md", text.encode())
    assert result.rules_dropped == 1
    assert result.unattached_markers == (cap + 1,)
    assert not any(r.ignored for r in result.rules)


# --- ReDoS (SECURITY-RULES R2.5, SEC-T09) ----------------------------------------------

_SIZE = 1 << 20  # the 1 MiB instruction-file size limit (R2.3)


def _adversarial(n: int) -> list[str]:
    """Long hostile strings aimed at each registered pattern's quantifiers."""
    return [
        "a" * n,
        " " * n,
        "\t" * n,
        "_" * n,
        "a_" * (n // 2),
        "," * n,
        "1" * n,
        "-" * n,
        "#" * n,
        "prefer " + "x " * (n // 2),
        "prefer x" + " over" * (n // 5),
        "store " + "x " * (n // 2),
        "keep x" + " as" * (n // 3),
        "x" * n + ", not",
        "do not" * (n // 6),
        " " * n + "-",
        " " * n + "1" * n,
    ]


def _best_time(func: Callable[[], object], repeat: int = 3) -> float:
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        func()
        best = min(best, time.perf_counter() - start)
    return best


def _run_all(pattern: re.Pattern[str], text: str) -> None:
    pattern.match(text)
    pattern.search(text)
    for _ in pattern.finditer(text):
        pass


@pytest.mark.parametrize("pattern", ex.REGEXES, ids=lambda p: p.pattern)
def test_registered_regex_is_linear_on_adversarial_input(pattern: re.Pattern[str]) -> None:
    # Sizes double from 16 KiB up to 512 KiB (half the 1 MiB size limit), so a
    # super-linear regex fails fast on a small input instead of hanging.
    sizes = [1 << k for k in range(14, 20)]
    inputs = [_adversarial(n) for n in sizes]
    for kind in range(len(inputs[0])):
        previous = 0.0
        for n, strings in zip(sizes, inputs, strict=True):
            text = strings[kind]
            elapsed = _best_time(partial(_run_all, pattern, text))
            assert elapsed < 0.5, (pattern.pattern, text[:20], n, elapsed)
            if previous:
                # Doubling the input must not much more than double the time.
                assert elapsed < 3 * previous + 0.005, (pattern.pattern, text[:20], n)
            previous = elapsed


@pytest.mark.parametrize("kind", range(len(_adversarial(10))))
def test_extract_file_at_size_cap_is_fast(kind: int) -> None:
    text = _adversarial(_SIZE)[kind][:_SIZE]
    for wrapped in (text, "- " + text, "Use " + text, f"{MARKER}\n" + text):
        elapsed = _best_time(partial(extract_file, "x.mdc", wrapped.encode()), repeat=1)
        assert elapsed < 3.0, (kind, wrapped[:20], elapsed)


def test_extract_file_with_many_short_lines_is_fast() -> None:
    blocks = ["- Use a.", "```", "Prose. " * 20, f"{MARKER}", "# H", "---", "Prefer x over y."]
    text = "\n".join(blocks * (_SIZE // 200))
    elapsed = _best_time(lambda: extract_file("AGENTS.md", text.encode()), repeat=1)
    assert elapsed < 5.0


def test_every_compiled_regex_in_the_module_is_registered() -> None:
    tree = ast.parse(inspect.getsource(ex))
    compiled = 0
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
        ):
            assert node.func.attr == "compile", "only precompiled, registered regexes"
            compiled += 1
    assert compiled == len(ex.REGEXES)
    registered = {id(p) for p in ex.REGEXES}
    module_patterns = [v for v in vars(ex).values() if isinstance(v, re.Pattern)]
    assert {id(p) for p in module_patterns} <= registered
    assert {id(shape.pattern) for shape in ex.SHAPES} <= registered


# --- properties ------------------------------------------------------------------------


_md_text = st.lists(
    st.sampled_from([*"ab ,.!?-*_`#~>\n\r\t1", "use ", "never ", MARKER, "```", "---\n"]),
    max_size=200,
).map("".join)


@settings(max_examples=200, deadline=None)
@given(_md_text)
def test_extraction_is_total_and_lines_are_in_range(text: str) -> None:
    result = extract_file("x.mdc", text.encode())
    line_count = len(text.split("\n"))
    lines = [r.line for r in result.rules]
    assert lines == sorted(lines)
    assert all(1 <= line <= line_count for line in lines)
    assert all(MARKER not in r.text for r in result.rules)
    assert all(recognize(r.normalized_text) == r.shape for r in result.rules)
    assert result == extract_file("x.mdc", text.encode())
