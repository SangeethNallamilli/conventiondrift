"""Unit tests for the string-format checker, conventiondrift.checkers.string_format (T-017).

Covers AC-F3.6 and the string formatting half of AC-F2.5. Counts go through the real walk
and pool.
"""

import ast
import sys
import textwrap

import pytest
from checker_support import counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.string_format import StringFormatChecker
from conventiondrift.checkers.string_format.match import OPTIONS, match_rule
from conventiondrift.checkers.string_format.sites import FormatSites
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site

USE_F_STRINGS = match_rule("use f-strings.")


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...] = ()) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), len(preferred + prohibited))


def src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def ctx(path: str = "a.py") -> FileContext:
    return FileContext(path, is_test_file=False, is_script=False, main_guard_spans=())


def options_of(source: str) -> list[str]:
    return [s.option for s in sites_of("string-format", {"src/a.py": source})]


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = StringFormatChecker()
    assert checker.id == "string-format"
    assert checker.experimental is False
    assert checker.options == frozenset({"f-string", "format", "percent"}) == OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert set(checker.ast_handlers()) == {
        ast.JoinedStr,
        ast.FormattedValue,
        ast.Call,
        ast.BinOp,
    }


def test_each_handler_table_has_its_own_state() -> None:
    first = StringFormatChecker().ast_handlers()
    second = StringFormatChecker().ast_handlers()
    assert first[ast.JoinedStr] != second[ast.JoinedStr]


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, StringFormatChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    sentence = "use f-strings, not .format()."
    assert StringFormatChecker().match_rule(sentence) == match_rule(sentence)


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "preferred", "prohibited"),
    [
        # AC-F2.5 line 5, AC-F3.6's rule, and the other DESIGN §7 shapes.
        ("use f-strings for string formatting.", ("f-string",), ()),
        ("use f-strings.", ("f-string",), ()),
        ("always use f-strings.", ("f-string",), ()),
        ("use f-string.", ("f-string",), ()),
        ("use fstrings.", ("f-string",), ()),
        ("use f strings.", ("f-string",), ()),
        ("use f-strings, not .format().", ("f-string",), ("format",)),
        ("use f-strings, not str.format().", ("f-string",), ("format",)),
        ("use f-strings, not the % operator.", ("f-string",), ("percent",)),
        ("prefer f-strings over .format() or %s formatting.", ("f-string",), ("format", "percent")),
        ("use str.format().", ("format",), ()),
        ("use .format() for templates.", ("format",), ()),
        ("don't use the % operator or .format().", (), ("percent", "format")),
        ("never use %-formatting.", (), ("percent",)),
        ("never use % formatting.", (), ("percent",)),
        ("avoid %d and %r placeholders.", (), ("percent",)),
        ("avoid percent formatting.", (), ("percent",)),
        ("avoid printf-style formatting.", (), ("percent",)),
        ("never use f-strings.", (), ("f-string",)),
        ("USE F-STRINGS.", ("f-string",), ()),
    ],
)
def test_match_rule_reads_the_formats_and_their_polarity(
    sentence: str, preferred: tuple[str, ...], prohibited: tuple[str, ...]
) -> None:
    assert match_rule(sentence) == match(preferred, prohibited)


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use string formatting.",
        "use of string formatting.",  # "of string" is not "f string"
        "keep coverage above 90%.",
        "use a format string.",
        "use formatting tools.",
        "use logging, not print.",
        "use pytest, not unittest.",
        "never use f-strings; always use f-strings.",  # one option, both polarities
        "never use f-strings, .format() or %s.",  # forbids every option
        "use f-strings, .format() and %s.",  # prefers every option
    ],
)
def test_match_rule_does_not_map_what_names_no_format_or_cannot_be_read(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_specificity_is_the_number_of_options_named() -> None:
    one = match_rule("use f-strings.")
    three = match_rule("use f-strings, not .format() or the % operator.")
    assert one is not None
    assert three is not None
    assert (one.specificity, three.specificity) == (1, 3)


def test_it_leaves_the_other_canonical_sentences_alone_ac_f2_5() -> None:
    others = [
        "use logging, not print.",
        "use httpx for http calls.",
        "use pytest, not unittest.",
        "store money as integer cents.",
        "do not use bare except.",
        "always use type hints.",
        "use uv for dependencies.",
    ]
    assert [s for s in others if match_rule(s)] == []


def test_the_registry_maps_the_rule_to_string_format_ac_f2_5() -> None:
    assert rules_of("Use f-strings for string formatting.") == [(1, "string-format")]
    assert rules_of("Use f-strings, not .format().") == [(1, "string-format")]


# --- sites: AC-F3.6 -------------------------------------------------------------------------


def test_f3_6_four_f_strings_two_format_calls_and_one_percent_count_4_and_3() -> None:
    source = src(
        """
        a = f"{x}"
        b = f"id {x}"
        c = f"{x} and {y}"
        d = f"plain"
        e = "{}".format(x)
        g = "{} {}".format(x, y)
        h = "%s" % x
        """
    )
    sites = sites_of("string-format", {"src/mod.py": source})
    assert USE_F_STRINGS is not None
    assert counts(USE_F_STRINGS, sites) == (4, 3)
    assert sorted(s.option for s in sites) == ["f-string"] * 4 + ["format"] * 2 + ["percent"]


def test_a_format_only_rule_counts_percent_as_following() -> None:
    forbidden = match_rule("never use .format().")
    assert forbidden is not None
    sites = sites_of("string-format", {"a.py": 'a = "{}".format(x)\nb = "%s" % x\nc = f"{x}"\n'})
    assert counts(forbidden, sites) == (2, 1)


def test_sites_are_at_the_start_of_the_expression() -> None:
    source = 'x = f"a"\ny = "{}".format(1)\nz = ("%s" % 1)\n'
    assert sites_of("string-format", {"src/a.py": source}) == [
        Site("src/a.py", 1, 4, "f-string"),
        Site("src/a.py", 2, 4, "format"),
        Site("src/a.py", 3, 5, "percent"),
    ]


@pytest.mark.parametrize(
    "source",
    [
        'x = f"{a:.2f}"',
        'x = f"{a:>{w}}"',
        'x = f"{a:{w}.{p}}"',
        'x = f"{a!r:>10}"',
        'x = f"{a:}"',
        'x = f"{a}" f"{b:.1f}"',  # joined by the parser into one string
        'x = f"a{b:.2f}c" "d"',
    ],
)
def test_the_spec_of_a_field_is_not_a_second_f_string(source: str) -> None:
    assert options_of(source + "\n") == ["f-string"]


def test_an_f_string_inside_a_field_is_a_site_of_its_own() -> None:
    assert options_of("x = f\"{f'{a}'}\"\n") == ["f-string", "f-string"]
    assert options_of("x = f\"{f'{a:.1f}':>{w}}\"\n") == ["f-string", "f-string"]


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 701 syntax needs 3.12")
@pytest.mark.parametrize(
    ("source", "count"),
    [('x = f"{f"{a:.1f}"}"\n', 2), ('x = f"{a:{w:>{z}}}"\n', 1)],
)
def test_pep_701_nesting(source: str, count: int) -> None:
    assert options_of(source) == ["f-string"] * count


def test_f_strings_in_two_statements_with_specs_each_count_once() -> None:
    source = 'a = f"{x:.2f}"\nb = f"{y:>{w}}"\nc = f"{z}"\n'
    assert options_of(source) == ["f-string"] * 3


@pytest.mark.parametrize(
    ("code", "option"),
    [
        ('"{}".format(x)', "format"),
        ('"{a}".format(a=1)', "format"),
        ('"a" "b {}".format(x)', "format"),
        ('"{}".format()', "format"),
        ('"%s" % x', "percent"),
        ('"%s %s" % (a, b)', "percent"),
        ('"%(a)s" % {"a": 1}', "percent"),
        ('"no placeholder" % ()', "percent"),
        ('"a" "%s" % x', "percent"),
    ],
)
def test_each_form_of_formatting_with_a_string_literal_is_a_site(code: str, option: str) -> None:
    assert options_of(code + "\n") == [option]


@pytest.mark.parametrize(
    "code",
    [
        "template.format(x)",  # not a literal: can't be told from other code
        "text % x",
        "x % 3",
        "3 % x",
        'b"%s" % x',  # bytes
        'b"{}".format(x)',
        '"{}".strip()',
        '"{}".formatted(x)',
        'str.format("{}", x)',
        'logger.info("%s", x)',
        '"a" + "b"',
        '"%s" + x',
        '"a" * 3',
        'x = "plain"',
        "format(x)",
    ],
)
def test_other_code_is_not_a_site(code: str) -> None:
    assert options_of(code + "\n") == []


def test_formatting_is_found_inside_nested_code_and_arguments() -> None:
    source = 'def f():\n    return [g("{}".format(f"{x}" % y)) for x in xs]\n'
    assert sorted(options_of(source)) == ["f-string", "format"]


def test_tests_and_scripts_count_like_other_files() -> None:
    sites = sites_of("string-format", {"tests/test_x.py": 'f"{a}"\n', "scripts/run.py": 'f"{b}"\n'})
    assert [s.file for s in sites] == ["scripts/run.py", "tests/test_x.py"]


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": 'x = f"{a:.1f}"\n' for i in range(3)}
    assert len(sites_of("string-format", files, max_workers=2)) == 3


# --- the handlers, read directly ----------------------------------------------------------


def _field(source: str) -> ast.FormattedValue:
    node = parse(source.encode()).body[0]
    assert isinstance(node, ast.Assign)
    assert isinstance(node.value, ast.JoinedStr)
    field = node.value.values[0]
    assert isinstance(field, ast.FormattedValue)
    return field


def test_a_spec_that_was_noted_is_skipped_once() -> None:
    handlers = FormatSites()
    field = _field('x = f"{a:.2f}"\n')
    spec = field.format_spec
    assert spec is not None
    assert list(handlers.note_spec(field, ctx())) == []
    assert list(handlers.f_string(spec, ctx())) == []
    # The note is used up: the same node would now be a site.
    assert [s.option for s in handlers.f_string(spec, ctx())] == ["f-string"]


def test_a_field_without_a_spec_notes_nothing() -> None:
    handlers = FormatSites()
    field = _field('x = f"{a}"\n')
    assert list(handlers.note_spec(field, ctx())) == []
    assert list(handlers.f_string(ast.JoinedStr(values=[], lineno=1, col_offset=0), ctx())) != []


def test_each_walk_starts_with_no_notes() -> None:
    field = _field('x = f"{a:.2f}"\n')
    spec = field.format_spec
    assert spec is not None
    FormatSites().note_spec(field, ctx())  # a walk that stopped early
    assert [s.option for s in FormatSites().f_string(spec, ctx())] == ["f-string"]


def test_the_handlers_give_nothing_for_a_node_of_another_kind() -> None:
    handlers = FormatSites()
    other = ast.Name("x")
    for handler in (handlers.note_spec, handlers.f_string, handlers.format_call, handlers.percent):
        assert list(handler(other, ctx())) == []
