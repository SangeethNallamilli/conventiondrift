"""Unit tests for the type-hints checker, conventiondrift.checkers.type_hints (T-018).

Covers AC-F3.8 (D-PM-05 #9; ``self``/``cls`` ignored) and the type-hints half of AC-F2.5.
Counts go through the real walk and pool.
"""

import ast
import textwrap

import pytest
from checker_support import assert_linear, counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.type_hints import TypeHintsChecker
from conventiondrift.checkers.type_hints.match import (
    HINT_WORDS,
    HYPHENATED,
    OPTIONS,
    SCOPE_WORDS,
    match_rule,
)
from conventiondrift.checkers.type_hints.sites import IGNORED_FIRST, is_annotated, type_hint_sites
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site

ALWAYS = match_rule("always use type hints.")
CTX = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...] = ()) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), len(preferred + prohibited))


ANNOTATED = match(("annotated",))
NO_HINTS = match((), ("annotated",))


def src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = TypeHintsChecker()
    assert checker.id == "type-hints"
    assert checker.experimental is False
    assert checker.options == frozenset({"annotated", "unannotated"}) == OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert dict(checker.ast_handlers()) == {
        ast.FunctionDef: type_hint_sites,
        ast.AsyncFunctionDef: type_hint_sites,
    }


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, TypeHintsChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    sentence = "always use type hints."
    assert TypeHintsChecker().match_rule(sentence) == match_rule(sentence)


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "expected"),
    [
        # AC-F2.5 line 7 and AC-F3.8's rule.
        ("always use type hints.", ANNOTATED),
        ("use a type hint on every function.", ANNOTATED),
        ("add type annotations.", ANNOTATED),
        ("every function needs a type annotation.", ANNOTATED),
        ("use type-hints.", ANNOTATED),
        ("use type-hint.", ANNOTATED),
        ("use type-annotations.", ANNOTATED),
        ("use type-annotation.", ANNOTATED),
        ("use type hints and type annotations.", ANNOTATED),
        ("never use type hints.", NO_HINTS),
        ("don't add type annotations.", NO_HINTS),
        ("type hints are forbidden.", NO_HINTS),
        ("type hints and type annotations are forbidden.", NO_HINTS),
        ("ALWAYS USE TYPE HINTS.", ANNOTATED),
    ],
)
def test_match_rule_reads_the_polarity_of_each_mention(sentence: str, expected: RuleMatch) -> None:
    assert match_rule(sentence) == expected


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use logging, not print.",
        "use pytest, not unittest.",
        "annotate every function.",
        "run mypy in strict mode.",
        "keep the code typed.",
        "use hints.",
        "check the type.",  # "type" as the last word
        "type the hints.",  # a word between "type" and "hints"
        "use typehints.",
        "use type-checking.",
        "use type hints; never use type hints.",  # preferred and prohibited
        "never use type hints, use type annotations.",
    ],
)
def test_match_rule_does_not_map_what_it_cannot_read(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_a_two_word_mention_spans_both_words() -> None:
    # In a trailing-cue clause the mentions must be one unbroken list (I-10 item 4a): "type
    # hints and type annotations" is one, so the span covers "hints" too.
    assert match_rule("type hints or type annotations are banned.") == NO_HINTS
    assert match_rule("type hints and the type annotations are banned.") is None
    assert match_rule("type hints the type annotations are banned.") is None  # "the" is no span


def test_the_words_it_reads() -> None:
    assert HINT_WORDS == {"hint", "hints", "annotation", "annotations"}
    assert HYPHENATED == {"type-hint", "type-hints", "type-annotation", "type-annotations"}


def test_it_takes_only_line_7_of_the_canonical_sentences_ac_f2_5() -> None:
    sentences = [
        "use logging, not print.",
        "use httpx for http calls.",
        "use pytest, not unittest.",
        "store money as integer cents.",
        "use f-strings for string formatting.",
        "do not use bare except.",
        "always use type hints.",
        "use uv for dependencies.",
    ]
    assert [i for i, s in enumerate(sentences, start=1) if match_rule(s)] == [7]


def test_the_registry_maps_the_type_hints_rule_to_type_hints() -> None:
    assert rules_of("Always use type hints.") == [(1, "type-hints")]


# D-TL-63 list, pinned so a silent edit of the constant fails (D-TL-25).
_SCOPE_WORDS = frozenset(
    {
        "public",
        "private",
        "internal",
        "exported",
        "api",
        "apis",
        "interface",
        "interfaces",
        "endpoint",
        "endpoints",
        "new",
        "test",
        "tests",
        "script",
        "scripts",
        "library",
        "libraries",
    }
)
_UNSCOPED_WORDS = (
    "function",
    "functions",
    "method",
    "methods",
    "class",
    "classes",
    "code",
    "module",
    "modules",
    "package",
    "packages",
    "all",
    "every",
)


def test_the_scope_words_are_the_d_tl_63_list() -> None:
    assert SCOPE_WORDS == _SCOPE_WORDS


@pytest.mark.parametrize("word", sorted(_SCOPE_WORDS))
def test_a_scope_word_makes_a_type_hints_rule_not_verifiable(word: str) -> None:
    # Over the pinned list, which the test above holds equal to the code constant (D-TL-25),
    # so dropping a word from the code fails here as well as there.
    assert match_rule(f"use type hints in {word}.") is None
    assert rules_of(f"Use type hints in {word}.") == [(1, None)]


def test_named_scoped_type_hints_rules_are_not_mapped() -> None:
    assert match_rule("use type hints in public apis.") is None
    assert match_rule("add type hints to new code.") is None
    assert rules_of("Use type hints in public APIs.") == [(1, None)]
    # "Add ..." is not an extract shape, so it is not a rule; match_rule still
    # returns None, and a same-scope imperative does not map either.
    assert rules_of("Add type hints to new code.") == []
    assert rules_of("Use type hints in new code.") == [(1, None)]


def test_unscoped_type_hints_rules_still_map() -> None:
    assert match_rule("always use type hints.") == ANNOTATED
    assert match_rule("use type hints in every module.") == ANNOTATED
    assert rules_of("Always use type hints.") == [(1, "type-hints")]
    assert rules_of("Use type hints in every module.") == [(1, "type-hints")]


@pytest.mark.parametrize("word", _UNSCOPED_WORDS)
def test_deliberately_unscoped_words_still_map(word: str) -> None:
    assert match_rule(f"use type hints in {word}.") == ANNOTATED
    assert rules_of(f"Use type hints in {word}.") == [(1, "type-hints")]


def test_the_scope_words_are_whole_words() -> None:
    # Same mechanism as string_format: membership in phrases.clauses tokens, not substrings.
    # "newline"/"testing" contain "new"/"test" but are different words, so they still map.
    assert match_rule("use type hints in newline.") == ANNOTATED
    assert match_rule("use type hints in testing.") == ANNOTATED
    assert match_rule("use type hints in newest code.") == ANNOTATED
    assert match_rule("use type hints publicly.") == ANNOTATED


def test_a_scope_word_in_any_clause_is_enough() -> None:
    assert match_rule("always use type hints; keep them on public apis.") is None


# --- sites: AC-F3.8 -------------------------------------------------------------------------

AC_F3_8 = """
    def params(a: int, b):
        return a


    def returns(a) -> int:
        return a


    async def both(a: int) -> int:
        return a


    class Box:
        def method(self, value: int):
            self.value = value

        def bare_method(self):
            return self

        @classmethod
        def bare_class_method(cls):
            return cls
"""


def test_f3_8_four_annotated_and_two_without_count_4_and_2() -> None:
    sites = sites_of("type-hints", {"src/mod.py": src(AC_F3_8)})
    assert ALWAYS is not None
    assert counts(ALWAYS, sites) == (4, 2)
    assert [(s.line, s.option) for s in sites] == [
        (1, "annotated"),
        (5, "annotated"),
        (9, "annotated"),
        (14, "annotated"),
        (17, "unannotated"),
        (21, "unannotated"),
    ]


def test_a_rule_against_type_hints_counts_unannotated_as_following() -> None:
    sites = sites_of("type-hints", {"src/mod.py": src(AC_F3_8)})
    assert counts(NO_HINTS, sites) == (2, 4)


@pytest.mark.parametrize(
    ("signature", "annotated"),
    [
        ("def f():", False),
        ("def f(a, b=1, *args, c, **kwargs):", False),
        ("def f() -> None:", True),
        ("def f(a: int):", True),
        ("def f(a, b: int = 1):", True),
        ("def f(a, /, b: int):", True),
        ("def f(a: int, /):", True),
        ("def f(*args: int):", True),
        ("def f(*, c: int):", True),
        ("def f(**kwargs: int):", True),
        # self and cls, as the first positional parameter, are ignored.
        ("def f(self):", False),
        ("def f(cls):", False),
        ('def f(self: "Box"):', False),
        ("def f(cls: type):", False),
        ("def f(self: int, /):", False),
        ("def f(self: int, /, x):", False),
        ("def f(self, x: int):", True),
        ("def f(self, /, x: int):", True),
        ("def f(self) -> None:", True),
        # Anywhere else, a parameter named self or cls is like any other.
        ("def f(x, self: int):", True),
        ("def f(x, /, cls: int):", True),
        ("def f(*, self: int):", True),
        ("def f(other: int):", True),
        ("async def f(self):", False),
        ("async def f(self, x: int):", True),
    ],
)
def test_what_counts_as_annotated(signature: str, annotated: bool) -> None:
    node = parse(f"{signature}\n    pass\n".encode()).body[0]
    assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    assert is_annotated(node) is annotated


def test_self_and_cls_are_the_ignored_names() -> None:
    assert IGNORED_FIRST == {"self", "cls"}


def test_nested_functions_count_and_lambdas_do_not() -> None:
    source = "def outer():\n    def inner(x: int):\n        pass\n    f = lambda x: x\n"
    assert sites_of("type-hints", {"src/a.py": source}) == [
        Site("src/a.py", 1, 0, "unannotated"),
        Site("src/a.py", 2, 4, "annotated"),
    ]


def test_a_site_is_at_the_def_keyword() -> None:
    source = "@deco\ndef f(x: int):\n    pass\n"
    assert sites_of("type-hints", {"src/a.py": source}) == [Site("src/a.py", 2, 0, "annotated")]


def test_tests_and_scripts_are_not_exempt() -> None:
    source = "def f():\n    pass\n"
    sites = sites_of("type-hints", {"tests/test_x.py": source, "scripts/run.py": source})
    assert [(s.file, s.option) for s in sites] == [
        ("scripts/run.py", "unannotated"),
        ("tests/test_x.py", "unannotated"),
    ]


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": "def f(x: int):\n    pass\n" for i in range(3)}
    assert len(sites_of("type-hints", files, max_workers=2)) == 3


def test_the_handler_reads_the_node_directly() -> None:
    tree = parse(b"async def f():\n    pass\n")
    assert list(type_hint_sites(tree.body[0], CTX)) == [Site("a.py", 1, 0, "unannotated")]


def test_the_handler_gives_nothing_for_a_node_that_is_not_a_function() -> None:
    assert list(type_hint_sites(ast.Name("x"), CTX)) == []
    assert list(type_hint_sites(parse(b"f = lambda x: x\n"), CTX)) == []


# --- linear time (R2.5) ---------------------------------------------------------------------

HOSTILE_RULES = {
    "no cue": lambda n: "always use " + "type hints " * (n // 11),
    "dangling type": lambda n: "never use " + "type " * (n // 5),
}


@pytest.mark.timing
@pytest.mark.parametrize("kind", HOSTILE_RULES)
def test_match_rule_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    assert_linear(HOSTILE_RULES[kind], match_rule, label=kind)
