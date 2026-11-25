"""Unit tests for the test-framework checker, conventiondrift.checkers.test_framework (T-018).

Covers AC-F3.4 and the test-framework half of AC-F2.5, with is-test-file at any depth (DESIGN
§10 B2). Counts go through the real walk and pool. The checker class and the handler are
reached through their modules, so pytest doesn't try to collect them by their names.
"""

import ast
import textwrap

import pytest
from checker_support import assert_linear, counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers import test_framework as package
from conventiondrift.checkers.test_framework import match as matcher
from conventiondrift.checkers.test_framework import sites as finder
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site

PYTEST_NOT_UNITTEST = matcher.match_rule("use pytest, not unittest.")
TEST_CTX = FileContext("tests/a.py", is_test_file=True, is_script=False, main_guard_spans=())


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...] = ()) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), len(preferred + prohibited))


def src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def options_in(path: str, source: str) -> list[str]:
    return [s.option for s in sites_of("test-framework", {path: src(source)})]


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = package.TestFrameworkChecker()
    assert checker.id == "test-framework"
    assert checker.experimental is False
    assert checker.options == frozenset({"pytest", "unittest"}) == matcher.OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert dict(checker.ast_handlers()) == {
        ast.Module: finder.framework_sites,
        ast.ClassDef: finder.framework_sites,
    }


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, package.TestFrameworkChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    sentence = "use pytest, not unittest."
    assert package.TestFrameworkChecker().match_rule(sentence) == matcher.match_rule(sentence)


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "expected"),
    [
        # AC-F2.5 line 3 and AC-F3.4's rule.
        ("use pytest, not unittest.", match(("pytest",), ("unittest",))),
        ("use pytest.", match(("pytest",))),
        ("write tests with py.test.", match(("pytest",))),
        ("use `pytest` for every test.", match(("pytest",))),
        ("use unittest.", match(("unittest",))),
        ("avoid unittest.", match((), ("unittest",))),
        ("never subclass unittest.testcase.", match((), ("unittest",))),
        ("don't use unittest, use pytest.", match(("pytest",), ("unittest",))),
        ("use pytest instead of unittest.", match(("pytest",), ("unittest",))),
        ("use pytest rather than unittest.", match(("pytest",), ("unittest",))),
        ("unittest is deprecated; use pytest.", match(("pytest",), ("unittest",))),
        ("use unittest, not pytest.", match(("unittest",), ("pytest",))),
        ("USE PYTEST, NOT UNITTEST.", match(("pytest",), ("unittest",))),
        # I-10 item 5d / AC-F2.3 line 2: "over" after a comparative verb prohibits what follows.
        ("prefer pytest over unittest.", match(("pytest",), ("unittest",))),
    ],
)
def test_match_rule_reads_the_polarity_of_each_mention(sentence: str, expected: RuleMatch) -> None:
    assert matcher.match_rule(sentence) == expected


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use logging, not print.",
        "always use type hints.",
        "write tests for every bug fix.",
        "use pytest-style tests.",  # a hyphen joins words: "pytest-style" is not "pytest"
        "use pytest.mark.parametrize.",  # a dotted name is one word
        "use unittest.mock for fakes.",
        "never use pytest or unittest.",  # every option prohibited: nothing is allowed
        "use pytest and unittest.",  # every option preferred: the rule would always hold
        "use pytest; never use pytest.",  # pytest both preferred and prohibited
    ],
)
def test_match_rule_does_not_map_what_it_cannot_read(sentence: str) -> None:
    assert matcher.match_rule(sentence) is None


def test_specificity_is_the_number_of_options_named() -> None:
    one = matcher.match_rule("use pytest.")
    two = matcher.match_rule("use pytest, not unittest.")
    assert (one and one.specificity, two and two.specificity) == (1, 2)


def test_it_takes_only_line_3_of_the_canonical_sentences_ac_f2_5() -> None:
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
    assert [i for i, s in enumerate(sentences, start=1) if matcher.match_rule(s)] == [3]


def test_the_registry_maps_the_pytest_rule_to_test_framework() -> None:
    assert rules_of("Use pytest, not unittest.") == [(1, "test-framework")]
    assert rules_of("Prefer pytest over unittest.") == [(1, "test-framework")]


# --- sites: AC-F3.4 -------------------------------------------------------------------------

AC_F3_4_UNITTEST = """
    import unittest
    from unittest import TestCase


    class TestA(unittest.TestCase):
        def test_one(self):
            self.assertTrue(True)


    class TestB(TestCase):
        def test_two(self):
            self.assertTrue(True)
"""

AC_F3_4_PYTEST = """
    def test_one():
        assert True


    def test_two():
        assert True


    async def test_three():
        assert True


    class TestGroup:
        def test_four(self):
            assert True

        def test_five(self):
            assert True

        def helper(self):
            return 1


    def test_six():
        assert True
"""


def test_f3_4_two_testcase_subclasses_and_six_pytest_functions_count_6_and_2() -> None:
    sites = sites_of(
        "test-framework",
        {"tests/test_old.py": src(AC_F3_4_UNITTEST), "tests/test_new.py": src(AC_F3_4_PYTEST)},
    )
    assert PYTEST_NOT_UNITTEST is not None
    assert counts(PYTEST_NOT_UNITTEST, sites) == (6, 2)
    assert sorted(s.option for s in sites) == ["pytest"] * 6 + ["unittest"] * 2


def test_the_same_code_outside_test_files_has_no_sites() -> None:
    files = {"src/old.py": src(AC_F3_4_UNITTEST), "src/new.py": src(AC_F3_4_PYTEST)}
    assert sites_of("test-framework", files) == []


@pytest.mark.parametrize(
    "path",
    [
        "tests/a.py",
        "test/a.py",
        "pkg/tests/a.py",  # B2: is-test-file is not anchored to the root
        "a/b/test/c/d.py",
        "test_a.py",
        "pkg/sub/test_a.py",
        "pkg/a_test.py",
        "conftest.py",
        "pkg/conftest.py",
    ],
)
def test_test_files_are_found_at_any_depth(path: str) -> None:
    assert options_in(path, "def test_x():\n    pass\n") == ["pytest"]


@pytest.mark.parametrize(
    "path",
    [
        "src/a.py",
        "testing/a.py",
        "pkg/tests_x/a.py",
        "pkg/mytests/a.py",
        "atest_b.py",
        "a_tests.py",
    ],
)
def test_other_files_are_not_test_files(path: str) -> None:
    assert options_in(path, "def test_x():\n    pass\n") == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("class T(unittest.TestCase):\n    pass\n", ["unittest"]),
        ("class T(TestCase):\n    pass\n", ["unittest"]),
        ("class T(unittest.IsolatedAsyncioTestCase):\n    pass\n", ["unittest"]),
        ("class T(IsolatedAsyncioTestCase):\n    pass\n", ["unittest"]),
        ("class T(Mixin, unittest.TestCase):\n    pass\n", ["unittest"]),
        # A TestCase subclass is one site; its test methods are not pytest sites.
        ("class TestT(TestCase):\n    def test_a(self):\n        pass\n", ["unittest"]),
        # Names only (D-PM-42): another module's TestCase, or a project base class, isn't read.
        ("class T(other.TestCase):\n    pass\n", []),
        ("class T(unittest.mock.Mock):\n    pass\n", []),
        ("class T(unittest.Mock):\n    pass\n", []),
        ("class T(BaseTest):\n    def test_a(self):\n        pass\n", []),
        ("class TestT(BaseTest):\n    def test_a(self):\n        pass\n", []),
        ("class T(base()):\n    pass\n", []),
        # pytest-style classes: a Test* name and no base other than object.
        ("class TestT:\n    def test_a(self):\n        pass\n", ["pytest"]),
        ("class TestT(object):\n    async def test_a(self):\n        pass\n", ["pytest"]),
        ("class Tests:\n    def test_a(self):\n        pass\n    x = 1\n", ["pytest"]),
        ("class Helper:\n    def test_a(self):\n        pass\n", []),
        ("class TestT:\n    def check_a(self):\n        pass\n", []),
        # pytest-style functions: module level, named test_*.
        ("def test_a():\n    pass\n", ["pytest"]),
        ("async def test_a():\n    pass\n", ["pytest"]),
        ("def test():\n    pass\n", []),
        ("def testing():\n    pass\n", []),
        ("def helper_test_a():\n    pass\n", []),
        ("def outer():\n    def test_a():\n        pass\n", []),
        ("if True:\n    def test_a():\n        pass\n", []),
        ("test_a = lambda: None\n", []),
        ("x = 1\n", []),
    ],
)
def test_each_kind_of_definition(source: str, expected: list[str]) -> None:
    assert options_in("tests/test_a.py", source) == expected


def test_a_site_is_at_the_class_or_def_keyword() -> None:
    source = src(
        """
        @deco
        class T(TestCase):
            pass


        class TestU:
            def test_a(self):
                pass
        """
    )
    assert sites_of("test-framework", {"tests/a.py": source}) == [
        Site("tests/a.py", 2, 0, "unittest"),
        Site("tests/a.py", 7, 4, "pytest"),
    ]


def test_a_nested_testcase_class_is_a_site_too() -> None:
    # The walk visits every class; a TestCase subclass inside another class still counts.
    source = "class Outer:\n    class T(TestCase):\n        pass\n"
    assert sites_of("test-framework", {"tests/a.py": source}) == [
        Site("tests/a.py", 2, 4, "unittest")
    ]


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"tests/test_{i}.py": "def test_a():\n    pass\n" for i in range(3)}
    assert len(sites_of("test-framework", files, max_workers=2)) == 3


def test_the_handler_reads_the_node_directly() -> None:
    tree = parse(b"def test_a():\n    pass\nclass T(TestCase):\n    pass\n")
    assert list(finder.framework_sites(tree, TEST_CTX)) == [Site("tests/a.py", 1, 0, "pytest")]
    assert list(finder.framework_sites(tree.body[1], TEST_CTX)) == [
        Site("tests/a.py", 3, 0, "unittest")
    ]


def test_the_handler_gives_nothing_outside_a_test_file_or_for_other_nodes() -> None:
    tree = parse(b"def test_a():\n    pass\n")
    plain = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())
    assert list(finder.framework_sites(tree, plain)) == []
    assert list(finder.framework_sites(tree.body[0], TEST_CTX)) == []
    assert list(finder.framework_sites(ast.Name("x"), TEST_CTX)) == []


def test_the_testcase_names() -> None:
    assert finder.TESTCASE_NAMES == {"TestCase", "IsolatedAsyncioTestCase"}


# --- linear time (R2.5) ---------------------------------------------------------------------

HOSTILE_RULES = {
    "no cue": lambda n: "use " + "pytest " * (n // 7),
    "both options": lambda n: "never use unittest " + "or pytest " * (n // 10),
}


@pytest.mark.timing
@pytest.mark.parametrize("kind", HOSTILE_RULES)
def test_match_rule_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    assert_linear(HOSTILE_RULES[kind], matcher.match_rule, label=kind)
