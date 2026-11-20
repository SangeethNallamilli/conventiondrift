"""Unit tests for the exceptions checker, conventiondrift.checkers.exceptions (T-016).

Covers AC-F3.7 and the exceptions half of AC-F2.5. Counts go through the real walk and pool.
"""

import ast
import textwrap

import pytest
from checker_support import counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.exceptions import ExceptionsChecker
from conventiondrift.checkers.exceptions.match import OPTIONS, match_rule
from conventiondrift.checkers.exceptions.sites import BROAD_NAMES, exception_sites
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site

NO_BARE_OR_BROAD = match_rule("do not use bare except or catch exception")


def match(prohibited: tuple[str, ...]) -> RuleMatch:
    return RuleMatch(frozenset(), frozenset(prohibited), len(prohibited))


def src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = ExceptionsChecker()
    assert checker.id == "exceptions"
    assert checker.experimental is False
    assert checker.options == frozenset({"bare-except", "broad-except", "specific"}) == OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert set(checker.ast_handlers()) == {ast.ExceptHandler}


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, ExceptionsChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    sentence = "do not use bare except."
    assert ExceptionsChecker().match_rule(sentence) == match_rule(sentence)


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "prohibited"),
    [
        # AC-F2.5 line 6 and AC-F3.7's rule.
        ("do not use bare except.", ("bare-except",)),
        ("do not use bare except or catch exception", ("bare-except", "broad-except")),
        ("never use bare except", ("bare-except",)),
        ("never use bare excepts.", ("bare-except",)),
        ("don't use a bare except clause.", ("bare-except",)),
        ("don\u2019t use bare exceptions.", ("bare-except",)),
        ("avoid bare-except.", ("bare-except",)),
        ("never catch exception.", ("broad-except",)),
        ("avoid catching exception.", ("broad-except",)),
        ("do not catches exception.", ("broad-except",)),
        ("never write except exception.", ("broad-except",)),
        ("avoid broad except clauses.", ("broad-except",)),
        ("avoid generic exceptions.", ("broad-except",)),
        ("never use blanket exception handlers.", ("broad-except",)),
        ("never catch baseexception.", ("broad-except",)),
        ("never use a bare except and do not catch exception.", ("bare-except", "broad-except")),
        ("do not use bare except, do not catch exception.", ("bare-except", "broad-except")),
        ("NEVER USE BARE EXCEPT.", ("bare-except",)),
    ],
)
def test_match_rule_reads_prohibitions(sentence: str, prohibited: tuple[str, ...]) -> None:
    assert match_rule(sentence) == match(prohibited)


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use logging, not print.",
        "always use type hints.",
        "do not use f-strings.",
        "never catch exceptions.",  # the plural names no class
        "never raise exception.",  # not a catch
        "bare means empty.",
        "never use bare.",
        "use bare except.",  # a request, not a prohibition
        "always catch exception.",
        "always catch exception, never use bare except.",  # asks and forbids
        "never use bare except; always use bare except.",
        "use bare except and bare except.",
    ],
)
def test_match_rule_does_not_map_what_is_not_a_prohibition_about_except(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_specificity_is_the_number_of_options_named() -> None:
    one = match_rule("do not use bare except.")
    two = match_rule("do not use bare except or catch exception")
    assert one is not None
    assert two is not None
    assert (one.specificity, two.specificity) == (1, 2)


def test_a_first_word_is_not_judged_by_the_last_word_of_its_clause() -> None:
    # "exception" is first, so nothing is before it; it must not read the clause's last word.
    assert match_rule("exception catch, never use bare except.") == match(("bare-except",))


def test_it_leaves_the_other_canonical_sentences_alone_ac_f2_5() -> None:
    others = [
        "use logging, not print.",
        "use httpx for http calls.",
        "use pytest, not unittest.",
        "store money as integer cents.",
        "use f-strings for string formatting.",
        "always use type hints.",
        "use uv for dependencies.",
    ]
    assert [s for s in others if match_rule(s)] == []


def test_the_registry_maps_the_bare_except_rule_to_exceptions() -> None:
    assert rules_of("Do not use bare except.") == [(1, "exceptions")]
    assert rules_of("Do not use bare except or catch Exception") == [(1, "exceptions")]


# --- sites: AC-F3.7 -------------------------------------------------------------------------


def test_f3_7_one_bare_one_exception_and_five_specific_count_5_and_2() -> None:
    source = src(
        """
        def work() -> None:
            try:
                pass
            except:
                pass
            try:
                pass
            except Exception:
                pass
            try:
                pass
            except ValueError:
                pass
            try:
                pass
            except KeyError:
                pass
            try:
                pass
            except ValueError:
                pass
            try:
                pass
            except KeyError:
                pass
            try:
                pass
            except ValueError:
                pass
        """
    )
    sites = sites_of("exceptions", {"src/mod.py": source})
    assert NO_BARE_OR_BROAD is not None
    assert counts(NO_BARE_OR_BROAD, sites) == (5, 2)
    assert sorted(s.option for s in sites) == ["bare-except", "broad-except"] + ["specific"] * 5


def test_the_bare_except_only_rule_counts_exception_as_following() -> None:
    source = "try:\n    pass\nexcept:\n    pass\ntry:\n    pass\nexcept Exception:\n    pass\n"
    sites = sites_of("exceptions", {"a.py": source})
    only_bare = match_rule("do not use bare except.")
    assert only_bare is not None
    assert counts(only_bare, sites) == (1, 1)


def test_a_site_is_at_the_except_keyword() -> None:
    source = "try:\n    pass\nexcept ValueError:\n    pass\n"
    assert sites_of("exceptions", {"src/a.py": source}) == [Site("src/a.py", 3, 0, "specific")]


def test_a_nested_handler_has_its_own_column() -> None:
    source = "def f():\n    try:\n        pass\n    except:\n        pass\n"
    assert sites_of("exceptions", {"src/a.py": source}) == [Site("src/a.py", 4, 4, "bare-except")]


@pytest.mark.parametrize(
    ("clause", "option"),
    [
        ("except:", "bare-except"),
        ("except Exception:", "broad-except"),
        ("except Exception as exc:", "broad-except"),
        ("except BaseException:", "broad-except"),
        ("except builtins.Exception:", "broad-except"),
        ("except (ValueError, Exception):", "broad-except"),
        ("except (ValueError, (KeyError, Exception)):", "broad-except"),
        ("except* Exception:", "broad-except"),
        ("except ValueError:", "specific"),
        ("except (ValueError, KeyError):", "specific"),
        ("except KeyError as exc:", "specific"),
        ("except errors.ValueError:", "specific"),
        ("except mylib.Exception:", "specific"),
        ("except builtins.ValueError:", "specific"),
        ("except exceptions.Exception:", "specific"),
        ("except MyException:", "specific"),
        ("except ():", "specific"),
        ("except get_errors():", "specific"),
        ("except* ValueError:", "specific"),
    ],
)
def test_each_kind_of_clause(clause: str, option: str) -> None:
    source = f"try:\n    pass\n{clause}\n    pass\n"
    assert [s.option for s in sites_of("exceptions", {"src/a.py": source})] == [option]


def test_the_broad_names_are_exception_and_baseexception() -> None:
    assert BROAD_NAMES == {"Exception", "BaseException"}


def test_tests_and_scripts_are_not_exempt() -> None:
    source = "try:\n    pass\nexcept:\n    pass\n"
    sites = sites_of("exceptions", {"tests/test_x.py": source, "scripts/run.py": source})
    assert [(s.file, s.option) for s in sites] == [
        ("scripts/run.py", "bare-except"),
        ("tests/test_x.py", "bare-except"),
    ]


def test_a_deeply_nested_type_tuple_does_not_recurse() -> None:
    depth = 150
    expr = "(" * depth + "ValueError," + ")," * (depth - 1) + ")"
    source = f"try:\n    pass\nexcept {expr}:\n    pass\n"
    assert [s.option for s in sites_of("exceptions", {"src/a.py": source})] == ["specific"]


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": "try:\n    pass\nexcept:\n    pass\n" for i in range(3)}
    assert len(sites_of("exceptions", files, max_workers=2)) == 3


def test_the_handler_reads_the_node_directly() -> None:
    tree = parse(b"try:\n    pass\nexcept Exception:\n    pass\n")
    node = tree.body[0]
    assert isinstance(node, ast.Try)
    ctx = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())
    assert list(exception_sites(node.handlers[0], ctx)) == [Site("a.py", 3, 0, "broad-except")]


def test_the_handler_gives_nothing_for_a_node_that_is_not_a_handler() -> None:
    ctx = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())
    assert list(exception_sites(ast.Name("x"), ctx)) == []
