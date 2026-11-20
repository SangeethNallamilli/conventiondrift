"""Unit tests for the logging checker, conventiondrift.checkers.logging (T-016).

Covers AC-F3.2, AC-F3.12 and the logging half of AC-F2.5. Counts go through the real
walk and pool, so the scope flags (script paths, ``__main__`` guards, console scripts)
reach the checker the way they do in a run.
"""

import ast
import textwrap

import pytest
from checker_support import counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.logging import LoggingChecker
from conventiondrift.checkers.logging.match import OPTIONS, match_rule
from conventiondrift.checkers.logging.sites import LEVEL_METHODS, logging_sites
from conventiondrift.checkers.walk import parse
from conventiondrift.discover.globmatch import GlobSet
from conventiondrift.model import FileContext, RuleMatch, Site

USE_LOGGING = match_rule("use logging, not print.")


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...], specificity: int) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), specificity)


def src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = LoggingChecker()
    assert checker.id == "logging"
    assert checker.experimental is False
    assert checker.options == frozenset({"logging", "print"}) == OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert set(checker.ast_handlers()) == {ast.Call}


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, LoggingChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    assert LoggingChecker().match_rule("never use print().") == match_rule("never use print().")


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "expected"),
    [
        # AC-F2.5 line 1, and the other shapes the DESIGN §7 table can give.
        ("use logging, not print.", match(("logging",), ("print",), 2)),
        ("use logging, not print", match(("logging",), ("print",), 2)),
        ("use the logging module.", match(("logging",), (), 1)),
        ("always use a logger.", match(("logging",), (), 1)),
        ("use loggers, never print statements.", match(("logging",), ("print",), 2)),
        ("don't use print; use logging.", match(("logging",), ("print",), 2)),
        ("don't use print, instead use logging.", match(("logging",), ("print",), 2)),
        ("never use print or logging.warn.", match((), ("print",), 1)),
        ("prefer logging over print.", match(("logging",), ("print",), 2)),
        ("use logging instead of print.", match(("logging",), ("print",), 2)),
        ("use logging rather than print.", match(("logging",), ("print",), 2)),
        ("use logging and never print.", match(("logging",), ("print",), 2)),
        ("never use print().", match((), ("print",), 1)),
        ("never use print or requests.", match((), ("print",), 1)),
        ("don't use print.", match((), ("print",), 1)),
        ("don\u2019t use prints.", match((), ("print",), 1)),
        ("do not use print() for debug output.", match((), ("print",), 1)),
        ("avoid print.", match((), ("print",), 1)),
        ("use print() for debug output.", match(("print",), (), 1)),
        ("use print, not logging.", match(("print",), ("logging",), 2)),
        ("USE LOGGING, NOT PRINT.", match(("logging",), ("print",), 2)),
    ],
)
def test_match_rule_reads_the_polarity_of_each_mention(sentence: str, expected: RuleMatch) -> None:
    assert match_rule(sentence) == expected


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use httpx for http calls.",
        "use pytest, not unittest.",
        "do not use bare except.",
        "always use f-strings.",
        "use logging.info for logs.",  # a dotted name is one word, not a mention of logging
        "never use footprint or blueprint.",
        "use print and never print.",  # print both preferred and prohibited: unreadable
        "do not use print for logging.",  # every option prohibited: nothing is allowed
        "never use logging or print.",
        "never log with print, use logging.",  # the negation runs on through the comma
        "don't print, use logging.",
        # Every option preferred: every site would follow, so the rule would always hold.
        "use logging; no print.",
        "use logging (print is banned).",
        "use the logger to print status messages.",
    ],
)
def test_match_rule_does_not_map_what_it_cannot_read(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_a_prohibition_that_names_only_print_is_not_every_option() -> None:
    # The "every option prohibited" guard must not drop a one-option prohibition.
    assert match_rule("never use print.") is not None


def test_it_ties_with_another_checker_that_finds_one_option_ac_f2_6() -> None:
    # "Never use print or requests": the logging side has specificity 1, the same as a checker
    # that finds only `requests`; the C6 tie rule then makes the rule Not verifiable.
    found = match_rule("never use print or requests.")
    assert found is not None
    assert found.specificity == 1


def test_the_eight_canonical_sentences_only_line_1_is_logging_ac_f2_5() -> None:
    sentences = [
        "Use logging, not print.",
        "Use httpx for HTTP calls.",
        "Use pytest, not unittest.",
        "Store money as integer cents.",
        "Use f-strings for string formatting.",
        "Do not use bare except.",
        "Always use type hints.",
        "Use uv for dependencies.",
    ]
    taken = [i for i, s in enumerate(sentences, start=1) if match_rule(" ".join(s.lower().split()))]
    assert taken == [1]


def test_the_registry_maps_the_canonical_file_to_logging_and_exceptions_ac_f2_5() -> None:
    text = "\n".join(
        [
            "Use logging, not print.",
            "Use httpx for HTTP calls.",
            "Use pytest, not unittest.",
            "Store money as integer cents.",
            "Use f-strings for string formatting.",
            "Do not use bare except.",
            "Always use type hints.",
            "Use uv for dependencies.",
        ]
    )
    # All eight are rules at lines 1-8; the other six checkers arrive with T-017 to T-019, so
    # until then only these two lines are mapped, each to its own checker.
    assert rules_of(text) == [
        (1, "logging"),
        (2, None),
        (3, None),
        (4, None),
        (5, None),
        (6, "exceptions"),
        (7, None),
        (8, None),
    ]


def test_never_use_print_or_requests_is_still_mapped_to_logging_alone_until_t017() -> None:
    assert rules_of("Never use print or requests.") == [(1, "logging")]


# --- sites: AC-F3.2 -------------------------------------------------------------------------


def test_f3_2_seven_logging_calls_and_three_prints_count_7_and_3() -> None:
    source = src(
        """
        import logging

        logger = logging.getLogger(__name__)


        def work() -> None:
            logging.debug("a")
            logging.info("b")
            logger.warning("c")
            logger.error("d")
            logger.exception("e")
            logging.getLogger("x").critical("f")
            logging.log(10, "g")
            print("one")
            print("two")
            print("three")
        """
    )
    sites = sites_of("logging", {"src/mod.py": source})
    assert USE_LOGGING is not None
    assert counts(USE_LOGGING, sites) == (7, 3)
    assert sorted(s.option for s in sites) == ["logging"] * 7 + ["print"] * 3


def test_sites_are_at_the_call_with_its_line_and_column() -> None:
    source = "def f():\n    print('x')\n    log.info('y')\n"
    assert sites_of("logging", {"src/a.py": source}) == [
        Site("src/a.py", 2, 4, "print"),
        Site("src/a.py", 3, 4, "logging"),
    ]


@pytest.mark.parametrize(
    "call",
    [
        "logging.info('x')",
        "logger.info('x')",
        "log.info('x')",
        "LOGGER.info('x')",
        "_logger.info('x')",
        "app_logger.info('x')",
        "self.logger.info('x')",
        "self._log.info('x')",
        "logging.getLogger('a').info('x')",
        "getLogger('a').info('x')",
        "log.exception('x')",
        "log.fatal('x')",
        "log.warn('x')",
    ],
)
def test_logging_calls_by_receiver_name(call: str) -> None:
    assert [s.option for s in sites_of("logging", {"src/a.py": call + "\n"})] == ["logging"]


@pytest.mark.parametrize(
    "call",
    [
        "math.log(2)",
        "catalog.info()",
        "dialog.error('x')",
        "obj.info('x')",
        "logger.name",
        "logger.setLevel(10)",
        "logger.info",
        "make()('x')",
        "get_logger().info('x')",
        "pool[0].info('x')",
        "(a or b).info('x')",
        "builtins.print('x')",
        "pprint('x')",
        "print.__doc__",
    ],
)
def test_calls_that_are_not_logging_or_print_are_not_sites(call: str) -> None:
    assert sites_of("logging", {"src/a.py": call + "\n"}) == []


def test_every_level_method_counts() -> None:
    assert LEVEL_METHODS == {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "exception",
        "critical",
        "fatal",
        "log",
    }
    calls = "\n".join(f"logger.{name}('x')" for name in sorted(LEVEL_METHODS))
    assert len(sites_of("logging", {"src/a.py": calls + "\n"})) == len(LEVEL_METHODS)


def test_a_call_inside_a_nested_expression_and_a_decorator_is_found() -> None:
    source = src(
        """
        @decorate(print("deco"))
        def f(x=print("default")):
            return [print(i) for i in x] + [logger.info(i) for i in x]
        """
    )
    options = [s.option for s in sites_of("logging", {"src/a.py": source})]
    assert options.count("print") == 3
    assert options.count("logging") == 1


# --- sites: AC-F3.12 ------------------------------------------------------------------------

PRINT_ONLY = "def run():\n    print('hi')\n"
MAIN_FILE = src(
    """
    def main() -> None:
        pass


    if __name__ == "__main__":
        print("running")
        main()
    """
)
FIVE_LOGGER_CALLS = "".join(f"logger.info('{i}')\n" for i in range(5))


def test_f3_12_script_contexts_are_not_sites_and_relevant_sites_are_5() -> None:
    files = {
        "tests/test_x.py": PRINT_ONLY,
        "conftest.py": PRINT_ONLY,
        "scripts/run.py": PRINT_ONLY,
        "bin/tool.py": PRINT_ONLY,
        "cli.py": MAIN_FILE,
        "src/pkg/entry.py": PRINT_ONLY,  # declared as a console-script entry point
        "src/lib.py": FIVE_LOGGER_CALLS,
    }
    sites = sites_of("logging", files, entry_points=frozenset({"src/pkg/entry.py"}))
    assert all(site.option == "logging" for site in sites)
    assert {site.file for site in sites} == {"src/lib.py"}
    assert len(sites) == 5
    assert USE_LOGGING is not None
    assert counts(USE_LOGGING, sites) == (5, 0)


@pytest.mark.parametrize(
    "path",
    [
        "conftest.py",
        "pkg/conftest.py",
        "tests/test_x.py",
        "pkg/tests/helper.py",
        "test/helper.py",
        "pkg/test_mod.py",
        "pkg/mod_test.py",
        "scripts/run.py",
        "tools/scripts/run.py",
        "bin/tool.py",
        "pkg/bin/tool.py",
    ],
)
def test_f3_12_a_print_in_a_default_script_path_at_any_depth_is_not_a_site(path: str) -> None:
    assert sites_of("logging", {path: PRINT_ONLY}) == []


@pytest.mark.parametrize("path", ["src/lib.py", "app/cli.py", "testing/x.py", "src/binary.py"])
def test_a_print_outside_the_script_paths_is_a_site(path: str) -> None:
    assert [s.option for s in sites_of("logging", {path: PRINT_ONLY})] == ["print"]


def test_only_a_print_in_the_main_guard_body_is_skipped() -> None:
    source = src(
        """
        print("import time")


        def main() -> None:
            print("inside main()")


        if __name__ == "__main__":
            print("guarded")
            main()
        print("after the guard")
        """
    )
    sites = sites_of("logging", {"src/cli.py": source})
    assert [s.line for s in sites] == [1, 5, 11]


def test_a_guard_nested_in_a_function_does_not_hide_a_print() -> None:
    source = src(
        """
        def f() -> None:
            if __name__ == "__main__":
                print("not a real guard")
        """
    )
    assert [s.option for s in sites_of("logging", {"src/a.py": source})] == ["print"]


def test_logging_calls_in_script_files_and_guards_still_count() -> None:
    source = src(
        """
        logger.info("in a script")
        if __name__ == "__main__":
            logger.info("guarded")
            print("guarded print")
        """
    )
    sites = sites_of("logging", {"scripts/run.py": source, "src/cli.py": source})
    assert [(s.file, s.option) for s in sites] == [
        ("scripts/run.py", "logging"),
        ("scripts/run.py", "logging"),
        ("src/cli.py", "logging"),
        ("src/cli.py", "logging"),
    ]


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": "print('x')\nlogger.info('y')\n" for i in range(3)}
    sites = sites_of("logging", files, max_workers=2)
    assert len(sites) == 6


def test_the_handler_reads_the_context_flags_directly() -> None:
    call = parse(b"print('x')\n").body[0]
    assert isinstance(call, ast.Expr)
    plain = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())
    script = FileContext("a.py", is_test_file=False, is_script=True, main_guard_spans=())
    guarded = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=((1, 1),))
    assert [s.option for s in logging_sites(call.value, plain)] == ["print"]
    assert list(logging_sites(call.value, script)) == []
    assert list(logging_sites(call.value, guarded)) == []


def test_a_print_in_a_test_file_that_is_not_a_script_is_a_site() -> None:
    # Only is_script and the main guard exempt a print: is_test_file alone does not.
    call = parse(b"print('x')\n").body[0]
    assert isinstance(call, ast.Expr)
    ctx = FileContext("a.py", is_test_file=True, is_script=False, main_guard_spans=())
    assert [s.option for s in logging_sites(call.value, ctx)] == ["print"]


def test_a_custom_script_paths_setting_replaces_the_default_in_a_run() -> None:
    # `script-paths` replaces the default list (I-6): here only tools/ is a script path, so a
    # print under scripts/ or tests/ (default paths; tests/ is also a test file) now counts.
    custom = GlobSet(["tools/**"]).excludes
    files = {
        "tools/run.py": PRINT_ONLY,
        "scripts/run.py": PRINT_ONLY,
        "tests/test_x.py": PRINT_ONLY,
        "conftest.py": PRINT_ONLY,
    }
    sites = sites_of("logging", files, is_script=custom)
    assert [(s.file, s.option) for s in sites] == [
        ("conftest.py", "print"),
        ("scripts/run.py", "print"),
        ("tests/test_x.py", "print"),
    ]


def test_the_handler_gives_nothing_for_a_node_that_is_not_a_call() -> None:
    plain = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())
    assert list(logging_sites(ast.Name("print"), plain)) == []
