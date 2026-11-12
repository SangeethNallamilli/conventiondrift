"""Unit tests for the shared AST walk, conventiondrift.checkers.walk (T-014)."""

import ast
import sys
from typing import get_args

import pytest
from checker_standins import CallChecker, ContextChecker, FaultyChecker, NodeCounter

from conventiondrift.checkers import walk
from conventiondrift.checkers.walk import (
    PARSE_SKIP_REASONS,
    CheckerFault,
    FileJob,
    SiteDefect,
    Walker,
    collect,
    in_main_guard,
    is_test_file,
    main_guard_spans,
    parse,
    site_defect,
)
from conventiondrift.errors import FileSkipped
from conventiondrift.model import FileContext, Site

PRINT = CallChecker("logging", frozenset({"print", "log"}))


def job(path: str, src: str | bytes, *, test: bool = False, script: bool = False) -> FileJob:
    data = src.encode() if isinstance(src, str) else src
    return FileJob(path, data, test, script)


# --- is_test_file (DESIGN §10 B2) ---------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "tests/a.py",
        "pkg/tests/a.py",
        "pkg/tests/deep/a.py",
        "test/a.py",
        "src/test/sub/a.py",
        "test_a.py",
        "src/pkg/test_a.py",
        "a_test.py",
        "src/a_test.py",
        "conftest.py",
        "src/pkg/conftest.py",
        "tests/data.txt",
    ],
)
def test_is_test_file_matches_each_b2_pattern_at_any_depth(path: str) -> None:
    assert is_test_file(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "src/a.py",
        "testing/a.py",
        "src/mytests/a.py",
        "Tests/a.py",  # case-sensitive
        "TEST_a.py",
        "test_a.txt",
        "a_test.pyi",
        "tests.py",
        "test.py",
        "mytest_a.py",
        "src/contest.py",
        "conftest.pyc",
        "src/tests",  # a file named "tests" is not inside a tests folder
    ],
)
def test_is_test_file_rejects_near_misses(path: str) -> None:
    assert is_test_file(path) is False


# --- main_guard_spans ---------------------------------------------------------------------


def spans(src: str) -> tuple[tuple[int, int], ...]:
    return main_guard_spans(ast.parse(src))


def test_main_guard_span_is_the_guard_body() -> None:
    src = "import x\n\nif __name__ == '__main__':\n    print(1)\n    run(\n        2)\n"
    assert spans(src) == ((4, 6),)


def test_main_guard_accepts_reversed_operands_and_lists_every_guard_in_order() -> None:
    src = "if '__main__' == __name__:\n    a()\nx = 1\nif __name__ == \"__main__\":\n    b()\n"
    assert spans(src) == ((2, 2), (5, 5))


def test_main_guard_excludes_the_else_branch() -> None:
    src = "if __name__ == '__main__':\n    a()\nelse:\n    b()\n"
    assert spans(src) == ((2, 2),)


@pytest.mark.parametrize(
    "src",
    [
        "if __name__ != '__main__':\n    a()\n",
        "if __name__ == 'main':\n    a()\n",
        "if name == '__main__':\n    a()\n",
        "if __name__ == '__main__' == x:\n    a()\n",
        "if __name__ is '__main__':\n    a()\n",
        "if __name__ == '__main__' and x:\n    a()\n",
        "def f():\n    if __name__ == '__main__':\n        a()\n",
        "if '__main__' == '__main__':\n    a()\n",
        "x = 1\n",
    ],
)
def test_main_guard_ignores_anything_else(src: str) -> None:
    assert spans(src) == ()


def test_in_main_guard_is_inclusive_at_both_ends() -> None:
    ctx = FileContext("a.py", False, False, ((3, 5), (9, 9)))
    assert [line for line in range(1, 11) if in_main_guard(ctx, line)] == [3, 4, 5, 9]


# --- parse (R2.4, AC-E.14, SEC-T09) -------------------------------------------------------

# Expected reasons are written by hand from DESIGN §4 / I-13, not read from the table.
EXPECTED_REASON = {
    SyntaxError: "syntax error",
    RecursionError: "syntax error",
    MemoryError: "syntax error",
    UnicodeDecodeError: "not decodable",
    ValueError: "syntax error",
}


def test_expected_reasons_cover_the_parse_table() -> None:
    assert {kind for kind, _ in PARSE_SKIP_REASONS} == set(EXPECTED_REASON)


def _raiser(kind: type[BaseException]) -> BaseException:
    if kind is UnicodeDecodeError:
        return UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")
    return kind("x")


@pytest.mark.parametrize("kind", [kind for kind, _ in PARSE_SKIP_REASONS], ids=lambda k: k.__name__)
def test_each_parse_error_class_skips_the_file_with_its_reason(
    kind: type[BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_parse(data: bytes) -> ast.Module:
        raise _raiser(kind)

    monkeypatch.setattr(ast, "parse", fake_parse)
    with pytest.raises(FileSkipped) as info:
        parse(b"x = 1\n")
    assert info.value.reason == EXPECTED_REASON[kind]


def test_an_unlisted_parse_exception_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_parse(data: bytes) -> ast.Module:
        raise KeyError("x")

    monkeypatch.setattr(ast, "parse", fake_parse)
    with pytest.raises(KeyError):
        parse(b"x = 1\n")


@pytest.mark.parametrize(
    "src",
    [
        b"def (:\n",
        b"if x:\npass\n",  # IndentationError
        b"(" * 300 + b"1" + b")" * 300,  # too many nested parentheses
        b"a = 1\x00\n",
        b"x = '\xe9'\n",  # not UTF-8 and no coding cookie
        b"# coding: bogus\nx = 1\n",
        b"a" + b".b" * 200_000,  # RecursionError during AST construction
        b"-" * 200_000 + b"1",  # MemoryError: parser stack overflow
    ],
    ids=["syntax", "indent", "parens", "nul", "latin1", "cookie", "recursion", "memory"],
)
def test_real_hostile_sources_are_skipped_as_syntax_errors(src: bytes) -> None:
    with pytest.raises(FileSkipped) as info:
        parse(src)
    assert info.value.reason == "syntax error"


def test_parse_honours_a_coding_cookie_and_a_bom() -> None:
    assert isinstance(parse("# -*- coding: latin-1 -*-\nx = 'é'\n".encode("latin-1")), ast.Module)
    assert isinstance(parse(b"\xef\xbb\xbfx = 1\n"), ast.Module)


# --- site_defect / collect (I-10) ---------------------------------------------------------

FILES = frozenset({"src/a.py"})
OPTIONS = frozenset({"print"})
GOOD = Site("src/a.py", 3, 4, "print")
# One mutation per defect class, written by hand.
BAD: dict[str, object] = {
    "not a site": ("src/a.py", 3, 4, "print"),
    "wrong file": Site("src/b.py", 3, 4, "print"),
    "unknown option": Site("src/a.py", 3, 4, "logging"),
    "bad position": Site("src/a.py", 0, 4, "print"),
}


def test_bad_values_cover_every_site_defect() -> None:
    assert set(BAD) == set(get_args(SiteDefect))


@pytest.mark.parametrize("defect", get_args(SiteDefect))
def test_each_site_defect_is_detected_and_faults_collect(defect: str) -> None:
    assert site_defect(BAD[defect], FILES, OPTIONS) == defect
    with pytest.raises(CheckerFault) as info:
        collect([GOOD, BAD[defect]], FILES, OPTIONS)
    assert str(info.value) == defect


@pytest.mark.parametrize(
    "value",
    [
        Site("src/a.py", 1, -1, "print"),
        Site("src/a.py", True, 0, "print"),
        Site("src/a.py", 1, 0.0, "print"),  # type: ignore[arg-type]
        Site("src/a.py", "1", 0, "print"),  # type: ignore[arg-type]
    ],
)
def test_bad_positions_include_negative_col_and_non_int_types(value: Site) -> None:
    assert site_defect(value, FILES, OPTIONS) == "bad position"


def test_valid_sites_pass_and_keep_their_order() -> None:
    other = Site("src/a.py", 1, 0, "print")
    assert site_defect(GOOD, FILES, OPTIONS) is None
    assert collect([GOOD, other], FILES, OPTIONS) == [GOOD, other]
    assert collect([], FILES, OPTIONS) == []


# --- Walker (ADR-0003, I-10 one walk per file) --------------------------------------------


def test_every_node_is_visited_exactly_once_and_counted() -> None:
    src = "import os\n\ndef f(a, b=1):\n    return [a + b for _ in range(3)]\n"
    seen: list[ast.AST] = []

    class Recorder(NodeCounter):
        def _on_node(self, node: ast.AST, ctx: FileContext) -> list[Site]:
            seen.append(node)
            return []

    outcome = Walker([Recorder()]).walk(job("src/a.py", src))
    expected = [type(n).__name__ for n in ast.walk(ast.parse(src))]
    assert outcome.nodes == len(expected) == len(seen)
    # Same nodes as ast.walk, each once (CPython shares the Load/Store context singletons,
    # so compare by type rather than identity).
    assert sorted(type(n).__name__ for n in seen) == sorted(expected)


def test_all_checkers_share_one_parse_and_one_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bytes] = []
    real = walk.parse

    def counting(data: bytes) -> ast.Module:
        calls.append(data)
        return real(data)

    monkeypatch.setattr(walk, "parse", counting)
    walker = Walker([PRINT, NodeCounter(), ContextChecker()])
    outcome = walker.walk(job("src/a.py", "print(1)\n"))
    assert len(calls) == 1
    assert [cid for cid, _ in outcome.sites] == ["logging", "string-format", "type-hints"]
    assert dict(outcome.sites)["logging"] == (Site("src/a.py", 1, 0, "print"),)


def test_sites_are_sorted_and_duplicates_dropped() -> None:
    # NodeCounter returns each site twice; Module, Expr and Constant share (1, 0).
    outcome = Walker([NodeCounter()]).walk(job("src/a.py", "x\n"))
    sites = dict(outcome.sites)["string-format"]
    assert sites == (Site("src/a.py", 1, 0, "node"),)
    outcome = Walker([PRINT]).walk(job("src/a.py", "log(print(1)); print(2)\nprint(3)\n"))
    assert dict(outcome.sites)["logging"] == (
        Site("src/a.py", 1, 0, "log"),
        Site("src/a.py", 1, 4, "print"),
        Site("src/a.py", 1, 15, "print"),
        Site("src/a.py", 2, 0, "print"),
    )


def test_a_handler_on_a_base_class_receives_its_subclasses() -> None:
    class ExprChecker(NodeCounter):
        def ast_handlers(self):  # type: ignore[no-untyped-def]
            return {ast.expr: self._on_node}

    outcome = Walker([ExprChecker()]).walk(job("src/a.py", "a = b\n"))
    # Name a (Store ctx node is not an expr), Name b; Assign and Module are not exprs.
    assert outcome.nodes == 6
    assert dict(outcome.sites)["string-format"] == (
        Site("src/a.py", 1, 0, "node"),
        Site("src/a.py", 1, 4, "node"),
    )


def test_file_context_carries_scope_flags_and_main_guard_spans() -> None:
    src = "x = 1\nif __name__ == '__main__':\n    f()\n"
    for test, script, option in [
        (False, False, "plain"),
        (True, False, "test"),
        (False, True, "script"),
        (True, True, "test+script"),
    ]:
        outcome = Walker([ContextChecker()]).walk(job("a.py", src, test=test, script=script))
        assert dict(outcome.sites)["type-hints"] == (
            Site("a.py", 1, 0, option),
            Site("a.py", 3, 4, "guarded"),
        )


def test_a_skipped_file_has_no_sites_and_no_nodes() -> None:
    outcome = Walker([PRINT]).walk(job("src/broken.py", "def (:\n"))
    assert (outcome.skipped, outcome.sites, outcome.nodes) == ("syntax error", (), 0)


def test_deep_nesting_does_not_overflow_the_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    depth = 900
    tree = ast.parse("a" + ".b" * depth + "\n")  # parses on every 3.11+ interpreter
    monkeypatch.setattr(walk, "parse", lambda data: tree)
    walker = Walker([NodeCounter()])
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(300)  # far below the tree depth: a recursive walk would overflow
    try:
        outcome = walker.walk(job("src/deep.py", b""))
    finally:
        sys.setrecursionlimit(limit)
    assert outcome.skipped is None
    assert outcome.nodes == sum(1 for _ in ast.walk(tree))
    assert outcome.nodes > depth


def test_checkers_without_the_python_ast_input_are_not_asked_for_handlers() -> None:
    from checker_standins import ManifestChecker

    walker = Walker([ManifestChecker()])
    assert walker.ast_checker_ids == ()
    assert walker.walk(job("a.py", "print(1)\n")).sites == ()
    assert walker.failed == {}


FAULT_MODES = [
    "ast_handlers raises",
    "bad handler table",
    "handler raises",
    "iteration raises",
    "not a site",
    "wrong file",
    "unknown option",
    "bad position",
    "system exit",
]


def test_fault_modes_cover_every_site_defect() -> None:
    assert set(get_args(SiteDefect)) <= set(FAULT_MODES)


@pytest.mark.parametrize("mode", FAULT_MODES)
def test_a_failing_checker_is_isolated_and_never_called_again(mode: str) -> None:
    faulty = FaultyChecker(mode)  # type: ignore[arg-type]
    walker = Walker([faulty, PRINT])
    first = walker.walk(job("src/a.py", "print(1)\n"))
    second = walker.walk(job("src/b.py", "print(2)\n"))
    assert set(walker.failed) == {"exceptions"}
    assert [cid for cid, _ in first.sites] == ["logging"]
    assert dict(second.sites)["logging"] == (Site("src/b.py", 1, 0, "print"),)


def test_a_failure_records_only_the_exception_class_name() -> None:
    walker = Walker([FaultyChecker("handler raises")])
    walker.walk(job("a.py", "f()\n"))
    assert walker.failed == {"exceptions": "ValueError"}
    walker = Walker([FaultyChecker("not a site")])
    walker.walk(job("a.py", "f()\n"))
    assert walker.failed == {"exceptions": "CheckerFault"}


def test_keyboard_interrupt_from_a_checker_propagates() -> None:
    class Interrupting(NodeCounter):
        def _on_node(self, node: ast.AST, ctx: FileContext) -> list[Site]:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        Walker([Interrupting()]).walk(job("a.py", "x\n"))

    class InterruptingTable(NodeCounter):
        def ast_handlers(self):  # type: ignore[no-untyped-def]
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        Walker([InterruptingTable()])
