"""Unit tests for the I-10 checker Protocol in conventiondrift.checkers.base (T-005)."""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal, Protocol

from conventiondrift import model
from conventiondrift.checkers import base
from conventiondrift.checkers.base import Checker, CheckerId, FileContext, RuleMatch, Site


class _PrintChecker:
    """A minimal checker written only against the Protocol."""

    id: CheckerId = "logging"
    experimental = False
    options = frozenset({"logging", "print"})
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        if "print" not in normalized_text:
            return None
        return RuleMatch(
            preferred=frozenset({"logging"}), prohibited=frozenset({"print"}), specificity=1
        )

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        def on_call(node: ast.AST, ctx: FileContext) -> Iterable[Site]:
            assert isinstance(node, ast.Call)
            if isinstance(node.func, ast.Name) and node.func.id == "print" and not ctx.is_script:
                yield Site(file=ctx.path, line=node.lineno, col=node.col_offset, option="print")

        return {ast.Call: on_call}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()


def test_checker_is_a_protocol() -> None:
    assert issubclass(Checker, Protocol)
    assert base.__all__ == ["Checker", "CheckerId", "FileContext", "RuleMatch", "Site"]


def test_reexports_are_the_model_types() -> None:
    # I-13 Q1: the types live in model.py; base.py only re-exports them.
    assert base.RuleMatch is model.RuleMatch
    assert base.Site is model.Site
    assert base.FileContext is model.FileContext
    assert base.CheckerId is model.CheckerId


def test_structural_checker_is_usable_through_the_protocol() -> None:
    checker: Checker = _PrintChecker()
    assert checker.match_rule("use logging, not print") == RuleMatch(
        preferred=frozenset({"logging"}), prohibited=frozenset({"print"}), specificity=1
    )
    assert checker.match_rule("use httpx") is None

    tree = ast.parse("print('x')\n")
    call = tree.body[0].value  # type: ignore[attr-defined]
    handler = checker.ast_handlers()[ast.Call]
    ctx = FileContext(path="src/a.py", is_test_file=False, is_script=False, main_guard_spans=())
    assert list(handler(call, ctx)) == [Site(file="src/a.py", line=1, col=0, option="print")]
    script = FileContext(path="bin/run.py", is_test_file=False, is_script=True, main_guard_spans=())
    assert list(handler(call, script)) == []
    assert list(checker.manifest_sites({"pyproject.toml": b""})) == []
