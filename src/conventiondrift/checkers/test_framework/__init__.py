"""The ``test-framework`` checker (C7, INTERFACES I-10; T-018).

Compares pytest-style test functions with ``unittest.TestCase`` subclasses in test files.
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.test_framework.match import OPTIONS, match_rule
from conventiondrift.checkers.test_framework.sites import framework_sites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["TestFrameworkChecker"]


class TestFrameworkChecker:
    """I-10 ``Checker`` for pytest versus unittest."""

    id: CheckerId = "test-framework"
    experimental = False
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        return {ast.Module: framework_sites, ast.ClassDef: framework_sites}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()
