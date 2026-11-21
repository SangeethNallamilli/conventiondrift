"""The ``money`` checker (C7, INTERFACES I-8, I-10; T-019a).

Experimental and off by default (AC-F3.14). Compares integer-cents values with float
literals on money-named assignment targets (I-8).
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.money.match import OPTIONS, match_rule
from conventiondrift.checkers.money.sites import money_sites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["MoneyChecker"]


class MoneyChecker:
    """I-10 ``Checker`` for money stored as integer cents (experimental)."""

    id: CheckerId = "money"
    experimental = True
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        return {
            ast.Assign: money_sites,
            ast.AnnAssign: money_sites,
            ast.AugAssign: money_sites,
            ast.NamedExpr: money_sites,
            ast.Call: money_sites,
        }

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()
