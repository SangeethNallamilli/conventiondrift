"""The ``type-hints`` checker (C7, INTERFACES I-10; T-018).

Compares annotated with unannotated function signatures (D-PM-05 #9).
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.type_hints.match import OPTIONS, match_rule
from conventiondrift.checkers.type_hints.sites import type_hint_sites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["TypeHintsChecker"]


class TypeHintsChecker:
    """I-10 ``Checker`` for annotated versus unannotated functions."""

    id: CheckerId = "type-hints"
    experimental = False
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        return {ast.FunctionDef: type_hint_sites, ast.AsyncFunctionDef: type_hint_sites}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()
