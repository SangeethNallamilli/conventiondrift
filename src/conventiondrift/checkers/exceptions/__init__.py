"""The ``exceptions`` checker (C7, INTERFACES I-10; T-016).

Compares bare ``except:`` and ``except Exception:`` clauses with clauses that
name specific exception classes.
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.exceptions.match import OPTIONS, match_rule
from conventiondrift.checkers.exceptions.sites import exception_sites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["ExceptionsChecker"]


class ExceptionsChecker:
    """I-10 ``Checker`` for bare, broad and specific ``except`` clauses."""

    id: CheckerId = "exceptions"
    experimental = False
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        return {ast.ExceptHandler: exception_sites}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()
