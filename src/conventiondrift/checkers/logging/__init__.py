"""The ``logging`` checker (C7, INTERFACES I-10, I-6 ``checkers.logging``; T-016).

Compares ``logging`` calls with ``print()`` calls. Its scope flags (script
paths, ``__main__`` guards, console-script entry points) come from C7's
``FileContext``, so the checker itself reads no config.
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.logging.match import OPTIONS, match_rule
from conventiondrift.checkers.logging.sites import logging_sites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["LoggingChecker"]


class LoggingChecker:
    """I-10 ``Checker`` for ``logging`` versus ``print``."""

    id: CheckerId = "logging"
    experimental = False
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        return {ast.Call: logging_sites}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()
