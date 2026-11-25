"""The ``string-format`` checker (C7, INTERFACES I-10; T-017).

Compares f-strings with ``"...".format()`` calls and ``"..." % x`` expressions.
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.string_format.match import OPTIONS, match_rule
from conventiondrift.checkers.string_format.sites import FormatSites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["StringFormatChecker"]


class StringFormatChecker:
    """I-10 ``Checker`` for f-strings, ``str.format`` and ``%`` formatting."""

    id: CheckerId = "string-format"
    experimental = False
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        # One tracker per table: it remembers the format specs the walk is about to reach.
        sites = FormatSites()
        return {
            ast.JoinedStr: sites.f_string,
            ast.FormattedValue: sites.note_spec,
            ast.Call: sites.format_call,
            ast.BinOp: sites.percent,
        }

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()
