"""The checker interface (INTERFACES I-10, ADR-0003; DESIGN §12 A-1).

Internal in v1, shaped as a future plugin API. Checkers are pure: they see
only the parsed AST and a ``FileContext``.
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal, Protocol

from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["Checker", "CheckerId", "FileContext", "RuleMatch", "Site"]


class Checker(Protocol):
    """One convention family (e.g. logging) compared across its options."""

    id: CheckerId
    experimental: bool
    options: frozenset[str]
    inputs: frozenset[Literal["python-ast", "manifest"]]

    def match_rule(self, normalized_text: str) -> RuleMatch | None: ...

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]: ...

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]: ...
