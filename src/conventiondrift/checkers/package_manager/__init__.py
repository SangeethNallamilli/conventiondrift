"""The ``package-manager`` checker (C7, INTERFACES I-10 ``manifest_sites``; T-019).

Compares the package manager a rule names with the manifests and lockfiles in the repo
(project brief checker 8: pip, Poetry, uv, PDM). It reads manifests only, never the AST.
Its sites are evidence files and tables, usually 1 to 3 per repository, so with the
default minimum of 5 relevant sites it nearly always reports Insufficient data (AC-F3.9
known v1 limit, D-PM-10).
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.package_manager.match import OPTIONS, match_rule
from conventiondrift.checkers.package_manager.sites import manifest_sites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["PackageManagerChecker"]


class PackageManagerChecker:
    """I-10 ``Checker`` for the package manager (manifest input only)."""

    id: CheckerId = "package-manager"
    experimental = False
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"manifest"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        return {}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return manifest_sites(files)
