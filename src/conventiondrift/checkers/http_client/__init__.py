"""The ``http-client`` checker (C7, INTERFACES I-10; T-017).

Compares HTTP calls made through ``requests``, ``httpx``, ``aiohttp`` and
``urllib.request``. Only calls and client constructions are sites; an
``import`` is not (D-PM-27 #3). Names are resolved through top-level imports; the limits
(method calls on variables, star imports, imports inside functions, ``urllib3`` and
``http.client``) are listed in ``sites.py``.
"""

import ast
from collections.abc import Callable, Iterable, Mapping
from typing import Literal

from conventiondrift.checkers.http_client.match import OPTIONS, match_rule
from conventiondrift.checkers.http_client.sites import HttpSites
from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

__all__ = ["HttpClientChecker"]


class HttpClientChecker:
    """I-10 ``Checker`` for HTTP client libraries."""

    id: CheckerId = "http-client"
    experimental = False
    options = OPTIONS
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return match_rule(normalized_text)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        # One table per file (I-10): the import table is read from the module before its calls.
        sites = HttpSites()
        return {ast.Module: sites.imports, ast.Call: sites.calls}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()
