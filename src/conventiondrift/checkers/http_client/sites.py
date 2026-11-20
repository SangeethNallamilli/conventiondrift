"""Site finding for the http-client checker (INTERFACES I-10; AC-F3.3).

A site is a call or a client construction made through a library's module name:
``requests.get(...)``, ``httpx.AsyncClient()``, ``aiohttp.ClientSession()`` or
``urllib.request.urlopen(...)``. The option is the library. Only the names in
``CALLS`` count, so ``requests.codes`` or ``httpx.URL(...)`` are not sites, and an
``import`` is not one either. A site is found only through the module's own name:
calls through an alias (``import requests as r``), a name imported from the module,
or a session object (``session.get(...)``) are not seen. The site is at the call.
"""

import ast
from collections.abc import Iterator
from typing import Final

from conventiondrift.model import FileContext, Site

__all__ = ["CALLS", "http_sites"]

_VERBS: Final = ("get", "post", "put", "patch", "delete", "head", "options", "request")

CALLS: Final = {
    ("requests",): frozenset({*_VERBS, "Session", "session"}),
    ("httpx",): frozenset({*_VERBS, "stream", "Client", "AsyncClient"}),
    ("aiohttp",): frozenset({"ClientSession", "request"}),
    ("urllib", "request"): frozenset({"urlopen", "urlretrieve"}),
}
"""Module path to the names in it that make an HTTP call or build a client."""


def _dotted(node: ast.expr) -> tuple[str, ...] | None:
    """``a.b.c`` as ``("a", "b", "c")``, or None when the chain doesn't start at a name."""
    names: list[str] = []
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    names.append(node.id)
    names.reverse()
    return tuple(names)


def http_sites(node: ast.AST, ctx: FileContext) -> Iterator[Site]:
    """Handler for ``ast.Call`` nodes; any other node gives no site."""
    if not isinstance(node, ast.Call):
        return
    path = _dotted(node.func)
    if path is None:
        return
    *module, name = path
    if name in CALLS.get(tuple(module), ()):
        yield Site(ctx.path, node.lineno, node.col_offset, module[0])
