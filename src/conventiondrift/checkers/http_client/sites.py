"""Site finding for the http-client checker (INTERFACES I-10; AC-F3.3, D-PM-27 #3).

A site is a call, or a client construction, that resolves to one of the names in ``CALLS``:
``requests.get(...)``, ``httpx.AsyncClient()``, ``aiohttp.ClientSession()`` or
``urllib.request.urlopen(...)``. The option is the library. An ``import`` is not a site, and
neither is a name that is not in ``CALLS`` (``requests.codes``, ``httpx.URL(...)``).

Names are resolved through the imports at the top level of the file (INTERFACES I-10,
"Import resolution"): ``import m``, ``import m as a``, ``from m import n`` and
``from m import n as a``, with dotted forms such as ``import urllib.request`` and
``from urllib import request``. Imports under a module-level ``if``, ``try``, ``with``
or loop count. The import table is per file and built from that file's tree only.

Limits in v1 (the docs list them):

* Method calls on variables (``session.get(...)``, ``client.post(...)``) are not seen. The
  construction (``requests.Session()``) is the site.
* Star imports (``from requests import *``) are not followed.
* Imports inside a function, a class or a lambda are not followed.
* ``urllib3`` and ``http.client`` are not counted.
* A name that is rebound after its import is still read as the import.
* Relative imports are not followed.
"""

import ast
from collections.abc import Iterator
from typing import Final

from conventiondrift.model import FileContext, Site

__all__ = ["CALLS", "HttpSites"]

_VERBS: Final = ("get", "post", "put", "patch", "delete", "head", "options", "request")

_NAMES: Final = {
    "requests": (*_VERBS, "Session", "session"),
    "httpx": (*_VERBS, "stream", "Client", "AsyncClient"),
    "aiohttp": ("ClientSession", "request"),
    "urllib.request": ("urlopen", "urlretrieve"),
}

CALLS: Final = {
    (*module.split("."), name): module.split(".")[0]
    for module, names in _NAMES.items()
    for name in names
}
"""Full dotted path of each call or construction that is a site, and its option."""


def _blocks(stmt: ast.stmt) -> tuple[list[ast.stmt], ...]:
    """Statement lists of a compound statement that runs at module level."""
    if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
        return (stmt.body, stmt.orelse)
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return (stmt.body,)
    if isinstance(stmt, (ast.Try, ast.TryStar)):
        return (stmt.body, *(h.body for h in stmt.handlers), stmt.orelse, stmt.finalbody)
    if isinstance(stmt, ast.Match):
        return tuple(case.body for case in stmt.cases)
    return ()


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


class HttpSites:
    """The handlers for one file. ``imports`` runs on the module before any call is reached.

    The walk starts at the module, so the table is complete by the first call. C7 builds
    new handlers for every file (I-10, "Per-file handler state"), so nothing carries over.
    """

    def __init__(self) -> None:
        self._bound: dict[str, tuple[str, ...]] = {}

    def imports(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        """Handler for ``ast.Module``: read its top-level imports; gives no site."""
        if isinstance(node, ast.Module):
            stack = list(reversed(node.body))
            while stack:
                stmt = stack.pop()
                if isinstance(stmt, ast.Import):
                    self._import(stmt)
                elif isinstance(stmt, ast.ImportFrom):
                    self._import_from(stmt)
                for block in reversed(_blocks(stmt)):
                    stack.extend(reversed(block))
        return iter(())

    def _import(self, stmt: ast.Import) -> None:
        for alias in stmt.names:
            if alias.asname is None:
                top = alias.name.split(".")[0]
                self._bound[top] = (top,)
            else:
                self._bound[alias.asname] = tuple(alias.name.split("."))

    def _import_from(self, stmt: ast.ImportFrom) -> None:
        if stmt.level or not stmt.module:
            return
        module = tuple(stmt.module.split("."))
        for alias in stmt.names:
            if alias.name != "*":
                self._bound[alias.asname or alias.name] = (*module, alias.name)

    def calls(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        """Handler for ``ast.Call``."""
        if not isinstance(node, ast.Call):
            return
        chain = _dotted(node.func)
        if chain is None:
            return
        root = self._bound.get(chain[0])
        if root is None:
            return
        option = CALLS.get((*root, *chain[1:]))
        if option is not None:
            yield Site(ctx.path, node.lineno, node.col_offset, option)
