"""Site finding for the string-format checker (INTERFACES I-10; AC-F3.6).

A site is one of:

* ``f-string``: an f-string literal. The spec of a replacement field (``f"{x:>{w}}"``)
  is also a ``JoinedStr`` node, but it is part of its f-string and is not a site.
* ``format``: a call to ``.format`` on a string literal, ``"...".format(...)``.
* ``percent``: a ``%`` expression whose left side is a string literal, ``"..." % x``.

The site is at the start of the string (for ``format`` and ``percent``, of the call or
expression). Formatting through a name (``template.format(x)``, ``text % x``) can't be
told from other code without types, so it is not a site, and neither is a ``bytes`` literal.
Logging arguments such as ``logger.info("%s", x)`` are not ``%`` expressions.
"""

import ast
from collections.abc import Iterator

from conventiondrift.model import FileContext, Site

__all__ = ["FormatSites"]


def _is_str_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


class FormatSites:
    """The handlers for one walk. ``note_spec`` runs on a field before its spec is reached.

    The walk visits a node before its children, so by the time the spec's ``JoinedStr`` is
    handled it has been noted and is skipped. The nodes are held, not their ``id``s, so a
    note left by a walk that stopped early can't match a later node.
    """

    def __init__(self) -> None:
        self._specs: set[ast.AST] = set()

    def note_spec(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        """Handler for ``ast.FormattedValue``; gives no site."""
        if isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            self._specs.add(node.format_spec)
        return iter(())

    def f_string(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        """Handler for ``ast.JoinedStr``."""
        if not isinstance(node, ast.JoinedStr):
            return
        if node in self._specs:
            self._specs.discard(node)
            return
        yield Site(ctx.path, node.lineno, node.col_offset, "f-string")

    def format_call(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        """Handler for ``ast.Call``."""
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and _is_str_literal(node.func.value)
        ):
            yield Site(ctx.path, node.lineno, node.col_offset, "format")

    def percent(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        """Handler for ``ast.BinOp``."""
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and _is_str_literal(node.left)
        ):
            yield Site(ctx.path, node.lineno, node.col_offset, "percent")
