"""Site finding for the exceptions checker (INTERFACES I-10; AC-F3.7).

Every ``except`` clause is one site: ``bare-except`` for ``except:``,
``broad-except`` for a clause that catches ``Exception`` or ``BaseException``
(by name, as ``builtins.Exception``, or inside a tuple), and ``specific``
for any other clause. The site is at the ``except`` keyword. Test and script
files count like any other (the spec makes no exception for them).
"""

import ast
from collections.abc import Iterator
from typing import Final

from conventiondrift.model import FileContext, Site

__all__ = ["BROAD_NAMES", "exception_sites"]

BROAD_NAMES: Final = frozenset({"Exception", "BaseException"})
"""Built-in classes that catch (nearly) everything a program should handle."""


def _is_broad(expr: ast.expr) -> bool:
    """Whether the clause's type expression names a broad class, also inside a tuple."""
    pending = [expr]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Tuple):
            pending.extend(node.elts)
        elif isinstance(node, ast.Name):
            if node.id in BROAD_NAMES:
                return True
        elif (
            isinstance(node, ast.Attribute)
            and node.attr in BROAD_NAMES
            and isinstance(node.value, ast.Name)
            and node.value.id == "builtins"
        ):
            return True
    return False


def exception_sites(node: ast.AST, ctx: FileContext) -> Iterator[Site]:
    """Handler for ``except`` and ``except*`` clauses; any other node gives no site."""
    if not isinstance(node, ast.ExceptHandler):
        return
    if node.type is None:
        option = "bare-except"
    elif _is_broad(node.type):
        option = "broad-except"
    else:
        option = "specific"
    yield Site(ctx.path, node.lineno, node.col_offset, option)
