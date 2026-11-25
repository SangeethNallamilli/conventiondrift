"""Site finding for the type-hints checker (INTERFACES I-10; AC-F3.8, D-PM-05 #9).

Every ``def`` and ``async def`` is one site, at its ``def`` line: ``annotated`` when it has at
least one parameter or return annotation, else ``unannotated``. A first positional parameter
named ``self`` or ``cls`` is ignored, so its annotation alone doesn't make a function annotated.
Lambdas can't be annotated and are not sites. Test and script files count like any other.
"""

import ast
from collections.abc import Iterator
from typing import Final

from conventiondrift.model import FileContext, Site

__all__ = ["IGNORED_FIRST", "is_annotated", "type_hint_sites"]

IGNORED_FIRST: Final = frozenset({"self", "cls"})
"""Names of a first positional parameter whose annotation doesn't count."""


def is_annotated(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether the function has a return annotation or an annotation on a counted parameter."""
    args = node.args
    positional = [*args.posonlyargs, *args.args]
    if positional and positional[0].arg in IGNORED_FIRST:
        positional = positional[1:]
    params = [*positional, *args.kwonlyargs, args.vararg, args.kwarg]
    return node.returns is not None or any(
        param is not None and param.annotation is not None for param in params
    )


def type_hint_sites(node: ast.AST, ctx: FileContext) -> Iterator[Site]:
    """Handler for ``def`` and ``async def``; any other node gives no site."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        option = "annotated" if is_annotated(node) else "unannotated"
        yield Site(ctx.path, node.lineno, node.col_offset, option)
