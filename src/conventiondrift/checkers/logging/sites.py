"""Site finding for the logging checker (INTERFACES I-10; AC-F3.2, AC-F3.12).

A site is a call to the builtin ``print`` (option ``print``) or a logging call
such as ``logging.info(...)``, ``logger.warning(...)`` or
``logging.getLogger(name).error(...)`` (option ``logging``). ``print()`` calls
in script files (the ``script-paths`` default, B2, or a console-script entry
point; ``ctx.is_script``) and inside an ``if __name__ == "__main__":`` body are
not sites, because a command-line tool prints on purpose. Logging calls always count.
"""

import ast
from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.walk import in_main_guard
from conventiondrift.model import FileContext, Site

__all__ = ["LEVEL_METHODS", "logging_sites"]

LEVEL_METHODS: Final = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
"""Method names of ``logging`` and of ``Logger`` objects that emit a record."""


def _last_name(node: ast.expr) -> str | None:
    """The name a value ends in: ``logger`` for ``logger`` and for ``self.logger``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_logger(node: ast.expr) -> bool:
    """Whether ``node`` looks like the logging module or a logger, judged by its name only."""
    if isinstance(node, ast.Call):
        return _last_name(node.func) == "getLogger"
    name = _last_name(node)
    if name is None:
        return False
    name = name.lower().strip("_")
    return name in ("log", "logging") or "logger" in name


def logging_sites(node: ast.AST, ctx: FileContext) -> Iterator[Site]:
    """Handler for ``ast.Call`` nodes; any other node gives no site."""
    if not isinstance(node, ast.Call):
        return
    func = node.func
    if isinstance(func, ast.Name) and func.id == "print":
        if not (ctx.is_script or in_main_guard(ctx, node.lineno)):
            yield Site(ctx.path, node.lineno, node.col_offset, "print")
    elif isinstance(func, ast.Attribute) and func.attr in LEVEL_METHODS and _is_logger(func.value):
        yield Site(ctx.path, node.lineno, node.col_offset, "logging")
