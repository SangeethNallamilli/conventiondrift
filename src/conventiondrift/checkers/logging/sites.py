"""Site finding for the logging checker (INTERFACES I-10; AC-F3.2, AC-F3.12).

A site is a call to the builtin ``print`` (option ``print``) or a logging call
such as ``logging.info(...)``, ``logger.warning(...)`` or
``logging.getLogger(name).error(...)`` (option ``logging``). ``print()`` calls
in script files (the ``script-paths`` default, B2, or a console-script entry
point; ``ctx.is_script``) and inside an ``if __name__ == "__main__":`` body are
not sites, because a command-line tool prints on purpose. Logging calls always count.
"""

import ast
from bisect import bisect_right
from collections.abc import Iterable, Iterator
from typing import Final

from conventiondrift.model import FileContext, Site

__all__ = ["LEVEL_METHODS", "LoggingSites", "in_guard", "logging_sites", "merge_spans"]

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


def merge_spans(spans: Iterable[tuple[int, int]]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """The union of ``(first, last)`` line spans as sorted, disjoint ``(firsts, lasts)``.

    Nested and overlapping spans (a guard inside a guard) are merged, so a line is in
    some span exactly when it is in one merged interval, which a bisect then finds.
    """
    firsts: list[int] = []
    lasts: list[int] = []
    for first, last in sorted(spans):
        if lasts and first <= lasts[-1]:
            lasts[-1] = max(lasts[-1], last)
        else:
            firsts.append(first)
            lasts.append(last)
    return tuple(firsts), tuple(lasts)


def in_guard(guards: tuple[tuple[int, ...], tuple[int, ...]], line: int) -> bool:
    """Whether ``line`` is inside one of the merged ``(firsts, lasts)`` intervals."""
    firsts, lasts = guards
    found = bisect_right(firsts, line) - 1
    return found >= 0 and line <= lasts[found]


class LoggingSites:
    """The ``ast.Call`` handler. C7 asks the checker for its handlers once per walker, so one
    instance walks one batch of files, and it keeps the guard index of the file in hand.

    Asking ``ctx.main_guard_spans`` for every print would cost one scan of all the guards
    per call, which is quadratic in a file with many of both. The index is built once per
    file, and each question is then a bisect.
    """

    def __init__(self) -> None:
        self._ctx: FileContext | None = None
        self._guards: tuple[tuple[int, ...], tuple[int, ...]] = ((), ())

    def _in_main_guard(self, ctx: FileContext, line: int) -> bool:
        if ctx is not self._ctx:
            self._ctx = ctx
            self._guards = merge_spans(ctx.main_guard_spans)
        return in_guard(self._guards, line)

    def __call__(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        """The sites of one node; any node that is not a call gives none."""
        if not isinstance(node, ast.Call):
            return
        func = node.func
        if isinstance(func, ast.Name) and func.id == "print":
            if not (ctx.is_script or self._in_main_guard(ctx, node.lineno)):
                yield Site(ctx.path, node.lineno, node.col_offset, "print")
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in LEVEL_METHODS
            and _is_logger(func.value)
        ):
            yield Site(ctx.path, node.lineno, node.col_offset, "logging")


def logging_sites(node: ast.AST, ctx: FileContext) -> Iterator[Site]:
    """The sites of one node with a fresh handler (no cached guard index)."""
    return LoggingSites()(node, ctx)
