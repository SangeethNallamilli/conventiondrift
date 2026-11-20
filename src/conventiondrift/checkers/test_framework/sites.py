"""Site finding for the test-framework checker (INTERFACES I-10; AC-F3.4, DESIGN §10 B2).

Only test files have sites (``ctx.is_test_file``: the B2 is-test-file patterns, matched at
any depth). In a test file:

* a class with ``TestCase`` or ``IsolatedAsyncioTestCase`` among its bases, by name or as
  ``unittest.<name>``, is one ``unittest`` site, at the ``class`` line;
* a module-level ``def test_*`` or ``async def test_*`` is one ``pytest`` site; so is a
  ``test_*`` method of a pytest-style class, one whose name starts with ``Test`` and that has
  no base other than ``object``.

Names are matched as written, with no import tracking (D-PM-42): a subclass of a project's own
``TestCase`` subclass, and test functions under a module-level ``if`` or inside a function, are
not sites. Methods of a ``TestCase`` subclass are part of its one site. The handlers only read
the direct body of the node they are given; the shared walk visits every class.
"""

import ast
from collections.abc import Iterator
from typing import Final

from conventiondrift.model import FileContext, Site

__all__ = ["TESTCASE_NAMES", "framework_sites"]

TESTCASE_NAMES: Final = frozenset({"TestCase", "IsolatedAsyncioTestCase"})
"""``unittest`` base classes a test class names directly or as ``unittest.<name>``."""


def _base_name(base: ast.expr) -> str | None:
    """``TestCase`` for ``TestCase`` and ``unittest.TestCase``; ``object`` for ``object``."""
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
        if base.value.id == "unittest":
            return base.attr
    return None


def _tests(body: list[ast.stmt], ctx: FileContext) -> Iterator[Site]:
    """A ``pytest`` site for each ``test_*`` function directly in ``body``."""
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name.startswith("test_"):
                yield Site(ctx.path, stmt.lineno, stmt.col_offset, "pytest")


def framework_sites(node: ast.AST, ctx: FileContext) -> Iterator[Site]:
    """Handler for the module and for each class; any other node gives no site."""
    if not ctx.is_test_file:
        return
    if isinstance(node, ast.Module):
        yield from _tests(node.body, ctx)
    elif isinstance(node, ast.ClassDef):
        bases = [_base_name(base) for base in node.bases]
        if TESTCASE_NAMES.intersection(bases):
            yield Site(ctx.path, node.lineno, node.col_offset, "unittest")
        elif node.name.startswith("Test") and all(name == "object" for name in bases):
            yield from _tests(node.body, ctx)
