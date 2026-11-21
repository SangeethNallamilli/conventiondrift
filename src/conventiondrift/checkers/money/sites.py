"""Site finding for the money checker (INTERFACES I-8, I-10; AC-F3.5).

An assignment target (a name, attribute or keyword argument) is named like money when its
identifier, split into words at ``_`` and camelCase boundaries and lowercased, contains a
word from the fixed I-8 list ``MONEY_WORDS``. A named target is a site when its value is an
``int`` literal or a ``Decimal(...)`` call or a name ending in ``_cents`` (``integer-cents``,
which follows "Store money as integer cents"), or a ``float`` literal (``float``, which
contradicts that rule). Other values are not sites. ``bool`` literals are not ints.
"""

import ast
import re
from collections.abc import Iterator
from typing import Final

from conventiondrift.model import FileContext, Site

__all__ = ["MONEY_WORDS", "is_named_like_money", "money_sites", "option_of", "words_of"]

MONEY_WORDS: Final = frozenset(
    {
        "price",
        "prices",
        "amount",
        "amounts",
        "total",
        "totals",
        "subtotal",
        "cost",
        "costs",
        "cents",
        "fee",
        "fees",
        "balance",
        "payment",
        "refund",
        "tax",
        "discount",
        "salary",
        "wage",
        "revenue",
    }
)
"""The fixed v1 money-name list (INTERFACES I-8). ``size`` / ``sizes`` are not included."""

_PARTS: Final = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
"""One camelCase or digit run inside a ``_``-separated identifier part."""


def words_of(identifier: str) -> tuple[str, ...]:
    """The identifier split at ``_`` and camelCase boundaries, each word lowercased (I-8)."""
    return tuple(
        token.lower() for part in identifier.split("_") if part for token in _PARTS.findall(part)
    )


def is_named_like_money(identifier: str) -> bool:
    """Whether ``identifier`` contains an I-8 money word as a whole split word."""
    return not MONEY_WORDS.isdisjoint(words_of(identifier))


def _is_decimal_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "Decimal"
    return isinstance(func, ast.Attribute) and func.attr == "Decimal"


def _ends_with_cents(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id.endswith("_cents")
    return isinstance(node, ast.Attribute) and node.attr.endswith("_cents")


def _literal(node: ast.AST) -> ast.AST:
    """The operand of a leading unary ``+`` or ``-``, so ``-5`` still counts as an int literal."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return node.operand
    return node


def option_of(value: ast.AST) -> str | None:
    """``integer-cents`` or ``float`` when ``value`` is a form I-8 names, else None."""
    value = _literal(value)
    if isinstance(value, ast.Constant):
        if type(value.value) is int:
            return "integer-cents"
        if type(value.value) is float:
            return "float"
        return None
    if isinstance(value, ast.Call) and _is_decimal_call(value):
        return "integer-cents"
    if _ends_with_cents(value):
        return "integer-cents"
    return None


def _identifier(target: ast.AST) -> tuple[str, int, int] | None:
    """The name, line and column of a Name or Attribute target, else None."""
    if isinstance(target, ast.Name):
        return target.id, target.lineno, target.col_offset
    if isinstance(target, ast.Attribute):
        return target.attr, target.lineno, target.col_offset
    return None


def _site(target: ast.AST, value: ast.AST, ctx: FileContext) -> Site | None:
    found = _identifier(target)
    if found is None:
        return None
    ident, line, column = found
    if not is_named_like_money(ident):
        return None
    option = option_of(value)
    if option is None:
        return None
    return Site(ctx.path, line, column, option)


def money_sites(node: ast.AST, ctx: FileContext) -> Iterator[Site]:
    """Handler for assignments, annotated assignments and calls (keyword arguments)."""
    if isinstance(node, ast.Assign):
        for target in node.targets:
            site = _site(target, node.value, ctx)
            if site is not None:
                yield site
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        if node.value is not None:
            site = _site(node.target, node.value, ctx)
            if site is not None:
                yield site
    elif isinstance(node, ast.Call):
        for keyword in node.keywords:
            if keyword.arg is None or not is_named_like_money(keyword.arg):
                continue
            option = option_of(keyword.value)
            if option is not None:
                yield Site(ctx.path, keyword.lineno, keyword.col_offset, option)
