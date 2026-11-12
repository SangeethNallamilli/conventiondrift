"""Stand-in checkers for the C7 framework tests (T-014), written only against I-10.

They live at module level so the spawn process pool can pickle them by name.
"""

import ast
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Literal

from conventiondrift.model import CheckerId, FileContext, RuleMatch, Site

Inputs = frozenset[Literal["python-ast", "manifest"]]
AST_ONLY: Inputs = frozenset({"python-ast"})
MANIFEST_ONLY: Inputs = frozenset({"manifest"})
Handlers = Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]


class CallChecker:
    """Reports each call to a bare name in ``options``, e.g. ``print(...)``."""

    experimental = False
    inputs: Inputs = AST_ONLY

    def __init__(self, checker_id: CheckerId, options: frozenset[str]) -> None:
        self.id: CheckerId = checker_id
        self.options = options

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return None

    def ast_handlers(self) -> Handlers:
        return {ast.Call: self._on_call}

    def _on_call(self, node: ast.AST, ctx: FileContext) -> Iterator[Site]:
        assert isinstance(node, ast.Call)
        if isinstance(node.func, ast.Name) and node.func.id in self.options:
            yield Site(ctx.path, node.lineno, node.col_offset, node.func.id)

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()


class ContextChecker:
    """Reports one site per module whose option spells out the file's scope flags."""

    id: CheckerId = "type-hints"
    experimental = False
    inputs: Inputs = AST_ONLY
    options = frozenset({"test", "script", "test+script", "plain", "guarded"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return None

    def ast_handlers(self) -> Handlers:
        return {ast.Module: self._on_module, ast.Expr: self._on_expr}

    def _on_module(self, node: ast.AST, ctx: FileContext) -> list[Site]:
        flags = [n for n, on in (("test", ctx.is_test_file), ("script", ctx.is_script)) if on]
        return [Site(ctx.path, 1, 0, "+".join(flags) or "plain")]

    def _on_expr(self, node: ast.AST, ctx: FileContext) -> list[Site]:
        assert isinstance(node, ast.Expr)
        if any(a <= node.lineno <= b for a, b in ctx.main_guard_spans):
            return [Site(ctx.path, node.lineno, node.col_offset, "guarded")]
        return []

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()


class NodeCounter:
    """Reports every node it is handed (registered on ``ast.AST``, so every type)."""

    id: CheckerId = "string-format"
    experimental = False
    inputs: Inputs = AST_ONLY
    options = frozenset({"node"})

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return None

    def ast_handlers(self) -> Handlers:
        return {ast.AST: self._on_node}

    def _on_node(self, node: ast.AST, ctx: FileContext) -> list[Site]:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        return [Site(ctx.path, line, col, "node"), Site(ctx.path, line, col, "node")]

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()


FaultMode = Literal[
    "ast_handlers raises",
    "bad handler table",
    "handler raises",
    "iteration raises",
    "not a site",
    "wrong file",
    "unknown option",
    "bad position",
    "raises on one file",
    "system exit",
]


class FaultyChecker:
    """A checker that breaks the I-10 contract in one chosen way (``mode``)."""

    id: CheckerId = "exceptions"
    experimental = False
    inputs: Inputs = AST_ONLY
    options = frozenset({"bad"})

    def __init__(self, mode: FaultMode) -> None:
        self.mode = mode

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return None

    def ast_handlers(self) -> Handlers:
        if self.mode == "ast_handlers raises":
            raise RuntimeError("boom")
        if self.mode == "bad handler table":
            return {"Call": self._on_call}  # type: ignore[dict-item]
        return {ast.Call: self._on_call}  # type: ignore[dict-item]

    def _on_call(self, node: ast.AST, ctx: FileContext) -> Iterable[object]:
        assert isinstance(node, ast.Call)
        good = Site(ctx.path, node.lineno, node.col_offset, "bad")
        mode = self.mode
        if mode == "handler raises":
            raise ValueError("boom")
        if mode == "system exit":
            raise SystemExit(0)
        if mode == "iteration raises":
            return _broken_iter(good)
        if mode == "raises on one file":
            if ctx.path == "src/poison.py":
                raise RuntimeError("boom")
            return [good]
        bad: dict[str, object] = {
            "not a site": ("src/a.py", 1, 0, "bad"),
            "wrong file": Site("elsewhere.py", node.lineno, node.col_offset, "bad"),
            "unknown option": Site(ctx.path, node.lineno, node.col_offset, "nope"),
            "bad position": Site(ctx.path, 0, node.col_offset, "bad"),
        }
        return [good, bad[mode]]

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()


def _broken_iter(first: Site) -> Iterator[Site]:
    yield first
    raise RuntimeError("boom")


class ManifestChecker:
    """Reports a site at line 1 of every manifest that mentions ``uv`` or ``pip``."""

    id: CheckerId = "package-manager"
    experimental = False
    inputs: Inputs = MANIFEST_ONLY
    options = frozenset({"uv", "pip"})

    def __init__(self, fault: Literal["none", "raises", "wrong file"] = "none") -> None:
        self.fault = fault
        self.asked_for_handlers = False

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        return None

    def ast_handlers(self) -> Handlers:
        raise AssertionError("a manifest-only checker is never asked for AST handlers")

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        if self.fault == "raises":
            raise RuntimeError("boom")
        out = [
            Site(p, 1, 0, o)
            for p, data in files.items()
            for o in ("uv", "pip")
            if o.encode() in data
        ]
        if self.fault == "wrong file":
            out.append(Site("not-a-manifest.toml", 1, 0, "uv"))
        return out
