"""The shared AST walk for C7 (INTERFACES I-10, ADR-0003; DESIGN §5, §12 A-1).

Each Python file is parsed once with ``ast.parse`` and walked once. Every node
is handed to the handlers that the checkers registered for its type, so no
checker walks the tree itself. Repo code is only ever parsed, never imported
or run (SECURITY-RULES R1.2).

A parse failure skips the file with a reason (R2.4, AC-E.14). A checker that
fails, or that returns something that is not a valid ``Site`` for this file,
is a checker bug: it is recorded as failed and not called again, and the
caller drops that checker (I-11 C7, DESIGN §4). Other checkers carry on.
"""

import ast
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from conventiondrift.checkers.base import Checker
from conventiondrift.errors import FileSkipped
from conventiondrift.model import FileContext, Site, SkipReason

Handler = Callable[[ast.AST, FileContext], Iterable[Site]]

PARSE_SKIP_REASONS: tuple[tuple[type[BaseException], SkipReason], ...] = (
    (SyntaxError, "syntax error"),
    (RecursionError, "syntax error"),
    (MemoryError, "syntax error"),
    (UnicodeDecodeError, "not decodable"),
    (ValueError, "syntax error"),
)
"""What ``ast.parse`` may raise on hostile input, and the skip reason for each (R2.4).

Checked in order, so ``UnicodeDecodeError`` is matched before its base
``ValueError``. ``SyntaxError`` covers ``IndentationError`` and "too many nested
parentheses"; ``RecursionError`` and ``MemoryError`` are CPython's limits on deep
or complex source (SEC-T09).
"""

SiteDefect = Literal["not a site", "wrong file", "unknown option", "bad position"]
"""Ways a value returned by a checker can fail to be a valid ``Site`` for its file."""

TEST_DIRS = frozenset({"tests", "test"})
"""Folder names that make a file a test file at any depth (DESIGN §10 B2)."""


def parse(data: bytes) -> ast.Module:
    """Parse one file's bytes, or raise ``FileSkipped`` with the reason (R1.2, R2.4).

    The bytes go to ``ast.parse`` as they are, so a PEP 263 coding cookie and a
    UTF-8 BOM are honoured exactly as Python would.
    """
    try:
        return ast.parse(data)
    except BaseException as exc:
        for kind, reason in PARSE_SKIP_REASONS:
            if isinstance(exc, kind):
                raise FileSkipped(reason) from None
        raise


def is_test_file(path: str) -> bool:
    """DESIGN §10 B2 "is-test-file", matched at any depth and case-sensitively.

    The patterns are ``**/tests/**``, ``**/test/**``, ``**/test_*.py``,
    ``**/*_test.py`` and ``**/conftest.py``.
    """
    *dirs, name = path.split("/")
    if TEST_DIRS.intersection(dirs):
        return True
    if name == "conftest.py":
        return True
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _is_main_guard(test: ast.expr) -> bool:
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
    ):
        return False
    pair = (test.left, test.comparators[0])

    def is_name(node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and node.id == "__name__"

    def is_main(node: ast.expr) -> bool:
        return isinstance(node, ast.Constant) and node.value == "__main__"

    return (is_name(pair[0]) and is_main(pair[1])) or (is_main(pair[0]) and is_name(pair[1]))


def main_guard_spans(tree: ast.Module) -> tuple[tuple[int, int], ...]:
    """(first, last) lines of the body of each module-level ``if __name__ == "__main__":``.

    Only the body counts: an ``else`` branch runs on import too. Both operand
    orders are accepted. Spans are in file order (I-13 Q10).
    """
    spans: list[tuple[int, int]] = []
    for stmt in tree.body:
        if isinstance(stmt, ast.If) and _is_main_guard(stmt.test):
            first, last = stmt.body[0], stmt.body[-1]
            spans.append((first.lineno, last.end_lineno or last.lineno))
    return tuple(spans)


def in_main_guard(ctx: FileContext, line: int) -> bool:
    """Whether ``line`` is inside one of the file's ``__main__`` guard bodies."""
    return any(first <= line <= last for first, last in ctx.main_guard_spans)


def site_defect(value: object, files: frozenset[str], options: frozenset[str]) -> SiteDefect | None:
    """Why ``value`` isn't a valid site in one of ``files`` under ``options``, or None if it is."""
    if not isinstance(value, Site):
        return "not a site"
    if value.file not in files:
        return "wrong file"
    if value.option not in options:
        return "unknown option"
    if type(value.line) is not int or type(value.col) is not int or value.line < 1 or value.col < 0:
        return "bad position"
    return None


class CheckerFault(Exception):
    """A checker broke the I-10 contract; the message is fixed and never quotes input."""


@dataclass(frozen=True, slots=True)
class FileJob:
    """One file to analyze, with the scope flags the main process worked out (I-13 Q10)."""

    path: str
    data: bytes
    is_test_file: bool
    is_script: bool


@dataclass(frozen=True, slots=True)
class FileOutcome:
    """What the walk found in one file.

    ``sites`` holds one ``(checker id, sites)`` pair per checker still healthy
    after this file, in sorted id order, with each site list sorted and unique.
    """

    path: str
    skipped: SkipReason | None
    sites: tuple[tuple[str, tuple[Site, ...]], ...]
    nodes: int


def site_key(site: Site) -> tuple[str, int, int, str]:
    """The I-9 site order: (file, line, col, option)."""
    return (site.file, site.line, site.col, site.option)


def collect(values: Iterable[object], files: frozenset[str], options: frozenset[str]) -> list[Site]:
    """Validate a checker's returned values; raise ``CheckerFault`` on the first bad one."""
    sites: list[Site] = []
    for value in values:
        defect = site_defect(value, files, options)
        if defect is not None or not isinstance(value, Site):
            raise CheckerFault(defect or "not a site")
        sites.append(value)
    return sites


class Walker:
    """One shared walk for a fixed set of checkers (ADR-0003).

    It asks each checker with the ``python-ast`` input for its handlers once.
    ``failed`` maps a checker id to the exception class name of its first
    failure; a failed checker is never called again by this walker.
    """

    def __init__(self, checkers: Sequence[Checker]) -> None:
        self.failed: dict[str, str] = {}
        self._checkers = sorted(checkers, key=lambda c: c.id)
        self._handlers: dict[str, Mapping[type[ast.AST], Handler]] = {}
        self._options: dict[str, frozenset[str]] = {}
        self._dispatch: dict[type[ast.AST], list[tuple[str, Handler]]] = {}
        for checker in self._checkers:
            if "python-ast" not in checker.inputs:
                continue
            self._options[checker.id] = checker.options
            try:
                handlers = checker.ast_handlers()
                if not isinstance(handlers, Mapping) or not all(
                    isinstance(k, type) and issubclass(k, ast.AST) and callable(v)
                    for k, v in handlers.items()
                ):
                    raise CheckerFault("bad handler table")
                self._handlers[checker.id] = dict(handlers)
            except KeyboardInterrupt:
                raise
            except BaseException as exc:  # noqa: BLE001 -- I-11: a failing checker is isolated
                self.failed[checker.id] = type(exc).__name__

    @property
    def ast_checker_ids(self) -> tuple[str, ...]:
        """Ids of the checkers this walker runs on Python files, sorted."""
        return tuple(sorted(self._options))

    def _handlers_for(self, kind: type[ast.AST]) -> list[tuple[str, Handler]]:
        found = self._dispatch.get(kind)
        if found is None:
            mro = kind.__mro__
            found = [
                (cid, table[key])
                for cid, table in sorted(self._handlers.items())
                for key in table
                if key in mro
            ]
            self._dispatch[kind] = found
        return found

    def walk(self, job: FileJob) -> FileOutcome:
        """Parse ``job`` once, walk it once, and gather each healthy checker's sites."""
        try:
            tree = parse(job.data)
        except FileSkipped as skip:
            return FileOutcome(job.path, skip.reason, (), 0)
        ctx = FileContext(
            path=job.path,
            is_test_file=job.is_test_file,
            is_script=job.is_script,
            main_guard_spans=main_guard_spans(tree),
        )
        found: dict[str, set[Site]] = {cid: set() for cid in self._options}
        files = frozenset((job.path,))
        nodes = 0
        # An explicit stack, not recursion: hostile nesting can't overflow the walk (SEC-T09).
        stack: list[ast.AST] = [tree]
        while stack:
            node = stack.pop()
            nodes += 1
            for cid, handler in self._handlers_for(type(node)):
                if cid in self.failed:
                    continue
                try:
                    found[cid].update(collect(handler(node, ctx), files, self._options[cid]))
                except KeyboardInterrupt:
                    raise
                except BaseException as exc:  # noqa: BLE001 -- I-11: a failing checker is isolated
                    self.failed[cid] = type(exc).__name__
            children = list(ast.iter_child_nodes(node))
            children.reverse()
            stack.extend(children)
        sites = tuple(
            (cid, tuple(sorted(found[cid], key=site_key)))
            for cid in sorted(found)
            if cid not in self.failed
        )
        return FileOutcome(job.path, None, sites, nodes)
