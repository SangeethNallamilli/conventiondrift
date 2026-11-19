"""C4 discover (DESIGN §12 A-1, §10 S6, T-010a): instruction files and Python files
in a commit's tree.

The path and file-read primitives live in :mod:`conventiondrift.discover.safefs` and the
gitignore-style matcher in :mod:`conventiondrift.discover.globmatch`. :func:`discover_tree`
lists a commit through C3 (``tree`` then ``blob``), so no working-tree path is touched
and ``.git/`` is never read (SEC-T10, SC-2.43). Problems with a file are
:class:`~conventiondrift.model.SkippedFile` entries, never errors (I-11).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from conventiondrift.defaults import DEFAULT_EXCLUDES
from conventiondrift.discover.globmatch import GlobSet, compile_glob
from conventiondrift.discover.safefs import (
    AlwaysExcluded,
    FileKind,
    check_size,
    decode_text,
    escape_unsupported_path,
    has_hard_excluded_component,
    size_limit,
    validate_relpath,
)
from conventiondrift.errors import FileSkipped
from conventiondrift.model import InstructionFile, ManifestFile, PyFile, SkippedFile, SkipReason

if TYPE_CHECKING:
    from conventiondrift.components import TreeEntry
    from conventiondrift.core import BasePhaseDone

__all__ = [
    "MAX_INSTRUCTION_FILES",
    "MAX_PY_FILES",
    "Discovery",
    "TreeReader",
    "discover_tree",
    "instruction_scope",
    "is_generated",
]

MAX_INSTRUCTION_FILES: Final = 200  # R2.6
MAX_PY_FILES: Final = 100_000  # R2.6

# DESIGN §10 S6. The root tool folders come first: they configure the tool, not the
# code under them, so a file such as ``.claude/rules/CLAUDE.md`` is whole-repo.
_WHOLE_REPO: Final = tuple(
    compile_glob(p)
    for p in (
        "/.cursorrules",
        "/.github/copilot-instructions.md",
        "/.claude/rules/**/*.md",
        "/.cursor/rules/**/*.md",
        "/.cursor/rules/**/*.mdc",
        "/.github/instructions/**/*.md",
    )
)
_OWN_FOLDER: Final = tuple(
    compile_glob(f"**/{name}")
    for name in (
        "AGENTS.md",
        "AGENT.md",
        "AGENTS.override.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        "GEMINI.md",
    )
)
_GENERATED_LINES: Final = 5
_REGULAR_MODES: Final = frozenset({"100644", "100755", "100664"})


def instruction_scope(path: str) -> str | None:
    """The S6 scope folder (``""`` is the whole repo) of an instruction file, else ``None``."""
    if any(g.match(path) for g in _WHOLE_REPO):
        return ""
    if any(g.match(path) for g in _OWN_FOLDER):
        return path.rpartition("/")[0]
    return None


def is_generated(text: str) -> bool:
    """True if the first 5 lines hold both "generated" and "do not edit", ignoring case (S6)."""
    head = "\n".join(text.splitlines()[:_GENERATED_LINES]).casefold()
    return "generated" in head and "do not edit" in head


class TreeReader(Protocol):
    """The two C3 calls C4 makes; ``GitReaderProtocol`` and ``GitReader`` satisfy it."""

    def tree(self, sha: str) -> Sequence[TreeEntry]: ...

    def blob(self, oid: str, max_bytes: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class Discovery:
    """What C4 found at one commit. Each tuple is sorted by path as UTF-8 bytes (A-5)."""

    instruction_files: tuple[InstructionFile, ...]
    py_files: tuple[PyFile, ...]
    manifest_files: tuple[ManifestFile, ...]  # empty until T-010c (A-4)
    entry_points: frozenset[str]  # empty until T-010c (A-4)
    skipped: tuple[SkippedFile, ...]
    notes: tuple[str, ...]  # summary notes: "`x` is always excluded", "`x` was not found"


def _sort_key(path: str) -> bytes:
    return path.encode("utf-8", "surrogateescape")


def _in_scope(path: str, scopes: frozenset[str]) -> bool:
    if "" in scopes:
        return True
    return any(path.startswith(f"{scope}/") for scope in scopes)


def _venv_roots(paths: Iterable[str]) -> frozenset[str]:
    """Folders (never the repo root) that hold a ``pyvenv.cfg`` (S6 default exclude)."""
    found = set()
    for path in paths:
        folder, _, name = path.rpartition("/")
        if folder and name == "pyvenv.cfg":
            found.add(folder)
    return frozenset(found)


def _inside(path: str, folders: frozenset[str]) -> bool:
    parts = path.split("/")[:-1]
    return any("/".join(parts[:i]) in folders for i in range(1, len(parts) + 1))


class _Reader:
    """Reads tree entries through C3, turning every per-file problem into a reason."""

    def __init__(self, git: TreeReader, max_file_bytes: int | None) -> None:
        self._git = git
        self._max = max_file_bytes

    def read(self, entry: TreeEntry, kind: FileKind) -> tuple[bytes, str] | SkipReason:
        """The bytes and their decoded text, or the reason the file is skipped."""
        mode, oid, size, _ = entry
        if mode == "120000":
            return "symlink"
        if mode not in _REGULAR_MODES or size is None:
            return "special file"
        try:
            check_size(size, kind, self._max)  # known before any read (R2.3)
            data = self._git.blob(oid, size_limit(kind, self._max))
            text = decode_text(data, "python" if kind == "python" else "instruction")
        except FileSkipped as exc:
            return exc.reason
        return data, text


def discover_tree(
    phase: BasePhaseDone,
    git: TreeReader,
    sha: str,
    *,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    paths: Sequence[str] | None = None,
    max_file_bytes: int | None = None,
) -> Discovery:
    """List instruction files and Python files in scope at commit ``sha`` (DESIGN §10 S6).

    ``phase`` is the SR-015 token: the base config load has already run (I-13 C4 rulings).

    * ``excludes`` is the effective glob set (``Policy.excludes``). The hard ``.git/`` and
      ``node_modules/`` exclusions (any component, I-5) and the two content rules, a
      folder holding ``pyvenv.cfg`` and the generated-file header, always apply and are
      silent: an excluded file is not a ``SkippedFile``.
    * ``paths`` (``Policy.paths``; ``None`` or empty means auto-detect, AC-F9.2) names the
      only instruction files. An entry that matches an S6 pattern keeps its scope, any
      other scopes to the whole repo (A-6). Named files are not subject to ``excludes``;
      one that is hard-excluded, or missing from the tree (SC-2.54), is dropped with a
      note, not a ``SkippedFile``, and a missing one never falls back to auto-detection.
    * A ``.py`` file is kept only if some kept instruction file's scope contains it.
    * At most ``MAX_INSTRUCTION_FILES`` and ``MAX_PY_FILES`` are kept, first by path bytes
      (A-5); the rest are ``"cap exceeded"``. Symlinks, special files and bad names are
      reported only when the file would otherwise be analyzed (I-13 ruling 6).
    """
    reader = _Reader(git, max_file_bytes)
    skipped: list[SkippedFile] = []
    notes: list[str] = []
    live = sorted(
        (e for e in git.tree(sha) if e[0] != "160000" and not has_hard_excluded_component(e[3])),
        key=lambda e: _sort_key(e[3]),
    )
    by_path = {e[3]: e for e in live}
    excluded = GlobSet(excludes)
    venvs = _venv_roots(by_path)

    def skip(path: str, reason: SkipReason) -> None:
        skipped.append(SkippedFile(path, reason))

    def usable(path: str) -> bool:
        try:
            validate_relpath(path, origin="tree")
        except FileSkipped as exc:
            skip(escape_unsupported_path(path), exc.reason)
            return False
        return True

    named: dict[str, str] = {}  # path -> scope, for `paths` mode
    if paths:
        for raw in dict.fromkeys(paths):
            try:
                rel = validate_relpath(raw, origin="input")
            except FileSkipped as exc:
                skip(raw, exc.reason)
                continue
            if has_hard_excluded_component(rel):
                notes.append(AlwaysExcluded(rel).note)
            elif rel not in by_path:
                notes.append(f"`{rel}` was not found")
            else:
                scope = instruction_scope(rel)
                named.setdefault(rel, "" if scope is None else scope)

    def wanted(path: str) -> bool:
        return not (_inside(path, venvs) or excluded.excludes(path))

    instruction_candidates = (
        sorted(named, key=_sort_key)
        if paths
        else [p for p in by_path if instruction_scope(p) is not None and wanted(p)]
    )
    instructions: list[InstructionFile] = []
    for path in instruction_candidates:
        if len(instructions) >= MAX_INSTRUCTION_FILES:
            skip(path, "cap exceeded")
        elif path in named or usable(path):
            got = reader.read(by_path[path], "instruction")
            if isinstance(got, tuple):
                scope = named[path] if path in named else instruction_scope(path) or ""
                instructions.append(InstructionFile(path, got[0], scope, path in named))
            else:
                skip(path, got)

    scopes = frozenset(f.scope_dir for f in instructions)
    pys: list[PyFile] = []
    for path in by_path:
        if (
            not path.endswith(".py")
            or path in named
            or not _in_scope(path, scopes)
            or not wanted(path)
        ):
            continue
        if len(pys) >= MAX_PY_FILES:
            skip(path, "cap exceeded")
        elif usable(path):
            got = reader.read(by_path[path], "python")
            if not isinstance(got, tuple):
                skip(path, got)
            elif not is_generated(got[1]):
                pys.append(PyFile(path, got[0]))
    return Discovery(
        tuple(instructions),
        tuple(pys),
        (),
        frozenset(),
        tuple(sorted(skipped, key=lambda s: _sort_key(s.path))),
        tuple(notes),
    )
