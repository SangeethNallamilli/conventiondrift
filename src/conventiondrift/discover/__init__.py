"""C4 discover (DESIGN §12 A-1, §10 S6, A-4, T-010a, T-010c): instruction files,
Python files, package-manager manifests and console-script entry points in a
commit's tree.

The path and file-read primitives live in :mod:`conventiondrift.discover.safefs` and the
gitignore-style matcher in :mod:`conventiondrift.discover.globmatch`. :func:`discover_tree`
lists a commit through C3 (``tree`` then ``blob``), so no working-tree path is touched
and ``.git/`` is never read (SEC-T10, SC-2.43). Problems with a file are
:class:`~conventiondrift.model.SkippedFile` entries, never errors (I-11).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from conventiondrift.core import BasePhaseDone
from conventiondrift.defaults import DEFAULT_EXCLUDES
from conventiondrift.discover import safefs
from conventiondrift.discover.entrypoints import (
    REASON_MANIFEST_PARSE,
    entry_points_from_scripts,
    is_manifest_name,
    manifest_kind,
    scripts_from_toml,
)
from conventiondrift.discover.globmatch import GlobSet, compile_glob
from conventiondrift.discover.safefs import (
    REASON_WALK_LIMIT,
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

__all__ = [
    "MAX_INSTRUCTION_FILES",
    "MAX_PY_FILES",
    "Discovery",
    "TreeReader",
    "discover_tree",
    "instruction_scope",
    "is_generated",
    "is_manifest_name",
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
    """True if the first 5 lines hold both "generated" and "do not edit", ignoring case (S6).

    ``text`` is the whole decoded blob, which C4 has already read up to the size limit
    (1 MiB); only its first 5 lines are inspected.
    """
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
    manifest_files: tuple[ManifestFile, ...]  # A-4 package-manager names, in scope
    entry_points: frozenset[str]  # discovered .py paths of console scripts (A-4)
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
    """True if any folder above ``path`` is in ``folders``; prefixes are sliced, not rejoined."""
    end = path.find("/")
    while end != -1:
        if path[:end] in folders:
            return True
        end = path.find("/", end + 1)
    return False


def _head(path: str, components: int) -> str:
    """The first ``components`` components of ``path`` (which has more) as a folder path."""
    end = -1
    for _ in range(components):
        end = path.find("/", end + 1)
    return path[:end]


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
    """List instruction files, Python files and manifests in scope at commit ``sha``.

    ``phase`` is the SR-015 token: the base config load has already run (I-13 C4 rulings).

    * ``excludes`` is the effective glob set (``Policy.excludes``). The hard ``.git/`` and
      ``node_modules/`` exclusions (any component, I-5) and the two content rules, a
      folder holding ``pyvenv.cfg`` and the generated-file header, always apply and are
      silent: an excluded file is not a ``SkippedFile``. The header check needs the
      decoded blob, so C4 reads each ``.py`` file (up to the size limit, 1 MiB) and
      inspects its first 5 lines.
    * ``paths`` (``Policy.paths``; ``None`` or empty means auto-detect, AC-F9.2) names the
      only instruction files. An entry that matches an S6 pattern keeps its scope, any
      other scopes to the whole repo (A-6). Named files are not subject to ``excludes``;
      one that is hard-excluded, or missing from the tree (SC-2.54), is dropped with a
      note, not a ``SkippedFile``, and a missing one never falls back to auto-detection.
    * A ``.py`` file or a package-manager manifest (A-4) is kept only if some kept
      instruction file's scope contains it. A manifest belongs to its folder, the
      same as a ``.py`` file. ``setup.py`` / ``setup.cfg`` are stored as text only.
    * At most ``MAX_INSTRUCTION_FILES`` and ``MAX_PY_FILES`` files are read, first by path
      bytes (A-5), so the kept set is never larger; the rest are ``"cap exceeded"`` and are
      never read. A file dropped after its read, such as a generated one, still used a slot.
    * A file whose folder is deeper than ``safefs.WALK_MAX_DEPTH`` components (so a path of
      more than ``WALK_MAX_DEPTH + 1`` components), the scan-mode walker's rule, is never
      read or fully matched (SR M-50-1). It is ``"walk limit"`` only if it would otherwise
      be analyzed (I-13 ruling 6): an instruction-file pattern, a ``.py`` in scope, or a
      manifest name in scope, that the excludes do not drop, judged on its first
      ``WALK_MAX_DEPTH + 1`` levels. A named
      ``paths`` entry in the tree is ``"walk limit"``; a missing one is "not found".
    * Symlinks, special files and bad names are reported only when the file would
      otherwise be analyzed (I-13 ruling 6).
    """
    if not isinstance(phase, BasePhaseDone):
        raise TypeError("discover_tree needs the BasePhaseDone token as its first argument")
    reader = _Reader(git, max_file_bytes)
    skipped: list[SkippedFile] = []
    notes: list[str] = []
    # The walker's rule (T-010b): a folder is entered if it is at most WALK_MAX_DEPTH
    # components deep, so a file path may have WALK_MAX_DEPTH + 1 components. Read per call.
    max_folder_depth = safefs.WALK_MAX_DEPTH
    skip_paths: set[str] = set()

    def skip(path: str, reason: SkipReason) -> None:
        # setup.py is both a manifest and a .py file (I-9, D-TL-65 #5): record one skip.
        if path in skip_paths:
            return
        skip_paths.add(path)
        skipped.append(SkippedFile(path, reason))

    # Deeper paths are set aside before any matching (SR M-50-1) and never read.
    listed: list[TreeEntry] = []
    deep: list[str] = []
    for entry in git.tree(sha):
        if entry[0] == "160000" or has_hard_excluded_component(entry[3]):
            continue
        if entry[3].count("/") > max_folder_depth:
            deep.append(entry[3])
        else:
            listed.append(entry)
    deep_set = frozenset(deep)
    live = sorted(listed, key=lambda e: _sort_key(e[3]))
    by_path = {e[3]: e for e in live}
    excluded = GlobSet(excludes)
    venvs = _venv_roots(by_path)

    def deep_wanted(path: str) -> bool:
        """The exclusion test for a deep path, on its first levels only, never the whole path."""
        head = _head(path, max_folder_depth + 1)
        return not (_inside(f"{head}/_", venvs) or excluded.excludes(head, is_dir=True))

    def usable(path: str) -> bool:
        try:
            validate_relpath(path, origin="tree")
        except FileSkipped as exc:
            skip(escape_unsupported_path(path), exc.reason)
            return False
        return True

    named: dict[str, str] = {}  # path -> scope, for `paths` mode
    named_deep: set[str] = set()  # named entries already reported as "walk limit"
    if paths:
        for raw in dict.fromkeys(paths):
            try:
                rel = validate_relpath(raw, origin="input")
            except FileSkipped as exc:
                skip(escape_unsupported_path(raw), exc.reason)
                continue
            label = escape_unsupported_path(rel)
            if has_hard_excluded_component(rel):
                notes.append(AlwaysExcluded(label).note)
            elif rel in deep_set:
                skip(label, REASON_WALK_LIMIT)
                named_deep.add(rel)
            elif rel not in by_path:
                notes.append(f"`{label}` was not found")  # also for a missing deep entry
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
    if not paths:  # I-13 ruling 6: only what would otherwise be analyzed is reported
        for path in deep:
            if instruction_scope(path) is not None and deep_wanted(path):
                skip(escape_unsupported_path(path), REASON_WALK_LIMIT)
    instructions: list[InstructionFile] = []
    reads = 0  # the R2.6 cap bounds blob reads, so a file dropped later still uses a slot
    for path in instruction_candidates:
        if reads >= MAX_INSTRUCTION_FILES:
            skip(path, "cap exceeded")
        elif path in named or usable(path):
            reads += 1
            got = reader.read(by_path[path], "instruction")
            if isinstance(got, tuple):
                scope = named[path] if path in named else instruction_scope(path) or ""
                instructions.append(InstructionFile(path, got[0], scope, path in named))
            else:
                skip(path, got)

    scopes = frozenset(f.scope_dir for f in instructions)
    for path in deep:
        if (
            path not in named_deep
            and _in_scope(path, scopes)
            and (path.endswith(".py") or is_manifest_name(path))
        ):
            if deep_wanted(path):
                skip(escape_unsupported_path(path), REASON_WALK_LIMIT)
    pys: list[PyFile] = []
    reads = 0
    for path in by_path:
        if (
            not path.endswith(".py")
            or path in named
            or not _in_scope(path, scopes)
            or not wanted(path)
        ):
            continue
        if reads >= MAX_PY_FILES:
            skip(path, "cap exceeded")
        elif usable(path):
            reads += 1
            got = reader.read(by_path[path], "python")
            if not isinstance(got, tuple):
                skip(path, got)
            elif not is_generated(got[1]):
                pys.append(PyFile(path, got[0]))
    manifests, entry_points = _manifests(
        by_path, scopes, wanted, usable, reader, skip, frozenset(p.path for p in pys)
    )
    return Discovery(
        tuple(instructions),
        tuple(pys),
        tuple(manifests),
        entry_points,
        tuple(sorted(skipped, key=lambda s: _sort_key(s.path))),
        tuple(notes),
    )


def _manifests(
    by_path: dict[str, TreeEntry],
    scopes: frozenset[str],
    wanted: Callable[[str], bool],
    usable: Callable[[str], bool],
    reader: _Reader,
    skip: Callable[[str, SkipReason], None],
    py_paths: frozenset[str],
) -> tuple[list[ManifestFile], frozenset[str]]:
    """Kept manifests in path-byte order, plus console-script paths from well-formed TOML."""
    manifests: list[ManifestFile] = []
    points: set[str] = set()
    for path in by_path:
        if not is_manifest_name(path) or not _in_scope(path, scopes) or not wanted(path):
            continue
        if not usable(path):
            continue
        got = reader.read(by_path[path], manifest_kind(path))
        if not isinstance(got, tuple):
            skip(path, got)
            continue
        data, text = got
        if path.rsplit("/", 1)[-1] == "pyproject.toml":
            refs = scripts_from_toml(text)
            if refs is False:
                skip(path, REASON_MANIFEST_PARSE)
                continue
            points.update(entry_points_from_scripts(refs, py_paths, path))
        manifests.append(ManifestFile(path, data))
    return manifests, frozenset(points)
