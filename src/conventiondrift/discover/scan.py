"""C4 scan-mode discovery: the working tree, ``.gitignore`` and changed/unchanged
tracked files (T-010b part 2, DESIGN §12 A-3, INTERFACES I-13 and I-14, D-TL-55).

:func:`discover_worktree` is the scan-mode counterpart of
:func:`~conventiondrift.discover.discover_tree`. It walks the working tree with
:func:`~conventiondrift.discover.safefs.walk_worktree`, which drops hard-excluded
names, never follows a symlink and keeps to the walk caps. A walk filter applies
the rest of A-3 while the walk runs:

* folders the effective excludes drop are not entered, unless a ``paths`` entry
  is below them;
* folders that are submodules at ``HEAD`` (mode ``160000``) are not entered;
* untracked paths that ``.gitignore`` ignores are left out (see
  :mod:`conventiondrift.discover.gitignore`). Files tracked at ``HEAD``, ``paths``
  entries and ``pyvenv.cfg`` files are never left out by ``.gitignore``. Once the
  ``.gitignore`` match budget is spent, nothing more is left out by it, with a note.

The kept files then go through the same rules as a commit tree (S6 patterns and
scopes, ``paths``, excludes, the generated-file header, R2.6 caps, I-13 ruling 6),
because :func:`discover_tree` runs unchanged over a reader that serves the walk.
Every file is read with ``safefs`` (``O_NOFOLLOW``, ``fstat`` on the same handle,
``realpath`` containment). Nothing here runs git: ``HEAD``'s file list is passed in,
already read through C3 (A-3 condition 6).

For each kept ``.py`` file that is tracked at ``HEAD``, the git blob id of its
working-tree bytes is computed in Python and compared with the ``HEAD`` object id
(A-3 "Tracked files"); if they differ and the file has CRLF line ends, it is hashed
again with CRLF read as LF, so a checkout with ``core.autocrlf`` is unchanged
(D-TL-69 #2). The result is the I-14 ``scan_tracked`` mapping C8 takes.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from conventiondrift.core import BasePhaseDone
from conventiondrift.defaults import DEFAULT_EXCLUDES
from conventiondrift.discover import Discovery, TreeReader, discover_tree, safefs
from conventiondrift.discover.gitignore import (
    GITIGNORE_MATCH_ALLOWANCE,
    GITIGNORE_MATCH_ALLOWANCE_PER_CHAR,
    GITIGNORE_MATCH_BUDGET,
    GITIGNORE_MAX_BYTES,
    GITIGNORE_MAX_PATTERNS,
    IgnoreRules,
)
from conventiondrift.discover.globmatch import GlobSet
from conventiondrift.discover.safefs import (
    REASON_SIZE,
    REASON_WALK_LIMIT,
    escape_unsupported_path,
    validate_relpath,
)
from conventiondrift.errors import ComponentError, FileSkipped
from conventiondrift.model import SkippedFile, SkipReason, TrackedState

if TYPE_CHECKING:
    from conventiondrift.components import TreeEntry

__all__ = [
    "ScanDiscovery",
    "discover_worktree",
    "git_blob_id",
]

_GITLINK: Final = "160000"
_REGULAR_MODES: Final = frozenset({"100644", "100755", "100664"})  # as discover_tree reads
_PYVENV_CFG: Final = "pyvenv.cfg"  # S6 content rule: never hidden by .gitignore
# Object id length -> hash: SHA-1 repositories (40 hex) and SHA-256 ones (64 hex).
_OBJECT_HASHES: Final = {40: "sha1", 64: "sha256"}
_HEX: Final = frozenset("0123456789abcdef")
_WALK_MODE: Final = "100644"  # walk files are served to discover_tree as regular files
_BAD_OBJECT_ID: Final = "HEAD listed an object id that is not a git hash"


def git_blob_id(data: bytes, object_id_length: int) -> str:
    """The git blob id of ``data``: ``sha1`` (40 hex) or ``sha256`` (64 hex) of
    ``b"blob <size>\\0" + data``, so it equals what ``git hash-object`` prints.

    ``object_id_length`` picks the hash, as ``HEAD``'s object ids do. Any other
    length raises ``ValueError``.
    """
    name = _OBJECT_HASHES.get(object_id_length)
    if name is None:
        raise ValueError(f"no git object hash has {object_id_length} hex digits")
    digest = hashlib.new(name)
    digest.update(b"blob %d\0" % len(data))
    digest.update(data)
    return digest.hexdigest()


def _unchanged(data: bytes, oid: str) -> bool:
    """True if the working-tree bytes ``data`` are the ``HEAD`` blob ``oid``: as they
    are, or with each CRLF read as LF (D-TL-69 #2), as git stores a file checked out
    with ``core.autocrlf``. git config is never read, so both are tried. As in git, a
    file with a CR that does not end a line is never converted (git takes it as binary).
    """
    if git_blob_id(data, len(oid)) == oid:
        return True
    crlf = data.count(b"\r\n")
    if not crlf or data.count(b"\r") != crlf:
        return False
    return git_blob_id(data.replace(b"\r\n", b"\n"), len(oid)) == oid


@dataclass(frozen=True, slots=True)
class ScanDiscovery:
    """What C4 found in the working tree in scan mode.

    * ``discovery``: the same result :func:`discover_tree` gives for a commit, for the
      working tree. Walk-limit folders are in ``discovery.skipped``, with their
      path-byte order kept; notes about ``.gitignore`` files, the pattern cap and the
      match budget follow the ``paths`` notes in ``discovery.notes``.
    * ``scan_tracked``: I-14. One entry per kept ``.py`` file that is tracked at
      ``HEAD``, keyed by path; untracked files are absent. Empty without ``HEAD``.
    * ``stats``: the I-12 counters C4 owns, in schema order (``scan_walk_entries``,
      ``scan_walk_skipped``, ``gitignore_patterns_loaded``,
      ``gitignore_patterns_skipped``), exact for a given tree.
    """

    discovery: Discovery
    scan_tracked: Mapping[str, TrackedState]  # read-only (MappingProxyType)
    stats: Mapping[str, int]  # read-only (MappingProxyType)

    __hash__ = None  # type: ignore[assignment]  # holds mappings: unhashable like Policy


def _parents(paths: Sequence[str] | frozenset[str]) -> frozenset[str]:
    """Every folder above each path (never ``""``); prefixes are sliced, not rejoined."""
    found: set[str] = set()
    for path in paths:
        end = path.find("/")
        while end != -1:
            found.add(path[:end])
            end = path.find("/", end + 1)
    return frozenset(found)


def _note_oversize(path: str) -> str:
    return f"`{escape_unsupported_path(path)}` is over 64 KiB, so its patterns were not used"


def _note_pattern_cap(skipped: int) -> str:
    noun = "pattern was" if skipped == 1 else "patterns were"
    return (
        f"only the first {GITIGNORE_MAX_PATTERNS:,} .gitignore patterns were used; "
        f"{skipped:,} more {noun} not"
    )


def _note_match_budget(unchecked: int) -> str:
    rest = (
        "the last path was not checked against .gitignore, so it was not left out"
        if unchecked == 1
        else f"the last {unchecked:,} paths were not checked against .gitignore, "
        "so none of them was left out"
    )
    budget = (
        f"{GITIGNORE_MATCH_BUDGET:,} steps plus {GITIGNORE_MATCH_ALLOWANCE:,} per path checked"
        f" and {GITIGNORE_MATCH_ALLOWANCE_PER_CHAR:,} per character of its name"
    )
    return f".gitignore matching used up its budget ({budget}); {rest}"


class _ScanFilter:
    """The :class:`~conventiondrift.discover.safefs.WalkFilter` for scan mode."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        tracked: frozenset[str],
        gitlinks: frozenset[str],
        named: frozenset[str],
        excludes: GlobSet,
    ) -> None:
        self._root = root
        self._tracked = tracked
        self._tracked_dirs = _parents(tracked)
        self._gitlinks = gitlinks
        self._named = named
        self._named_dirs = _parents(named)
        self._excludes = excludes
        self.rules = IgnoreRules()
        self.oversize: list[str] = []

    def load_info_exclude(self) -> None:
        try:
            data = safefs.read_git_info_exclude(self._root, GITIGNORE_MAX_BYTES)
        except FileSkipped as exc:
            self._refused(".git/info/exclude", exc.reason)
            return
        if data is not None:
            self.rules.add("", data)

    def _refused(self, path: str, reason: SkipReason) -> None:
        # Only an over-size file gets a note (A-3 condition 4). A symlinked, special
        # or unreadable one is not used, as git does with a symlinked .gitignore.
        if reason == REASON_SIZE:
            self.oversize.append(path)

    def enter(self, folder: str, names: Sequence[str]) -> None:
        if ".gitignore" not in names:
            return
        path = f"{folder}/.gitignore" if folder else ".gitignore"
        try:
            got = safefs.read_unless_hard_excluded(
                self._root,
                path,
                "instruction",
                max_file_bytes=GITIGNORE_MAX_BYTES,
                origin="tree",
            )
        except FileSkipped as exc:
            self._refused(path, exc.reason)
            return
        if isinstance(got, bytes):  # the walk never enters a hard-excluded folder
            self.rules.add(folder, got)

    def drop(self, path: str, is_dir: bool) -> bool:
        if path in self._named or (is_dir and path in self._named_dirs):
            return False
        if is_dir and (path in self._gitlinks or self._excludes.excludes(path, is_dir=True)):
            return True
        if path in self._tracked or (is_dir and path in self._tracked_dirs):
            return False
        if not is_dir and path.rpartition("/")[2] == _PYVENV_CFG:
            return False
        return self.rules.ignored(path, is_dir)


class _WalkTree:
    """A :class:`~conventiondrift.discover.TreeReader` over a working-tree walk.

    Each walked file is an entry whose object id is its path; its bytes are read
    with ``safefs`` only when :func:`discover_tree` asks. A walk entry that could
    not be listed as a file (symlink, special file, bad name, unreadable) is an
    entry whose read raises its reason, so ruling 6 decides whether it is reported.
    """

    def __init__(
        self, root: str | os.PathLike[str], files: Sequence[str], refused: Sequence[SkippedFile]
    ) -> None:
        self._root = root
        self._reasons = {s.path: s.reason for s in refused}
        self._entries: tuple[TreeEntry, ...] = tuple(
            (_WALK_MODE, path, 0, path) for path in (*files, *self._reasons)
        )

    def tree(self, sha: str) -> Sequence[TreeEntry]:
        return self._entries

    def blob(self, oid: str, max_bytes: int) -> bytes:
        reason = self._reasons.get(oid)
        if reason is not None:
            raise FileSkipped(reason)
        got = safefs.read_unless_hard_excluded(
            self._root, oid, "python", max_file_bytes=max_bytes, origin="tree"
        )
        if not isinstance(got, bytes):  # the walk never lists a hard-excluded name
            raise FileSkipped(safefs.REASON_UNREADABLE)
        return got


def _head_files(git: TreeReader, head_sha: str) -> dict[str, TreeEntry]:
    """``HEAD``'s entries by path, with object ids checked before any is compared."""
    entries: dict[str, TreeEntry] = {}
    for entry in git.tree(head_sha):
        oid = entry[1]
        if len(oid) not in _OBJECT_HASHES or not _HEX.issuperset(oid):
            raise ComponentError("discover", _BAD_OBJECT_ID)
        entries[entry[3]] = entry
    return entries


def _named_paths(paths: Sequence[str] | None) -> frozenset[str]:
    named: set[str] = set()
    for raw in paths or ():
        try:
            named.add(validate_relpath(raw, origin="input"))
        except FileSkipped:
            continue  # discover_tree reports it
    return frozenset(named)


def discover_worktree(
    phase: BasePhaseDone,
    root: str | os.PathLike[str],
    git: TreeReader | None = None,
    head_sha: str | None = None,
    *,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    paths: Sequence[str] | None = None,
    max_file_bytes: int | None = None,
) -> ScanDiscovery:
    """Discover instruction files, ``.py`` files and manifests in the working tree at
    ``root`` (scan mode), and mark each tracked ``.py`` file changed or unchanged.

    ``phase`` is the SR-015 token, as for :func:`discover_tree`. ``git`` and
    ``head_sha`` are given together (``HEAD`` resolved by the caller) or not at all
    (no ``HEAD`` commit: every file is untracked and ``scan_tracked`` is empty).
    ``excludes``, ``paths`` and ``max_file_bytes`` mean what they mean for
    :func:`discover_tree`.

    A root that can't be listed, or an object id in ``HEAD`` that is not 40 or 64
    lowercase hex digits, raises ``ComponentError("discover")``. A ``ComponentError``
    from ``git.tree`` (C3) propagates as it is. Every per-file problem is a
    :class:`~conventiondrift.model.SkippedFile` or is silent, as in a commit tree.
    """
    if not isinstance(phase, BasePhaseDone):
        raise TypeError("discover_worktree needs the BasePhaseDone token as its first argument")
    if git is None or head_sha is None:
        if git is not None or head_sha is not None:
            raise ValueError("discover_worktree needs both git and head_sha, or neither")
        head: dict[str, TreeEntry] = {}
    else:
        head = _head_files(git, head_sha)
    gitlinks = frozenset(p for p, e in head.items() if e[0] == _GITLINK)
    walk_filter = _ScanFilter(
        root,
        tracked=frozenset(head.keys() - gitlinks),
        gitlinks=gitlinks,
        named=_named_paths(paths),
        excludes=GlobSet(excludes),
    )
    walk_filter.load_info_exclude()
    walk = safefs.walk_worktree(root, walk_filter=walk_filter)
    limits = [s for s in walk.skipped if s.reason == REASON_WALK_LIMIT]
    refused = [s for s in walk.skipped if s.reason != REASON_WALK_LIMIT]
    found = discover_tree(
        phase,
        _WalkTree(root, walk.files, refused),
        "",
        excludes=excludes,
        paths=paths,
        max_file_bytes=max_file_bytes,
    )
    rules = walk_filter.rules
    notes = [*found.notes, *map(_note_oversize, walk_filter.oversize)]
    if rules.skipped:
        notes.append(_note_pattern_cap(rules.skipped))
    if rules.unchecked:
        notes.append(_note_match_budget(rules.unchecked))
    skipped = sorted(
        (*found.skipped, *limits), key=lambda s: s.path.encode("utf-8", "surrogateescape")
    )
    discovery = Discovery(
        found.instruction_files,
        found.py_files,
        found.manifest_files,
        found.entry_points,
        tuple(skipped),
        tuple(notes),
    )
    tracked: dict[str, TrackedState] = {}
    for py in found.py_files:
        entry = head.get(py.path)
        if entry is None or entry[0] == _GITLINK:
            continue
        mode, oid = entry[0], entry[1]
        same = mode in _REGULAR_MODES and _unchanged(py.data, oid)
        tracked[py.path] = TrackedState(oid, same)
    stats = {  # I-12 schema order
        "scan_walk_entries": walk.entries,
        "scan_walk_skipped": len(walk.skipped),
        "gitignore_patterns_loaded": rules.loaded,
        "gitignore_patterns_skipped": rules.skipped,
    }
    return ScanDiscovery(discovery, MappingProxyType(tracked), MappingProxyType(stats))
