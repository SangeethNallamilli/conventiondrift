"""C4 ``discover/safefs.py``: path and file-read primitives (T-009, DESIGN §12 A-1).

These are the only safe way C4 (and C5, for the config file and its path
entries) turns an untrusted repo-relative path into bytes or text:

* :func:`validate_relpath` - repo-root containment on the string (R2.1, AC-N3.8).
* :func:`read_worktree_file` - no symlinks on any component, ``O_NOFOLLOW``,
  ``fstat`` regular-file and size check on the same handle before reading,
  ``realpath`` containment (R2.2, R2.3, AC-N3.7, AC-N3.9, DESIGN §12 A-3 #1).
* :func:`check_size` - the same size rule for bytes whose length is known
  before they are read (git blobs).
* :func:`decode_text` - binary detection and decoding: UTF-8 everywhere,
  PEP 263 for ``.py`` (AC-E.15, AC-E.16).
* :func:`entry_kind` - classify an ``lstat`` result so walks skip FIFOs,
  sockets and devices without opening them (DESIGN §12 A-3 #2).
* :func:`is_hard_excluded` - the I-5 hard-exclusion name check for ``.git`` and
  ``node_modules`` (SC-2.43, SR N4), applied to repo-relative components only;
  :func:`read_unless_hard_excluded` applies it before a named read (T-010b).
* :func:`walk_worktree` - the scan-mode working-tree walk: no symlinks followed,
  hard-excluded names never listed or entered, walk caps (DESIGN §12 A-3 #1-#3).

Every problem with a file is a normal outcome: :class:`FileSkipped` with one
of the I-9 ``skipped_files`` reasons. Nothing here runs git.
"""

from __future__ import annotations

import codecs
import errno
import io
import os
import re
import stat
import tokenize
from dataclasses import dataclass
from typing import Final, Literal

from conventiondrift.errors import FileSkipped
from conventiondrift.model import SkippedFile, SkipReason

__all__ = [
    "CONFIG_MAX_BYTES",
    "FILE_MAX_BYTES",
    "HARD_EXCLUDE_IGNORABLE",
    "REASON_BINARY",
    "REASON_NOT_DECODABLE",
    "REASON_OUTSIDE",
    "REASON_SIZE",
    "REASON_SPECIAL",
    "REASON_SYMLINK",
    "REASON_UNREADABLE",
    "REASON_UNSUPPORTED",
    "REASON_WALK_LIMIT",
    "REGEXES",
    "WALK_MAX_DEPTH",
    "WALK_MAX_ENTRIES",
    "EntryKind",
    "FileKind",
    "PathOrigin",
    "WalkResult",
    "check_size",
    "decode_text",
    "entry_kind",
    "has_hard_excluded_component",
    "is_hard_excluded",
    "read_unless_hard_excluded",
    "read_worktree_file",
    "size_limit",
    "validate_relpath",
    "walk_worktree",
]

FileKind = Literal["instruction", "python", "manifest", "lockfile", "config"]
EntryKind = Literal["file", "dir", "symlink", "other"]
# Where a path string came from (D-PM-28): a value the user typed, or a name in the repo tree.
PathOrigin = Literal["input", "tree"]

# SECURITY-RULES R2.3, AC-N3.7.
FILE_MAX_BYTES: Final = 1_048_576  # instruction, .py, manifest, lockfile (1 MiB)
CONFIG_MAX_BYTES: Final = 65_536  # .conventiondrift.yml (64 KiB)

# INTERFACES I-9 `skipped_files[].reason` values used by these primitives.
REASON_SIZE: Final = "size limit"
REASON_SYMLINK: Final = "symlink"
REASON_OUTSIDE: Final = "outside repository"
REASON_BINARY: Final = "binary"
REASON_NOT_DECODABLE: Final = "not decodable"
# FIFOs, sockets, devices, and a folder where a file was expected (I-13).
REASON_SPECIAL: Final = "special file"
# Tree names Windows cannot hold or reads differently (D-PM-28 as narrowed, I-13): a
# backslash, a trailing dot or space, a device name, a lone surrogate, a name too long
# for the OS, and a ``:`` only when ``os.name == "nt"``.
REASON_UNSUPPORTED: Final = "unsupported path"
# Permission denied, I/O error, a file that vanished after listing, any other OS error (I-13).
REASON_UNREADABLE: Final = "unreadable"
# A folder the walk did not list because of a DESIGN §12 A-3 #3 cap (I-13).
REASON_WALK_LIMIT: Final = "walk limit"

# DESIGN §12 A-3 #3: the scan-mode walk lists at most this many entries in total and
# enters folders at most this many components deep. Read per call, so tests can patch them.
WALK_MAX_ENTRIES = 500_000
WALK_MAX_DEPTH = 64

# Windows reserved device names (D-PM-28 #5, SR-012 F5, SR N2 / I-13): the Python 3.13
# ``ntpath`` set, superscript digits and console names included. A segment whose part
# before the first dot, without trailing spaces, is one of these, in any case, is a
# device name on every OS: "nul.txt", "Com1.py", "conin$.log", "lpt\u00b2".
_DEVICE_NAMES: Final = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{c}" for c in "123456789\u00b9\u00b2\u00b3"]
    + [f"LPT{c}" for c in "123456789\u00b9\u00b2\u00b3"]
)
# INTERFACES I-5 "Hard-exclusion name check" step 1: code points dropped before the
# name is compared (a superset of git's HFS+-ignorable set). Design-controlled.
HARD_EXCLUDE_IGNORABLE: Final = frozenset(
    map(
        chr,
        [
            0x00AD,
            0x034F,
            *range(0x180B, 0x180F),
            *range(0x200B, 0x2010),
            *range(0x202A, 0x202F),
            *range(0x2060, 0x2070),
            *range(0xFE00, 0xFE10),
            0xFEFF,
        ],
    )
)
_DROP_IGNORABLE: Final = str.maketrans(dict.fromkeys(HARD_EXCLUDE_IGNORABLE))
_HARD_EXCLUDED_NAMES: Final = frozenset([".git", "node_modules"])
# I-5 step 4: NTFS 8.3 short names, always applied with fullmatch (never ``$``, which
# also matches before a trailing newline). Both patterns are linear: no nested repeats.
_GIT_SHORT_NAME: Final = re.compile(r"(?:git|gi[0-9a-f]{4})~[1-9][0-9]*")
_NODE_MODULES_SHORT_NAME: Final = re.compile(r"(?:node_m|no[0-9a-f]{4})~[1-9][0-9]*")
# SECURITY-RULES R2.5: every regex this module applies to repo text is listed here
# and gets a ReDoS unit test. A test fails if a compiled pattern appears in the
# module but not here.
REGEXES: Final[tuple[re.Pattern[str], ...]] = (_GIT_SHORT_NAME, _NODE_MODULES_SHORT_NAME)
# BOMs that mean "this is not UTF-8 text" (UTF-32 first: its LE BOM starts with UTF-16's).
_FOREIGN_BOMS: Final = (
    codecs.BOM_UTF32_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,
)
_READ_CHUNK: Final = 65_536
# Windows: the longest name one path segment may have, in UTF-16 code units (NTFS, ReFS,
# exFAT and FAT all use 255). Longer names never reach the OS there (see _name_too_long).
_NT_NAME_MAX: Final = 255
# Windows error ERROR_FILENAME_EXCED_RANGE: the whole path is too long, Windows'
# counterpart of ENAMETOOLONG. Python maps it to errno ENOENT, so it is checked by winerror.
_WINERROR_FILENAME_EXCED_RANGE: Final = 206


def _has_lone_surrogate(segment: str) -> bool:
    """True if ``segment`` holds a code point in U+D800..U+DFFF (SR N1, I-13).

    Python strings never pair surrogates, so this covers a stray ``\\ud800`` and the
    ``\\udc80``-``\\udcff`` that ``surrogateescape`` (``os.fsdecode``) makes from
    non-UTF-8 bytes. A plain scan, not ``encode``, so nothing is encoded first.
    """
    return any("\ud800" <= ch <= "\udfff" for ch in segment)


def _windows_only_form(segment: str, *, colon: bool) -> bool:
    """True for a segment Windows cannot hold or reads differently (D-PM-28 #5).

    A backslash, a trailing dot or space, or a reserved device name with or
    without an extension; and, when ``colon`` is set, a ``:`` anywhere (drive
    forms like ``c:x.py`` and NTFS ``:`` streams).
    """
    return (
        "\\" in segment
        or (colon and ":" in segment)
        or segment.endswith((".", " "))
        or segment.split(".", 1)[0].rstrip(" ").upper() in _DEVICE_NAMES
    )


def validate_relpath(value: str, *, origin: PathOrigin) -> str:
    """Return ``value`` as a normalized repo-relative POSIX path, or reject it.

    Rejected with ``FileSkipped("outside repository")`` (R2.1, AC-N3.8):
    absolute paths, any ``..`` segment, a NUL character, and values that
    normalize to nothing. ``.`` and empty segments are dropped, so ``./a//b/``
    becomes ``a/b``.

    Windows-only forms in **any** segment (D-PM-28 #5 as narrowed, I-13):

    * A value the user typed (``origin="input"``: ``paths``, ``config``,
      ``exclude``, ignore entries) is "outside repository" on every OS if a
      segment has a backslash, a ``:`` (``c:x.py``, ``src/c:x.py``,
      ``a.py:stream``), a trailing dot or space, or a device name such as
      ``CON``, ``nul.txt`` or ``Com1.py``.
    * A name found in the repo tree (``origin="tree"``) is "unsupported path"
      on every OS for a backslash, a trailing dot or space, or a device name.
      A ``:`` (drive form included) is "unsupported path" only when
      ``os.name == "nt"``, where it would open an NTFS stream; on POSIX such
      names are analyzed normally (AC-N3.13 needs a ``::warning::`` file name).
    * Any other ``origin`` (a bug: mypy rejects it) gets the strict typed-value
      handling above, never the permissive tree one (CR2 S4).

    A lone surrogate (U+D800..U+DFFF) in any segment, including the ``\\udc80``
    style names ``surrogateescape`` decoding gives for non-UTF-8 bytes, gets the
    same split (SR N1, I-13), so it never reaches ``os.fsencode`` and no
    ``UnicodeEncodeError`` escapes.

    Traversal and absolute forms win over these. Glob characters are left
    alone, so the same check serves ``exclude`` entries. Plain string tests
    only: no regex, linear in ``value``.
    """
    if not value or "\x00" in value or value.startswith("/"):
        raise FileSkipped(REASON_OUTSIDE)
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise FileSkipped(REASON_OUTSIDE)
    # Anything but "tree" takes the strict typed-value branch (CR2 S4); os.name is read
    # per call, so tests can patch it.
    colon = origin != "tree" or os.name == "nt"
    if any(_has_lone_surrogate(p) or _windows_only_form(p, colon=colon) for p in parts):
        raise FileSkipped(REASON_UNSUPPORTED if origin == "tree" else REASON_OUTSIDE)
    return "/".join(parts)


def _name_too_long(parts: list[str]) -> bool:
    """True on Windows if a segment is longer than the OS allows (I-13 ENAMETOOLONG).

    POSIX reports such a name as ENAMETOOLONG. Windows reports it with errors that
    Python maps to EINVAL or ENOENT, which also mean other things, so the length is
    checked on the string before any file system call. ``os.name`` is read per
    call, so tests can patch it.
    """
    return os.name == "nt" and any(_utf16_units(p) > _NT_NAME_MAX for p in parts)


def _utf16_units(segment: str) -> int:
    """Length of ``segment`` in UTF-16 code units: code points above U+FFFF count twice.

    Counted, not encoded, so no codec module is loaded (that would be a file open).
    """
    return len(segment) + sum(ch > "\uffff" for ch in segment)


def size_limit(kind: FileKind, max_file_bytes: int | None = None) -> int:
    """Byte limit for ``kind``. ``max_file_bytes`` (I-6 ``limits``) can only lower it."""
    if kind == "config":
        return CONFIG_MAX_BYTES
    if max_file_bytes is not None and max_file_bytes < FILE_MAX_BYTES:
        return max_file_bytes
    return FILE_MAX_BYTES


def check_size(size: int, kind: FileKind, max_file_bytes: int | None = None) -> None:
    """Raise ``FileSkipped("size limit")`` if ``size`` is over the limit for ``kind``."""
    if size > size_limit(kind, max_file_bytes):
        raise FileSkipped(REASON_SIZE)


def entry_kind(mode: int) -> EntryKind:
    """Classify an ``lstat`` ``st_mode``. Never needs the file to be opened."""
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return "other"  # FIFO, socket, character or block device, door, ...


def _is_reparse_point(st: os.stat_result) -> bool:
    # Windows junctions and other reparse points act like symlinks.
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _reject_link_or_other(st: os.stat_result, *, final: bool) -> None:
    kind = entry_kind(st.st_mode)
    if kind == "symlink" or _is_reparse_point(st):
        raise FileSkipped(REASON_SYMLINK)
    if final and kind != "file":
        raise FileSkipped(REASON_SPECIAL)
    if not final and kind != "dir":
        raise FileSkipped(REASON_SPECIAL)  # a file, FIFO, ... used as a parent folder


def _contained(root_real: str, full: str) -> bool:
    """True if ``realpath(full)`` is ``root_real`` or below it, by whole path segments.

    ``os.path.commonpath`` compares segments, so ``/x/repo2`` is not under
    ``/x/repo``, and a root of ``/`` (or ``C:\\``) needs no special case.
    """
    root = os.path.normcase(root_real)
    real = os.path.normcase(os.path.realpath(full))
    try:
        return os.path.commonpath([root, real]) == root
    except ValueError:  # different drives on Windows, or a relative realpath
        return False


_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_O_BINARY: Final = getattr(os, "O_BINARY", 0)
_O_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)
_O_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_FILE_FLAGS: Final = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY | _O_NONBLOCK
# openat-style walk: every component opened relative to its parent's handle.
_USE_DIR_FD: bool = (
    os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and _O_NOFOLLOW != 0
)


def _os_reason(exc: OSError, origin: PathOrigin) -> SkipReason:
    """The fixed skip reason for an ``OSError`` (INTERFACES "OS errors in safefs")."""
    code = exc.errno
    # ELOOP (Linux, macOS), EMLINK (FreeBSD) and EFTYPE (NetBSD, some macOS calls)
    # are what O_NOFOLLOW returns for a symlink.
    if code is not None and code in (
        errno.ELOOP,
        getattr(errno, "EMLINK", None),
        getattr(errno, "EFTYPE", None),
    ):
        return REASON_SYMLINK
    if code == errno.ENOTDIR:
        return REASON_SPECIAL
    if (
        code == errno.ENAMETOOLONG
        or getattr(exc, "winerror", None) == _WINERROR_FILENAME_EXCED_RANGE
    ):
        return REASON_UNSUPPORTED if origin == "tree" else REASON_OUTSIDE
    return REASON_UNREADABLE  # EACCES, EPERM, EIO, ENOENT (vanished) and every other errno


def _open_subdir(name: str, dir_fd: int) -> int:
    try:
        return os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno != errno.ENOTDIR:
            raise
    # Linux returns ENOTDIR, not ELOOP, for O_NOFOLLOW | O_DIRECTORY on a symlink, so the
    # name is lstat-ed again (INTERFACES I-14): a symlink is "symlink", anything else
    # "special file", and an lstat that fails is "unreadable" whatever its errno.
    try:
        st = os.lstat(name, dir_fd=dir_fd)
    except OSError:
        st = None
    if st is None:
        raise FileSkipped(REASON_UNREADABLE)  # outside the handler: no __context__
    _reject_link_or_other(st, final=False)
    raise FileSkipped(REASON_SPECIAL)


def _open_dir_fd(root_real: str, parts: list[str]) -> int:
    """Open the file's final component through no-follow handles; return its fd."""
    dir_fd = os.open(root_real, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    try:
        for name in parts[:-1]:
            _reject_link_or_other(os.lstat(name, dir_fd=dir_fd), final=False)
            child = _open_subdir(name, dir_fd)
            os.close(dir_fd)
            dir_fd = child
        _reject_link_or_other(os.lstat(parts[-1], dir_fd=dir_fd), final=True)
        # ELOOP here means the file was swapped for a symlink after the lstat.
        return os.open(parts[-1], _FILE_FLAGS, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def _lstat_prefixes(root_real: str, parts: list[str]) -> list[tuple[int, int]]:
    """lstat every prefix of ``parts``; refuse links and non-folders; return (dev, ino)s."""
    ids: list[tuple[int, int]] = []
    path = root_real
    for i, name in enumerate(parts):
        path = os.path.join(path, name)
        st = os.lstat(path)
        _reject_link_or_other(st, final=i == len(parts) - 1)
        ids.append((st.st_dev, st.st_ino))
    return ids


def _open_by_path(root_real: str, parts: list[str]) -> int:
    """Fallback where ``dir_fd`` is unsupported (Windows).

    lstat each prefix, open, check the handle is the file the final lstat saw,
    then lstat the whole relative path again (SR-012 F4): a folder swapped for
    a link or junction, or for another folder, while the file was being opened
    is refused as "symlink", the same as a swapped final component.
    """
    before = _lstat_prefixes(root_real, parts)
    fd = os.open(os.path.join(root_real, *parts), _FILE_FLAGS)
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) != before[-1] or _lstat_prefixes(root_real, parts) != before:
            raise FileSkipped(REASON_SYMLINK)
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_worktree_file(
    root: str | os.PathLike[str],
    relpath: str,
    kind: FileKind,
    *,
    max_file_bytes: int | None = None,
    origin: PathOrigin,
) -> bytes:
    """Read one working-tree file under ``root`` safely, or raise ``FileSkipped``.

    Order (DESIGN §12 A-3 #1, R2.1-R2.3): validate the path string; refuse a
    symlink (or junction) at any component, judged by ``lstat`` and enforced
    with ``O_NOFOLLOW``; refuse non-regular files without opening them;
    require the ``realpath`` to stay under the repo root; open, then ``fstat``
    the same handle for a regular file and the size limit; only then read, and
    never more than limit + 1 bytes (a file that grew is still "size limit").
    ``origin`` is required so every caller states whether ``relpath`` was typed
    by the user or found in the repo tree (D-PM-28; see :func:`validate_relpath`).

    No ``OSError`` ever escapes (INTERFACES "OS errors in discover/safefs.py"):
    ELOOP/EMLINK/EFTYPE are "symlink", ENOTDIR is "special file", ENAMETOOLONG
    is "unsupported path" for a tree name and "outside repository" for a typed
    value (on Windows also ERROR_FILENAME_EXCED_RANGE, and a segment over 255
    UTF-16 code units, checked before any file system call), and every other
    errno (EACCES, EPERM, EIO, ENOENT, ...) is "unreadable". The ``FileSkipped``
    carries only the fixed reason: no OS message, errno text or host path,
    and no ``__cause__``/``__context__``. Exceptions that are not ``OSError`` are
    bugs and propagate.
    """
    parts = validate_relpath(relpath, origin=origin).split("/")
    if _name_too_long(parts):
        raise FileSkipped(REASON_UNSUPPORTED if origin == "tree" else REASON_OUTSIDE)
    limit = size_limit(kind, max_file_bytes)
    try:
        return _read(root, parts, limit)
    except OSError as exc:
        reason = _os_reason(exc, origin)
    # Raised outside the handler, so the OSError is not even kept as __context__.
    raise FileSkipped(reason) from None


def _read(root: str | os.PathLike[str], parts: list[str], limit: int) -> bytes:
    root_real = os.path.realpath(root)
    if not _contained(root_real, os.path.join(root_real, *parts)):
        # Only reached for a symlinked parent that the component walk below
        # would also refuse; kept as the design's defence in depth.
        raise FileSkipped(REASON_SYMLINK if _has_link(root_real, parts) else REASON_OUTSIDE)
    fd = (_open_dir_fd if _USE_DIR_FD else _open_by_path)(root_real, parts)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise FileSkipped(REASON_SPECIAL)
        if st.st_size > limit:
            raise FileSkipped(REASON_SIZE)
        buf = io.BytesIO()
        while buf.tell() <= limit:
            chunk = os.read(fd, min(_READ_CHUNK, limit + 1 - buf.tell()))
            if not chunk:
                break
            buf.write(chunk)
        if buf.tell() > limit:
            raise FileSkipped(REASON_SIZE)
        return buf.getvalue()
    finally:
        os.close(fd)


def _has_link(root_real: str, parts: list[str]) -> bool:
    """True if a component of ``parts`` is a symlink or a junction (any reparse point).

    Reached only when ``realpath`` leaves the root: a link or junction pointing
    outside, which is "symlink" like every other link (AC-N3.9). ``os.path.islink``
    is False for a Windows junction, so this lstat-s each component instead (CR2 S3).
    Tests reach it with a real symlink on POSIX, a real junction on Windows, and a
    mocked ``realpath`` (CR2 N4).
    """
    path = root_real
    for name in parts:
        path = os.path.join(path, name)
        try:
            st = os.lstat(path)
        except OSError:
            return False  # nothing here, so nothing below it can be a link
        if stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
            return True
    return False


def decode_text(data: bytes, kind: FileKind) -> str:
    """Decode file bytes, or raise ``FileSkipped("binary" | "not decodable")``.

    A UTF-16/UTF-32 BOM means "not decodable" (checked first, because such
    text is full of NULs). Otherwise any NUL byte means "binary". ``.py``
    files follow PEP 263 (UTF-8 default, a UTF-8 BOM, or a coding cookie on
    line 1 or 2); every other kind is strict UTF-8 with an optional UTF-8 BOM.
    Any cookie that names a codec which is unknown, not an ASCII superset or
    that fails to decode (``undefined``, ``hex``, ``utf-16``, ...) is "not decodable".
    """
    if data.startswith(_FOREIGN_BOMS):
        raise FileSkipped(REASON_NOT_DECODABLE)
    if b"\x00" in data:
        raise FileSkipped(REASON_BINARY)
    try:
        if kind == "python":
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            if b"#\n".decode(encoding) != "#\n":  # PEP 263: cookie must name an ASCII superset
                raise LookupError(encoding)
        else:
            encoding = "utf-8-sig"
        return data.decode(encoding)
    except (SyntaxError, LookupError, ValueError):
        # ValueError covers UnicodeDecodeError and the bare UnicodeError that a
        # hostile cookie such as ``# coding: undefined`` raises (R2.4, SR-012 F1).
        pass
    raise FileSkipped(REASON_NOT_DECODABLE) from None


def is_hard_excluded(component: str) -> bool:
    """True if one repo-relative path component is ``.git`` or ``node_modules`` (I-5).

    The INTERFACES I-5 steps, in order: drop :data:`HARD_EXCLUDE_IGNORABLE`
    code points, strip trailing dots and spaces, ``str.casefold()``, then compare
    with ``.git`` and ``node_modules`` or fully match their 8.3 short names
    (``GIT~1``, ``GI1A2B~1``, ``NODE_M~1``). Name only, whatever the entry's type,
    so a ``.git`` gitlink file or symlink is excluded too. Never pass the
    checkout's own absolute path, or a parent of it, to this check.
    """
    name = component.translate(_DROP_IGNORABLE).rstrip(". ").casefold()
    return (
        name in _HARD_EXCLUDED_NAMES
        or _GIT_SHORT_NAME.fullmatch(name) is not None
        or _NODE_MODULES_SHORT_NAME.fullmatch(name) is not None
    )


def has_hard_excluded_component(relpath: str) -> bool:
    """True if any ``/``-separated component of a repo-relative path is hard-excluded."""
    return any(is_hard_excluded(part) for part in relpath.split("/"))


def read_unless_hard_excluded(
    root: str | os.PathLike[str],
    relpath: str,
    kind: FileKind,
    *,
    max_file_bytes: int | None = None,
    origin: PathOrigin,
) -> bytes | None:
    """:func:`read_worktree_file`, or ``None`` without touching the filesystem if any
    component of the validated ``relpath`` is hard-excluded (I-5, SR N4).

    For named reads such as a config ``paths:`` entry. The path is validated first,
    so traversal and Windows-only forms keep their I-13 reasons; only the
    repo-relative path is checked, never ``root``.
    """
    rel = validate_relpath(relpath, origin=origin)
    # A hard-excluded `paths:` entry is dropped, not a SkippedFile. I-13 scan-walk
    # ruling 1 adds a summary note for it; that note comes in the T-010b follow-up.
    if has_hard_excluded_component(rel):
        return None
    return read_worktree_file(root, rel, kind, max_file_bytes=max_file_bytes, origin=origin)


@dataclass(frozen=True, slots=True)
class WalkResult:
    """What :func:`walk_worktree` found. Paths are repo-relative POSIX strings."""

    files: tuple[str, ...]  # regular files, sorted by path bytes (DESIGN §12 A-5)
    skipped: tuple[SkippedFile, ...]  # symlinks, special files, bad names, walk limits
    entries: int  # names listed, for the I-12 ``scan_walk_entries`` counter


def walk_worktree(root: str | os.PathLike[str]) -> WalkResult:
    """List every regular file under ``root`` for scan mode (DESIGN §12 A-3).

    * Hard-excluded names (I-5) are dropped by name before they are ``lstat``-ed,
      listed or entered, and are not reported. ``root`` itself is never checked.
    * Symlinks (and Windows junctions) are never followed: "symlink". FIFOs,
      sockets and devices are judged by ``lstat`` and never opened: "special
      file". Tree names Windows can't hold: "unsupported path" (I-13).
    * Folders are opened with ``O_NOFOLLOW`` relative to their parent's handle;
      the Windows fallback re-checks every folder of the path after listing.
    * A folder deeper than :data:`WALK_MAX_DEPTH`, or one whose listing would take
      the total past :data:`WALK_MAX_ENTRIES`, is "walk limit", and so is every
      folder reached after the total is spent. Folders are walked in sorted name
      order, so the result is the same for the same tree.
    * No ``OSError`` escapes: it becomes a fixed reason, as for reads. A root that
      can't be listed is reported with the path ``"."``.

    Effective excludes and ``.gitignore`` are not applied here; callers filter.
    """
    walk = _Walk(os.path.realpath(root))
    walk.folder([], None)
    return WalkResult(
        tuple(sorted(walk.files, key=os.fsencode)),
        tuple(sorted(walk.skipped, key=lambda s: os.fsencode(s.path))),
        walk.entries,
    )


def _skip_reason(exc: FileSkipped | OSError) -> SkipReason:
    return exc.reason if isinstance(exc, FileSkipped) else _os_reason(exc, "tree")


class _Walk:
    def __init__(self, root_real: str) -> None:
        self.root = root_real
        self.files: list[str] = []
        self.skipped: list[SkippedFile] = []
        self.entries = 0
        self.spent = False

    def skip(self, parts: list[str], reason: SkipReason) -> None:
        # The root is reported as ".". I-13 scan-walk ruling 2 makes an unlistable root
        # a ComponentError("discover") in the T-010b follow-up; a root over the cap stays ".".
        self.skipped.append(SkippedFile("/".join(parts) or ".", reason))

    def folder(self, parts: list[str], parent_fd: int | None) -> None:
        if self.spent:
            self.skip(parts, REASON_WALK_LIMIT)
            return
        try:
            handle = self.open(parts, parent_fd)
        except (FileSkipped, OSError) as exc:
            self.skip(parts, _skip_reason(exc))
            return
        try:
            self.visit(handle, parts)
        finally:
            if isinstance(handle, int):
                os.close(handle)

    def open(self, parts: list[str], parent_fd: int | None) -> int | str:
        """A no-follow handle on the folder, or its path on the Windows fallback."""
        if not _USE_DIR_FD:
            return os.path.join(self.root, *parts)
        if parent_fd is None:
            return os.open(self.root, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
        return _open_subdir(parts[-1], parent_fd)

    def visit(self, handle: int | str, parts: list[str]) -> None:
        try:
            names = self.listing(handle, parts)
        except (FileSkipped, OSError) as exc:
            self.skip(parts, _skip_reason(exc))
            return
        if names is None:
            self.spent = True
            self.skip(parts, REASON_WALK_LIMIT)
            return
        for name in sorted(names, key=os.fsencode):
            self.entry(parts, name, handle)

    def listing(self, handle: int | str, parts: list[str]) -> list[str] | None:
        """Names in the folder, or ``None`` if they would take the walk past its cap."""
        budget = WALK_MAX_ENTRIES - self.entries
        before = None if isinstance(handle, int) else self.folder_ids(parts)
        names: list[str] = []
        with os.scandir(handle) as it:
            for entry in it:
                if len(names) == budget:
                    return None
                names.append(entry.name)
        if before is not None and self.folder_ids(parts) != before:
            raise FileSkipped(REASON_SYMLINK)  # swapped while listed (Windows fallback)
        self.entries += len(names)
        return names

    def folder_ids(self, parts: list[str]) -> list[tuple[int, int]]:
        ids: list[tuple[int, int]] = []
        path = self.root
        for name in parts:
            path = os.path.join(path, name)
            st = os.lstat(path)
            _reject_link_or_other(st, final=False)
            ids.append((st.st_dev, st.st_ino))
        return ids

    def entry(self, parts: list[str], name: str, handle: int | str) -> None:
        if is_hard_excluded(name):
            return  # I-5: never lstat-ed, listed, entered or reported
        child = [*parts, name]
        # A name that is not valid UTF-8 (a lone surrogate under surrogateescape) is listed
        # as is here; I-13 scan-walk ruling 3 makes it "unsupported path" in the follow-up.
        try:
            validate_relpath(name, origin="tree")
            if isinstance(handle, int):
                st = os.lstat(name, dir_fd=handle)
            else:
                st = os.lstat(os.path.join(handle, name))
        except (FileSkipped, OSError) as exc:
            self.skip(child, _skip_reason(exc))
            return
        kind = entry_kind(st.st_mode)
        if kind == "symlink" or _is_reparse_point(st):
            self.skip(child, REASON_SYMLINK)
        elif kind == "file":
            self.files.append("/".join(child))
        elif kind == "other":
            self.skip(child, REASON_SPECIAL)
        elif len(child) > WALK_MAX_DEPTH:
            self.skip(child, REASON_WALK_LIMIT)
        else:
            self.folder(child, handle if isinstance(handle, int) else None)
