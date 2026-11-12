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

Every problem with a file is a normal outcome: :class:`FileSkipped` with one
of the I-9 ``skipped_files`` reasons. Nothing here runs git.
"""

from __future__ import annotations

import codecs
import errno
import io
import os
import stat
import tokenize
from typing import Final, Literal

from conventiondrift.errors import FileSkipped
from conventiondrift.model import SkipReason

__all__ = [
    "CONFIG_MAX_BYTES",
    "FILE_MAX_BYTES",
    "REASON_BINARY",
    "REASON_NOT_DECODABLE",
    "REASON_OUTSIDE",
    "REASON_SIZE",
    "REASON_SPECIAL",
    "REASON_SYMLINK",
    "REASON_UNREADABLE",
    "REASON_UNSUPPORTED",
    "EntryKind",
    "FileKind",
    "PathOrigin",
    "check_size",
    "decode_text",
    "entry_kind",
    "read_worktree_file",
    "size_limit",
    "validate_relpath",
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
# Backslash or drive-form names found in the repo tree, e.g. ``a\\b.py`` (D-PM-28).
REASON_UNSUPPORTED: Final = "unsupported path"
# Permission denied, I/O error, a file that vanished after listing, any other OS error (I-13).
REASON_UNREADABLE: Final = "unreadable"

# Windows reserved device names (D-PM-28 #5, SR-012 F5): a segment whose part before
# the first dot, without trailing spaces, is one of these, in any case: "nul.txt", "Com1.py".
_DEVICE_NAMES: Final = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)
# BOMs that mean "this is not UTF-8 text" (UTF-32 first: its LE BOM starts with UTF-16's).
_FOREIGN_BOMS: Final = (
    codecs.BOM_UTF32_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,
)
_READ_CHUNK: Final = 65_536


def _windows_only_form(segment: str) -> bool:
    """True for a segment Windows cannot hold or reads differently (D-PM-28 #5).

    A backslash, a ``:`` anywhere (drive forms like ``c:x.py`` and ``:`` streams),
    a trailing dot or space, or a reserved device name with or without an extension.
    """
    return (
        "\\" in segment
        or ":" in segment
        or segment.endswith((".", " "))
        or segment.split(".", 1)[0].rstrip(" ").upper() in _DEVICE_NAMES
    )


def validate_relpath(value: str, origin: PathOrigin = "input") -> str:
    """Return ``value`` as a normalized repo-relative POSIX path, or reject it.

    Rejected with ``FileSkipped("outside repository")`` (R2.1, AC-N3.8):
    absolute paths, any ``..`` segment, a NUL character, and values that
    normalize to nothing. ``.`` and empty segments are dropped, so ``./a//b/``
    becomes ``a/b``.

    Windows-only forms in **any** segment (D-PM-28 #5): a backslash, a ``:``
    (``c:x.py``, ``src/c:x.py``, ``a.py:stream``), a trailing dot or space, or a
    device name such as ``CON``, ``nul.txt`` or ``Com1.py``. They are "outside
    repository" for a value the user typed (``origin="input"``: ``paths``,
    ``config``, ``exclude``, ignore entries) and "unsupported path" for a name
    found in the repo tree (``origin="tree"``). Traversal and absolute forms
    win over these. Glob characters are left alone, so the same check serves
    ``exclude`` entries. Plain string tests only: no regex, linear in ``value``.
    """
    if not value or "\x00" in value or value.startswith("/"):
        raise FileSkipped(REASON_OUTSIDE)
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise FileSkipped(REASON_OUTSIDE)
    if any(_windows_only_form(p) for p in parts):
        raise FileSkipped(REASON_UNSUPPORTED if origin == "tree" else REASON_OUTSIDE)
    return "/".join(parts)


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
    if code == errno.ENAMETOOLONG:
        return REASON_UNSUPPORTED if origin == "tree" else REASON_OUTSIDE
    return REASON_UNREADABLE  # EACCES, EPERM, EIO, ENOENT (vanished) and every other errno


def _open_subdir(name: str, dir_fd: int) -> int:
    try:
        return os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno != errno.ENOTDIR:
            raise
    # Linux returns ENOTDIR, not ELOOP, for O_NOFOLLOW | O_DIRECTORY on a symlink, so a
    # folder swapped for a symlink after the lstat is told apart from one swapped for a file.
    _reject_link_or_other(os.lstat(name, dir_fd=dir_fd), final=False)
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
    value, and every other errno (EACCES, EPERM, EIO, ENOENT, ...) is
    "unreadable". The ``FileSkipped`` carries only the fixed reason: no OS
    message, errno text or host path, and no ``__cause__``/``__context__``.
    Exceptions that are not ``OSError`` are bugs and propagate.
    """
    parts = validate_relpath(relpath, origin=origin).split("/")
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
    path = root_real
    for name in parts:
        path = os.path.join(path, name)
        if os.path.islink(path):
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
