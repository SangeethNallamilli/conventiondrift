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
import io
import os
import re
import stat
import tokenize
from typing import Final, Literal

from conventiondrift.errors import FileSkipped

__all__ = [
    "CONFIG_MAX_BYTES",
    "FILE_MAX_BYTES",
    "REASON_BINARY",
    "REASON_NOT_DECODABLE",
    "REASON_OUTSIDE",
    "REASON_SIZE",
    "REASON_SPECIAL",
    "REASON_SYMLINK",
    "EntryKind",
    "FileKind",
    "check_size",
    "decode_text",
    "entry_kind",
    "read_worktree_file",
    "size_limit",
    "validate_relpath",
]

FileKind = Literal["instruction", "python", "manifest", "lockfile", "config"]
EntryKind = Literal["file", "dir", "symlink", "other"]

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

_DRIVE: Final = re.compile(r"[A-Za-z]:")  # anchored with .match; linear, no repetition
# BOMs that mean "this is not UTF-8 text" (UTF-32 first: its LE BOM starts with UTF-16's).
_FOREIGN_BOMS: Final = (
    codecs.BOM_UTF32_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,
)
_READ_CHUNK: Final = 65_536


def validate_relpath(value: str) -> str:
    """Return ``value`` as a normalized repo-relative POSIX path, or reject it.

    Rejected with ``FileSkipped("outside repository")`` (R2.1, AC-N3.8):
    absolute paths, any ``..`` segment, a Windows drive prefix (``C:``), any
    backslash, a NUL character, and values that normalize to nothing. ``.``
    and empty segments are dropped, so ``./a//b/`` becomes ``a/b``. Glob
    characters are left alone, so the same check serves ``exclude`` entries.
    """
    if not value or "\x00" in value or "\\" in value:
        raise FileSkipped(REASON_OUTSIDE)
    if value.startswith("/") or _DRIVE.match(value):
        raise FileSkipped(REASON_OUTSIDE)
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise FileSkipped(REASON_OUTSIDE)
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
        raise NotADirectoryError(f"not a directory: {kind}")


def _contained(root_real: str, full: str) -> bool:
    real = os.path.realpath(full)
    return real == root_real or real.startswith(root_real.rstrip(os.sep) + os.sep)


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


def _open_dir_fd(root_real: str, parts: list[str]) -> int:
    """Open the file's final component through no-follow handles; return its fd."""
    dir_fd = os.open(root_real, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    try:
        for name in parts[:-1]:
            _reject_link_or_other(os.lstat(name, dir_fd=dir_fd), final=False)
            try:
                child = os.open(
                    name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd
                )
            except OSError as exc:  # swapped for a symlink after the lstat
                raise FileSkipped(REASON_SYMLINK) from exc
            os.close(dir_fd)
            dir_fd = child
        _reject_link_or_other(os.lstat(parts[-1], dir_fd=dir_fd), final=True)
        try:
            return os.open(parts[-1], _FILE_FLAGS, dir_fd=dir_fd)
        except OSError as exc:  # ELOOP: swapped for a symlink after the lstat
            raise FileSkipped(REASON_SYMLINK) from exc
    finally:
        os.close(dir_fd)


def _open_by_path(root_real: str, parts: list[str]) -> int:
    """Fallback where ``dir_fd`` is unsupported (Windows): lstat each prefix, then
    check the opened handle is the same file the final lstat saw."""
    path = root_real
    for i, name in enumerate(parts):
        path = os.path.join(path, name)
        last = os.lstat(path)
        _reject_link_or_other(last, final=i == len(parts) - 1)
    fd = os.open(path, _FILE_FLAGS)
    st = os.fstat(fd)
    if (st.st_dev, st.st_ino) != (last.st_dev, last.st_ino):
        os.close(fd)
        raise FileSkipped(REASON_SYMLINK)
    return fd


def read_worktree_file(
    root: str | os.PathLike[str],
    relpath: str,
    kind: FileKind,
    *,
    max_file_bytes: int | None = None,
) -> bytes:
    """Read one working-tree file under ``root`` safely, or raise ``FileSkipped``.

    Order (DESIGN §12 A-3 #1, R2.1-R2.3): validate the path string; refuse a
    symlink (or junction) at any component, judged by ``lstat`` and enforced
    with ``O_NOFOLLOW``; refuse non-regular files without opening them;
    require the ``realpath`` to stay under the repo root; open, then ``fstat``
    the same handle for a regular file and the size limit; only then read, and
    never more than limit + 1 bytes (a file that grew is still "size limit").
    Other ``OSError`` (missing file, permission) propagates to the caller.
    """
    parts = validate_relpath(relpath).split("/")
    root_real = os.path.realpath(root)
    if not _contained(root_real, os.path.join(root_real, *parts)):
        # Only reached for a symlinked parent that the component walk below
        # would also refuse; kept as the design's defence in depth.
        raise FileSkipped(REASON_SYMLINK if _has_link(root_real, parts) else REASON_OUTSIDE)
    limit = size_limit(kind, max_file_bytes)
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
    except (SyntaxError, LookupError, UnicodeDecodeError) as exc:
        raise FileSkipped(REASON_NOT_DECODABLE) from exc
