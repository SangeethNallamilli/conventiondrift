"""T-009 unit tests: file-read primitives (R2.2-R2.4, AC-N3.7, AC-N3.9, AC-E.15,
AC-E.16, DESIGN §12 A-3 security conditions 1-2)."""

from __future__ import annotations

import codecs
import encodings.aliases
import errno
import os
import socket
import stat
import tempfile
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import conventiondrift.discover.safefs as d
from conventiondrift.discover.safefs import (
    CONFIG_MAX_BYTES,
    FILE_MAX_BYTES,
    REASON_BINARY,
    REASON_NOT_DECODABLE,
    REASON_OUTSIDE,
    REASON_SIZE,
    REASON_SPECIAL,
    REASON_SYMLINK,
    REASON_UNREADABLE,
    REASON_UNSUPPORTED,
    FileKind,
    PathOrigin,
    check_size,
    decode_text,
    entry_kind,
    read_worktree_file,
    size_limit,
)
from conventiondrift.errors import FileSkipped

POSIX = os.name == "posix"


@pytest.fixture(params=["dir_fd", "by_path"])
def strategy(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Run every read test through both open strategies (openat walk, Windows fallback)."""
    if request.param == "dir_fd" and not d._USE_DIR_FD:
        pytest.skip("platform has no dir_fd/O_NOFOLLOW")  # never on Linux CI
    monkeypatch.setattr(d, "_USE_DIR_FD", request.param == "dir_fd")
    return str(request.param)


@pytest.fixture
def outside() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as t:
        p = Path(t)
        (p / "secret.txt").write_text("SECRET-OUTSIDE")
        (p / "AGENTS.md").write_text("- Use httpx\n")
        (p / "x.py").write_text("print(1)\n")
        yield p


def _reason(fn: object, *args: object, **kw: object) -> str:
    if fn is read_worktree_file and "origin" not in kw:
        # The config file path is typed by the user; every other kind is a tree name.
        kw["origin"] = "input" if "config" in args else "tree"
    with pytest.raises(FileSkipped) as exc:
        fn(*args, **kw)  # type: ignore[operator]
    return exc.value.reason


# ---- AC-N3.7 size limits (R2.3) -------------------------------------------------------

SIZE_CASES: dict[str, tuple[str, FileKind, int]] = {
    "instruction": ("AGENTS.md", "instruction", FILE_MAX_BYTES),
    "py": ("src/big.py", "python", FILE_MAX_BYTES),
    "pyproject": ("pyproject.toml", "manifest", FILE_MAX_BYTES),
    "uv.lock": ("uv.lock", "lockfile", FILE_MAX_BYTES),
    "config": (".conventiondrift.yml", "config", CONFIG_MAX_BYTES),
}


@pytest.mark.parametrize("case", list(SIZE_CASES))
def test_read_size_limit_boundary(case: str, tmp_path: Path, strategy: str) -> None:
    rel, kind, limit = SIZE_CASES[case]
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(b"a" * limit)  # exactly the limit: read
    assert read_worktree_file(tmp_path, rel, kind, origin="tree") == b"a" * limit
    f.write_bytes(b"a" * (limit + 1))  # one byte over: skipped
    assert _reason(read_worktree_file, tmp_path, rel, kind) == REASON_SIZE
    check_size(limit, kind)
    assert _reason(check_size, limit + 1, kind) == REASON_SIZE


def test_size_checked_on_handle_before_any_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    (tmp_path / "AGENTS.md").write_bytes(b"a" * (FILE_MAX_BYTES + 1))
    calls: list[int] = []

    def spy(fd: int, n: int) -> bytes:
        calls.append(n)
        return b""

    monkeypatch.setattr(os, "read", spy)
    assert _reason(read_worktree_file, tmp_path, "AGENTS.md", "instruction") == REASON_SIZE
    assert calls == [], "an oversized file must not be read at all"


def test_file_growing_after_fstat_is_still_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    (tmp_path / "c.yml").write_bytes(b"x")
    real_read = os.read
    monkeypatch.setattr(os, "read", lambda fd, n: b"y" * n if n > 1 else real_read(fd, n))
    assert _reason(read_worktree_file, tmp_path, "c.yml", "config") == REASON_SIZE


def test_read_never_requests_more_than_limit_plus_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    (tmp_path / "c.yml").write_bytes(b"z" * CONFIG_MAX_BYTES)
    real_read = os.read
    asked: list[int] = []

    def spy(fd: int, n: int) -> bytes:
        asked.append(n)
        return real_read(fd, n)

    monkeypatch.setattr(os, "read", spy)
    assert len(read_worktree_file(tmp_path, "c.yml", "config", origin="input")) == CONFIG_MAX_BYTES
    assert sum(asked) <= CONFIG_MAX_BYTES + 1


@pytest.mark.parametrize(
    ("kind", "override", "expected"),
    [
        ("python", None, FILE_MAX_BYTES),
        ("python", 1024, 1024),
        ("instruction", FILE_MAX_BYTES, FILE_MAX_BYTES),
        ("manifest", FILE_MAX_BYTES + 1, FILE_MAX_BYTES),  # can only be lowered
        ("lockfile", 2048, 2048),
        ("config", 1024, CONFIG_MAX_BYTES),  # config limit is fixed
    ],
)
def test_size_limit_override_only_lowers(
    kind: FileKind, override: int | None, expected: int
) -> None:
    assert size_limit(kind, override) == expected


def test_lowered_limit_applies_to_reads(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "m.py").write_bytes(b"#" * 1025)
    assert (
        _reason(read_worktree_file, tmp_path, "m.py", "python", max_file_bytes=1024) == REASON_SIZE
    )
    assert (
        len(read_worktree_file(tmp_path, "m.py", "python", max_file_bytes=1025, origin="tree"))
        == 1025
    )


def test_empty_file_reads_empty(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "AGENTS.md").write_bytes(b"")
    assert read_worktree_file(tmp_path, "AGENTS.md", "instruction", origin="tree") == b""


# ---- AC-N3.9 symlinks (R2.2, A-3 #1) --------------------------------------------------


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, link)


@pytest.mark.skipif(not POSIX, reason="POSIX variant; Windows variant is TE's (D-PM-21)")
@pytest.mark.parametrize("which", ["file", "py", "dir", "config"])
def test_symlink_kinds_skipped(
    which: str, tmp_path: Path, outside: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    read_paths: list[str] = []
    real_open = os.open

    def spy(path: str, flags: int, *a: object, **kw: object) -> int:
        read_paths.append(str(path))
        return real_open(path, flags, *a, **kw)  # type: ignore[arg-type]

    if which == "file":
        _symlink(tmp_path / "AGENTS.md", outside / "secret.txt")
        rel, kind = "AGENTS.md", "instruction"
    elif which == "py":
        _symlink(tmp_path / "src/link.py", outside / "x.py")
        rel, kind = "src/link.py", "python"
    elif which == "dir":
        _symlink(tmp_path / "docs", outside)
        rel, kind = "docs/AGENTS.md", "instruction"
    else:
        (tmp_path / "real.yml").write_text("version: 1\n")
        _symlink(tmp_path / ".conventiondrift.yml", tmp_path / "real.yml")  # inside target
        rel, kind = ".conventiondrift.yml", "config"
    monkeypatch.setattr(os, "open", spy)
    assert _reason(read_worktree_file, tmp_path, rel, kind) == REASON_SYMLINK
    assert not any(str(outside) in p for p in read_paths)
    assert not any(p.endswith(("secret.txt", "x.py", "real.yml")) for p in read_paths)


@pytest.mark.skipif(not POSIX, reason="POSIX")
def test_config_symlink_to_outside(tmp_path: Path, outside: Path, strategy: str) -> None:
    _symlink(tmp_path / ".conventiondrift.yml", outside / "secret.txt")
    assert _reason(read_worktree_file, tmp_path, ".conventiondrift.yml", "config") == REASON_SYMLINK


@pytest.mark.skipif(not POSIX, reason="POSIX")
def test_symlinked_parent_inside_repo_is_still_symlink(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "real/a.py").write_text("x = 1\n")
    _symlink(tmp_path / "alias", tmp_path / "real")
    assert _reason(read_worktree_file, tmp_path, "alias/a.py", "python") == REASON_SYMLINK
    assert read_worktree_file(tmp_path, "real/a.py", "python", origin="tree") == b"x = 1\n"


@pytest.mark.skipif(not POSIX, reason="POSIX")
def test_deep_component_symlink(tmp_path: Path, outside: Path, strategy: str) -> None:
    (tmp_path / "a/b").mkdir(parents=True)
    _symlink(tmp_path / "a/b/c", outside)
    assert _reason(read_worktree_file, tmp_path, "a/b/c/x.py", "python") == REASON_SYMLINK


@pytest.mark.skipif(not POSIX, reason="POSIX")
def test_dangling_symlink(tmp_path: Path, strategy: str) -> None:
    _symlink(tmp_path / "AGENTS.md", tmp_path / "nope")
    assert _reason(read_worktree_file, tmp_path, "AGENTS.md", "instruction") == REASON_SYMLINK


@pytest.mark.skipif(not POSIX, reason="POSIX")
def test_repo_root_given_through_symlink_is_fine(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo/AGENTS.md").write_text("- Use httpx\n")
    _symlink(tmp_path / "rootlink", tmp_path / "repo")
    assert (
        read_worktree_file(tmp_path / "rootlink", "AGENTS.md", "instruction", origin="tree")
        == b"- Use httpx\n"
    )


@pytest.mark.skipif(not d._USE_DIR_FD, reason="needs openat")
def test_swap_to_symlink_after_lstat_final(
    tmp_path: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOCTOU: lstat saw a regular file, but O_NOFOLLOW open hits a symlink (ELOOP)."""
    monkeypatch.setattr(d, "_USE_DIR_FD", True)
    (tmp_path / "AGENTS.md").write_text("ok")
    real_lstat = os.lstat

    def racing_lstat(name: str, *, dir_fd: int | None = None) -> os.stat_result:
        st = real_lstat(name, dir_fd=dir_fd)
        if name == "AGENTS.md":
            os.unlink(tmp_path / "AGENTS.md")
            os.symlink(outside / "secret.txt", tmp_path / "AGENTS.md")
        return st

    monkeypatch.setattr(os, "lstat", racing_lstat)
    assert _reason(read_worktree_file, tmp_path, "AGENTS.md", "instruction") == REASON_SYMLINK


@pytest.mark.skipif(not d._USE_DIR_FD, reason="needs openat")
def test_swap_to_symlink_after_lstat_dir(
    tmp_path: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(d, "_USE_DIR_FD", True)
    (tmp_path / "docs").mkdir()
    real_lstat = os.lstat

    def racing_lstat(name: str, *, dir_fd: int | None = None) -> os.stat_result:
        st = real_lstat(name, dir_fd=dir_fd)
        if name == "docs" and not os.path.islink(tmp_path / "docs"):  # swap once
            os.rmdir(tmp_path / "docs")
            os.symlink(outside, tmp_path / "docs")
        return st

    monkeypatch.setattr(os, "lstat", racing_lstat)
    assert _reason(read_worktree_file, tmp_path, "docs/AGENTS.md", "instruction") == REASON_SYMLINK


@pytest.mark.skipif(not POSIX, reason="POSIX")
def test_fallback_detects_swapped_inode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows fallback: the opened handle must be the file the final lstat saw."""
    monkeypatch.setattr(d, "_USE_DIR_FD", False)
    (tmp_path / "a.py").write_text("a")
    (tmp_path / "b.py").write_text("b")
    real_lstat = os.lstat
    monkeypatch.setattr(
        os,
        "lstat",
        lambda p: real_lstat(tmp_path / "b.py") if str(p).endswith("a.py") else real_lstat(p),
    )
    assert _reason(read_worktree_file, tmp_path, "a.py", "python") == REASON_SYMLINK


def test_reparse_point_counts_as_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows junctions: FILE_ATTRIBUTE_REPARSE_POINT is refused like a symlink."""
    monkeypatch.setattr(d, "_USE_DIR_FD", False)
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, raising=False)
    (tmp_path / "j").mkdir()
    (tmp_path / "j/a.py").write_text("a")
    real_lstat = os.lstat

    class FakeStat:
        def __init__(self, st: os.stat_result) -> None:
            self._st = st
            self.st_file_attributes = 0x400

        def __getattr__(self, name: str) -> object:
            return getattr(self._st, name)

    monkeypatch.setattr(
        os, "lstat", lambda p: FakeStat(real_lstat(p)) if str(p).endswith("j") else real_lstat(p)
    )
    assert _reason(read_worktree_file, tmp_path, "j/a.py", "python") == REASON_SYMLINK


def test_realpath_containment_defence_in_depth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    """If realpath ever lands outside the root (no symlink seen), it is 'outside repository'."""
    (tmp_path / "AGENTS.md").write_text("x")
    real_realpath = os.path.realpath
    monkeypatch.setattr(
        os.path,
        "realpath",
        lambda p: "/elsewhere/AGENTS.md" if str(p).endswith("AGENTS.md") else real_realpath(p),
    )
    assert _reason(read_worktree_file, tmp_path, "AGENTS.md", "instruction") == REASON_OUTSIDE


def test_sibling_prefix_is_not_contained(tmp_path: Path) -> None:
    root = str(tmp_path / "repo")
    assert not d._contained(root, str(tmp_path / "repo-evil" / "x"))
    assert d._contained(root, root)
    assert d._contained(root, os.path.join(root, "x"))


# ---- A-3 #2: FIFOs, sockets, devices are never opened ---------------------------------


FIFO_TIMEOUT_S = 10.0


def _within(seconds: float, fn: Callable[[], str]) -> str:
    """Run ``fn`` in a daemon thread; fail (instead of hanging pytest) if it blocks."""
    out: list[str] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            out.append(fn())
        except BaseException as exc:  # noqa: BLE001 - pytest.fail is a BaseException; re-raised below
            errors.append(exc)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        pytest.fail(f"blocked for over {seconds}s: a FIFO was opened without O_NONBLOCK")
    if errors:
        raise errors[0]
    return out[0]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX")
def test_fifo_skipped_without_opening(tmp_path: Path, strategy: str) -> None:
    os.mkfifo(tmp_path / "AGENTS.md")
    reason = _within(
        FIFO_TIMEOUT_S,
        lambda: _reason(read_worktree_file, tmp_path, "AGENTS.md", "instruction"),
    )
    assert reason == REASON_SPECIAL


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX")
def test_fifo_swapped_in_before_open_does_not_hang(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    """lstat saw a regular file, but a FIFO is what os.open gets: O_NONBLOCK keeps it
    from blocking, and the fstat on the handle refuses it (SR-012 F6)."""
    os.mkfifo(tmp_path / "a.py")
    (tmp_path / "regular").write_text("x")
    real_lstat = os.lstat
    regular = real_lstat(tmp_path / "regular")

    def fake_lstat(p: str, *, dir_fd: int | None = None) -> os.stat_result:
        st = real_lstat(p, dir_fd=dir_fd)
        if str(p).endswith("a.py"):
            return os.stat_result((regular.st_mode, *st[1:]))  # FIFO's inode, file's mode
        return st

    monkeypatch.setattr(os, "lstat", fake_lstat)
    reason = _within(
        FIFO_TIMEOUT_S, lambda: _reason(read_worktree_file, tmp_path, "a.py", "python")
    )
    assert reason == REASON_SPECIAL


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="POSIX")
def test_socket_skipped(strategy: str) -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as t:  # short path for AF_UNIX
        s = socket.socket(socket.AF_UNIX)
        try:
            s.bind(os.path.join(t, "x.py"))
            assert _reason(read_worktree_file, t, "x.py", "python") == REASON_SPECIAL
        finally:
            s.close()


def test_directory_where_file_expected(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "AGENTS.md").mkdir()
    assert _reason(read_worktree_file, tmp_path, "AGENTS.md", "instruction") == REASON_SPECIAL


def test_fstat_must_show_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    (tmp_path / "a.py").write_text("a")
    real_fstat = os.fstat
    fake = os.stat_result((stat.S_IFIFO | 0o644, *real_fstat(0)[1:]))
    monkeypatch.setattr(os, "fstat", lambda fd: fake)
    assert _reason(read_worktree_file, tmp_path, "a.py", "python") in (
        REASON_SPECIAL,
        REASON_SYMLINK,  # by_path compares inodes first
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [("/dev/null", "other"), (".", "dir"), (__file__, "file")],
)
def test_entry_kind(path: str, expected: str) -> None:
    if not os.path.exists(path):
        pytest.skip("no /dev/null")
    assert entry_kind(os.lstat(path).st_mode) == expected


def test_entry_kind_symlink(tmp_path: Path) -> None:
    if not POSIX:
        pytest.skip("POSIX")
    os.symlink(tmp_path, tmp_path / "l")
    assert entry_kind(os.lstat(tmp_path / "l").st_mode) == "symlink"
    assert entry_kind(stat.S_IFSOCK) == "other"
    assert entry_kind(stat.S_IFBLK) == "other"


def test_normal_nested_read(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "src/pkg").mkdir(parents=True)
    (tmp_path / "src/pkg/m.py").write_bytes(b"x = 1\n")
    assert read_worktree_file(tmp_path, "./src//pkg/m.py", "python", origin="tree") == b"x = 1\n"
    assert read_worktree_file(str(tmp_path), "src/pkg/m.py", "python", origin="tree") == b"x = 1\n"


def test_no_fd_leak(tmp_path: Path, strategy: str) -> None:
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("needs /proc")
    (tmp_path / "a").mkdir()
    (tmp_path / "a/ok.py").write_text("x")
    (tmp_path / "a/big.py").write_bytes(b"x" * (FILE_MAX_BYTES + 1))
    os.mkfifo(tmp_path / "a/fifo.py")
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(20):
        read_worktree_file(tmp_path, "a/ok.py", "python", origin="tree")
        for bad in ("a/big.py", "a/fifo.py"):
            with pytest.raises(FileSkipped):
                read_worktree_file(tmp_path, bad, "python", origin="tree")
        with pytest.raises(FileSkipped):
            read_worktree_file(tmp_path, "a/none.py", "python", origin="tree")
        with pytest.raises(FileSkipped):
            read_worktree_file(tmp_path, "a/ok.py/x.py", "python", origin="tree")
    assert len(os.listdir("/proc/self/fd")) == before


# ---- AC-E.15 decoding, AC-E.16 binary (R2.4) ------------------------------------------


def test_decode_text_cases() -> None:
    latin1_py = "name = 'café'\n".encode("latin-1")  # 0xE9 is invalid UTF-8
    assert _reason(decode_text, latin1_py, "python") == REASON_NOT_DECODABLE
    utf16_md = "- Use httpx\n".encode("utf-16")  # with BOM, as Python writes it
    assert _reason(decode_text, utf16_md, "instruction") == REASON_NOT_DECODABLE
    pep263 = b"# -*- coding: latin-1 -*-\nname = 'caf\xe9'\n"
    assert decode_text(pep263, "python") == "# -*- coding: latin-1 -*-\nname = 'café'\n"


@pytest.mark.parametrize(
    ("data", "kind", "expected"),
    [
        (b"x = 1\n", "python", "x = 1\n"),
        ("s = 'é'\n".encode(), "python", "s = 'é'\n"),
        (codecs.BOM_UTF8 + b"x = 1\n", "python", "x = 1\n"),
        (b"#!/usr/bin/env python\n# coding=cp1252\nx = '\x80'\n", "python", None),  # line 2 cookie
        (b"- Use httpx\n", "instruction", "- Use httpx\n"),
        (codecs.BOM_UTF8 + b"- Use httpx\n", "instruction", "- Use httpx\n"),
        ("[project]\nname = 'é'\n".encode(), "manifest", "[project]\nname = 'é'\n"),
        (b"version: 1\n", "config", "version: 1\n"),
        (b"", "lockfile", ""),
    ],
)
def test_decode_ok(data: bytes, kind: FileKind, expected: str | None) -> None:
    out = decode_text(data, kind)
    if expected is not None:
        assert out == expected
    else:
        assert out.endswith("x = '€'\n")


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (b"# coding: no-such-codec\nx = 1\n", "python"),  # unknown cookie
        (codecs.BOM_UTF8 + b"# coding: latin-1\nx = 1\n", "python"),  # BOM + non-UTF-8 cookie
        (b"# coding: utf-16\nx = 1\n", "python"),  # cookie must name an ASCII superset
        (b"x = '\xff'\n", "python"),
        (b"\n\n# coding: latin-1\nx = '\xe9'\n", "python"),  # cookie on line 3 ignores
        ("- café\n".encode("latin-1"), "instruction"),  # no cookies outside .py
        (b"# coding: latin-1\n- caf\xe9\n", "instruction"),
    ],
)
def test_decode_not_decodable(data: bytes, kind: FileKind) -> None:
    assert _reason(decode_text, data, kind) == REASON_NOT_DECODABLE


@pytest.mark.parametrize(
    "bom",
    [codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE, codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE],
)
@pytest.mark.parametrize("kind", ["python", "instruction", "config"])
def test_foreign_bom_is_not_decodable_not_binary(bom: bytes, kind: FileKind) -> None:
    assert _reason(decode_text, bom + b"a\x00b\x00", kind) == REASON_NOT_DECODABLE


def test_binary_detection() -> None:
    blob = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    assert _reason(decode_text, blob, "instruction") == REASON_BINARY  # binary AGENTS.md
    assert _reason(decode_text, b"x = 1\n\x00\n", "python") == REASON_BINARY  # binary x.py


@pytest.mark.parametrize("kind", ["python", "instruction", "manifest", "lockfile", "config"])
@pytest.mark.parametrize("where", [0, 1, 4096, FILE_MAX_BYTES - 1])
def test_nul_anywhere_is_binary(kind: FileKind, where: int) -> None:
    data = bytearray(b"a" * FILE_MAX_BYTES)
    data[where] = 0
    assert _reason(decode_text, bytes(data), kind) == REASON_BINARY


def test_bomless_utf16_is_binary() -> None:
    # Documents current behaviour; see open question Q-decode (order/BOM-less UTF-16).
    assert _reason(decode_text, "version: 1\n".encode("utf-16-le"), "config") == REASON_BINARY


def test_read_then_decode_end_to_end(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "x.py").write_bytes(b"\x00\x01")
    raw = read_worktree_file(tmp_path, "x.py", "python", origin="tree")
    assert _reason(decode_text, raw, "python") == REASON_BINARY


# ---- CR S1: containment is by whole segments, also for a root of "/" -------------------


def test_root_slash_contains_everything_below_it() -> None:
    assert d._contained("/", "/")
    assert d._contained("/", "/etc/x")


def test_sibling_prefix_repo2_is_not_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os.path, "realpath", lambda p: str(p))
    assert d._contained("/x/repo", "/x/repo/a.py")
    assert not d._contained("/x/repo", "/x/repo2")
    assert not d._contained("/x/repo", "/x/repo2/a.py")
    assert not d._contained("/x/repo", "/x")


def test_uncomparable_paths_are_not_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    """commonpath raises ValueError for mixed absolute/relative (or, on Windows, drives)."""
    monkeypatch.setattr(os.path, "realpath", lambda p: "relative/x")
    assert not d._contained("/x/repo", "/x/repo/a.py")


# ---- CR S2, SR-012 F2/F3: no OSError escapes; fixed reasons, no host path ------------


def _chain(exc: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        todo += [e.__cause__, e.__context__]


def _skip_without_leak(root: Path, rel: str, *, origin: PathOrigin = "tree") -> str:
    """Read ``rel``; it must be skipped with nothing but the fixed reason in the exception."""
    with pytest.raises(FileSkipped) as info:
        read_worktree_file(root, rel, "python", origin=origin)
    exc = info.value
    assert exc.__cause__ is None
    assert exc.__context__ is None
    assert exc.args == (exc.reason,)
    host = str(root)
    for e in _chain(exc):
        for text in (str(e), repr(e), *map(str, e.args)):
            assert host not in text, "host path leaked"
            assert "Errno" not in text and "denied" not in text.lower()
    return exc.reason


def test_missing_file_is_unreadable(tmp_path: Path, strategy: str) -> None:
    """ENOENT from lstat: the file vanished after listing."""
    assert _skip_without_leak(tmp_path, "nope.py") == REASON_UNREADABLE
    assert _skip_without_leak(tmp_path, "no/dir/x.py") == REASON_UNREADABLE


def test_file_used_as_parent_is_special_file(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "f").write_text("x")
    assert _skip_without_leak(tmp_path, "f/x.py") == REASON_SPECIAL


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX")
def test_fifo_used_as_parent_is_special_file(tmp_path: Path, strategy: str) -> None:
    os.mkfifo(tmp_path / "p")
    assert _skip_without_leak(tmp_path, "p/x.py") == REASON_SPECIAL


@pytest.mark.parametrize("where", ["x.py", "d/x.py"])
def test_name_too_long_split_by_origin(tmp_path: Path, strategy: str, where: str) -> None:
    """ENAMETOOLONG (a real one: 300 bytes > NAME_MAX on every common file system)."""
    (tmp_path / "d").mkdir()
    long = "a" * 300
    rel = where.replace("x", long, 1) if where == "x.py" else f"{long}/x.py"
    assert _skip_without_leak(tmp_path, rel, origin="tree") == REASON_UNSUPPORTED
    assert _skip_without_leak(tmp_path, rel, origin="input") == REASON_OUTSIDE


needs_non_root = pytest.mark.skipif(
    not POSIX or os.geteuid() == 0, reason="chmod 000 needs POSIX and a non-root user"
)


@needs_non_root
def test_unreadable_file_chmod_000(tmp_path: Path, strategy: str) -> None:
    f = tmp_path / "a.py"
    f.write_text("x")
    f.chmod(0)
    try:
        assert _skip_without_leak(tmp_path, "a.py") == REASON_UNREADABLE
    finally:
        f.chmod(0o644)


@needs_non_root
def test_unreadable_folder_chmod_000(tmp_path: Path, strategy: str) -> None:
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked/a.py").write_text("x")
    (tmp_path / "locked").chmod(0)
    try:
        assert _skip_without_leak(tmp_path, "locked/a.py") == REASON_UNREADABLE
    finally:
        (tmp_path / "locked").chmod(0o755)


def _os_error(code: int, path: Path) -> OSError:
    return OSError(code, os.strerror(code), str(path / "leak"))


ERRNO_CASES = [
    ("ELOOP", REASON_SYMLINK),
    ("EMLINK", REASON_SYMLINK),
    ("ENOTDIR", REASON_SPECIAL),
    ("ENAMETOOLONG", REASON_UNSUPPORTED),
    ("EACCES", REASON_UNREADABLE),
    ("EPERM", REASON_UNREADABLE),
    ("EIO", REASON_UNREADABLE),
    ("ENOENT", REASON_UNREADABLE),
    ("EBUSY", REASON_UNREADABLE),  # "any other errno"
]


@pytest.mark.parametrize(("name", "expected"), ERRNO_CASES)
@pytest.mark.parametrize("step", ["final open", "parent open", "fstat", "read"])
def test_every_errno_maps_to_a_fixed_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    strategy: str,
    name: str,
    expected: str,
    step: str,
) -> None:
    """The lstat-to-open race and later failures: each errno, on each step, on both paths."""
    if step == "parent open" and strategy == "by_path":
        pytest.skip("by_path opens only the final component")
    (tmp_path / "d").mkdir()
    (tmp_path / "d/a.py").write_text("x = 1\n")
    code = getattr(errno, name)
    err = _os_error(code, tmp_path)
    real_open = os.open
    target_fds: set[int] = set()

    def fake_open(path: str, flags: int, *a: object, **kw: object) -> int:
        target = "d" if step == "parent open" else "a.py"
        if step.endswith("open") and str(path).endswith(target):
            raise err
        fd = real_open(path, flags, *a, **kw)  # type: ignore[arg-type]
        if str(path).endswith("a.py"):
            target_fds.add(fd)
        return fd

    monkeypatch.setattr(os, "open", fake_open)
    if step in ("fstat", "read"):
        _fail_on(monkeypatch, step, target_fds, err)
    if step == "parent open" and code == errno.ENOTDIR:
        expected = REASON_SPECIAL  # re-lstat still sees a folder, not a symlink
    assert _skip_without_leak(tmp_path, "d/a.py") == expected
    if code == errno.ENAMETOOLONG:
        assert _skip_without_leak(tmp_path, "d/a.py", origin="input") == REASON_OUTSIDE


def _fail_on(
    monkeypatch: pytest.MonkeyPatch, step: str, fds: set[int] | None, err: BaseException
) -> None:
    """Make ``os.fstat``/``os.read`` raise ``err`` for the file under test only."""
    real = getattr(os, step)

    def fake(fd: int, *a: object) -> object:
        if fds is None or fd in fds:
            raise err
        return real(fd, *a)

    monkeypatch.setattr(os, step, fake)


def _track_fds(monkeypatch: pytest.MonkeyPatch, suffix: str) -> set[int]:
    fds: set[int] = set()
    real_open = os.open

    def spy(path: str, flags: int, *a: object, **kw: object) -> int:
        fd = real_open(path, flags, *a, **kw)  # type: ignore[arg-type]
        if str(path).endswith(suffix):
            fds.add(fd)
        return fd

    monkeypatch.setattr(os, "open", spy)
    return fds


@pytest.mark.parametrize("name", ["ENOENT", "EACCES"])
def test_race_lstat_then_open_is_unreadable_not_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str, name: str
) -> None:
    """SR-012 F3: the file vanishing or losing permission after lstat is not a "symlink"."""
    (tmp_path / "a.py").write_text("x")
    real_open = os.open

    def racing_open(path: str, flags: int, *a: object, **kw: object) -> int:
        if str(path).endswith("a.py"):
            raise _os_error(getattr(errno, name), tmp_path)
        return real_open(path, flags, *a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", racing_open)
    assert _skip_without_leak(tmp_path, "a.py") == REASON_UNREADABLE


@pytest.mark.skipif(not d._USE_DIR_FD, reason="needs openat")
@pytest.mark.parametrize("name", ["ENOENT", "EACCES"])
def test_race_on_parent_folder_is_unreadable_not_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setattr(d, "_USE_DIR_FD", True)
    (tmp_path / "d").mkdir()
    (tmp_path / "d/a.py").write_text("x")
    real_open = os.open

    def racing_open(path: str, flags: int, *a: object, **kw: object) -> int:
        if path == "d":
            raise _os_error(getattr(errno, name), tmp_path)
        return real_open(path, flags, *a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", racing_open)
    assert _skip_without_leak(tmp_path, "d/a.py") == REASON_UNREADABLE


@pytest.mark.skipif(not d._USE_DIR_FD, reason="needs openat")
def test_folder_swapped_for_file_after_lstat_is_special_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real ENOTDIR from O_DIRECTORY; the re-lstat sees a file, so "special file"."""
    monkeypatch.setattr(d, "_USE_DIR_FD", True)
    (tmp_path / "docs").mkdir()
    real_lstat = os.lstat
    calls: list[str] = []

    def racing_lstat(name: str, *, dir_fd: int | None = None) -> os.stat_result:
        st = real_lstat(name, dir_fd=dir_fd)
        if name == "docs" and not calls:
            calls.append(name)
            os.rmdir(tmp_path / "docs")
            (tmp_path / "docs").write_text("not a folder")
        return st

    monkeypatch.setattr(os, "lstat", racing_lstat)
    assert _skip_without_leak(tmp_path, "docs/AGENTS.md") == REASON_SPECIAL


def test_eftype_where_it_exists_is_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    """EFTYPE exists on BSDs only; simulate it with a free errno number."""
    monkeypatch.setattr(errno, "EFTYPE", 10_079, raising=False)
    (tmp_path / "a.py").write_text("x")
    real_open = os.open

    def fake_open(path: str, flags: int, *a: object, **kw: object) -> int:
        if str(path).endswith("a.py"):
            raise OSError(10_079, "Inappropriate file type", str(tmp_path / "a.py"))
        return real_open(path, flags, *a, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", fake_open)
    assert _skip_without_leak(tmp_path, "a.py") == REASON_SYMLINK


def test_oserror_without_errno_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    (tmp_path / "a.py").write_text("x")
    _fail_on(monkeypatch, "fstat", _track_fds(monkeypatch, "a.py"), OSError("no errno"))
    assert _skip_without_leak(tmp_path, "a.py") == REASON_UNREADABLE


def test_non_oserror_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    (tmp_path / "a.py").write_text("x")
    _fail_on(monkeypatch, "fstat", _track_fds(monkeypatch, "a.py"), RuntimeError("bug"))
    with pytest.raises(RuntimeError, match="bug"):
        read_worktree_file(tmp_path, "a.py", "python", origin="tree")


# ---- SR-012 F1: a hostile coding cookie never escapes as an exception (R2.4) ----------


def test_coding_undefined_is_not_decodable() -> None:
    """``undefined`` raises a bare UnicodeError (a ValueError), not UnicodeDecodeError."""
    with pytest.raises(FileSkipped) as info:
        decode_text(b"# coding: undefined\nx = 1\n", "python")
    assert info.value.reason == REASON_NOT_DECODABLE
    assert info.value.__context__ is None and info.value.__cause__ is None


CODEC_NAMES = sorted(
    set(encodings.aliases.aliases) | set(encodings.aliases.aliases.values()) | {"undefined"}
)


@pytest.mark.parametrize("name", CODEC_NAMES)
def test_every_stdlib_codec_cookie_decodes_or_is_skipped(name: str) -> None:
    for spelling in {name, name.replace("_", "-")}:
        data = f"# -*- coding: {spelling} -*-\nx = 'caf\xe9'\n".encode("latin-1")
        try:
            out = decode_text(data, "python")
        except FileSkipped as exc:
            assert exc.reason == REASON_NOT_DECODABLE
        else:
            assert isinstance(out, str)


# ---- SR-012 F4: the Windows fallback re-checks the whole path after opening ----------


@pytest.mark.parametrize(
    ("swap", "expected"),
    [
        ("symlink", REASON_SYMLINK),  # folder became a link or junction
        ("other dir", REASON_SYMLINK),  # folder replaced by a different folder
        ("file", REASON_SPECIAL),  # folder replaced by a file
        ("gone", REASON_UNREADABLE),  # folder vanished
    ],
)
def test_fallback_rechecks_every_parent_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str, expected: str
) -> None:
    monkeypatch.setattr(d, "_USE_DIR_FD", False)
    (tmp_path / "a/b").mkdir(parents=True)
    (tmp_path / "a/b/m.py").write_text("x")
    (tmp_path / "other").mkdir()
    (tmp_path / "f").write_text("x")
    real_lstat = os.lstat
    opened: list[str] = []
    real_open = os.open

    def spy_open(path: str, flags: int, *a: object, **kw: object) -> int:
        opened.append(str(path))
        return real_open(path, flags, *a, **kw)  # type: ignore[arg-type]

    def fake_lstat(p: str) -> os.stat_result:
        if opened and str(p) == str(tmp_path / "a"):  # only after the file was opened
            if swap == "gone":
                raise OSError(errno.ENOENT, "gone", str(p))
            if swap == "symlink":
                return os.stat_result((stat.S_IFLNK | 0o777, *real_lstat(p)[1:]))
            return real_lstat(tmp_path / ("other" if swap == "other dir" else "f"))
        return real_lstat(p)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "lstat", fake_lstat)
    assert _skip_without_leak(tmp_path, "a/b/m.py") == expected


def test_fallback_recheck_passes_for_an_unchanged_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(d, "_USE_DIR_FD", False)
    (tmp_path / "a/b").mkdir(parents=True)
    (tmp_path / "a/b/m.py").write_text("x = 1\n")
    seen: list[str] = []
    real_lstat = os.lstat

    def spy(p: str) -> os.stat_result:
        seen.append(str(p))
        return real_lstat(p)

    monkeypatch.setattr(os, "lstat", spy)
    assert read_worktree_file(tmp_path, "a/b/m.py", "python", origin="tree") == b"x = 1\n"
    mine = [p for p in seen if p.startswith(str(tmp_path / "a"))]  # realpath lstats too
    assert mine[-6:] == [str(tmp_path / p) for p in ("a", "a/b", "a/b/m.py")] * 2
