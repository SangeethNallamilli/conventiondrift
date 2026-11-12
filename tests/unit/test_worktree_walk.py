"""T-010b unit tests: the scan-mode working-tree walk (DESIGN §12 A-3 #1-#3, I-5 hard
excludes, SR N4)."""

from __future__ import annotations

import errno
import os
import socket
from pathlib import Path

import pytest

import conventiondrift.discover.safefs as d
from conventiondrift.discover.safefs import WalkResult, walk_worktree
from conventiondrift.model import SkippedFile

POSIX = os.name == "posix"


@pytest.fixture(params=["dir_fd", "by_path"])
def strategy(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Run every walk test through both listing strategies (openat, Windows fallback)."""
    if request.param == "dir_fd" and not d._USE_DIR_FD:
        pytest.skip("platform has no dir_fd/O_NOFOLLOW")  # never on Linux/macOS CI
    monkeypatch.setattr(d, "_USE_DIR_FD", request.param == "dir_fd")
    return str(request.param)


def make(root: Path, *files: str) -> None:
    for rel in files:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x = 1\n")


def symlink(target: Path, link: Path, *, is_dir: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except OSError as exc:  # Windows without developer mode
        pytest.skip(f"symlinks unavailable: {exc.strerror}")


def lstat_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []
    real = os.lstat

    def spy(path: str, *a: object, **k: object) -> os.stat_result:
        seen.append(os.fsdecode(path))
        return real(path, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "lstat", spy)
    return seen


def test_lists_regular_files_sorted(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "b.py", "a/z.py", "a/b/c.md", "A.py", ".github/w.yml")
    res = walk_worktree(tmp_path)
    assert res == WalkResult(
        files=(".github/w.yml", "A.py", "a/b/c.md", "a/z.py", "b.py"), skipped=(), entries=8
    )


def _excluded_dir_names() -> list[str]:
    """D-TL-25: one folder per hard-excluded name and per I-5 normalisation class."""
    ignorable = sorted(d.HARD_EXCLUDE_IGNORABLE)
    out: list[str] = []
    for name in sorted(d._HARD_EXCLUDED_NAMES):
        out += [name, name.upper(), name.title()]  # case
        out += [name[:2] + ch + name[2:] for ch in ignorable]  # every ignorable code point
        if POSIX:  # Windows strips these itself, so the folder would be `name`
            out += [name + ".", name + " ", name + ". ."]
    out += ["GIT~1", "GI1A2B~1", "NODE_M~1", "NO1A2B~12"]  # 8.3 short names
    return out


def test_hard_excluded_folders_are_never_entered(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    names = _excluded_dir_names()
    assert set(d._HARD_EXCLUDED_NAMES) <= set(names)
    assert all(any(ch in n for n in names) for ch in d.HARD_EXCLUDE_IGNORABLE)
    for i, name in enumerate(names):
        (tmp_path / name).mkdir(exist_ok=True)  # case-insensitive FS: same folder, fine
        (tmp_path / name / f"x{i}.py").write_text("x = 1\n")
    make(tmp_path, "src/a.py", "src/.GIT/config", "src/node_modules/m.py", "gitx~1/a.py")
    seen = lstat_spy(monkeypatch)
    res = walk_worktree(tmp_path)
    assert res.files == ("gitx~1/a.py", "src/a.py")
    assert res.skipped == ()
    assert not any(d.is_hard_excluded(os.path.basename(p)) for p in seen)  # not even lstat-ed


def test_git_symlink_and_gitlink_file_are_skipped_silently(tmp_path: Path, strategy: str) -> None:
    outside = tmp_path / "outside"
    make(outside, "config", "x.py")
    repo = tmp_path / "repo"
    make(repo, "a.py")
    symlink(outside, repo / ".git", is_dir=True)
    symlink(outside, repo / "NODE_MODULES", is_dir=True)
    (repo / "sub").mkdir()
    (repo / "sub" / ".git").write_text("gitdir: ../../outside\n")  # submodule gitlink
    res = walk_worktree(repo)
    assert res.files == ("a.py",)
    assert res.skipped == ()


def test_symlinks_and_special_files_are_skipped(tmp_path: Path, strategy: str) -> None:
    outside = tmp_path / "outside"
    make(outside, "secret.py")
    repo = tmp_path / "repo"
    make(repo, "a.py")
    symlink(outside / "secret.py", repo / "link.py")
    symlink(outside, repo / "linkdir", is_dir=True)
    expected = [SkippedFile("link.py", "symlink"), SkippedFile("linkdir", "symlink")]
    if hasattr(os, "mkfifo"):
        os.mkfifo(repo / "fifo.py")
        expected.insert(0, SkippedFile("fifo.py", "special file"))
    res = walk_worktree(repo)
    assert res.files == ("a.py",)
    assert list(res.skipped) == expected


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs AF_UNIX sockets")
def test_socket_is_special_file(strategy: str) -> None:
    import tempfile

    with tempfile.TemporaryDirectory(dir="/tmp") as t:  # short path for sun_path
        s = socket.socket(socket.AF_UNIX)
        try:
            s.bind(os.path.join(t, "s"))
            assert walk_worktree(t).skipped == (SkippedFile("s", "special file"),)
        finally:
            s.close()


@pytest.mark.skipif(not POSIX, reason="Windows can't create these names")
def test_windows_only_tree_names_are_unsupported(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "ok.py", "nul.py", "Com1/x.py", "a\\b.py", "trail. ", "dir./x.py")
    res = walk_worktree(tmp_path)
    assert res.files == ("ok.py",)
    reasons = {s.path: s.reason for s in res.skipped}
    assert reasons == dict.fromkeys(
        ["Com1", "a\\b.py", "dir.", "nul.py", "trail. "], "unsupported path"
    )


def test_check_ignores_the_absolute_root(tmp_path: Path, strategy: str) -> None:
    root = tmp_path / ".git" / "node_modules" / "GIT~1" / "repo"
    make(root, "a.py")
    assert walk_worktree(root).files == ("a.py",)


def test_depth_cap(tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(d, "WALK_MAX_DEPTH", 3)
    make(tmp_path, "1/2/3/ok.py", "1/2/3/4/no.py", "1/top.py")
    res = walk_worktree(tmp_path)
    assert res.files == ("1/2/3/ok.py", "1/top.py")
    assert res.skipped == (SkippedFile("1/2/3/4", "walk limit"),)


def test_real_depth_cap_is_64(tmp_path: Path, strategy: str) -> None:
    assert d.WALK_MAX_DEPTH == 64
    deep = "/".join(["d"] * 64)
    make(tmp_path, f"{deep}/ok.py", f"{deep}/e/no.py")
    res = walk_worktree(tmp_path)
    assert res.files == (f"{deep}/ok.py",)
    assert res.skipped == (SkippedFile(f"{deep}/e", "walk limit"),)


def test_entry_cap(tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert d.WALK_MAX_ENTRIES == 500_000
    make(tmp_path, "a/1.py", "a/2.py", "b/1.py", "b/2.py", "c/1.py", "z.py", ".git/x")
    monkeypatch.setattr(d, "WALK_MAX_ENTRIES", 8)  # root 5 + a 2 = 7; b's 2 would make 9
    res = walk_worktree(tmp_path)
    assert res.files == ("a/1.py", "a/2.py", "z.py")
    assert res.skipped == (SkippedFile("b", "walk limit"), SkippedFile("c", "walk limit"))
    assert res.entries == 7
    monkeypatch.setattr(d, "WALK_MAX_ENTRIES", 9)  # exactly at the cap: b fits, c does not
    res = walk_worktree(tmp_path)
    assert res.skipped == (SkippedFile("c", "walk limit"),)
    assert res.entries == 9


def test_root_over_the_entry_cap(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    make(tmp_path, "a.py", "b.py")
    monkeypatch.setattr(d, "WALK_MAX_ENTRIES", 1)
    assert walk_worktree(tmp_path) == WalkResult((), (SkippedFile(".", "walk limit"),), 0)


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        (errno.EACCES, "unreadable"),
        (errno.ENOENT, "unreadable"),
        (errno.EIO, "unreadable"),
        (errno.ELOOP, "symlink"),
        (errno.ENAMETOOLONG, "unsupported path"),  # a tree name (I-14), never "outside"
    ],
)
def test_lstat_error_is_a_fixed_reason(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch, code: int, reason: str
) -> None:
    make(tmp_path, "a.py", "b.py")
    real = os.lstat

    def fail(path: str, *a: object, **k: object) -> os.stat_result:
        if os.fsdecode(path).endswith("b.py"):
            raise OSError(code, "boom", str(tmp_path / "b.py"))
        return real(path, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "lstat", fail)
    res = walk_worktree(tmp_path)
    assert res.files == ("a.py",)
    assert res.skipped == (SkippedFile("b.py", reason),)  # type: ignore[arg-type]


@pytest.mark.skipif(not POSIX or os.geteuid() == 0, reason="needs POSIX permissions, not root")
def test_unreadable_folder(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "a.py", "locked/x.py")
    (tmp_path / "locked").chmod(0)
    try:
        res = walk_worktree(tmp_path)
    finally:
        (tmp_path / "locked").chmod(0o755)
    assert res.files == ("a.py",)
    assert res.skipped == (SkippedFile("locked", "unreadable"),)


def test_root_that_cannot_be_listed(tmp_path: Path, strategy: str) -> None:
    res = walk_worktree(tmp_path / "missing")
    assert res == WalkResult((), (SkippedFile(".", "unreadable"),), 0)


def test_folder_swapped_for_a_symlink_after_lstat(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    make(outside, "secret.py")
    repo = tmp_path / "repo"
    make(repo, "a.py", "sub/x.py")
    real = os.lstat

    def racing(path: str, *a: object, **k: object) -> os.stat_result:
        st = real(path, *a, **k)  # type: ignore[arg-type]
        if os.fsdecode(path).endswith("sub") and not (repo / "sub").is_symlink():
            (repo / "sub").rename(tmp_path / "moved")
            symlink(outside, repo / "sub", is_dir=True)
        return st

    monkeypatch.setattr(os, "lstat", racing)
    res = walk_worktree(repo)
    assert res.files == ("a.py",)
    assert res.skipped == (SkippedFile("sub", "symlink"),)


def test_fallback_rechecks_the_folder_after_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(d, "_USE_DIR_FD", False)
    repo = tmp_path / "repo"
    make(repo, "a.py", "sub/x.py")
    make(tmp_path, "elsewhere/y.py")
    real = os.scandir

    def racing(path: str) -> object:
        it = real(path)
        if path.endswith("sub"):
            (repo / "sub").rename(tmp_path / "moved")
            (tmp_path / "elsewhere").rename(repo / "sub")  # another real folder
        return it

    monkeypatch.setattr(os, "scandir", racing)
    res = walk_worktree(repo)
    assert res.files == ("a.py",)
    assert res.skipped == (SkippedFile("sub", "symlink"),)


def test_walk_result_is_immutable() -> None:
    res = WalkResult((), (), 0)
    with pytest.raises(AttributeError):
        res.entries = 1  # type: ignore[misc]


@pytest.mark.skipif(not os.path.isdir("/dev/fd"), reason="needs /dev/fd")
def test_every_folder_handle_is_closed(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "a/b/c.py", "d/e.py", "f.py")
    if POSIX:
        (tmp_path / "locked").mkdir(mode=0)
    before = len(os.listdir("/dev/fd"))
    walk_worktree(tmp_path)
    assert len(os.listdir("/dev/fd")) == before


def test_dir_fd_strategy_lists_through_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not d._USE_DIR_FD:
        pytest.skip("platform has no dir_fd/O_NOFOLLOW")
    make(tmp_path, "a/b.py")
    seen: list[object] = []
    real = os.scandir

    def spy(path: int) -> object:
        seen.append(path)
        return real(path)

    monkeypatch.setattr(os, "scandir", spy)
    assert walk_worktree(tmp_path).files == ("a/b.py",)
    assert len(seen) == 2
    assert all(isinstance(p, int) for p in seen)


def test_links_and_special_files_are_never_opened(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    make(outside, "x.py")
    repo = tmp_path / "repo"
    make(repo, "a.py")
    symlink(outside, repo / "linkdir", is_dir=True)
    if hasattr(os, "mkfifo"):
        os.mkfifo(repo / "fifo")
    opened: list[str] = []
    real_open, real_scandir = os.open, os.scandir

    def spy_open(path: str, *a: object, **k: object) -> int:
        opened.append(os.fsdecode(path))
        return real_open(path, *a, **k)  # type: ignore[arg-type]

    def spy_scandir(path: str | int) -> object:
        opened.append(path if isinstance(path, int) else os.fsdecode(path))  # type: ignore[arg-type]
        return real_scandir(path)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "scandir", spy_scandir)
    res = walk_worktree(repo)
    assert res.files == ("a.py",)
    names = {os.path.basename(p) for p in opened if isinstance(p, str)}
    assert not names & {"linkdir", "fifo"}


def test_junction_is_symlink(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    make(tmp_path, "a.py", "junction/x.py")
    real = d._is_reparse_point
    junction = os.lstat(tmp_path / "junction")
    monkeypatch.setattr(d, "_is_reparse_point", lambda st: st.st_ino == junction.st_ino or real(st))
    res = walk_worktree(tmp_path)
    assert res.files == ("a.py",)
    assert res.skipped == (SkippedFile("junction", "symlink"),)
