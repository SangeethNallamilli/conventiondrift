"""T-010b unit tests: the scan-mode working-tree walk (DESIGN §12 A-3 #1-#3, I-5 hard
excludes, SR N4)."""

from __future__ import annotations

import errno
import os
import socket
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import conventiondrift.discover.safefs as d
from conventiondrift.discover.safefs import WalkResult, walk_worktree
from conventiondrift.errors import ComponentError
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
    """Create ``link`` -> ``target``.

    Skip only on a local non-Windows machine without CI, where symlink support may
    be missing. Under CI, GitHub Actions, or on Windows, a failure is a hard fail so
    a CI run cannot hide these tests in the skipped count (as in #40's
    ``_symlink_or_skip``).
    """
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except OSError as exc:
        message = f"failed to create symlink {link} -> {target}: {exc}"
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or sys.platform == "win32":
            pytest.fail(message)
        pytest.skip(message)


def lstat_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []
    real = os.lstat

    def spy(path: str, *a: object, **k: object) -> os.stat_result:
        seen.append(os.fsdecode(path))
        return real(path, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "lstat", spy)
    return seen


def _refuse_symlinks(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(self: Path, target: object, target_is_directory: bool = False) -> None:
        raise OSError(errno.EPERM, "symlinks refused")

    monkeypatch.setattr(Path, "symlink_to", refuse)


@pytest.mark.parametrize(
    ("env", "platform", "outcome"),
    [
        ({"CI": "1"}, "linux", pytest.fail.Exception),
        ({"GITHUB_ACTIONS": "true"}, "linux", pytest.fail.Exception),
        ({}, "win32", pytest.fail.Exception),
        ({}, "linux", pytest.skip.Exception),
    ],
    ids=["CI", "GITHUB_ACTIONS", "win32", "local-posix"],
)
def test_symlink_helper_fails_under_ci_and_skips_only_locally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    env: dict[str, str],
    platform: str,
    outcome: type[BaseException],
) -> None:
    """S1 / SR-013 (CR1): a symlink that can't be made fails CI and Windows, never skips."""
    target, link = tmp_path / "t", tmp_path / "l"  # built before any patching (SR N-9)
    _refuse_symlinks(monkeypatch)
    for name in ("CI", "GITHUB_ACTIONS"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with monkeypatch.context() as m:
        m.setattr(sys, "platform", platform)  # only around the helper call
        # Catch both outcomes: an uncaught skip would only mark this test skipped.
        with pytest.raises((pytest.fail.Exception, pytest.skip.Exception)) as exc:
            symlink(target, link)
    assert exc.type is outcome
    assert "symlinks refused" in str(exc.value)
    assert not os.path.lexists(link)


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


def test_git_symlinks_are_skipped_silently(tmp_path: Path, strategy: str) -> None:
    outside = tmp_path / "outside"
    make(outside, "config", "x.py")
    repo = tmp_path / "repo"
    make(repo, "a.py")
    symlink(outside, repo / ".git", is_dir=True)
    symlink(outside, repo / "NODE_MODULES", is_dir=True)
    res = walk_worktree(repo)
    assert res.files == ("a.py",)
    assert res.skipped == ()


def fs_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every name given to os.lstat, os.open and os.scandir during the walk.

    The wrappers call only the saved originals and os.fsdecode, never a Path or
    os.path helper, so nothing re-enters a patched function (Python 3.14+).
    """
    seen: list[str] = []

    def wrap(real: Callable[..., Any]) -> Callable[..., Any]:
        def spy(path: Any, *a: Any, **k: Any) -> Any:
            if isinstance(path, (str, bytes)):
                seen.append(os.fsdecode(path))
            return real(path, *a, **k)

        return spy

    for name in ("lstat", "open", "scandir"):
        monkeypatch.setattr(os, name, wrap(getattr(os, name)))
    return seen


def _last_name(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def test_gitlink_file_is_skipped_silently(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-5: a submodule gitlink file ``sub/.git`` is never lstat-ed, opened or listed."""
    outside = tmp_path / "outside"
    make(outside, "config", "x.py")
    repo = tmp_path / "repo"
    make(repo, "a.py")
    (repo / "sub").mkdir()
    (repo / "sub" / ".git").write_bytes(b"gitdir: ../../outside\n")  # submodule gitlink
    seen = fs_spy(monkeypatch)
    res = walk_worktree(repo)
    assert res.files == ("a.py",)
    assert res.skipped == ()
    assert any(_last_name(p) == "sub" for p in seen), "the spy must see the walk"
    assert not [p for p in seen if _last_name(p) == ".git"]
    assert not [p for p in seen if "outside" in p.replace("\\", "/").split("/")]


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
    """I-13 ruling 5: the root is depth 0; depth 64 is entered; 65 is a walk-limit entry."""
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
    """I-13 ruling 2 / QA F1: a missing or unlistable root is ComponentError('discover')."""
    missing = tmp_path / "missing"
    with pytest.raises(ComponentError) as exc:
        walk_worktree(missing)
    assert exc.value.component == "discover"
    assert str(missing) not in exc.value.message
    assert str(tmp_path) not in exc.value.message


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
        # Only the saved, unpatched lstat in here: Path.is_symlink goes through os.lstat
        # on 3.14+, which would re-enter this wrapper (RecursionError).
        if os.fsdecode(path).endswith("sub") and not stat.S_ISLNK(real(repo / "sub").st_mode):
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
        # Swap after the walk took the folder's ids and before it lists: the listing is
        # of the other folder. Renaming before scandir opens the folder also works on
        # Windows, which may refuse to rename a folder with an open listing handle.
        if path.endswith("sub"):
            (repo / "sub").rename(tmp_path / "moved")
            (tmp_path / "elsewhere").rename(repo / "sub")  # another real folder
        return real(path)

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


def test_reparse_point_attribute_is_symlink(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk's own check reads FILE_ATTRIBUTE_REPARSE_POINT (a simulated Windows lstat)."""
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400, raising=False)
    make(tmp_path, "a.py", "j/x.py", "r.py")
    real = os.lstat

    class FakeStat:
        def __init__(self, st: os.stat_result) -> None:
            self._st = st
            self.st_file_attributes = 0x400

        def __getattr__(self, name: str) -> object:
            return getattr(self._st, name)

    def fake(path: str, *a: object, **k: object) -> object:
        st = real(path, *a, **k)  # type: ignore[arg-type]
        return FakeStat(st) if os.fsdecode(path).endswith(("j", "r.py")) else st

    monkeypatch.setattr(os, "lstat", fake)
    res = walk_worktree(tmp_path)
    assert res.files == ("a.py",)
    assert res.skipped == (SkippedFile("j", "symlink"), SkippedFile("r.py", "symlink"))


@pytest.mark.skipif(
    sys.platform != "win32", reason="real Windows behaviour; runs on windows-latest"
)
def test_windows_real_junction_is_never_entered(tmp_path: Path) -> None:
    """A real NTFS junction, inside the repo or out, is "symlink" and never listed."""
    if sys.platform == "win32":  # mypy checks this block as Windows code
        import _winapi

        assert not d._USE_DIR_FD, "Windows walks through the by-path fallback"
        outside = tmp_path / "outside"
        make(outside, "secret.py")
        repo = tmp_path / "repo"
        make(repo, "a.py", "real/x.py")
        links = [repo / "j_in", repo / "j_out"]
        _winapi.CreateJunction(str(repo / "real"), str(links[0]))
        _winapi.CreateJunction(str(outside), str(links[1]))
        try:
            assert all(
                os.lstat(j).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT for j in links
            )
            res = walk_worktree(repo)
        finally:
            for j in links:
                os.rmdir(j)  # removes the junction itself, never its target
        assert res.files == ("a.py", "real/x.py")
        assert res.skipped == (SkippedFile("j_in", "symlink"), SkippedFile("j_out", "symlink"))
        assert (outside / "secret.py").exists()
    else:  # the skipif keeps other platforms out
        pytest.fail("Windows-only")


@pytest.mark.skipif(not POSIX or os.geteuid() == 0, reason="needs POSIX permissions, not root")
def test_unlistable_root_is_a_discover_error(tmp_path: Path, strategy: str) -> None:
    """I-13 ruling 2: a root that exists but cannot be listed also fails closed."""
    tmp_path.chmod(0)
    try:
        with pytest.raises(ComponentError) as exc:
            walk_worktree(tmp_path)
        assert exc.value.component == "discover"
        assert str(tmp_path) not in exc.value.message
    finally:
        tmp_path.chmod(0o755)


def test_realpath_failure_on_the_root_is_a_discover_error(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(path: object) -> str:
        raise OSError(errno.EIO, "boom", str(path))

    monkeypatch.setattr(os.path, "realpath", boom)
    with pytest.raises(ComponentError) as exc:
        walk_worktree(tmp_path)
    assert exc.value.component == "discover"
    assert str(tmp_path) not in exc.value.message


def test_hard_excluded_names_count_toward_the_entry_cap(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-13 ruling 5: every listed name counts, hard-excluded ones included."""
    make(tmp_path, ".git/x", "node_modules/y", "a/1.py", "a/2.py", "z.py")
    # Root names, sorted: .git, a, node_modules, z.py (4). Cap 5: a has 2 children
    # and would take the total to 6, so a is one "walk limit" entry.
    monkeypatch.setattr(d, "WALK_MAX_ENTRIES", 5)
    res = walk_worktree(tmp_path)
    assert res.files == ("z.py",)
    assert res.skipped == (SkippedFile("a", "walk limit"),)
    assert res.entries == 4


@pytest.mark.skipif(os.name != "posix", reason="needs a file system that takes non-UTF-8 names")
def test_non_utf8_tree_name_is_unsupported_path(tmp_path: Path, strategy: str) -> None:
    """I-13 ruling 3 / QA F2: a surrogateescape name is SkippedFile with a U+XXXX path."""
    weird = tmp_path / "weird"
    weird.mkdir()
    fd = os.open(os.fsencode(weird) + b"/\xff.py", os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"x = 1\n")
    os.close(fd)
    (name,) = os.listdir(weird)
    assert name == "\udcff.py"
    res = walk_worktree(tmp_path)
    assert res.files == ()
    # Expected path is I-14's U+XXXX form, taken from the spec, not from the helper.
    assert res.skipped == (SkippedFile("weird/U+DCFF.py", "unsupported path"),)


@pytest.mark.skipif(not POSIX, reason="Windows cannot create a name containing ':'")
def test_ntfs_stream_style_names_are_not_entered(tmp_path: Path, strategy: str) -> None:
    """SR L2: '.git::$INDEX_ALLOCATION' and '.GIT:stream' are hard-excluded by name."""
    make(tmp_path, "ok.py", ".git::$INDEX_ALLOCATION/config", ".GIT:stream")
    res = walk_worktree(tmp_path)
    assert res.files == ("ok.py",)
    assert res.skipped == ()
