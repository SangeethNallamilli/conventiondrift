"""T-010b part 2 unit tests: the ``walk_worktree`` filter hook and
``read_git_info_exclude`` (DESIGN §12 A-3 condition 4, I-13 scan-walk rulings 4 and 6)."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

import conventiondrift.discover.safefs as d
from conventiondrift.discover.safefs import read_git_info_exclude, walk_worktree
from conventiondrift.errors import FileSkipped
from conventiondrift.model import SkippedFile

POSIX = os.name == "posix"


@pytest.fixture(params=["dir_fd", "by_path"])
def strategy(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    if request.param == "dir_fd" and not d._USE_DIR_FD:
        pytest.skip("platform has no dir_fd/O_NOFOLLOW")  # never on Linux/macOS CI
    monkeypatch.setattr(d, "_USE_DIR_FD", request.param == "dir_fd")
    return str(request.param)


def make(root: Path, *files: str) -> None:
    for rel in files:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x = 1\n")


def symlink(target: Path | str, link: Path, *, is_dir: bool = False) -> None:
    """As in test_worktree_walk.py: a failure only skips locally, never under CI."""
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except OSError as exc:
        message = f"failed to create symlink {link} -> {target}: {exc}"
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or sys.platform == "win32":
            pytest.fail(message)
        pytest.skip(message)


class Recorder:
    """A walk filter that drops the paths it is given and records every call."""

    def __init__(self, drop: Sequence[str] = ()) -> None:
        self.to_drop = set(drop)
        self.calls: list[tuple[str, ...]] = []

    def enter(self, folder: str, names: Sequence[str]) -> None:
        self.calls.append(("enter", folder, *sorted(names)))

    def drop(self, path: str, is_dir: bool) -> bool:
        self.calls.append(("drop", path, {True: "dir", False: "file"}[is_dir]))
        return path in self.to_drop


# ------------------------------------------------------------------ walk filter


def test_without_a_filter_nothing_changes(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "a.py", "b/c.py")
    assert walk_worktree(tmp_path) == walk_worktree(tmp_path, walk_filter=Recorder())


def test_enter_sees_each_folder_before_its_entries(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "a.py", "b/c.py", "b/d/e.py")
    (tmp_path / ".git").mkdir()
    rec = Recorder()
    walk_worktree(tmp_path, walk_filter=rec)
    assert rec.calls == [
        ("enter", "", ".git", "a.py", "b"),  # hard-excluded names are seen, never offered
        ("drop", "a.py", "file"),
        ("drop", "b", "dir"),
        ("enter", "b", "c.py", "d"),
        ("drop", "b/c.py", "file"),
        ("drop", "b/d", "dir"),
        ("enter", "b/d", "e.py"),
        ("drop", "b/d/e.py", "file"),
    ]


def test_a_dropped_file_is_not_listed(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "a.py", "b.py")
    result = walk_worktree(tmp_path, walk_filter=Recorder(["a.py"]))
    assert result.files == ("b.py",)
    assert result.entries == 2  # listed names still count (I-12 scan_walk_entries)


def test_a_dropped_folder_is_not_entered(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "b/c.py", "b/d/e.py", "f.py")
    rec = Recorder(["b"])
    result = walk_worktree(tmp_path, walk_filter=rec)
    assert result.files == ("f.py",)
    assert not any(call[1].startswith("b/") for call in rec.calls)
    assert result.entries == 2


def test_a_dropped_deep_folder_is_not_a_walk_limit(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(d, "WALK_MAX_DEPTH", 1)
    make(tmp_path, "a/b/c.py", "a/k/c.py")
    result = walk_worktree(tmp_path, walk_filter=Recorder(["a/b"]))
    assert result.skipped == (SkippedFile("a/k", "walk limit"),)


@pytest.mark.skipif(not POSIX, reason="FIFOs are POSIX only")
def test_a_dropped_special_file_is_not_reported(tmp_path: Path, strategy: str) -> None:
    os.mkfifo(tmp_path / "p")
    os.mkfifo(tmp_path / "q")
    result = walk_worktree(tmp_path, walk_filter=Recorder(["p"]))
    assert result.skipped == (SkippedFile("q", "special file"),)


def test_a_dropped_symlink_is_not_reported(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "t.py")
    symlink("t.py", tmp_path / "l1.py")
    symlink("t.py", tmp_path / "l2.py")
    result = walk_worktree(tmp_path, walk_filter=Recorder(["l1.py"]))
    assert result.skipped == (SkippedFile("l2.py", "symlink"),)


@pytest.mark.skipif(not POSIX, reason="a backslash is a separator on Windows")
def test_a_bad_name_is_offered_as_a_file(tmp_path: Path, strategy: str) -> None:
    make(tmp_path, "a\\b.py", "c\\d.py")
    rec = Recorder(["a\\b.py"])
    result = walk_worktree(tmp_path, walk_filter=rec)
    assert result.skipped == (SkippedFile("c\\d.py", "unsupported path"),)
    assert ("drop", "a\\b.py", "file") in rec.calls


def test_an_unlistable_entry_is_offered_as_a_file(
    tmp_path: Path, strategy: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    make(tmp_path, "a.py", "b.py")
    real = os.lstat

    def fail(path: str, *a: object, **k: object) -> os.stat_result:
        if str(path).endswith(".py"):
            raise PermissionError("no")
        return real(path, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "lstat", fail)
    result = walk_worktree(tmp_path, walk_filter=Recorder(["a.py"]))
    assert result.skipped == (SkippedFile("b.py", "unreadable"),)


# ------------------------------------------------------------------ .git/info/exclude


def test_info_exclude_is_read_from_a_real_git_folder(tmp_path: Path) -> None:
    (tmp_path / ".git" / "info").mkdir(parents=True)
    (tmp_path / ".git" / "info" / "exclude").write_bytes(b"*.tmp\n")
    assert read_git_info_exclude(tmp_path, 65_536) == b"*.tmp\n"


def test_no_git_folder_reads_nothing(tmp_path: Path) -> None:
    assert read_git_info_exclude(tmp_path, 65_536) is None


def test_a_gitlink_file_is_never_followed(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "info").mkdir(parents=True)
    (elsewhere / "info" / "exclude").write_bytes(b"*.tmp\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / ".git").write_text(f"gitdir: {elsewhere}\n")
    assert read_git_info_exclude(root, 65_536) is None


def test_a_symlinked_git_folder_is_never_followed(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "info").mkdir(parents=True)
    (elsewhere / "info" / "exclude").write_bytes(b"*.tmp\n")
    root = tmp_path / "root"
    root.mkdir()
    symlink(elsewhere, root / ".git", is_dir=True)
    assert read_git_info_exclude(root, 65_536) is None


def test_a_junction_git_folder_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".git" / "info").mkdir(parents=True)
    (tmp_path / ".git" / "info" / "exclude").write_bytes(b"*.tmp\n")
    monkeypatch.setattr(d, "_is_reparse_point", lambda st: isinstance(st, os.stat_result))
    assert read_git_info_exclude(tmp_path, 65_536) is None


def test_a_symlinked_info_folder_is_refused(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "exclude").write_bytes(b"*.tmp\n")
    root = tmp_path / "root"
    (root / ".git").mkdir(parents=True)
    symlink(elsewhere, root / ".git" / "info", is_dir=True)
    with pytest.raises(FileSkipped) as caught:
        read_git_info_exclude(root, 65_536)
    assert caught.value.reason == "symlink"


def test_a_symlinked_exclude_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "patterns").write_bytes(b"*.tmp\n")
    (tmp_path / ".git" / "info").mkdir(parents=True)
    symlink(tmp_path / "patterns", tmp_path / ".git" / "info" / "exclude")
    with pytest.raises(FileSkipped) as caught:
        read_git_info_exclude(tmp_path, 65_536)
    assert caught.value.reason == "symlink"


@pytest.mark.skipif(not POSIX, reason="FIFOs are POSIX only")
def test_a_fifo_exclude_file_is_refused_without_opening(tmp_path: Path) -> None:
    (tmp_path / ".git" / "info").mkdir(parents=True)
    os.mkfifo(tmp_path / ".git" / "info" / "exclude")
    with pytest.raises(FileSkipped) as caught:
        read_git_info_exclude(tmp_path, 65_536)
    assert caught.value.reason == "special file"


def test_an_exclude_file_over_the_limit_is_size_limit(tmp_path: Path) -> None:
    (tmp_path / ".git" / "info").mkdir(parents=True)
    (tmp_path / ".git" / "info" / "exclude").write_bytes(b"x" * 11)
    assert read_git_info_exclude(tmp_path, 11) == b"x" * 11
    (tmp_path / ".git" / "info" / "exclude").write_bytes(b"x" * 12)
    with pytest.raises(FileSkipped) as caught:
        read_git_info_exclude(tmp_path, 11)
    assert caught.value.reason == "size limit"


def test_a_missing_exclude_file_is_unreadable(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    with pytest.raises(FileSkipped) as caught:
        read_git_info_exclude(tmp_path, 65_536)
    assert caught.value.reason == "unreadable"
