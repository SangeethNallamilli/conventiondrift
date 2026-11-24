"""The shared long-path tree helper (D-TL-78 #5)."""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import long_paths
import pytest

POSIX = os.name == "posix"
pytestmark = pytest.mark.skipif(not POSIX, reason="the helper builds with dir_fd (POSIX only)")


def test_files_are_made_below_the_chain_with_their_folders(tmp_path: Path) -> None:
    long_paths.build_tree(tmp_path, ["a", "b"], ["x.py", "c/d/y.py", "c/z.py"])
    made = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file())
    assert made == ["a/b/c/d/y.py", "a/b/c/z.py", "a/b/x.py"]
    assert (tmp_path / "a/b/x.py").read_bytes() == b""


def test_paths_past_path_max_are_built(tmp_path: Path) -> None:
    chain = [f"{k:02d}" + "n" * 198 for k in range(24)]  # about 4,800 characters
    long_paths.build_tree(tmp_path, chain, ["f.py"])
    assert len(os.path.join(tmp_path, *chain, "f.py")) > 4_096
    fd = os.open(tmp_path, os.O_RDONLY)
    try:
        for name in chain:
            inner = os.open(name, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = inner
        assert os.listdir(fd) == ["f.py"]
    finally:
        os.close(fd)


def _refuse(code: int) -> object:
    def mkdir(*args: object, **kwargs: object) -> None:
        raise OSError(code, os.strerror(code))

    return mkdir


def test_a_refused_name_skips_where_the_tree_may_be_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(long_paths, "MUST_BUILD_LONG_PATHS", False)
    monkeypatch.setattr(os, "mkdir", _refuse(errno.ENAMETOOLONG))
    with pytest.raises(pytest.skip.Exception):
        long_paths.build_or_skip(tmp_path, ["a"], ["f.py"])


def test_a_refused_name_fails_on_the_legs_that_must_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(long_paths, "MUST_BUILD_LONG_PATHS", True)
    monkeypatch.setattr(os, "mkdir", _refuse(errno.ENAMETOOLONG))
    with pytest.raises(OSError) as raised:
        try:
            long_paths.build_or_skip(tmp_path, ["a"], ["f.py"])
        except pytest.skip.Exception as exc:
            pytest.fail(f"build_or_skip skipped instead of failing: {exc}")
    assert raised.value.errno == errno.ENAMETOOLONG


def test_any_other_error_fails_even_where_skips_are_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(long_paths, "MUST_BUILD_LONG_PATHS", False)
    monkeypatch.setattr(os, "mkdir", _refuse(errno.EACCES))
    with pytest.raises(PermissionError):
        try:
            long_paths.build_or_skip(tmp_path, ["a"], ["f.py"])
        except pytest.skip.Exception as exc:
            pytest.fail(f"build_or_skip skipped instead of failing: {exc}")


def test_the_legs_that_must_build_are_ubuntu_and_macos_ci_only() -> None:
    must = (
        bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
        and sys.platform in ("linux", "darwin")
        and not os.environ.get("GIT_MIN_VERSION")
    )
    assert long_paths.MUST_BUILD_LONG_PATHS is must
