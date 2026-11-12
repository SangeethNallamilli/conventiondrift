"""Behaviour test: ``-c core.fsmonitor=false`` blocks a repo-configured fsmonitor hook (SR N-1).

A hostile repository sets ``core.fsmonitor`` to a script that writes a sentinel.
The control proves the hook is real on this git: ``changed_files``' exact
``diff-tree`` argv and environment, minus only ``-c core.fsmonitor=false``,
creates the sentinel. The same argv with the flag does not, and neither does
any T-008 operation through GitReader.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from conventiondrift import gitread
from conventiondrift.gitread import GitReader

_REAL_RUN = subprocess.run
_GIT = shutil.which("git") or "git"
_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the hook is a POSIX shell script")


def _git(repo: Path, *args: str) -> str:
    """Test helper only: plain git, with no hardening."""
    out = _REAL_RUN(
        [_GIT, *args], cwd=repo, env=dict(_ENV, HOME=str(repo)), check=True, capture_output=True
    )
    return out.stdout.decode().strip()


@pytest.fixture
def hostile(tmp_path: Path) -> tuple[Path, Path, str, str]:
    """A repo whose ``core.fsmonitor`` hook writes a sentinel: (repo, sentinel, base, head)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    sentinel = tmp_path / "sentinel"
    hook = tmp_path / "fsmonitor-hook"
    hook.write_text(f"#!/bin/sh\necho ran >> '{sentinel}'\nexit 1\n")
    hook.chmod(0o755)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.py").write_text("1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("2\n")
    _git(repo, "commit", "-q", "-am", "head")
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "config", "core.fsmonitor", str(hook))
    assert not sentinel.exists()
    return repo, sentinel, base, head


def _hardened_env(repo: Path, home: str) -> dict[str, str]:
    return gitread._environment(home, os.environ.get("PATH", ""), repo)


def _changed_files_argv(repo: Path, base: str, head: str, *, drop_fsmonitor: bool) -> list[str]:
    """The exact argv ``changed_files`` runs, optionally without the fsmonitor pair."""
    args = ["-r", "-M", "-z", "--name-status", "--end-of-options", base, head]
    argv = GitReader(repo)._command("diff-tree", args)
    i = argv.index("core.fsmonitor=false")
    assert argv[i - 1] == "-c"
    return argv[: i - 1] + argv[i + 1 :] if drop_fsmonitor else argv


def _run_hardened(repo: Path, argv: list[str]) -> int:
    with tempfile.TemporaryDirectory() as home:
        out = _REAL_RUN(argv, cwd=repo, env=_hardened_env(repo, home), capture_output=True)
    return out.returncode


def test_control_diff_tree_without_the_flag_runs_the_hook(
    hostile: tuple[Path, Path, str, str],
) -> None:
    repo, sentinel, base, head = hostile
    assert _run_hardened(repo, _changed_files_argv(repo, base, head, drop_fsmonitor=True)) == 0
    assert sentinel.exists()  # the hook is real: without the flag, diff-tree runs it


def test_the_same_diff_tree_with_the_flag_does_not(hostile: tuple[Path, Path, str, str]) -> None:
    repo, sentinel, base, head = hostile
    assert _run_hardened(repo, _changed_files_argv(repo, base, head, drop_fsmonitor=False)) == 0
    assert not sentinel.exists()


def test_no_t008_operation_runs_the_hook(hostile: tuple[Path, Path, str, str]) -> None:
    repo, sentinel, base, head = hostile
    reader = GitReader(repo)
    entries = reader.tree(head)
    reader.blob(entries[0][1], 100)
    assert reader.changed_files(base, head) == [("M", "a.py", "a.py")]
    reader.first_parent_chain(head, 5)
    assert b"+2\n" in b"".join(reader.patches(base, head))
    reader.is_shallow()
    assert not sentinel.exists()
