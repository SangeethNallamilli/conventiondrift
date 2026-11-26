"""Tests for scripts/ci/check_dco.py (uniform exclusion rule, 2026-11-26).

Builds throwaway git repos in tmp directories and runs the script as a
subprocess, mirroring how the dco job invokes it (DCO_BASE_SHA /
DCO_HEAD_SHA / DCO_EXCLUDE_REFS). No network, no fixtures.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "check_dco.py"


def _run_git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True, capture_output=True
    ).stdout.strip()


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(repo, "init", "-q", "--initial-branch=main", ".")
    _run_git(repo, "config", "user.name", "Test")
    _run_git(repo, "config", "user.email", "test@example.com")
    return repo


def _commit(repo: Path, message: str, *, signoff: bool) -> str:
    args = ["commit", "--allow-empty", "-m", message]
    if signoff:
        args.append("--signoff")
    _run_git(repo, *args)
    return _run_git(repo, "rev-parse", "HEAD")


def _env(base: str, head: str, exclude: list[str]) -> dict[str, str]:
    """Inherit the ambient environment (so `git` resolves on every OS,
    Windows included) and layer the script's inputs on top."""
    env = dict(os.environ)
    env["DCO_BASE_SHA"] = base
    env["DCO_HEAD_SHA"] = head
    env["DCO_EXCLUDE_REFS"] = " ".join(exclude)
    return env


def _run_script(
    repo: Path, base: str, head: str, exclude: list[str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
        ],
        env=_env(base, head, exclude),
        cwd=str(repo),
        text=True,
        capture_output=True,
    )


def test_commit_without_signoff_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    base = _commit(repo, "base", signoff=False)
    head = _commit(repo, "no trailer here", signoff=False)
    done = _run_script(repo, base, head, [])
    assert done.returncode == 1
    assert "no Signed-off-by" in done.stderr


def test_commit_with_signoff_passes(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    base = _commit(repo, "base", signoff=False)
    head = _commit(repo, "trailer present", signoff=True)
    done = _run_script(repo, base, head, [])
    assert done.returncode == 0, done.stderr


def test_excluded_ref_skips_trailerless_commit(tmp_path: Path) -> None:
    """The uniform exclusion rule: a trailer-less commit that already
    exists on an exclusion ref (e.g. main) must not fail a PR whose base
    lacks it."""
    repo = _init_repo(tmp_path)  # commits so far are on main
    shared = _commit(repo, "shared base", signoff=False)
    main_only = _commit(repo, "main-side commit without trailer", signoff=False)
    _run_git(repo, "checkout", "-q", "-b", "feature", shared)  # feature starts at shared
    feature = _commit(repo, "feature commit", signoff=True)
    # PR range: base=feature, head=main_only-side tip; main_only is
    # trailer-less but lives on the "main" exclusion ref.
    done = _run_script(repo, feature, main_only, ["main"])
    assert done.returncode == 0, done.stderr


def test_trailerless_commit_not_on_exclusion_refs_still_fails(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)  # main at base
    base = _commit(repo, "base", signoff=False)
    _run_git(repo, "checkout", "-q", "-b", "pr")
    head = _commit(repo, "unreachable without trailer", signoff=False)
    done = _run_script(repo, base, head, ["main"])
    assert done.returncode == 1


def test_merge_commit_on_exclusion_ref_is_skipped(tmp_path: Path) -> None:
    """A trailer-less merge commit that lives on an exclusion ref (the
    pre-reversal promotion shape) is out of scope for a new PR."""
    repo = _init_repo(tmp_path)
    shared = _commit(repo, "shared base", signoff=False)
    left = _commit(repo, "left", signoff=True)
    _run_git(repo, "checkout", "-q", "-b", "side", shared)
    right = _commit(repo, "right without trailer", signoff=False)
    _run_git(repo, "checkout", "-q", "main")
    _run_git(
        repo,
        "merge",
        "--no-ff",
        "-q",
        "--no-edit",
        "-m",
        "merge commit without trailer",
        "side",
    )
    merge = _run_git(repo, "rev-parse", "HEAD")
    _run_git(repo, "branch", "other", left)
    other = _commit(repo, "other commit", signoff=True)
    done = _run_script(repo, other, merge, ["main"])
    assert done.returncode == 0, done.stderr


def test_unresolvable_exclude_ref_fails_closed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    base = _commit(repo, "base", signoff=False)
    head = _commit(repo, "head", signoff=True)
    done = _run_script(repo, base, head, ["no/such/ref"])
    assert done.returncode != 0


def test_empty_range_passes(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    base = _commit(repo, "base", signoff=False)
    done = _run_script(repo, base, base, [])
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("missing_env", ["DCO_BASE_SHA", "DCO_HEAD_SHA"])
def test_missing_env_fails(tmp_path: Path, missing_env: str) -> None:
    repo = _init_repo(tmp_path)
    head = _commit(repo, "head", signoff=True)
    env = _env(head, head, [])
    env.pop(missing_env)
    done = subprocess.run(
        [sys.executable, str(SCRIPT)],
        env=env,
        cwd=str(repo),
        text=True,
        capture_output=True,
    )
    assert done.returncode == 2
