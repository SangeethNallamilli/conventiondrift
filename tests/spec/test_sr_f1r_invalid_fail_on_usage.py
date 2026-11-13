"""SR F1-R / AC-F9.1 / I-4: invalid explicit --fail-on with base fail-on none exits 2.

On the normal path T-031 must reject a bad --fail-on before error_fail_on() is
consulted. error_fail_on("bogus", "none") would otherwise return the already-read
base value "none" and exit 0. This is a strict xfail until T-031 lands
(XFAIL_T031). The assertions require the I-4 usage-error shape and a message
that lists the valid values, so the T-001 skeleton's generic exit 2 does not
xpass.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest

from conventiondrift.core import FailOn
from fixtures.gitrepo import GitRepo

XFAIL_T031 = pytest.mark.xfail(strict=True, reason="needs T-031 I-4 parsing")

# AC-F9.1 / I-4: the message must list these three values. Pin the code's
# FailOn literal to that list (D-TL-25).
SPEC_FAIL_ON: tuple[str, ...] = ("none", "new-stale", "any-stale")
assert get_args(FailOn) == SPEC_FAIL_ON
VALID = SPEC_FAIL_ON
# Look-alikes that must not be treated as a valid value (SR F1): unknown,
# case-folded, leading space, trailing space. None of these is in VALID.
INVALID = ("bogus", "NEW-STALE", " none", "none ")
assert not any(value in VALID for value in INVALID)


def _clean_env(home: Path) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "GIT_", "GITHUB_", "CONVENTIONDRIFT"))
    }
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "PYTHONUTF8": "1",
        }
    )
    return env


def _run(cwd: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv list, no shell
        [sys.executable, "-m", "conventiondrift", *args],
        cwd=cwd,
        env=_clean_env(cwd.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )


@pytest.fixture
def repo_with_base_none(tmp_path: Path) -> Path:
    repo = GitRepo.init(tmp_path / "repo")
    repo.commit_files(
        "base with fail-on none",
        {
            ".conventiondrift.yml": "fail-on: none\n",
            "AGENTS.md": "- Use logging, not print.\n",
            "src/app.py": "import logging\n",
        },
        date="2026-01-01T12:00:00+00:00",
    )
    return repo.path


@XFAIL_T031
@pytest.mark.parametrize("bad", INVALID)
def test_sr_f1r_invalid_explicit_fail_on_with_base_none_exits_2(
    repo_with_base_none: Path, bad: str
) -> None:
    proc = _run(
        repo_with_base_none,
        ["check", "--repo", str(repo_with_base_none), "--fail-on", bad],
    )
    assert proc.returncode == 2, (
        "AC-F9.1 / I-4 / SR F1-R: a bad --fail-on is a usage error even when the "
        f"base config is fail-on: none; got exit {proc.returncode}\n"
        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )
    assert proc.stdout == "", "I-4: usage error leaves stdout empty"
    err = proc.stderr
    assert "conventiondrift: error:" in err, f"I-4: stderr has the error line: {err!r}"
    for value in VALID:
        assert value in err, f"AC-F9.1: message lists valid value {value!r}: {err!r}"
