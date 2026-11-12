"""CLI contract tests from INTERFACES.md 1.0 I-4 (not from the current code).

Each case runs two ways, as a subprocess:
  * the installed `conventiondrift` console script ([project.scripts], I-4 synopsis)
  * `python -m conventiondrift`

I-4 says:
  * `conventiondrift --version` is part of the synopsis (exit 0).
  * Exit 2 is a usage error: "an unknown flag, a bad `--fail-on` value, an
    unresolvable revision or a missing `--repo`", and "Giving only one of the
    two [`--base`/`--head`] is a usage error."

Deliberately NOT asserted: that arbitrary or valid input exits 2. That is only
the T-001 skeleton's behaviour and the contract says otherwise.
"""

from __future__ import annotations

import importlib.metadata
import os
import subprocess
import sys
from pathlib import Path

import pytest

TIMEOUT_S = 60


def _console_script() -> list[str]:
    bindir = Path(sys.executable).parent
    for name in ("conventiondrift", "conventiondrift.exe"):
        candidate = bindir / name
        if candidate.is_file():
            if candidate.suffix == ".exe":
                return [str(candidate)]
            # A setuptools console script is a Python file; run it with this interpreter.
            return [sys.executable, str(candidate)]
    pytest.fail(f"installed console script 'conventiondrift' not found next to {sys.executable}")


INVOCATIONS = {
    "console_script": _console_script,
    "python_m": lambda: [sys.executable, "-m", "conventiondrift"],
}


@pytest.fixture(params=sorted(INVOCATIONS), ids=sorted(INVOCATIONS))
def cli(request: pytest.FixtureRequest) -> list[str]:
    return INVOCATIONS[request.param]()


def _clean_env(home: Path) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "GIT_", "GITHUB_", "CONVENTIONDRIFT"))
    }
    env.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LC_ALL": "C.UTF-8",
        }
    )
    return env


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """An empty git repo as cwd, so `--repo .` is valid and only the flag under test is wrong."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(  # noqa: S603
        ["git", "init", "-q", "-b", "main", str(repo)],  # noqa: S607
        check=True,
        env=_clean_env(tmp_path),
        capture_output=True,
    )
    return repo


def _run(cmd: list[str], args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [*cmd, *args],
        cwd=cwd,
        env=_clean_env(cwd.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=TIMEOUT_S,
        check=False,
    )


# (a) --version -------------------------------------------------------------------------------
def test_cli_contract_version(cli: list[str], workdir: Path) -> None:
    expected = f"conventiondrift {importlib.metadata.version('conventiondrift')}"
    proc = _run(cli, ["--version"], workdir)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [expected]


# (b) usage errors exit 2, non-empty stderr, empty stdout ----------------------------------------
USAGE_ERRORS = {
    "unknown_top_level_flag": ["--no-such-flag-cd"],
    "check_fail_on_bogus": ["check", "--fail-on", "bogus"],
    "check_base_without_head": ["check", "--base", "X"],
}


@pytest.mark.parametrize("args", list(USAGE_ERRORS.values()), ids=list(USAGE_ERRORS))
def test_cli_contract_usage_error_exit_2(cli: list[str], workdir: Path, args: list[str]) -> None:
    proc = _run(cli, args, workdir)
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)
    assert proc.stderr.strip(), "a usage error must explain itself on stderr"
    assert proc.stdout == "", "a usage error must print nothing on stdout"
