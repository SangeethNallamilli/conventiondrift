"""CLI contract tests from INTERFACES.md 1.0 I-4 (written from the contract, not the code).

Each case runs two ways, as a subprocess:
  * the installed `conventiondrift` console script, invoked directly from the venv bin
    directory ([project.scripts], I-4 synopsis)
  * `python -m conventiondrift`

I-4 says:
  * `--version` prints exactly one stdout line `conventiondrift <version>` with
    `<version>` = `conventiondrift.__version__`, writes nothing to stderr, exits 0, reads
    neither git nor config, and takes precedence over every other argument.
  * Exit 2 is a usage error: "an unknown flag, a bad `--fail-on` value, an unresolvable
    revision or a missing `--repo`"; "Giving only one of the two [`--base`/`--head`] is a
    usage error"; the synopsis also fixes the `--format` values and `--history-days N`.
  * On a usage error stdout stays empty, stderr gets the usage line then one line
    `conventiondrift: error: <message>`, and no file is written (`--stats-out` included).

What the T-001 skeleton does not do yet is `xfail(strict=True)` naming the task that
implements it (T-031 for `check` parsing, T-032 for `--version`), so the xfail turns into a
failure the moment the behaviour lands and the marker must be removed.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

import conventiondrift
from fixtures.gitrepo import GitRepo

TIMEOUT_S = 60
XFAIL_T031 = pytest.mark.xfail(strict=True, reason="needs T-031 I-4 parsing")
XFAIL_T032 = pytest.mark.xfail(strict=True, reason="needs T-032 --version precedence")


def _console_script() -> list[str]:
    bindir = Path(sys.executable).parent  # the venv's bin/ (Scripts\ on Windows)
    for name in ("conventiondrift", "conventiondrift.exe"):
        candidate = bindir / name
        if candidate.is_file():
            return [str(candidate)]
    pytest.fail(f"installed console script 'conventiondrift' not found in {bindir}")


def _python_m() -> list[str]:
    return [sys.executable, "-m", "conventiondrift"]


INVOCATIONS: dict[str, Callable[[], list[str]]] = {
    "console_script": _console_script,
    "python_m": _python_m,
}


@pytest.fixture(params=sorted(INVOCATIONS), ids=sorted(INVOCATIONS))
def cli(request: pytest.FixtureRequest) -> list[str]:
    make: Callable[[], list[str]] = INVOCATIONS[request.param]
    return make()


def _clean_env(home: Path, *, path: str | None = None) -> dict[str, str]:
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
            "PYTHONUTF8": "1",  # portable, unlike LC_ALL=C.UTF-8
        }
    )
    if path is not None:
        env["PATH"] = path
    return env


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """A repo with one commit as cwd, so `HEAD` resolves and only the flag under test is wrong."""
    repo = GitRepo.init(tmp_path / "repo")
    repo.commit_files(
        "initial",
        {"AGENTS.md": "- Use logging, not print.\n", "src/app.py": "import logging\n"},
        date="2026-01-01T12:00:00+00:00",
    )
    return repo.path


def _run(
    cmd: list[str], args: list[str], cwd: Path, *, path: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv list, no shell
        [*cmd, *args],
        cwd=cwd,
        env=_clean_env(cwd.parent, path=path),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=TIMEOUT_S,
        check=False,
    )


# (a) --version -------------------------------------------------------------------------------
EXPECTED_VERSION_STDOUT = f"conventiondrift {conventiondrift.__version__}\n"


def _assert_version_output(proc: subprocess.CompletedProcess[str]) -> None:
    assert proc.returncode == 0, f"I-4: --version exits 0 (got {proc.returncode}): {proc.stderr}"
    assert proc.stdout == EXPECTED_VERSION_STDOUT, "I-4: exactly one line 'conventiondrift <v>'"
    assert proc.stderr == "", "I-4: --version writes nothing to stderr"


def test_cli_contract_version(cli: list[str], workdir: Path) -> None:
    _assert_version_output(_run(cli, ["--version"], workdir))


def test_cli_contract_version_reads_no_git(cli: list[str], tmp_path: Path) -> None:
    """I-4: --version reads neither git nor config: no git on PATH, cwd not a repo."""
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    cwd = tmp_path / "not-a-repo"
    cwd.mkdir()
    _assert_version_output(_run(cli, ["--version"], cwd, path=str(empty_bin)))


VERSION_PRECEDENCE = {
    "version_then_bad_subcommand_flag": ["--version", "check", "--bogus"],
    "check_then_version": ["check", "--version"],
    "version_with_missing_repo": ["check", "--repo", "does-not-exist-cd", "--version"],
}


@XFAIL_T032
@pytest.mark.parametrize("args", list(VERSION_PRECEDENCE.values()), ids=list(VERSION_PRECEDENCE))
def test_cli_contract_version_takes_precedence(
    cli: list[str], workdir: Path, args: list[str]
) -> None:
    _assert_version_output(_run(cli, args, workdir))


# (b) usage errors --------------------------------------------------------------------------------
USAGE_ERRORS = {
    "unknown_top_level_flag": ["--no-such-flag-cd", "check"],
    "check_fail_on_bogus": ["check", "--fail-on", "bogus"],
    "check_format_bogus": ["check", "--format", "bogus"],
    "check_history_days_not_int": ["check", "--history-days", "ninety"],
    "check_missing_repo": ["check", "--repo", "does-not-exist-cd"],
    "check_unresolvable_revision": ["check", "--base", "no-such-rev-cd", "--head", "HEAD"],
    "check_base_without_head": ["check", "--base", "HEAD"],
    "check_head_without_base": ["check", "--head", "HEAD"],
}
_ERROR_LINE = re.compile(r"conventiondrift: error: \S.*")


@pytest.fixture(params=list(USAGE_ERRORS), ids=list(USAGE_ERRORS))
def usage_error(
    request: pytest.FixtureRequest, cli: list[str], workdir: Path
) -> tuple[subprocess.CompletedProcess[str], list[Path]]:
    """Run one usage-error case with --stats-out and --output pointing at fresh paths."""
    out_dir = workdir.parent / "out"
    out_dir.mkdir()
    stats, output = out_dir / "s.json", out_dir / "o"
    args = [*USAGE_ERRORS[request.param], "--stats-out", str(stats), "--output", str(output)]
    return _run(cli, args, workdir), [stats, output]


def test_cli_contract_usage_error_exit_2(
    usage_error: tuple[subprocess.CompletedProcess[str], list[Path]],
) -> None:
    proc, _ = usage_error
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)


def test_cli_contract_usage_error_stderr_not_empty(
    usage_error: tuple[subprocess.CompletedProcess[str], list[Path]],
) -> None:
    proc, _ = usage_error
    assert proc.stderr.strip(), "I-4: a usage error explains itself on stderr"


def test_cli_contract_usage_error_stdout_empty(
    usage_error: tuple[subprocess.CompletedProcess[str], list[Path]],
) -> None:
    proc, _ = usage_error
    assert proc.stdout == "", "I-4: on a usage error stdout stays empty"


def test_cli_contract_usage_error_writes_no_files(
    usage_error: tuple[subprocess.CompletedProcess[str], list[Path]],
) -> None:
    _, paths = usage_error
    written = [str(p) for p in paths if p.exists()]
    assert written == [], "I-4: a usage error writes no file, --stats-out included"


@XFAIL_T031
def test_cli_contract_usage_error_stderr_format(
    usage_error: tuple[subprocess.CompletedProcess[str], list[Path]],
) -> None:
    proc, _ = usage_error
    lines = proc.stderr.splitlines()
    assert lines, "I-4: stderr has the usage line and the error line"
    assert lines[0].startswith("usage: conventiondrift"), f"I-4: usage line first: {lines!r}"
    errors = [line for line in lines if line.startswith("conventiondrift: error:")]
    assert len(errors) == 1, f"I-4: exactly one 'conventiondrift: error:' line: {lines!r}"
    assert lines[-1] == errors[0], "I-4: the error line comes after the usage line"
    assert _ERROR_LINE.fullmatch(errors[0]), f"I-4: error line has a message: {errors[0]!r}"


# (c) positive control ----------------------------------------------------------------------------
@XFAIL_T031
def test_cli_contract_check_committed_repo_exits_0_or_1(
    cli: list[str], workdir: Path, tmp_path: Path
) -> None:
    """A valid scan of a committed repo is not a usage error (exit 0 or 1 by verdict)."""
    proc = _run(cli, ["check", "--repo", str(workdir)], tmp_path)
    assert proc.returncode in {0, 1}, (proc.returncode, proc.stdout, proc.stderr)
