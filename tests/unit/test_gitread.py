"""Unit tests for conventiondrift.gitread, part 1 (T-007; DESIGN §3, INTERFACES I-11 C3).

Uses real temporary git repositories. The spec and security suites under
tests/spec/ and tests/security/ own the TRACEABILITY test ids; these are unit
tests of the runner and the first five operations.
"""

import ast
import contextlib
import io
import ntpath
import os
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError, GitTooOld, GitUnavailable, UnresolvableRevision
from conventiondrift.gitread import GitReader, is_valid_sha

# Saved before any test patches subprocess.run, so fixture setup is never spied on.
_REAL_RUN = subprocess.run
_GIT = shutil.which("git") or "git"

_TEST_GIT_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str, date: str | None = None) -> str:
    """Test helper only: set up fixture repos (not the code under test)."""
    env = dict(_TEST_GIT_ENV, HOME=str(repo))
    if date is not None:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    out = _REAL_RUN([_GIT, *args], cwd=repo, env=env, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def _commit(repo: Path, msg: str, date: str | None = None) -> str:
    _git(repo, "commit", "-q", "--allow-empty", "-m", msg, date=date)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _commit(path, "first", date="2026-01-02T03:04:05+05:30")
    return path


Call = dict[str, Any]


_REAL_POPEN = subprocess.Popen


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Call]]:
    """Record every process gitread starts, then delegate to the real Popen."""
    calls: list[Call] = []
    real = _REAL_POPEN

    def recorder(*args: Any, **kwargs: Any) -> Any:
        env = kwargs.get("env") or {}
        if "GIT_OPTIONAL_LOCKS" not in env:  # a fixture helper's git, not gitread's
            return real(*args, **kwargs)
        if list(args[0])[1:] == ["--version"]:  # the once-per-reader version check
            return real(*args, **kwargs)
        home = env.get("HOME", "")
        calls.append(
            {
                "argv": list(args[0]),
                "kwargs": kwargs,
                "home_listing": os.listdir(home) if home and os.path.isdir(home) else None,
            }
        )
        return real(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", recorder)
    yield calls


def _fake_run(monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: bytes) -> None:
    """Stub the bounded runner for every git call except the version check."""
    real = gitread._run_bounded

    def fake(argv: list[str], **kwargs: Any) -> Any:
        if argv[1:] == ["--version"]:
            return real(argv, **kwargs)
        return gitread._Output(returncode, stdout)

    monkeypatch.setattr(gitread, "_run_bounded", fake)


HARDENING = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.untrackedCache=false",
    "-c", "diff.external=",
    "-c", "core.pager=cat",
    "-c", "protocol.allow=never",
    "-c", "log.showSignature=false",
    "-c", "safe.bareRepository=explicit",
]  # fmt: skip

BAD_SHAS = [
    "",
    "abc123",
    "a" * 39,
    "a" * 41,
    "a" * 63,
    "a" * 65,
    "A" * 40,
    "g" * 40,
    "a" * 40 + "\n",
    " " + "a" * 39,
    "--output=/tmp/x",
    "-" + "a" * 39,
    "HEAD",
    "a" * 39 + "\x00",
]


# --- SHA validation -------------------------------------------------------


@pytest.mark.parametrize("sha", ["0" * 40, "f" * 64, "0123456789abcdef" * 4, "deadbeef" * 5])
def test_is_valid_sha_accepts_40_and_64_lowercase_hex(sha: str) -> None:
    assert is_valid_sha(sha)


@pytest.mark.parametrize("sha", BAD_SHAS)
def test_is_valid_sha_rejects_everything_else(sha: str) -> None:
    assert not is_valid_sha(sha)


# --- the runner -----------------------------------------------------------


def test_every_call_uses_argv_list_fixed_flags_and_no_shell(repo: Path, spy: list[Call]) -> None:
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    reader.is_shallow()
    reader.has_object(head)
    reader.merge_base(head, head)
    reader.commit_date(head)
    assert len(spy) == 5
    for call in spy:
        argv = call["argv"]
        assert isinstance(call["argv"], list)
        assert os.path.isabs(argv[0])
        assert os.path.basename(argv[0]).startswith("git")
        assert argv[1 : 1 + len(HARDENING)] == HARDENING
        assert argv[1 + len(HARDENING)] in gitread.ALLOWED_SUBCOMMANDS
        assert call["kwargs"].get("shell", False) is False
        assert call["kwargs"]["stdin"] is subprocess.DEVNULL


def test_environment_is_fixed_and_nothing_else_leaks(
    repo: Path, spy: list[Call], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_DIR", "/nonexistent")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor'='touch /tmp/leak'")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "/bin/false")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(repo))
    monkeypatch.setenv("HOME", str(repo))
    assert is_valid_sha(GitReader(repo).resolve("HEAD"))
    env = spy[0]["kwargs"]["env"]
    assert env == {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_CEILING_DIRECTORIES": os.path.dirname(os.path.realpath(repo)),
        "HOME": env["HOME"],
    }
    assert env["HOME"] != str(repo)
    assert spy[0]["home_listing"] == []
    assert not os.path.exists(env["HOME"])  # removed after the call


def test_systemroot_passed_only_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    repo_dir = Path("/r/repo")  # built before os.name changes, so it stays a PosixPath
    with _simulated_windows(monkeypatch):
        nt_env = gitread._environment("/h", "/bin", repo_dir)
    posix_env = gitread._environment("/h", "/bin", repo_dir)
    base = dict(gitread.FIXED_ENV, PATH="/bin", HOME="/h", GIT_CEILING_DIRECTORIES="/r")
    assert nt_env == dict(base, SYSTEMROOT=r"C:\Windows")
    assert posix_env == base


def test_systemroot_absent_on_windows_is_not_invented(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SYSTEMROOT", raising=False)
    repo_dir = Path("/r/repo")
    with _simulated_windows(monkeypatch):
        env = gitread._environment("/h", "/bin", repo_dir)
    assert "SYSTEMROOT" not in env


def test_global_config_in_inherited_home_is_ignored(
    repo: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text("[core]\n\tfsmonitor = touch SENTINEL\n")
    monkeypatch.setenv("HOME", str(home))
    GitReader(repo).is_shallow()
    assert not (repo / "SENTINEL").exists()


def test_hostile_repo_config_runs_nothing(repo: Path, tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\ntouch {sentinel}\n")
    script.chmod(0o755)
    for hook in ("post-checkout", "pre-commit", "reference-transaction", "post-index-change"):
        (hooks / hook).write_text(f"#!/bin/sh\ntouch {sentinel}\n")
        (hooks / hook).chmod(0o755)
    with (repo / ".git" / "config").open("a") as cfg:
        cfg.write(
            f"[core]\n\tfsmonitor = {script}\n\thooksPath = {hooks}\n\tpager = {script}\n"
            f'[diff]\n\texternal = {script}\n[diff "x"]\n\ttextconv = {script}\n'
            f'[filter "x"]\n\tsmudge = {script}\n\tclean = {script}\n'
            f"[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {script}\n"
        )
    (repo / ".gitattributes").write_text("* diff=x filter=x\n")
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    assert reader.is_shallow() is False
    assert reader.has_object(head)
    assert reader.merge_base(head, head) == head
    reader.commit_date(head)
    assert not sentinel.exists()


@pytest.mark.parametrize(
    "sub",
    ["checkout", "fetch", "worktree", "blame", "config", "clone", "pull", "push", "gc",
     "update-ref", "filter-branch", "diff", "", "-c", "--exec-path", "rev-parse ", "REV-PARSE"],
)  # fmt: skip
def test_disallowed_subcommand_is_refused_before_running_git(
    repo: Path, spy: list[Call], sub: str
) -> None:
    with pytest.raises(ComponentError) as info:
        GitReader(repo)._run(sub, ["--end-of-options"])
    assert info.value.component == "gitread"
    assert spy == []


def test_allowlist_is_exactly_the_design_set() -> None:
    assert (
        frozenset(
            {
                "cat-file",
                "rev-parse",
                "rev-list",
                "merge-base",
                "ls-tree",
                "diff-tree",
                "log",
                "show",
            }
        )
        == gitread.ALLOWED_SUBCOMMANDS
    )


@pytest.mark.parametrize("sub", ["log", "show", "diff-tree"])
def test_diff_and_log_calls_get_no_ext_diff_no_textconv_no_color(
    repo: Path, spy: list[Call], sub: str
) -> None:
    head = GitReader(repo).resolve("HEAD")
    count = ["--max-count=1"] if sub == "log" else []
    GitReader(repo)._run(sub, [*count, "--end-of-options", head])
    argv = spy[-1]["argv"]
    i = argv.index(sub)
    assert argv[i + 1 : i + 4] == ["--no-ext-diff", "--no-textconv", "--no-color"]


def test_argument_with_nul_is_refused(repo: Path, spy: list[Call]) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo)._run("rev-parse", ["--verify", "HEAD\x00--output=x"])
    assert spy == []


def test_git_missing_raises_git_unavailable(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(repo / "no-such-dir"))
    with pytest.raises(GitUnavailable):
        GitReader(repo).is_shallow()


def test_git_that_cannot_start_raises_git_unavailable(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise PermissionError("exec")

    monkeypatch.setattr(subprocess, "Popen", boom)
    with pytest.raises(GitUnavailable):
        GitReader(repo).is_shallow()


def test_every_call_is_bounded(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []
    real = gitread._run_bounded

    def recorder(argv: list[str], **kwargs: Any) -> Any:
        seen.append(kwargs)
        return real(argv, **kwargs)

    monkeypatch.setattr(gitread, "_run_bounded", recorder)
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    reader.is_shallow()
    reader.has_object(head)
    reader.merge_base(head, head)
    reader.commit_date(head)
    assert seen
    for kwargs in seen:
        assert kwargs["timeout"] == gitread.GIT_TIMEOUT_SECONDS
        assert kwargs["max_stdout"] == gitread.SMALL_OUTPUT_MAX_BYTES


def test_popen_uses_pipes_devnull_stdin_and_no_shell(repo: Path, spy: list[Call]) -> None:
    GitReader(repo).is_shallow()
    for call in spy:
        kwargs = call["kwargs"]
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is subprocess.PIPE
        assert kwargs["shell"] is False
        assert "timeout" not in kwargs  # enforced by _run_bounded itself


def test_limits_are_conservative_constants() -> None:
    # I-14 bounds: 60 s per call, 4096 bytes on small-output calls.
    assert gitread.GIT_TIMEOUT_SECONDS == 60
    assert gitread.SMALL_OUTPUT_MAX_BYTES == 4096


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def _bounded(argv: list[str], tmp_path: Path, max_stdout: int = 16, timeout: float = 20.0) -> Any:
    return gitread._run_bounded(
        argv,
        cwd=tmp_path,
        env=dict(os.environ),
        label="rev-parse",
        max_stdout=max_stdout,
        timeout=timeout,
    )


def test_bounded_returns_exit_code_and_stdout(tmp_path: Path) -> None:
    out = _bounded(_py("import sys; sys.stdout.write('x' * 16); sys.exit(3)"), tmp_path)
    assert out == gitread._Output(3, b"x" * 16)


def test_bounded_stdout_over_cap_kills_with_fixed_text(tmp_path: Path) -> None:
    code = "import sys, time\nsys.stdout.write('secret' * 10); sys.stdout.flush(); time.sleep(30)"
    start = time.monotonic()
    with pytest.raises(ComponentError) as info:
        _bounded(_py(code), tmp_path)
    assert time.monotonic() - start < 10  # killed at the cap, not after the sleep
    assert info.value.component == "gitread"
    assert info.value.message == "git rev-parse output too large"
    assert "secret" not in str(info.value)


def test_bounded_large_stdout_is_never_held_whole(tmp_path: Path) -> None:
    code = "import sys\nfor _ in range(64): sys.stdout.write('y' * 1048576)"
    with pytest.raises(ComponentError, match="output too large"):
        _bounded(_py(code), tmp_path, max_stdout=1000)


def test_bounded_large_stderr_is_drained_and_discarded(tmp_path: Path) -> None:
    # 8 MiB of stderr: far past any pipe buffer, so an undrained pipe would hang.
    code = "import sys\nsys.stderr.write('fatal: secret ' * 600000); print('ok')"
    out = _bounded(_py(code), tmp_path, timeout=20.0)
    assert out == gitread._Output(0, b"ok\n")


def test_bounded_timeout_kills_with_fixed_text(tmp_path: Path) -> None:
    start = time.monotonic()
    with pytest.raises(ComponentError) as info:
        _bounded(_py("import time; time.sleep(30)"), tmp_path, timeout=0.5)
    assert time.monotonic() - start < 10
    assert info.value.message == "git rev-parse timed out"
    assert info.value.__cause__ is None


def test_bounded_timeout_after_output_closes(tmp_path: Path) -> None:
    # stdout and stderr closed, but the process keeps running: proc.wait() times out.
    code = "import os, time\nos.close(1); os.close(2); time.sleep(30)"
    with pytest.raises(ComponentError, match="timed out"):
        _bounded(_py(code), tmp_path, timeout=1.0)


def test_bounded_process_that_cannot_start_is_git_unavailable(tmp_path: Path) -> None:
    with pytest.raises(GitUnavailable):
        _bounded([str(tmp_path / "no-such-git")], tmp_path)


def test_drain_ends_quietly_on_a_closed_stream() -> None:
    stream = io.BytesIO(b"abc")
    stream.close()
    chunks: list[bytes] = []
    over = threading.Event()
    gitread._drain(stream, 10, chunks, over)
    assert chunks == [] and not over.is_set()


def test_drain_keeps_exactly_cap_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitread, "_CHUNK_BYTES", 3)
    chunks: list[bytes] = []
    over = threading.Event()
    gitread._drain(io.BytesIO(b"abcdefghij"), 4, chunks, over)
    assert b"".join(chunks) == b"abcde"
    assert over.is_set()


def test_drain_discards_everything_with_keep_minus_one() -> None:
    chunks: list[bytes] = []
    over = threading.Event()
    gitread._drain(io.BytesIO(b"x" * 200000), -1, chunks, over)
    assert chunks == [] and not over.is_set()


def test_hanging_git_is_killed_after_the_timeout(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_git = _sleeping_git(tmp_path)
    resolved = gitread._ResolvedGit(str(fake_git), os.environ["PATH"])
    monkeypatch.setattr(gitread, "_find_git", lambda _repo: resolved)
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.5)
    start = time.monotonic()
    with pytest.raises(ComponentError) as info:
        GitReader(repo).is_shallow()
    assert "timed out" in info.value.message
    assert time.monotonic() - start < 10


# --- SR-013 / I-14: locating git ------------------------------------------------


def _platform_git_name() -> str:
    return "git.exe" if os.name == "nt" else "git"


def _run_tool(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run ``argv`` if the executable is on PATH; ``None`` if it is missing."""
    resolved = shutil.which(argv[0])
    if resolved is None:
        return None
    return _REAL_RUN([resolved, *argv[1:]], check=False, capture_output=True, text=True)


def _compile_windows_exe(dest: Path, c_source: str, csharp_source: str) -> None:
    """Compile a tiny console exe so a planted git.exe is actually runnable.

    Tries gcc, clang, cl, then PowerShell Add-Type. Raises if none succeed,
    rather than skipping.
    """
    src = dest.with_suffix(".c")
    src.write_text(c_source, encoding="utf-8")
    compilers = (
        ["gcc", "-O0", "-s", "-o", str(dest), str(src)],
        ["clang", "-O0", "-s", "-o", str(dest), str(src)],
        ["cl", "/nologo", "/Fe" + str(dest), str(src)],
    )
    errors: list[str] = []
    for argv in compilers:
        completed = _run_tool(argv)
        if completed is None:
            continue
        if completed.returncode == 0 and dest.exists():
            return
        errors.append(f"{argv[0]}: {completed.stderr or completed.stdout}")
    csharp = dest.with_suffix(".cs")
    csharp.write_text(csharp_source, encoding="utf-8")
    ps = (
        "Add-Type -OutputType ConsoleApplication "
        f"-OutputAssembly '{dest}' "
        f"-TypeDefinition (Get-Content -Raw '{csharp}')"
    )
    completed = _run_tool(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
    if completed is not None and completed.returncode == 0 and dest.exists():
        return
    if completed is not None:
        errors.append(f"powershell: {completed.stderr or completed.stdout}")
    raise RuntimeError(
        "could not compile a runnable git.exe test stub; tried gcc, clang, cl, "
        "and PowerShell Add-Type. " + " | ".join(errors)
    )


def _sleeping_git(tmp_path: Path) -> Path:
    """A fake git that hangs, used by the timeout-kill test. Runnable on Windows."""
    dest = tmp_path / "bin" / _platform_git_name()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        _compile_windows_exe(
            dest,
            "#include <windows.h>\nint main(void) { Sleep(30000); return 0; }\n",
            "using System.Threading;\n"
            "class FakeGit { static void Main() { Thread.Sleep(30000); } }\n",
        )
    else:
        dest.write_text("#!/bin/sh\nexec sleep 30\n")
        dest.chmod(0o755)
    return dest


def _fake_git_in(folder: Path, name: str | None = None) -> Path:
    """Plant a git named for this platform. Resolution tests never execute it."""
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / (name if name is not None else _platform_git_name())
    # Resolution tests only need the right filename for the PATH walk. A
    # Windows .exe cannot be a shell script, and these files are never run.
    if exe.suffix.lower() == ".exe":
        exe.write_bytes(b"")
    else:
        exe.write_text("#!/bin/sh\nexit 0\n")
        exe.chmod(0o755)
    return exe


@pytest.fixture
def elsewhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A current folder that holds neither the repo nor a trusted git."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    return cwd


def _set_path(monkeypatch: pytest.MonkeyPatch, *entries: str | Path) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join(str(e) for e in entries))


_REAL_OS_NAME = os.name
_REAL_OS_PATH = os.path
_REAL_PATHSEP = os.pathsep
_REAL_GETCWD = os.getcwd


@contextlib.contextmanager
def _simulated_windows(
    monkeypatch: pytest.MonkeyPatch, *, cwd: str | None = None
) -> Iterator[None]:
    """Run the body with ``os.name == "nt"``; with ``cwd``, also with ``ntpath`` rules.

    Everything is restored on exit, before any assertion runs (SR N-9). On
    Python 3.11 ``Path(...)`` builds a ``WindowsPath`` while ``os.name`` is
    "nt" and raises, and pytest itself builds one when it reports a failure,
    which stops the whole run with INTERNALERROR. So build every ``Path``
    before entering, keep asserts outside, and put ``pytest.raises`` first in
    the ``with`` so it sees the exception after os is restored.
    ``test_windows_simulations_follow_the_rules`` checks this file for it.
    """
    monkeypatch.setattr(os, "name", "nt")
    if cwd is not None:
        monkeypatch.setattr(os, "path", ntpath)
        monkeypatch.setattr(os, "pathsep", ";")
        monkeypatch.setattr(os, "getcwd", lambda: cwd)
        monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    try:
        yield
    finally:
        monkeypatch.setattr(os, "name", _REAL_OS_NAME)
        monkeypatch.setattr(os, "path", _REAL_OS_PATH)
        monkeypatch.setattr(os, "pathsep", _REAL_PATHSEP)
        monkeypatch.setattr(os, "getcwd", _REAL_GETCWD)


def test_simulated_windows_restores_os_even_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeError), _simulated_windows(monkeypatch, cwd="C:\\"):
        inside = (os.name, os.path, os.pathsep, os.getcwd())
        raise RuntimeError
    assert inside == ("nt", ntpath, ";", "C:\\")
    assert (os.name, os.path, os.pathsep) == (_REAL_OS_NAME, _REAL_OS_PATH, _REAL_PATHSEP)
    assert os.getcwd is _REAL_GETCWD


def _is_simulation(item: ast.withitem) -> bool:
    call = item.context_expr
    return (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_simulated_windows"
    )


def test_windows_simulations_follow_the_rules() -> None:
    # SR N-9: os.name is only ever set to "nt" by _simulated_windows, and no
    # simulation builds a Path, asserts, or opens pytest.raises inside it.
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    simulations = 0
    sets_nt = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "monkeypatch.setattr":
            if [ast.unparse(a) for a in node.args[1:]] == ["'name'", "'nt'"]:
                sets_nt.append(node.lineno)
        if not isinstance(node, ast.With):
            continue
        sims = [i for i, item in enumerate(node.items) if _is_simulation(item)]
        if not sims:
            continue
        simulations += 1
        for item in node.items[sims[0] + 1 :]:
            assert "raises" not in ast.unparse(item.context_expr), f"line {node.lineno}"
        for inner in (n for stmt in node.body for n in ast.walk(stmt)):
            assert not isinstance(inner, ast.Assert), f"assert inside, line {inner.lineno}"
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
                assert inner.func.id != "Path", f"Path() inside, line {inner.lineno}"
            if isinstance(inner, ast.Attribute) and inner.attr == "raises":
                raise AssertionError(f"pytest.raises inside, line {inner.lineno}")
    helper = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_simulated_windows"
    )
    assert len(sets_nt) == 1, sets_nt  # only the helper sets os.name to "nt"
    assert helper.lineno < sets_nt[0] <= (helper.end_lineno or 0)
    assert simulations >= 20


def test_fake_git_helper_plants_git_exe_when_os_name_is_nt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _simulated_windows(monkeypatch):
        exe = _fake_git_in(tmp_path / "trusted")
        name = _platform_git_name()
    assert exe.name == "git.exe"
    assert exe.is_file()
    assert name == "git.exe"


def test_valid_absolute_path_entry_is_used(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _fake_git_in(tmp_path / "trusted")
    _set_path(monkeypatch, tmp_path / "trusted")
    found = gitread._find_git(repo)
    assert found == gitread._ResolvedGit(os.path.realpath(exe), str(tmp_path / "trusted"))


def test_symlinked_git_is_resolved_to_its_real_path(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _fake_git_in(tmp_path / "real")
    link_dir = tmp_path / "links"
    link_dir.mkdir()
    (link_dir / _platform_git_name()).symlink_to(exe)
    _set_path(monkeypatch, link_dir)
    assert gitread._find_git(repo).path == os.path.realpath(exe)


@pytest.mark.parametrize("entry", ["", ".", "bin", "./bin", "../cwd/bin"])
@pytest.mark.parametrize("windows", [False, True], ids=["posix", "nt"])
def test_empty_dot_and_relative_path_entries_are_dropped(
    repo: Path,
    tmp_path: Path,
    elsewhere: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry: str,
    windows: bool,
) -> None:
    name = "git.exe" if windows else "git"
    _fake_git_in(elsewhere, name)  # ./git, reachable through "" and "."
    _fake_git_in(elsewhere / "bin", name)  # ./bin/git, reachable through the relative entries
    trusted = _fake_git_in(tmp_path / "trusted", name)
    _set_path(monkeypatch, entry, tmp_path / "trusted")
    # On Windows, shutil.which would search the cwd first and refuse the
    # planted git.exe, knocking out a later trusted git (SR N-6).
    with _simulated_windows(monkeypatch) if windows else contextlib.nullcontext():
        found = gitread._find_git(repo)
    assert found.path == os.path.realpath(trusted)
    assert found.search_path == str(tmp_path / "trusted")  # the PATH git runs with


def test_relative_bin_entry_outside_untrusted_folders_is_never_chosen(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # N-3: a relative PATH entry must be dropped even when it resolves
    # outside the repo, workspace and cwd. A bare "bin" is still inside the
    # cwd, so the containment check would hide a missing isabs() drop; use
    # ../bin from a sibling cwd so only the relative-entry rule applies.
    # If relative entries were kept, the planted git would beat the trusted one.
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    planted = _fake_git_in(tmp_path / "bin")
    trusted = _fake_git_in(tmp_path / "trusted")
    _set_path(monkeypatch, "../bin", tmp_path / "trusted")
    found = gitread._find_git(repo)
    assert found.path == os.path.realpath(trusted)
    assert found.path != os.path.realpath(planted)
    assert found.search_path == str(tmp_path / "trusted")
    assert "../bin" not in found.search_path.split(os.pathsep)


def test_symlink_path_entry_into_the_repo_is_dropped_when_trusted_git_follows(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # N-3: per-entry realpath must drop a PATH folder that is a symlink into
    # the repo. Without realpath the entry looks innocent, which() / the walk
    # would hit the planted git first, and the binary re-check would fail
    # closed instead of using the later trusted git.
    _fake_git_in(repo / "tools")
    innocent = tmp_path / "innocent"
    innocent.symlink_to(repo / "tools")
    trusted = _fake_git_in(tmp_path / "trusted")
    _set_path(monkeypatch, innocent, tmp_path / "trusted")
    found = gitread._find_git(repo)
    assert found.path == os.path.realpath(trusted)
    assert found.search_path == str(tmp_path / "trusted")


@pytest.mark.parametrize("entry", ["", ".", "bin"])
def test_git_only_behind_a_relative_entry_fails_closed(
    repo: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch, entry: str, spy: list[Call]
) -> None:
    _fake_git_in(elsewhere)
    _fake_git_in(elsewhere / "bin")
    _set_path(monkeypatch, entry)
    with pytest.raises(ComponentError) as info:
        GitReader(repo).is_shallow()
    assert info.value.component == "gitread"
    assert info.value.message == gitread._UNTRUSTED_GIT
    assert spy == []


def test_no_git_anywhere_is_git_unavailable(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "empty").mkdir()
    _set_path(monkeypatch, "", ".", "rel", tmp_path / "empty", repo)
    with pytest.raises(GitUnavailable) as info:
        GitReader(repo).is_shallow()
    assert str(info.value) == "git executable not found"


def test_no_path_means_git_unavailable(
    repo: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PATH")
    with pytest.raises(GitUnavailable):
        GitReader(repo).is_shallow()


def test_filtered_path_is_passed_to_git(
    repo: Path, spy: list[Call], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    real_path = os.environ["PATH"]
    (repo / "tools").mkdir()
    _set_path(monkeypatch, "", ".", "rel/bin", repo / "tools", real_path)
    GitReader(repo).is_shallow()
    assert spy[0]["kwargs"]["env"]["PATH"] == real_path


def test_windows_looks_only_for_git_exe(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = tmp_path / "trusted"
    for name in ("git", "git.cmd", "git.bat"):
        _fake_git_in(trusted, name)
    _set_path(monkeypatch, trusted)
    with pytest.raises(GitUnavailable), _simulated_windows(monkeypatch):
        gitread._find_git(repo)
    exe = _fake_git_in(trusted, "git.exe")
    with _simulated_windows(monkeypatch):
        found = gitread._find_git(repo)
    assert found.path == os.path.realpath(exe)


def test_windows_git_exe_in_cwd_is_never_run(
    repo: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows' own lookup can search the current folder first; ours never does.
    _fake_git_in(elsewhere, "git.exe")
    _set_path(monkeypatch, ".")
    with pytest.raises(ComponentError) as info, _simulated_windows(monkeypatch):
        gitread._find_git(repo)
    assert info.value.message == gitread._UNTRUSTED_GIT


@pytest.mark.parametrize("where", ["repo", "cwd", "workspace"])
def test_git_inside_an_untrusted_folder_fails_closed(
    repo: Path,
    tmp_path: Path,
    elsewhere: Path,
    monkeypatch: pytest.MonkeyPatch,
    spy: list[Call],
    where: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    base = {"repo": repo, "cwd": elsewhere, "workspace": workspace}[where]
    _fake_git_in(base / "tools")
    _set_path(monkeypatch, base / "tools")  # absolute, but inside the folder
    with pytest.raises(ComponentError) as info:
        GitReader(repo).is_shallow()
    assert info.value.message == gitread._UNTRUSTED_GIT
    assert str(tmp_path) not in str(info.value)
    assert spy == []


def test_untrusted_entry_is_dropped_when_a_trusted_git_follows(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_git_in(repo / "tools")
    trusted = _fake_git_in(tmp_path / "trusted")
    _set_path(monkeypatch, repo / "tools", tmp_path / "trusted")
    found = gitread._find_git(repo)
    assert found == gitread._ResolvedGit(os.path.realpath(trusted), str(tmp_path / "trusted"))


def test_entry_symlinked_into_the_repo_is_dropped(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_git_in(repo / "tools")
    (tmp_path / "innocent").symlink_to(repo / "tools")
    _set_path(monkeypatch, tmp_path / "innocent")
    with pytest.raises(ComponentError, match="git found only"):
        gitread._find_git(repo)


def test_trusted_entry_with_git_symlinked_into_the_repo_fails_closed(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Defence in depth: the entry is trusted, but the git it holds really lives in the repo.
    exe = _fake_git_in(repo / "tools")
    link_dir = tmp_path / "links"
    link_dir.mkdir()
    (link_dir / _platform_git_name()).symlink_to(exe)
    _set_path(monkeypatch, link_dir)
    with pytest.raises(ComponentError) as info:
        gitread._find_git(repo)
    assert info.value.message == gitread._UNTRUSTED_GIT


def test_windows_cwd_git_exe_does_not_beat_a_trusted_path_entry(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # N-6 (a): shutil.which on Windows searches the cwd first even when path=
    # is given. A planted git.exe in the cwd must not hide a trusted PATH git.
    _fake_git_in(elsewhere, "git.exe")
    trusted = _fake_git_in(tmp_path / "trusted", "git.exe")
    _set_path(monkeypatch, tmp_path / "trusted")
    with _simulated_windows(monkeypatch):
        found = gitread._find_git(repo)
    assert found.path == os.path.realpath(trusted)
    assert found.search_path == str(tmp_path / "trusted")


def test_windows_git_cmd_bat_and_com_are_never_picked(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # N-6 (b): PATHEXT is ignored; only git.exe counts on Windows.
    folder = tmp_path / "trusted"
    for name in ("git.cmd", "git.bat", "git.com"):
        _fake_git_in(folder, name)
    _set_path(monkeypatch, folder)
    with pytest.raises(GitUnavailable), _simulated_windows(monkeypatch):
        gitread._find_git(repo)


def test_non_executable_posix_git_is_skipped_for_a_later_folder(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # N-6 (c): on POSIX a non-executable `git` is not accepted.
    first = _fake_git_in(tmp_path / "first")
    first.chmod(0o644)
    trusted = _fake_git_in(tmp_path / "second")
    _set_path(monkeypatch, tmp_path / "first", tmp_path / "second")
    found = gitread._find_git(repo)
    assert found.path == os.path.realpath(trusted)
    assert found.search_path == os.pathsep.join([str(tmp_path / "first"), str(tmp_path / "second")])


def test_directory_named_git_is_skipped(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # N-6 (d): a directory named git / git.exe is not a candidate.
    first = tmp_path / "first"
    first.mkdir()
    (first / "git").mkdir()
    (first / "git.exe").mkdir()
    trusted = _fake_git_in(tmp_path / "second")
    trusted_win = _fake_git_in(tmp_path / "second", "git.exe")
    _set_path(monkeypatch, first, tmp_path / "second")
    found = gitread._find_git(repo)
    assert found.path == os.path.realpath(trusted)
    with _simulated_windows(monkeypatch):
        found = gitread._find_git(repo)
    assert found.path == os.path.realpath(trusted_win)


def test_path_order_is_respected(
    repo: Path, tmp_path: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # N-6 (e): the first runnable git on the kept PATH wins.
    first = _fake_git_in(tmp_path / "first")
    second = _fake_git_in(tmp_path / "second")
    _set_path(monkeypatch, tmp_path / "first", tmp_path / "second")
    found = gitread._find_git(repo)
    assert found.path == os.path.realpath(first)
    _set_path(monkeypatch, tmp_path / "second", tmp_path / "first")
    found = gitread._find_git(repo)
    assert found.path == os.path.realpath(second)


def test_git_is_resolved_once_per_reader(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Path] = []
    real = gitread._find_git

    def counting(repo_dir: Path) -> Any:
        calls.append(repo_dir)
        return real(repo_dir)

    monkeypatch.setattr(gitread, "_find_git", counting)
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    reader.is_shallow()
    reader.commit_date(head)
    assert len(calls) == 1


def test_is_within() -> None:
    assert gitread._is_within("/a/b/git", "/a") is True
    assert gitread._is_within("/ab/git", "/a") is False
    assert gitread._is_within("/a", "/a") is True


def test_is_within_fails_closed_when_commonpath_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_paths: Any) -> str:
        raise ValueError("Can't mix absolute and relative paths")

    monkeypatch.setattr(os.path, "commonpath", boom)
    assert gitread._is_within("/x/git", "/y") is True


def test_is_within_posix_is_case_sensitive_and_ignores_windows_forms() -> None:
    assert gitread._is_within("/A/git", "/a") is False
    assert gitread._is_within("/a/.//b/git", "/a") is True


# --- SR N-7 / N-8: Windows containment forms ---------------------------------------


def _nt_is_within(monkeypatch: pytest.MonkeyPatch, path: str, folder: str) -> bool:
    """``_is_within`` evaluated with Windows path rules."""
    with _simulated_windows(monkeypatch, cwd="C:\\"):
        within = gitread._is_within(path, folder)
    return within


def _nt_comparable(monkeypatch: pytest.MonkeyPatch, path: str) -> str | None:
    with _simulated_windows(monkeypatch, cwd="C:\\"):
        comparable = gitread._nt_comparable(path)
    return comparable


# (folder, path, expected): every expected value is written by hand from the
# rule "path is folder or below it, on the same drive or share", not computed.
_NT_CONTAINMENT_CASES: list[tuple[str, str, bool]] = [
    # \\?\ drive form, either side
    (r"\\?\C:\Repo", r"C:\Repo\bin\git.exe", True),
    (r"C:\Repo", r"\\?\C:\Repo\bin\git.exe", True),
    (r"\\?\C:\Repo", r"C:\tools\git.exe", False),
    (r"C:\Repo", r"\\?\C:\tools\git.exe", False),
    (r"\\?\C:\Repo", r"D:\Repo\git.exe", False),
    # \\.\ device drive form, either side
    (r"\\.\C:\Repo", r"C:\Repo\bin\git.exe", True),
    (r"C:\Repo", r"\\.\C:\Repo\bin\git.exe", True),
    (r"\\.\C:\Repo", r"C:\tools\git.exe", False),
    (r"C:\Repo", r"\\.\C:\tools\git.exe", False),
    # \\?\UNC\ share form, either side
    (r"\\?\UNC\server\share\repo", r"\\server\share\repo\git.exe", True),
    (r"\\server\share\repo", r"\\?\UNC\server\share\repo\bin\git.exe", True),
    (r"\\?\UNC\server\share\repo", r"\\server\share\tools\git.exe", False),
    (r"\\server\share\repo", r"\\?\UNC\server\share\tools\git.exe", False),
    (r"\\?\UNC\server\share\repo", r"\\server\other\repo\git.exe", False),
    # \\.\UNC\ share form, either side
    (r"\\.\UNC\server\share\repo", r"\\server\share\repo\git.exe", True),
    (r"\\server\share\repo", r"\\.\UNC\server\share\repo\bin\git.exe", True),
    (r"\\.\UNC\server\share\repo", r"\\server\share\tools\git.exe", False),
    (r"\\server\share\repo", r"\\.\UNC\server\share\tools\git.exe", False),
    # share root as the checkout (the N-7 case)
    (r"\\server\share", r"\\server\share\git.exe", True),
    (r"\\server\share", r"\\server\share\tools\git.exe", True),
    (r"\\server\share", r"\\server\share", True),
    (r"\\server\share" + "\\", r"\\server\share\tools\git.exe", True),
    (r"\\?\UNC\server\share", r"\\server\share\tools\git.exe", True),
    (r"\\server\share", r"\\?\UNC\server\share\tools\git.exe", True),
    (r"\\server\share", r"\\server\other\git.exe", False),
    (r"\\server\share", r"\\elsewhere\share\git.exe", False),
    (r"\\server\share", r"C:\git.exe", False),
    # drive roots
    ("C:\\", r"C:\tools\git.exe", True),
    ("D:\\", r"C:\tools\git.exe", False),
    # case and slash folding (N-8)
    (r"C:\Repo", r"c:\repo\git.exe", True),
    (r"c:\Repo", r"c:\repo\git.exe", True),  # case differs only below the drive
    (r"c:\repo", r"c:\REPO\bin\git.exe", True),
    (r"\\server\Share", r"\\server\share\git.exe", True),
    (r"c:\repo", r"C:\REPO\GIT.EXE", True),
    (r"c:\repo", "C:/Repo/bin/git.exe", True),
    (r"\\server\share", r"\\SERVER\Share\git.exe", True),
    (r"\\SERVER\SHARE\Repo", r"\\?\unc\server\share\repo\git.exe", True),
    # plain prefix-free cases stay as before
    (r"C:\repo", r"C:\repox\git.exe", False),
    (r"C:\repo", r"D:\repo\git.exe", False),
]


def test_prefix_table_is_the_extended_and_device_forms_longest_first() -> None:
    prefixes = [prefix for prefix, _plain in gitread._NT_PATH_PREFIXES]
    assert set(prefixes) == {"\\\\?\\unc\\", "\\\\.\\unc\\", "\\\\?\\", "\\\\.\\"}
    for i, prefix in enumerate(prefixes):
        for later in prefixes[i + 1 :]:
            assert not later.startswith(prefix), "a shorter prefix would shadow a longer one"


def test_containment_cases_cover_every_prefix_form_on_both_sides() -> None:
    for prefix, _plain in gitread._NT_PATH_PREFIXES:
        on_folder = {e for f, _p, e in _NT_CONTAINMENT_CASES if f.lower().startswith(prefix)}
        on_path = {e for _f, p, e in _NT_CONTAINMENT_CASES if p.lower().startswith(prefix)}
        assert on_folder == {True, False}, prefix
        assert on_path == {True, False}, prefix
    assert any(f.lower() != f and p.lower() == p for f, p, _e in _NT_CONTAINMENT_CASES)
    assert any(f.lower() == f and p.lower() != p for f, p, _e in _NT_CONTAINMENT_CASES)


@pytest.mark.parametrize(("folder", "path", "expected"), _NT_CONTAINMENT_CASES)
def test_windows_containment(
    monkeypatch: pytest.MonkeyPatch, folder: str, path: str, expected: bool
) -> None:
    assert _nt_is_within(monkeypatch, path, folder) is expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (r"\\?\C:\Repo", r"c:\repo"),
        (r"\\.\C:\Repo", r"c:\repo"),
        (r"\\?\UNC\Server\Share\Repo", r"\\server\share\repo"),
        (r"\\.\UNC\Server\Share\Repo", r"\\server\share\repo"),
        (r"\\server\share", "\\\\server\\share\\"),
        (r"\\?\UNC\server\share", "\\\\server\\share\\"),
        ("C:", "c:\\"),
        (r"\\?\C:", "c:\\"),
        ("C:/Repo/./bin/", r"c:\repo\bin"),
    ],
)
def test_windows_comparable_form(monkeypatch: pytest.MonkeyPatch, raw: str, expected: str) -> None:
    assert _nt_comparable(monkeypatch, raw) == expected


@pytest.mark.parametrize(
    "odd",
    [
        "\\\\?\\Volume{0b1d}\\git.exe",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\git.exe",
        "\\\\.\\pipe\\git.exe",
        "C:repo\\git.exe",
        "\\git.exe",
        "\\\\server",
        r"\\?\\\?\C:\git.exe",  # a prefix left after one strip
        r"\\.\\\.\C:\git.exe",
        r"\\?\\\.\C:\git.exe",  # only one prefix is ever stripped
        r"1:\git.exe",  # not a drive letter
    ],
)
@pytest.mark.parametrize("odd_side", ["path", "folder"])
def test_undecidable_windows_form_fails_closed(
    monkeypatch: pytest.MonkeyPatch, odd: str, odd_side: str
) -> None:
    assert _nt_comparable(monkeypatch, odd) is None
    path, folder = (odd, "D:\\repo") if odd_side == "path" else ("D:\\tools\\git.exe", odd)
    assert _nt_is_within(monkeypatch, path, folder) is True


def test_windows_commonpath_error_on_one_drive_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(_paths: Any) -> str:
        raise ValueError("Can't mix absolute and relative paths")

    monkeypatch.setattr(ntpath, "commonpath", boom)
    assert _nt_is_within(monkeypatch, "C:\\tools\\git.exe", "C:\\repo") is True
    assert _nt_is_within(monkeypatch, "D:\\tools\\git.exe", "C:\\repo") is False


_SHARE_ROOT = "\\\\server\\share"
_EXTENDED_REPO = "\\\\?\\C:\\Repo"


@pytest.mark.parametrize(
    ("untrusted", "git_dir"),
    [(_SHARE_ROOT, _SHARE_ROOT + "\\tools"), (_EXTENDED_REPO, "C:\\Repo\\tools")],
)
@pytest.mark.parametrize("where", ["repo", "workspace"])
def test_git_under_share_root_or_extended_checkout_is_never_used(
    monkeypatch: pytest.MonkeyPatch, untrusted: str, git_dir: str, where: str
) -> None:
    repo = Path(untrusted if where == "repo" else "D:\\repo")  # built before os.name changes
    monkeypatch.setenv("PATH", git_dir)
    _accept_as_git(monkeypatch, git_dir + "\\git.exe")
    with pytest.raises(ComponentError) as info, _simulated_windows(monkeypatch, cwd="C:\\"):
        if where == "workspace":
            monkeypatch.setenv("GITHUB_WORKSPACE", untrusted)
        kept, dropped = gitread._split_path(gitread._untrusted_folders(repo))
        gitread._find_git(repo)
    assert kept == []
    assert git_dir in dropped
    assert info.value.message == gitread._UNTRUSTED_GIT


@pytest.mark.parametrize(
    ("untrusted", "git_dir"),
    [(_SHARE_ROOT, _SHARE_ROOT + "\\tools"), (_EXTENDED_REPO, "C:\\Repo\\tools")],
)
@pytest.mark.parametrize("where", ["repo", "workspace"])
def test_realpath_check_refuses_git_under_share_root_or_extended_checkout(
    monkeypatch: pytest.MonkeyPatch, untrusted: str, git_dir: str, where: str
) -> None:
    repo = Path(untrusted if where == "repo" else "D:\\repo")  # built before os.name changes
    monkeypatch.setenv("PATH", "E:\\tools")
    monkeypatch.setattr(gitread, "_look_for_git", lambda _folders: git_dir + "\\git.exe")
    with pytest.raises(ComponentError) as info, _simulated_windows(monkeypatch, cwd="C:\\"):
        if where == "workspace":
            monkeypatch.setenv("GITHUB_WORKSPACE", untrusted)
        gitread._find_git(repo)
    assert info.value.message == gitread._UNTRUSTED_GIT


def test_git_under_extended_length_cwd_is_never_used(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path("D:\\repo")
    monkeypatch.setenv("PATH", "c:\\repo\\tools")
    _accept_as_git(monkeypatch, "c:\\repo\\tools\\git.exe")
    with pytest.raises(ComponentError) as info, _simulated_windows(monkeypatch, cwd=_EXTENDED_REPO):
        kept, _dropped = gitread._split_path(gitread._untrusted_folders(repo))
        gitread._find_git(repo)
    assert kept == []
    assert info.value.message == gitread._UNTRUSTED_GIT


def test_share_root_cwd_is_a_filesystem_root_like_a_drive_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # I-14: the cwd rule is skipped when the cwd equals its anchor, and the
    # anchor of \\server\share is the share root, as C:\ is for C:.
    repo = Path("D:\\repo")
    tools = _SHARE_ROOT + "\\tools"
    monkeypatch.setenv("PATH", tools)
    _accept_as_git(monkeypatch, tools + "\\git.exe")
    with _simulated_windows(monkeypatch, cwd=_SHARE_ROOT):
        found = gitread._find_git(repo)
    assert found.search_path == tools


# --- I-14: cwd filesystem-root exemption ---------------------------------------


def test_is_filesystem_root_posix() -> None:
    assert gitread._is_filesystem_root("/") is True
    assert gitread._is_filesystem_root("/usr/bin") is False


def test_is_filesystem_root_windows_drive_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = ["C:\\", "C:/", "C:", "Z:\\", "C:\\Windows", "Z:\\tools", "git"]
    with _simulated_windows(monkeypatch, cwd="C:\\"):
        roots = [gitread._is_filesystem_root(p) for p in paths]
    assert roots == [True, True, True, True, False, False, False]


def _posix_root_cwd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate cwd=/ without chdir or creating a repo at /."""
    monkeypatch.setattr(os, "getcwd", lambda: "/")
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)


def _accept_as_git(monkeypatch: pytest.MonkeyPatch, *paths: str) -> None:
    """Treat each path as a runnable git, for filesystem-root simulations."""
    accepted = set(paths)

    def is_runnable(path: str) -> bool:
        return path in accepted

    monkeypatch.setattr(gitread, "_is_runnable_git", is_runnable)


def test_cwd_at_posix_root_keeps_usr_bin(
    repo: Path, elsewhere: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _posix_root_cwd(monkeypatch)
    _set_path(monkeypatch, "/usr/bin")
    kept, dropped = gitread._split_path(gitread._untrusted_folders(repo))
    assert "/usr/bin" in kept
    assert "/usr/bin" not in dropped
    _accept_as_git(monkeypatch, "/usr/bin/git")
    found = gitread._find_git(repo)
    assert found.path == os.path.realpath("/usr/bin/git")
    assert found.search_path == "/usr/bin"


def test_git_inside_the_repo_is_refused_when_cwd_is_posix_root(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _posix_root_cwd(monkeypatch)
    _fake_git_in(repo / "tools")
    _set_path(monkeypatch, repo / "tools")
    with pytest.raises(ComponentError) as info:
        gitread._find_git(repo)
    assert info.value.message == gitread._UNTRUSTED_GIT


def test_repo_at_posix_root_refuses_usr_bin_git(monkeypatch: pytest.MonkeyPatch) -> None:
    # Repo itself is /. The cwd exemption must not keep a git under the repo.
    _posix_root_cwd(monkeypatch)
    _set_path(monkeypatch, "/usr/bin")
    kept, dropped = gitread._split_path(gitread._untrusted_folders(Path("/")))
    assert kept == []
    assert "/usr/bin" in dropped
    _accept_as_git(monkeypatch, "/usr/bin/git")
    with pytest.raises(ComponentError) as info:
        gitread._find_git(Path("/"))
    assert info.value.message == gitread._UNTRUSTED_GIT
    assert info.value.component == "gitread"


def test_repo_at_posix_root_with_no_git_is_git_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _posix_root_cwd(monkeypatch)
    _set_path(monkeypatch, "/usr/bin")
    monkeypatch.setattr(gitread, "_is_runnable_git", lambda _path: False)
    with pytest.raises(GitUnavailable):
        gitread._find_git(Path("/"))


def test_realpath_check_refuses_git_inside_repo_at_posix_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Defence in depth: even if a kept-path walk returned a hit under /, refuse it.
    _posix_root_cwd(monkeypatch)
    _set_path(monkeypatch, "/usr/bin")
    monkeypatch.setattr(gitread, "_look_for_git", lambda _folders: "/usr/bin/git")
    with pytest.raises(ComponentError) as info:
        gitread._find_git(Path("/"))
    assert info.value.message == gitread._UNTRUSTED_GIT


def test_workspace_at_posix_root_still_drops_usr_bin(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "getcwd", lambda: "/")
    monkeypatch.setenv("GITHUB_WORKSPACE", "/")
    _set_path(monkeypatch, "/usr/bin")
    kept, dropped = gitread._split_path(gitread._untrusted_folders(repo))
    assert "/usr/bin" not in kept
    assert "/usr/bin" in dropped
    _accept_as_git(monkeypatch, "/usr/bin/git")
    with pytest.raises(ComponentError) as info:
        gitread._find_git(repo)
    assert info.value.message == gitread._UNTRUSTED_GIT


def test_cwd_at_windows_drive_root_keeps_git_on_that_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path("D:\\repo")  # built before os.name changes (SR N-9)
    monkeypatch.setenv("PATH", "C:\\Program Files\\Git\\cmd")
    exe = "C:\\Program Files\\Git\\cmd\\git.exe"
    _accept_as_git(monkeypatch, exe)
    with _simulated_windows(monkeypatch, cwd="C:\\"):
        kept, dropped = gitread._split_path(gitread._untrusted_folders(repo))
        found = gitread._find_git(repo)
        real_exe = ntpath.realpath(exe)
    assert kept == ["C:\\Program Files\\Git\\cmd"]
    assert "C:\\Program Files\\Git\\cmd" not in dropped
    assert found.path == real_exe
    assert found.search_path == "C:\\Program Files\\Git\\cmd"


@pytest.mark.parametrize("root", ["C:\\", "Z:\\"])
def test_repo_at_windows_drive_root_never_uses_git_inside_it(
    monkeypatch: pytest.MonkeyPatch, root: str
) -> None:
    repo = Path(root)  # built before os.name changes (SR N-9)
    tools = root + "tools"
    monkeypatch.setenv("PATH", tools)
    _accept_as_git(monkeypatch, tools + "\\git.exe")
    with pytest.raises(ComponentError) as info, _simulated_windows(monkeypatch, cwd=root):
        kept, dropped = gitread._split_path(gitread._untrusted_folders(repo))
        gitread._find_git(repo)
    assert kept == []
    assert tools in dropped
    assert info.value.message == gitread._UNTRUSTED_GIT
    assert info.value.component == "gitread"


def test_repo_at_windows_drive_root_with_no_git_is_git_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path("C:\\")  # built before os.name changes (SR N-9)
    monkeypatch.setenv("PATH", "C:\\tools")
    monkeypatch.setattr(gitread, "_is_runnable_git", lambda _path: False)
    with pytest.raises(GitUnavailable), _simulated_windows(monkeypatch, cwd="C:\\"):
        gitread._find_git(repo)


def test_realpath_check_refuses_git_inside_repo_at_windows_drive_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path("C:\\")  # built before os.name changes (SR N-9)
    monkeypatch.setenv("PATH", "C:\\tools")
    monkeypatch.setattr(gitread, "_look_for_git", lambda _folders: "C:\\tools\\git.exe")
    with pytest.raises(ComponentError) as info, _simulated_windows(monkeypatch, cwd="C:\\"):
        gitread._find_git(repo)
    assert info.value.message == gitread._UNTRUSTED_GIT


# --- I-14 / D-TL-18: version check ---------------------------------------------


def _git_printing(tmp_path: Path) -> Path:
    """A fake git whose ``--version`` prints $GIT_FAKE_VERSION and exits $GIT_FAKE_CODE."""
    exe = tmp_path / "fakebin" / _platform_git_name()
    exe.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        _compile_windows_exe(
            exe,
            (
                "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
                "int main(int argc, char **argv) {\n"
                '    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {\n'
                '        const char *v = getenv("GIT_FAKE_VERSION");\n'
                '        const char *c = getenv("GIT_FAKE_CODE");\n'
                "        if (v) fputs(v, stdout);\n"
                "        return c ? atoi(c) : 0;\n"
                "    }\n"
                "    return 0;\n"
                "}\n"
            ),
            (
                "using System;\n"
                "class FakeGit {\n"
                "  static int Main(string[] args) {\n"
                '    if (args.Length >= 1 && args[0] == "--version") {\n'
                "      string v = Environment.GetEnvironmentVariable(\n"
                '          "GIT_FAKE_VERSION"); Console.Write(v ?? "");\n'
                '      string c = Environment.GetEnvironmentVariable("GIT_FAKE_CODE") ?? "0";\n'
                "      int code; return int.TryParse(c, out code) ? code : 0;\n"
                "    }\n"
                "    return 0;\n"
                "  }\n"
                "}\n"
            ),
        )
    else:
        exe.write_bytes(
            b'#!/bin/sh\nif [ "$1" = --version ]; then printf \'%s\' "$GIT_FAKE_VERSION"; '
            b'exit "$GIT_FAKE_CODE"; fi\nexit 0\n'
        )
        exe.chmod(0o755)
    return exe


@pytest.fixture
def fake_version(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Point gitread at a fake git whose ``--version`` prints what the test sets."""
    exe = _git_printing(tmp_path)
    resolved = gitread._ResolvedGit(str(exe), os.environ["PATH"])
    monkeypatch.setattr(gitread, "_find_git", lambda _repo: resolved)
    real = gitread._run_bounded

    def run(argv: list[str], **kwargs: Any) -> Any:
        return real(argv, **dict(kwargs, env=dict(kwargs["env"], **state)))

    state: dict[str, str] = {"GIT_FAKE_VERSION": "", "GIT_FAKE_CODE": "0"}
    monkeypatch.setattr(gitread, "_run_bounded", run)

    def set_version(text: str, code: int = 0) -> None:
        state["GIT_FAKE_VERSION"] = text
        state["GIT_FAKE_CODE"] = str(code)

    yield set_version


@pytest.mark.parametrize(
    "text",
    [
        "git version 2.30.0\n",
        "git version 2.30\n",
        "git version 2.45.1\n",
        "git version 2.45.1.windows.1\n",
        "git version 2.39.3 (Apple Git-146)\n",
        "git version 3.0.0\n",
        "git version 10.1\n",
    ],
)
def test_supported_git_versions_pass(repo: Path, fake_version: Any, text: str) -> None:
    fake_version(text)
    reader = GitReader(repo)
    reader._run("rev-parse", ["--is-shallow-repository"])
    assert reader._version_ok is True


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("git version 2.29.9\n", 0),
        ("git version 2.24.0\n", 0),
        ("git version 1.99.0\n", 0),
        ("git version 2.3.0\n", 0),
        ("git version 2.29.2 (Apple Git-128)\n", 0),
        ("", 0),
        ("garbage\n", 0),
        ("Git version 2.45.1\n", 0),
        (" git version 2.45.1\n", 0),
        ("git version two.thirty\n", 0),
        ("git version 2.\n", 0),
        ("git version \u0662.\u0663\u0660\n", 0),  # non-ASCII digits
        ("git version 2.45.1\n", 1),  # right text, failing exit
    ],
)
def test_old_or_unparsable_git_is_too_old(
    repo: Path, fake_version: Any, text: str, code: int
) -> None:
    fake_version(text, code)
    with pytest.raises(GitTooOld) as info:
        GitReader(repo).is_shallow()
    err = info.value
    assert isinstance(err, ComponentError)
    assert err.component == "gitread"
    assert err.message == "git 2.30 or newer is required"
    assert str(err) == str(ComponentError("gitread", "git 2.30 or newer is required"))
    assert "2.29" not in err.message


def test_version_check_runs_once_first_with_fixed_env_and_no_flags(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[list[str], dict[str, Any]]] = []
    real = gitread._run_bounded

    def recorder(argv: list[str], **kwargs: Any) -> Any:
        seen.append((list(argv), kwargs))
        return real(argv, **kwargs)

    monkeypatch.setattr(gitread, "_run_bounded", recorder)
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    reader.is_shallow()
    reader.commit_date(head)
    argvs = [argv for argv, _ in seen]
    assert argvs[0] == [reader._resolved_git().path, "--version"]  # first, and no -c
    assert [a for a in argvs if a[1:] == ["--version"]] == [argvs[0]]  # once
    assert all(a[0] == argvs[0][0] for a in argvs)  # the same resolved git every time
    version_kwargs = seen[0][1]
    assert set(version_kwargs["env"]) == set(gitread.FIXED_ENV) | {
        "PATH",
        "HOME",
        "GIT_CEILING_DIRECTORIES",
    }
    assert version_kwargs["timeout"] == gitread.GIT_TIMEOUT_SECONDS
    assert version_kwargs["max_stdout"] == gitread.SMALL_OUTPUT_MAX_BYTES


def test_refused_subcommand_runs_no_version_check(repo: Path, spy: list[Call]) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo)._run("checkout", [])
    assert spy == []


def test_missing_repo_dir_is_a_component_error(tmp_path: Path) -> None:
    with pytest.raises(ComponentError):
        GitReader(tmp_path / "missing").is_shallow()


def test_not_a_repository_is_a_component_error(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / ".git").write_text("not a gitdir\n")  # stops discovery of any outer repo
    with pytest.raises(ComponentError) as info:
        GitReader(plain).is_shallow()
    assert info.value.component == "gitread"


def test_error_message_never_quotes_input_or_stderr(repo: Path) -> None:
    with pytest.raises(UnresolvableRevision) as info:
        GitReader(repo).resolve("secret-ref-name")
    assert str(info.value) == "unresolvable revision"
    with pytest.raises(ComponentError) as info2:
        GitReader(repo).has_object("ab" * 19 + "zz")
    assert "zz" not in str(info2.value)
    assert "fatal" not in info2.value.message


# --- resolve --------------------------------------------------------------


def test_resolve_head_branch_and_annotated_tag(repo: Path) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "tag", "-a", "v1", "-m", "tag")
    reader = GitReader(repo)
    assert reader.resolve("HEAD") == head
    assert reader.resolve("main") == head
    assert reader.resolve("v1") == head  # peeled to the commit, not the tag object
    assert reader.resolve(head) == head


def test_resolve_uses_verify_end_of_options_and_commit_peel(repo: Path, spy: list[Call]) -> None:
    GitReader(repo).resolve("main")
    argv = spy[0]["argv"]
    assert argv[-4:] == ["rev-parse", "--verify", "--end-of-options", "main^{commit}"]


@pytest.mark.parametrize(
    "rev",
    ["--output={out}", "--git-dir={out}", "-o{out}", "--exec-path={out}",
     "$(touch {out})", "`touch {out}`", "x; touch {out}", "x && touch {out}", "x | tee {out}",
     "x > {out}", "unknown-branch", "", "HEAD\nHEAD", "HEAD HEAD"],
)  # fmt: skip
def test_resolve_rejects_option_injection_and_shell_metacharacters(
    repo: Path, tmp_path: Path, rev: str
) -> None:
    out = tmp_path / "pwned"
    with pytest.raises(UnresolvableRevision) as info:
        GitReader(repo).resolve(rev.format(out=out))
    assert str(info.value) == "unresolvable revision"
    assert not out.exists()


def test_resolve_rejects_nul_without_running_git(repo: Path, spy: list[Call]) -> None:
    with pytest.raises(UnresolvableRevision):
        GitReader(repo).resolve("HEAD\x00")
    assert spy == []


def test_resolve_rejects_a_tree(repo: Path) -> None:
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    with pytest.raises(UnresolvableRevision):
        GitReader(repo).resolve(tree)


@pytest.mark.parametrize(
    "stdout", [b"", b"HEAD\n", b"a" * 40 + b"\n" + b"b" * 40 + b"\n", b"A" * 40 + b"\n",
               b"a" * 40, b"a" * 40 + b"\n\n", b"\xff" * 40 + b"\n"],
)  # fmt: skip
def test_resolve_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake_run(monkeypatch, 0, stdout)
    with pytest.raises(UnresolvableRevision):
        GitReader(repo).resolve("HEAD")


# --- is_shallow -----------------------------------------------------------


def test_is_shallow_false_for_full_repo(repo: Path) -> None:
    assert GitReader(repo).is_shallow() is False


def test_is_shallow_true_for_depth_one_clone(repo: Path, tmp_path: Path) -> None:
    _commit(repo, "second")
    clone = tmp_path / "shallow"
    _git(tmp_path, "-c", "protocol.file.allow=always", "clone", "-q", "--depth", "1",
         f"file://{repo}", str(clone))  # fmt: skip
    assert GitReader(clone).is_shallow() is True


@pytest.mark.parametrize("stdout", [b"", b"yes\n", b"true", b"true\nfalse\n"])
def test_is_shallow_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake_run(monkeypatch, 0, stdout)
    with pytest.raises(ComponentError):
        GitReader(repo).is_shallow()


# --- has_object -----------------------------------------------------------


def test_has_object_present_and_absent(repo: Path) -> None:
    reader = GitReader(repo)
    assert reader.has_object(reader.resolve("HEAD")) is True
    assert reader.has_object("0123456789" * 4) is False


@pytest.mark.parametrize("sha", BAD_SHAS)
def test_has_object_rejects_bad_sha_without_running_git(
    repo: Path, spy: list[Call], sha: str
) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).has_object(sha)
    assert spy == []


def test_has_object_passes_sha_after_end_of_options(repo: Path, spy: list[Call]) -> None:
    GitReader(repo).has_object("ab" * 20)
    assert spy[0]["argv"][-4:] == ["cat-file", "-e", "--end-of-options", "ab" * 20]


def test_has_object_maps_other_exit_codes_to_component_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_run(monkeypatch, 128, b"")
    with pytest.raises(ComponentError):
        GitReader(repo).has_object("ab" * 20)


# --- merge_base -----------------------------------------------------------


def test_merge_base_of_diverged_branches(repo: Path) -> None:
    root = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "feature")
    feature = _commit(repo, "feature")
    _git(repo, "checkout", "-q", "main")
    main = _commit(repo, "main")
    assert GitReader(repo).merge_base(main, feature) == root


def test_merge_base_none_for_unrelated_histories(repo: Path) -> None:
    first = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--orphan", "other")
    other = _commit(repo, "orphan")
    assert GitReader(repo).merge_base(first, other) is None


def test_merge_base_argv_has_only_shas_after_end_of_options(repo: Path, spy: list[Call]) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    GitReader(repo).merge_base(head, head)
    assert spy[0]["argv"][-4:] == ["merge-base", "--end-of-options", head, head]


@pytest.mark.parametrize("bad", BAD_SHAS)
def test_merge_base_rejects_bad_sha_either_side(repo: Path, spy: list[Call], bad: str) -> None:
    good = "ab" * 20
    for a, b in ((bad, good), (good, bad)):
        with pytest.raises(ComponentError):
            GitReader(repo).merge_base(a, b)
    assert spy == []


def test_merge_base_missing_object_is_a_component_error(repo: Path) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).merge_base("ab" * 20, "cd" * 20)


@pytest.mark.parametrize(
    ("code", "stdout"), [(0, b""), (0, b"zz\n"), (1, b"ab" * 20 + b"\n"), (0, b"ab" * 20)]
)
def test_merge_base_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, code: int, stdout: bytes
) -> None:
    _fake_run(monkeypatch, code, stdout)
    with pytest.raises(ComponentError):
        GitReader(repo).merge_base("ab" * 20, "cd" * 20)


# --- commit_date ----------------------------------------------------------


def test_commit_date_is_committer_date_with_offset(repo: Path) -> None:
    sha = _commit(repo, "dated", date="2025-06-07T08:09:10-04:00")
    got = GitReader(repo).commit_date(sha)
    assert got == datetime(2025, 6, 7, 12, 9, 10, tzinfo=UTC)
    assert got == datetime(2025, 6, 7, 8, 9, 10, tzinfo=timezone(timedelta(hours=-4)))
    assert got.tzinfo is UTC


def test_commit_date_argv(repo: Path, spy: list[Call]) -> None:
    sha = _git(repo, "rev-parse", "HEAD")
    GitReader(repo).commit_date(sha)
    argv = spy[0]["argv"]
    i = argv.index("log")
    assert argv[i:] == ["log", "--no-ext-diff", "--no-textconv", "--no-color",
                        "--no-walk", "--max-count=1", "--format=%cI", "--end-of-options",
                        sha]  # fmt: skip


@pytest.mark.parametrize("sha", BAD_SHAS)
def test_commit_date_rejects_bad_sha(repo: Path, spy: list[Call], sha: str) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).commit_date(sha)
    assert spy == []


def test_commit_date_of_missing_commit_is_a_component_error(repo: Path) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).commit_date("ab" * 20)


@pytest.mark.parametrize(
    "stdout", [b"", b"yesterday\n", b"2025-06-07T08:09:10\n",
               b"2025-06-07T08:09:10Z\n2025-06-07T08:09:10Z\n", b"\xff\n"],
)  # fmt: skip
def test_commit_date_rejects_malformed_or_naive_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake_run(monkeypatch, 0, stdout)
    with pytest.raises(ComponentError):
        GitReader(repo).commit_date("ab" * 20)


# --- option allowlist and --max-count (SR-014 lows) -----------------------------


@pytest.mark.parametrize(
    ("sub", "args"),
    [
        ("log", ["--max-count=1", "--ext-diff"]),
        ("log", ["--max-count=1", "--textconv"]),
        ("log", ["--max-count=1", "--output=x"]),
        ("log", ["--max-count=1", "--all"]),
        ("show", ["--ext-diff"]),
        ("show", ["--textconv"]),
        ("diff-tree", ["--ext-diff"]),
        ("diff-tree", ["--textconv"]),
        ("rev-parse", ["--git-dir=x"]),
        ("rev-parse", ["--exec-path"]),
        ("rev-parse", ["-c"]),
        ("cat-file", ["--batch-all-objects"]),
        ("merge-base", ["--all"]),
        ("ls-tree", ["--name-only", "x"]),
        ("rev-parse", ["HEAD"]),  # an operand before --end-of-options
    ],
)
def test_options_outside_the_allowlist_are_refused(
    repo: Path, spy: list[Call], sub: str, args: list[str]
) -> None:
    with pytest.raises(ComponentError) as info:
        GitReader(repo)._run(sub, [*args, "--end-of-options"])
    assert info.value.message == "git option not allowed"
    assert "x" not in info.value.message.split()
    assert spy == []


@pytest.mark.parametrize("sub", sorted(gitread.OPTION_ALLOWLIST))
def test_every_allowlisted_option_is_accepted(sub: str) -> None:
    count = ["--max-count=1"] if sub in ("log", "rev-list") else []
    gitread._check_options(sub, [*sorted(gitread.OPTION_ALLOWLIST[sub]), *count])


def test_option_allowlist_covers_exactly_the_allowed_subcommands() -> None:
    assert frozenset(gitread.OPTION_ALLOWLIST) == gitread.ALLOWED_SUBCOMMANDS


def test_operands_after_end_of_options_are_not_options() -> None:
    gitread._check_options("rev-parse", ["--verify", "--end-of-options", "--output=x", "-c"])


@pytest.mark.parametrize("sub", ["log", "rev-list"])
@pytest.mark.parametrize(
    ("counts", "message"),
    [
        ([], "git call needs exactly one --max-count"),
        (["--max-count=1", "--max-count=2"], "git call needs exactly one --max-count"),
        (["--max-count=10001"], "git --max-count over the cap"),
        (["--max-count=99999999999999999999"], "git --max-count over the cap"),
        (["--max-count=0"], "git option not allowed"),
        (["--max-count=-1"], "git option not allowed"),
        (["--max-count=01"], "git option not allowed"),
        (["--max-count=1x"], "git option not allowed"),
        (["--max-count=\u0661"], "git option not allowed"),  # non-ASCII digit
        (["-n1"], "git option not allowed"),
        (["--max-count", "1"], "git option not allowed"),
    ],
)
def test_log_and_rev_list_need_one_bounded_max_count(
    sub: str, counts: list[str], message: str
) -> None:
    with pytest.raises(ComponentError) as info:
        gitread._check_options(sub, [*counts, "--end-of-options", "a" * 40])
    assert info.value.message == message


def test_max_count_after_end_of_options_does_not_count() -> None:
    with pytest.raises(ComponentError, match="exactly one --max-count"):
        gitread._check_options("log", ["--end-of-options", "--max-count=1"])


@pytest.mark.parametrize("value", [1, 10_000])
def test_max_count_within_the_cap_is_accepted(value: int) -> None:
    gitread._check_options("rev-list", [f"--max-count={value}", "--end-of-options", "a" * 40])
    assert gitread.MAX_COUNT_CAP == 10_000  # R2.6: first-parent commits walked


def test_max_count_is_not_allowed_where_it_is_not_needed() -> None:
    with pytest.raises(ComponentError, match="option not allowed"):
        gitread._check_options("rev-parse", ["--max-count=1"])


# --- hardening, flag by flag (SR-014 (c)) ---------------------------------------
#
# Each test below removes ONE hardening setting and shows the attack then works,
# and shows that with the full hardening it does not. Mapping, setting -> test:
#   --no-textconv (diff/log flag)   -> test_no_textconv_is_load_bearing[log|show]
#   --no-color (diff/log flag)      -> test_no_color_is_load_bearing
#   log.showSignature=false         -> test_log_show_signature_false_is_load_bearing
#   safe.bareRepository=explicit    -> test_safe_bare_repository_is_load_bearing
#   protocol.allow=never            -> test_lazy_fetch_is_blocked_by_each_setting_alone
#   GIT_NO_LAZY_FETCH=1             -> test_lazy_fetch_is_blocked_by_each_setting_alone
#   GIT_NO_REPLACE_OBJECTS=1        -> test_no_replace_objects_is_load_bearing
#   GIT_CEILING_DIRECTORIES         -> test_ceiling_directories_is_load_bearing
#   HOME (fresh temp dir)           -> test_global_config_in_inherited_home_is_ignored
# core.fsmonitor=false is needed defence: plain diff-tree runs a repo's
# fsmonitor (git 2.30, 2.37 and 2.47). The load-bearing behaviour test is
# due in T-008, so it is not added here.
# Not observable through T-007's allowed subcommands, so kept as defence in
# depth (a test can't fail when they are removed): core.hooksPath,
# core.untrackedCache, GIT_OPTIONAL_LOCKS (no T-007 subcommand reads the index
# or runs hooks); diff.external= and --no-ext-diff (log/show/diff-tree run an
# external diff only with --ext-diff, which the option allowlist refuses);
# core.pager=cat (stdout is never a tty); GIT_TERMINAL_PROMPT (no transport is
# allowed); GIT_CONFIG_GLOBAL (HOME is empty and XDG_CONFIG_HOME is not passed);
# GIT_CONFIG_NOSYSTEM and GIT_ATTR_NOSYSTEM (need root to plant system files).


def _git_version() -> tuple[int, int]:
    out = _REAL_RUN([_GIT, "--version"], capture_output=True, text=True, check=True).stdout
    major, minor = out.split()[2].split(".")[:2]
    return int(major), int(minor)


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _drop_config(monkeypatch: pytest.MonkeyPatch, setting: str) -> None:
    assert setting in gitread.HARDENING_CONFIG
    kept = tuple(s for s in gitread.HARDENING_CONFIG if s != setting)
    monkeypatch.setattr(gitread, "HARDENING_CONFIG", kept)


def _drop_env(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    assert name in gitread.FIXED_ENV
    kept = {k: v for k, v in gitread.FIXED_ENV.items() if k != name}
    monkeypatch.setattr(gitread, "FIXED_ENV", kept)


def _drop_diff_flag(monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    assert flag in gitread._DIFF_FLAGS
    monkeypatch.setattr(gitread, "_DIFF_FLAGS", tuple(f for f in gitread._DIFF_FLAGS if f != flag))


def _sentinel_script(tmp_path: Path) -> tuple[Path, Path]:
    sentinel = tmp_path / "sentinel"
    script = tmp_path / "evil.sh"
    script.write_text(f'#!/bin/sh\ntouch {sentinel}\ncat "$1" 2>/dev/null\nexit 0\n')
    script.chmod(0o755)
    return script, sentinel


@pytest.fixture
def textconv_repo(repo: Path, tmp_path: Path) -> tuple[Path, Path, str]:
    """A repo whose config and attributes run a sentinel script as a textconv driver."""
    script, sentinel = _sentinel_script(tmp_path)
    (repo / "f.txt").write_text("a\n")
    _git(repo, "add", "f.txt")
    _commit(repo, "add f")
    (repo / "f.txt").write_text("b\n")
    _git(repo, "add", "f.txt")
    head = _commit(repo, "change f")
    with (repo / ".git" / "config").open("a") as cfg:
        cfg.write(f'[diff "x"]\n\ttextconv = {script}\n[diff]\n\texternal = {script}\n')
    (repo / ".gitattributes").write_text("* diff=x\n")
    return repo, sentinel, head


@needs_git
def test_plain_git_control_runs_the_hostile_textconv(textconv_repo: tuple[Path, Path, str]) -> None:
    # Control: without the hardening the planted config DOES run, so the
    # hardened tests below can fail.
    repo, sentinel, _head = textconv_repo
    _git(repo, "log", "-p", "-1")
    assert sentinel.exists()


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell script")
def test_hardened_patch_calls_run_nothing(textconv_repo: tuple[Path, Path, str]) -> None:
    repo, sentinel, head = textconv_repo
    parent = _git(repo, "rev-parse", "HEAD~1")
    reader = GitReader(repo)
    big = 65536
    reader._run("log", ["-p", "--max-count=2", "--end-of-options", head], max_stdout=big)
    reader._run("show", ["--end-of-options", head], max_stdout=big)
    reader._run("diff-tree", ["-p", "--end-of-options", parent, head], max_stdout=big)
    assert not sentinel.exists()


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell script")
@pytest.mark.parametrize("sub", ["log", "show"])
def test_no_textconv_is_load_bearing(
    textconv_repo: tuple[Path, Path, str], monkeypatch: pytest.MonkeyPatch, sub: str
) -> None:
    repo, sentinel, head = textconv_repo
    count = ["--max-count=1"] if sub == "log" else []
    args = [*(["-p"] if sub == "log" else []), *count, "--end-of-options", head]
    GitReader(repo)._run(sub, args, max_stdout=65536)
    assert not sentinel.exists()
    _drop_diff_flag(monkeypatch, "--no-textconv")
    GitReader(repo)._run(sub, args, max_stdout=65536)
    assert sentinel.exists()


def test_no_color_is_load_bearing(
    textconv_repo: tuple[Path, Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _sentinel, head = textconv_repo
    (repo / ".gitattributes").unlink()
    _git(repo, "config", "color.ui", "always")
    args = ["-p", "--max-count=1", "--end-of-options", head]
    assert b"\x1b[" not in GitReader(repo)._run("log", args, max_stdout=65536).stdout
    _drop_diff_flag(monkeypatch, "--no-color")
    assert b"\x1b[" in GitReader(repo)._run("log", args, max_stdout=65536).stdout


def _signed_commit(repo: Path) -> str:
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    parent = _git(repo, "rev-parse", "HEAD")
    body = (
        f"tree {tree}\nparent {parent}\n"
        "author t <t@example.invalid> 1700000000 +0000\n"
        "committer t <t@example.invalid> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n\nsigned\n"
    )
    env = dict(_TEST_GIT_ENV, HOME=str(repo))
    out = _REAL_RUN(
        [_GIT, "hash-object", "-t", "commit", "-w", "--stdin"],
        cwd=repo,
        env=env,
        input=body,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell script")
def test_log_show_signature_false_is_load_bearing(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script, sentinel = _sentinel_script(tmp_path)
    signed = _signed_commit(repo)
    _git(repo, "config", "log.showSignature", "true")
    _git(repo, "config", "gpg.program", str(script))
    assert GitReader(repo).commit_date(signed) == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert not sentinel.exists()
    _drop_config(monkeypatch, "log.showSignature=false")
    with contextlib.suppress(ComponentError):
        GitReader(repo).commit_date(signed)
    assert sentinel.exists()


def test_no_replace_objects_is_load_bearing(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = _git(repo, "rev-parse", "HEAD")
    second = _commit(repo, "second", date="2026-03-04T05:06:07+00:00")
    _git(repo, "replace", second, first)
    expected = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    assert GitReader(repo).commit_date(second) == expected
    _drop_env(monkeypatch, "GIT_NO_REPLACE_OBJECTS")
    assert GitReader(repo).commit_date(second) != expected  # the replacement's date


def test_ceiling_directories_is_load_bearing(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plain = repo / "plain"  # not a repository, but inside one
    plain.mkdir()
    with pytest.raises(ComponentError):
        GitReader(plain).is_shallow()
    real = gitread._environment

    def without_ceiling(*args: Any) -> dict[str, str]:
        env = real(*args)
        del env["GIT_CEILING_DIRECTORIES"]
        return env

    monkeypatch.setattr(gitread, "_environment", without_ceiling)
    assert GitReader(plain).is_shallow() is False  # found the outer repository


@pytest.mark.skipif(_git_version() < (2, 38), reason="safe.bareRepository needs git 2.38")
def test_safe_bare_repository_is_load_bearing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = tmp_path / "embedded.git"
    _git(tmp_path, "init", "-q", "--bare", str(bare))
    with pytest.raises(ComponentError):
        GitReader(bare).is_shallow()
    _drop_config(monkeypatch, "safe.bareRepository=explicit")
    assert GitReader(bare).is_shallow() is False


@pytest.fixture
def partial_clone(repo: Path, tmp_path: Path) -> tuple[Path, str]:
    """A blob:none partial clone of ``repo`` and the id of a blob it lacks."""
    (repo / "f.txt").write_text("payload\n")
    _git(repo, "add", "f.txt")
    _commit(repo, "blob")
    _git(repo, "config", "uploadpack.allowFilter", "true")
    clone = tmp_path / "partial"
    _git(tmp_path, "-c", "protocol.file.allow=always", "clone", "-q", "--no-checkout",
         "--filter=blob:none", f"file://{repo}", str(clone))  # fmt: skip
    return clone, _git(repo, "rev-parse", "HEAD:f.txt")


def _still_missing(clone: Path, blob: str) -> bool:
    env = dict(_TEST_GIT_ENV, HOME=str(clone), GIT_NO_LAZY_FETCH="1")
    probe = [_GIT, "-c", "protocol.allow=never", "cat-file", "-e", blob]
    return _REAL_RUN(probe, cwd=clone, env=env, capture_output=True, check=False).returncode != 0


@pytest.mark.skipif(_git_version() < (2, 44), reason="GIT_NO_LAZY_FETCH needs git 2.44")
def test_lazy_fetch_is_blocked_by_each_setting_alone(
    partial_clone: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    clone, blob = partial_clone
    assert GitReader(clone).has_object(blob) is False  # full hardening
    assert _still_missing(clone, blob)
    with monkeypatch.context() as m:  # only protocol.allow=never left
        _drop_env(m, "GIT_NO_LAZY_FETCH")
        with pytest.raises(ComponentError):
            GitReader(clone).has_object(blob)
    assert _still_missing(clone, blob)
    with monkeypatch.context() as m:  # only GIT_NO_LAZY_FETCH left
        _drop_config(m, "protocol.allow=never")
        assert GitReader(clone).has_object(blob) is False
    assert _still_missing(clone, blob)
    _drop_env(monkeypatch, "GIT_NO_LAZY_FETCH")  # neither: the control fetches
    _drop_config(monkeypatch, "protocol.allow=never")
    assert GitReader(clone).has_object(blob) is True
    assert not _still_missing(clone, blob)
