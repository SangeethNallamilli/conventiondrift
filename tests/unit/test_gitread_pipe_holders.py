"""CR2 S1 (#24 review): every kill path kills git's whole group and never blocks.

A grandchild that holds git's pipes must not stretch a kill or ``close()``: the
call returns promptly, a grandchild in git's group is gone, and one that left the
group (its own session) is left to exit on its own while nothing waits for it.

D-TL-25: the kill paths are taken from the code (every function that calls
``_kill_tree`` or a batch process's ``kill()``, found with ``ast``), and a test
asserts the triggers below cover exactly those; each trigger runs against each
grandchild kind separately.
"""

import ast
import inspect
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError
from conventiondrift.gitread import GitReader

SHA, SHA2 = "a" * 40, "b" * 40
TIMEOUT = 0.5
PROMPT = TIMEOUT + 4.0  # the timeout, plus the bounded reader joins and the reap
#: Grandchild kinds: (parent exits after the start, grandchild leaves the group).
KINDS: dict[str, tuple[bool, bool]] = {
    "in-group, git still running": (False, False),
    "in-group, git exited": (True, False),
    "own session, git exited": (True, True),
}


def _fake_git(tmp_path: Path, parent_exits: bool, escapes: bool, payload: str) -> list[str]:
    """A git that starts a 20 s grandchild holding stdin/stdout/stderr, then prints."""
    # On Windows, escaping git's kill scope means leaving its job object:
    # CREATE_BREAKAWAY_FROM_JOB (0x01000000) together with
    # CREATE_NEW_PROCESS_GROUP (0x200). 0x200 alone stays in the job and is
    # killed with git (CON-13 AC3). start_new_session is POSIX-only.
    code = (
        "import os, subprocess, sys, time\n"
        "kw = {}\n"
        f"if {escapes}:\n"
        "    if os.name == 'nt':\n"
        "        kw['creationflags'] = 0x01000000 | 0x00000200\n"
        "    else:\n"
        "        kw['start_new_session'] = True\n"
        "child = subprocess.Popen("
        "[sys.executable, '-c', 'import time; time.sleep(20)'], **kw)\n"
        # Atomic: the pid file appears whole or not at all (written, then renamed).
        f"open({str(tmp_path / 'grandchild.tmp')!r}, 'w').write(str(child.pid))\n"
        f"os.replace({str(tmp_path / 'grandchild.tmp')!r}, {str(tmp_path / 'grandchild.pid')!r})\n"
        f"sys.stdout.write({payload!r}); sys.stdout.flush()\n"
        + ("sys.exit(0)\n" if parent_exits else "time.sleep(20)\n")
    )
    return [sys.executable, "-c", code]


_HAS_PROC = Path("/proc/self/stat").exists()
#: The ways this OS can read a process state: /proc (Linux), /bin/ps (macOS and
#: Linux), or the Win32 process object (Windows has neither).
PROBES: tuple[str, ...] = (
    ("win32",)
    if os.name == "nt"
    else tuple(p for p, ok in (("proc", _HAS_PROC), ("ps", os.path.exists("/bin/ps"))) if ok)
)
_STILL_ACTIVE = 259  # GetExitCodeProcess while the process runs
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _win32_state(pid: int) -> str | None:
    """State "R" while running, "Z" once exited but still held open, else None.

    ``os.kill(pid, 0)`` can't probe on Windows: signal 0 is ``CTRL_C_EVENT``, so it
    would send Ctrl+C to a console process group instead of checking the pid.
    """
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not handle:
        return None
    try:
        code = ctypes.c_uint32()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return None
        return "R" if code.value == _STILL_ACTIVE else "Z"
    finally:
        kernel32.CloseHandle(handle)


def _state(pid: int, *, probe: str = PROBES[0] if PROBES else "none") -> str | None:
    """The process state letter(s), or None once the pid is gone.

    Linux reads /proc. macOS has no /proc, so it asks ``/bin/ps -o stat=``;
    reading /proc there always failed, so every pid looked dead (CON-10/11 #43).
    Windows asks the process object (:func:`_win32_state`).
    """
    if probe == "win32":
        return _win32_state(pid)
    if probe == "proc":
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            return None
    out = subprocess.run(  # noqa: S603 - fixed absolute argv, no shell
        ["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False
    )
    return out.stdout.strip() or None


def _alive(pid: int, *, probe: str = PROBES[0] if PROBES else "none") -> bool:
    """Running and not a zombie (a zombie still answers ``kill(pid, 0)``)."""
    if probe != "win32":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
    state = _state(pid, probe=probe)
    return state is not None and not state.startswith("Z")


def test_alive_tells_running_zombie_and_reaped_apart() -> None:
    """The helper itself, with every probe this OS has (/proc, /bin/ps, or Win32)."""
    assert PROBES, "no way to read a process state on this OS"
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE
    )
    try:
        for probe in PROBES:
            assert _alive(child.pid, probe=probe), probe
        assert child.stdin is not None
        child.stdin.close()
        deadline = time.monotonic() + 5.0  # exited but not yet reaped: a zombie
        while any(_alive(child.pid, probe=p) for p in PROBES):
            assert time.monotonic() < deadline, "the exited child still looks alive"
            time.sleep(0.05)
        for probe in PROBES:
            assert _state(child.pid, probe=probe) is not None  # zombie, not gone
    finally:
        child.kill()
        child.wait()
    for probe in PROBES:
        assert not _alive(child.pid, probe=probe)


def _gone_soon(pid: int) -> bool:
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


#: Longest wait for the fake git to start its grandchild (a slow runner's cold start).
READY_LIMIT = 30.0


class _Gate:
    """Make gitread's deadline count from the grandchild's start, not git's spawn.

    The fake git writes grandchild.pid only once its grandchild is running.
    Interpreter startup alone took longer than TIMEOUT on a macOS runner (main
    d7e911b, job 131748449282): the kill fired before the fake had started the
    grandchild, so grandchild.pid never existed and the case proved nothing.

    gitread reads ``_clock()`` right after spawning git to set its deadline. Once
    the fake is spawned (:meth:`arm`), the next read blocks until the pid file
    exists, so every kill below has a pipe-holding grandchild to deal with, and
    :attr:`ready_at` is when it started (the test bounds the kill from there).
    Reads before that (``GitReader``'s real-git version check) pass through.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.pidfile = tmp_path / "grandchild.pid"
        self.armed = False
        self.ready_at: float | None = None

    def arm(self) -> None:
        self.armed = True

    def wait(self) -> float:
        """Block until the fake has written grandchild.pid (bounded); return when."""
        if self.ready_at is None:
            end = time.monotonic() + READY_LIMIT
            while not self.pidfile.exists():
                assert time.monotonic() < end, "the fake git never started its grandchild"
                time.sleep(0.01)
            self.ready_at = time.monotonic()
        return self.ready_at

    def clock(self) -> float:
        if self.armed:
            self.wait()
        return time.monotonic()


#: Longest wait for the fake git to start its grandchild (a slow runner's cold start).
READY_LIMIT = 30.0


def _use_fake(monkeypatch: pytest.MonkeyPatch, argv: list[str], gate: _Gate) -> None:
    real = gitread._start_batch

    def start(_argv: list[str], **kwargs: Any) -> Any:
        process = real(argv, **kwargs)
        gate.arm()
        return process

    monkeypatch.setattr(gitread, "_start_batch", start)
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", TIMEOUT)


def _repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    return path


# Each trigger drives one kill path; it gets the fake git argv and returns nothing.
def _run_bounded_timeout(
    tmp_path: Path, argv: list[str], _m: pytest.MonkeyPatch, gate: _Gate
) -> None:
    gate.arm()  # _run_bounded spawns the fake, then sets its deadline
    with pytest.raises(ComponentError, match="git log timed out"):
        gitread._run_bounded(
            argv, cwd=tmp_path, env=dict(os.environ), label="log", max_stdout=4096, timeout=TIMEOUT
        )


def _run_bounded_cap(tmp_path: Path, argv: list[str], _m: pytest.MonkeyPatch, gate: _Gate) -> None:
    gate.arm()
    with pytest.raises(ComponentError, match="git log output too large"):
        gitread._run_bounded(
            argv, cwd=tmp_path, env=dict(os.environ), label="log", max_stdout=3, timeout=10.0
        )


def _reader_close(
    tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch, gate: _Gate
) -> None:
    _use_fake(monkeypatch, argv, gate)
    reader = GitReader(_repo(tmp_path))
    reader._batch_process("--batch-check")
    gate.wait()  # no deadline on this path: wait for the grandchild directly
    reader.close()


def _blob_failure(
    tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch, gate: _Gate
) -> None:
    _use_fake(monkeypatch, argv, gate)
    with pytest.raises(ComponentError):  # the fake prints no header: timeout or bad output
        GitReader(_repo(tmp_path)).blob(SHA, 10)


def _patches_close(
    tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch, gate: _Gate
) -> None:
    _use_fake(monkeypatch, argv, gate)
    stream = GitReader(_repo(tmp_path)).patches(SHA, SHA2)
    assert next(stream) == b"xxxxx"
    stream.close()


def _patches_timeout(
    tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch, gate: _Gate
) -> None:
    _use_fake(monkeypatch, argv, gate)
    with pytest.raises(ComponentError, match="git log timed out"):
        list(GitReader(_repo(tmp_path)).patches(SHA, SHA2))


Trigger = Callable[[Path, list[str], pytest.MonkeyPatch, _Gate], None]
#: (caller in gitread that kills, what it is called on, trigger, what git prints).
TRIGGERS: dict[str, tuple[str, Trigger, str]] = {
    "_run_bounded timeout": ("_run_bounded", _run_bounded_timeout, ""),
    "_run_bounded cap": ("_run_bounded", _run_bounded_cap, "xxxxx"),
    "GitReader.close": ("close", _reader_close, ""),
    "blob failure": ("close", _blob_failure, ""),
    "patches close": ("_stream_patches", _patches_close, "xxxxx"),
    "patches timeout": ("_stream_patches", _patches_timeout, ""),
}


def _killers() -> set[str]:
    """Functions in gitread that call ``_kill_tree`` or ``<process>.kill()``."""
    tree = ast.parse(inspect.getsource(gitread))
    found: set[str] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    f = node.func
                    if isinstance(f, ast.Name) and f.id == "_kill_tree":
                        found.add(fn.name)
                    if isinstance(f, ast.Attribute) and f.attr == "kill":
                        found.add(fn.name)
    return found


def test_triggers_cover_every_kill_path_in_the_code() -> None:
    # _kill_tree's own proc.kill() fallback and _BatchProcess.kill are the
    # mechanism; every other caller is a path that a trigger drives.
    assert _killers() - {"_kill_tree", "kill"} == {t[0] for t in TRIGGERS.values()}


def _pipe_cases() -> list[pytest.ParameterSet]:
    cases: list[pytest.ParameterSet] = []
    for path in sorted(TRIGGERS):
        for kind in sorted(KINDS):
            cases.append(pytest.param(path, kind, id=f"{path}-{kind}"))
    return cases


@pytest.mark.parametrize(("path", "kind"), _pipe_cases())
def test_a_pipe_holding_grandchild_never_stretches_a_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str, kind: str
) -> None:
    parent_exits, escapes = KINDS[kind]
    _, trigger, payload = TRIGGERS[path]
    argv = _fake_git(tmp_path, parent_exits, escapes, payload)
    gate = _Gate(tmp_path)
    monkeypatch.setattr(gitread, "_clock", gate.clock)
    try:
        trigger(tmp_path, argv, monkeypatch, gate)
        assert gate.ready_at is not None, "the kill came before the grandchild started"
        assert time.monotonic() - gate.ready_at < PROMPT
        pid = int((tmp_path / "grandchild.pid").read_text())
        if escapes:
            assert _alive(pid)  # outside git's group: not ours to kill, and not waited for
        else:
            assert _gone_soon(pid)  # the whole group is gone
    finally:
        pidfile = tmp_path / "grandchild.pid"
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), getattr(signal, "SIGKILL", 9))
            except (ProcessLookupError, PermissionError, OSError):
                pass
