"""Unit tests for killing git's whole process tree on a timeout or cap (T-008, SR N-4)."""

import ctypes
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError


def _gone(pid: int, wait: float = 10.0) -> bool:
    """True once ``pid`` no longer runs (exited, or a zombie waiting to be reaped)."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        stat = Path(f"/proc/{pid}/stat")
        try:
            if stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                return True
        except OSError:
            pass
        time.sleep(0.05)
    return False


def _fake_git(tmp_path: Path, parent_exits: bool) -> list[str]:
    """A 'git' that starts a long-sleeping grandchild holding stdout, then waits or exits."""
    pidfile = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
        + ("sys.exit(0)\n" if parent_exits else "time.sleep(60)\n")
    )
    return [sys.executable, "-c", code]


def _grandchild(tmp_path: Path) -> int:
    return int((tmp_path / "grandchild.pid").read_text())


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups; Windows is stubbed below")
@pytest.mark.parametrize("parent_exits", [False, True])
def test_timeout_kills_the_grandchild_too(tmp_path: Path, parent_exits: bool) -> None:
    start = time.monotonic()
    with pytest.raises(ComponentError, match="git log timed out"):
        gitread._run_bounded(
            _fake_git(tmp_path, parent_exits),
            cwd=tmp_path,
            env=dict(os.environ),
            label="log",
            max_stdout=1024,
            timeout=2.0,
        )
    assert time.monotonic() - start < 20
    assert _gone(_grandchild(tmp_path))


@pytest.mark.skipif(os.name == "nt", reason="POSIX sessions")
def test_git_runs_in_its_own_session(tmp_path: Path) -> None:
    out = gitread._run_bounded(
        [sys.executable, "-c", "import os; print(os.getsid(0) == os.getpid())"],
        cwd=tmp_path,
        env=dict(os.environ),
        label="log",
        max_stdout=64,
        timeout=20.0,
    )
    assert out.stdout == b"True\n"


SIGKILL = 9  # stubbed on every OS: Windows' signal module has no SIGKILL


class _OsAs:
    """gitread's view of ``os`` as another OS; the real ``os`` (and pathlib) is untouched."""

    def __init__(self, name: str, **overrides: Any) -> None:
        self.name = name
        self.__dict__.update(overrides)

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


def _as_posix(monkeypatch: pytest.MonkeyPatch, killpg: Any) -> None:
    monkeypatch.setattr(gitread, "os", _OsAs("posix", killpg=killpg))
    monkeypatch.setattr(signal, "SIGKILL", SIGKILL, raising=False)


def _as_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitread, "os", _OsAs("nt"))


def test_process_group_kwargs_per_os(monkeypatch: pytest.MonkeyPatch) -> None:
    _as_posix(monkeypatch, killpg=None)
    assert gitread._process_group_kwargs() == {"start_new_session": True}
    _as_windows(monkeypatch)
    assert gitread._process_group_kwargs() == {"creationflags": 0x200}


class _Proc:
    pid = 4242

    def __init__(self, kill_error: bool = False, wait_hangs: bool = False) -> None:
        self.events: list[str] = []
        self.kill_error = kill_error
        self.wait_hangs = wait_hangs
        self.wait_timeouts: list[float | None] = []

    def kill(self) -> None:
        self.events.append("kill")
        if self.kill_error:
            raise ProcessLookupError

    def wait(self, timeout: float | None = None) -> int:
        self.events.append("wait")
        self.wait_timeouts.append(timeout)
        if self.wait_hangs:
            raise subprocess.TimeoutExpired("git", timeout or 0.0)
        return -9


def test_posix_kill_signals_the_whole_group(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[int, int]] = []
    _as_posix(monkeypatch, killpg=lambda pid, sig: sent.append((pid, sig)))
    proc = _Proc()
    gitread._kill_tree(proc)  # type: ignore[arg-type]
    assert sent == [(4242, SIGKILL)]
    assert proc.events == ["kill", "wait"]


def test_posix_kill_of_an_empty_group_still_reaps(monkeypatch: pytest.MonkeyPatch) -> None:
    def gone(_pid: int, _sig: int) -> None:
        raise ProcessLookupError

    _as_posix(monkeypatch, killpg=gone)
    proc = _Proc(kill_error=True)
    gitread._kill_tree(proc)  # type: ignore[arg-type]
    assert proc.events == ["kill", "wait"]


def test_windows_kill_runs_taskkill_by_absolute_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _as_windows(monkeypatch)
    monkeypatch.setattr(gitread, "_system32", lambda: "C:\\Windows\\System32")
    runs: list[dict[str, Any]] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        runs.append({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", run)
    proc = _Proc()
    gitread._kill_tree(proc)  # type: ignore[arg-type]
    (call,) = runs
    exe = call["argv"][0]
    assert exe.startswith("C:\\Windows\\System32") and exe.endswith("taskkill.exe")
    assert call["argv"][1:] == ["/T", "/F", "/PID", "4242"]
    assert call["shell"] is False and call["timeout"] == gitread._TASKKILL_TIMEOUT_SECONDS
    assert call["stdin"] is subprocess.DEVNULL
    assert proc.events == ["kill", "wait"]


@pytest.mark.parametrize(
    "error", [OSError("no taskkill"), subprocess.TimeoutExpired("taskkill", 10.0)]
)
def test_windows_kill_falls_back_to_kill_when_taskkill_fails(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    _as_windows(monkeypatch)
    monkeypatch.setattr(gitread, "_system32", lambda: "C:\\Windows\\System32")

    def run(*_a: Any, **_k: Any) -> Any:
        raise error

    monkeypatch.setattr(subprocess, "run", run)
    proc = _Proc()
    gitread._kill_tree(proc)  # type: ignore[arg-type]
    assert proc.events == ["kill", "wait"]


class _Kernel32:
    def __init__(self, value: str, length: int) -> None:
        self.value = value
        self.length = length

    def GetSystemDirectoryW(self, buffer: Any, size: int) -> int:
        assert size == 260
        buffer.value = self.value
        return self.length


class _WinDLL:
    def __init__(self, kernel32: _Kernel32) -> None:
        self.kernel32 = kernel32


def test_system32_comes_from_the_os(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = _Kernel32("C:\\Windows\\System32", 19)
    monkeypatch.setattr(ctypes, "windll", _WinDLL(kernel), raising=False)
    assert gitread._system32() == "C:\\Windows\\System32"


@pytest.mark.parametrize("length", [0, 260])
def test_system32_failure_is_an_os_error(monkeypatch: pytest.MonkeyPatch, length: int) -> None:
    monkeypatch.setattr(ctypes, "windll", _WinDLL(_Kernel32("", length)), raising=False)
    with pytest.raises(OSError, match="system directory not found"):
        gitread._system32()


def test_reaping_waits_a_bounded_time_and_never_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    _as_posix(monkeypatch, killpg=lambda _pid, _sig: None)
    proc = _Proc(wait_hangs=True)
    gitread._kill_tree(proc)  # type: ignore[arg-type]  # returns despite the timeout
    assert proc.wait_timeouts == [5.0]  # _REAP_TIMEOUT_SECONDS, by hand
