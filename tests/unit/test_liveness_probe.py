"""The test-only liveness probe (backlog "goneprobe", CR1/SR L-42-1, D-TL-90).

A probe that answers "gone" for a live process, or ends the process it probes, makes
every "the tree was killed" test pass whatever gitread did. These tests pin that it
does neither, on the real OS, and pin the Win32 answers with a fake ``kernel32``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

import pytest
from tests.fixtures import liveness
from tests.fixtures.liveness import gone_within, running


def _sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


def test_a_live_process_reads_running_and_the_probe_leaves_it_running() -> None:
    proc = _sleeper()
    try:
        for _ in range(5):
            assert running(proc.pid)
        assert not gone_within(proc.pid, wait=0.3)
        time.sleep(0.3)
        assert proc.poll() is None  # probing never ended it (os.kill(pid, 0) on Windows did)
        assert running(proc.pid)
    finally:
        proc.kill()
        proc.wait()


def test_an_ended_process_reads_gone() -> None:
    proc = _sleeper()
    proc.kill()
    proc.wait()  # reaped (POSIX) and its last handle closed with the Popen (Windows)
    assert not running(proc.pid)
    assert gone_within(proc.pid, wait=0.0)


@pytest.mark.skipif(sys.platform == "win32", reason="zombies are POSIX")
def test_a_zombie_reads_gone() -> None:
    proc = _sleeper()
    proc.kill()
    deadline = time.monotonic() + 10
    while running(proc.pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not running(proc.pid)  # dead but not yet reaped
    proc.wait()


class _Kernel32:
    """``OpenProcess`` gives ``handle`` (0: fails), ``WaitForSingleObject`` gives ``wait``."""

    def __init__(self, handle: int, wait: int = 0x102) -> None:
        self.handle, self.wait = handle, wait
        self.calls: list[tuple[Any, ...]] = []

    def OpenProcess(self, access: int, inherit: int, pid: int) -> int:
        self.calls.append(("open", access, inherit, pid))
        return self.handle

    def WaitForSingleObject(self, handle: int, ms: int) -> int:
        self.calls.append(("wait", handle, ms))
        return self.wait

    def CloseHandle(self, handle: int) -> int:
        self.calls.append(("close", handle))
        return 1


@pytest.mark.parametrize(
    ("handle", "wait", "error", "expected"),
    [
        (0, 0, 87, False),  # ERROR_INVALID_PARAMETER: no process has this pid
        (0, 0, 5, True),  # ERROR_ACCESS_DENIED: it exists
        (7, 0x102, 0, True),  # WAIT_TIMEOUT: still running
        (7, 0x0, 0, False),  # WAIT_OBJECT_0: exited
    ],
)
def test_windows_answers(handle: int, wait: int, error: int, expected: bool) -> None:
    kernel = _Kernel32(handle, wait)
    assert liveness.windows_running(4242, kernel, lambda: error) is expected
    assert kernel.calls[0] == ("open", 0x00100000 | 0x1000, 0, 4242)  # SYNCHRONIZE | QUERY_LIMITED
    if handle:
        assert kernel.calls[1:] == [("wait", handle, 0), ("close", handle)]
    else:
        assert kernel.calls[1:] == []


@pytest.mark.parametrize(("handle", "wait", "error"), [(0, 0, 6), (0, 0, 0), (7, 0xFFFFFFFF, 6)])
def test_windows_errors_it_cannot_read_raise_never_gone(handle: int, wait: int, error: int) -> None:
    kernel = _Kernel32(handle, wait)
    with pytest.raises(OSError, match=f"WinError {error}$"):
        liveness.windows_running(4242, kernel, lambda: error)
    if handle:
        assert kernel.calls[-1] == ("close", handle)  # the handle is closed on the error path


def test_posix_errors_it_cannot_read_raise_never_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    def fails(pid: int, sig: int) -> None:
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(os, "kill", fails)
    with pytest.raises(OSError):
        liveness.posix_running(4242)


@pytest.mark.parametrize(
    ("exc", "expected"), [(ProcessLookupError, False), (PermissionError, True)]
)
def test_posix_lookup_and_permission(
    monkeypatch: pytest.MonkeyPatch, exc: type[OSError], expected: bool
) -> None:
    def kill(pid: int, sig: int) -> None:
        assert sig == 0
        raise exc()

    monkeypatch.setattr(os, "kill", kill)
    assert liveness.posix_running(4242) is expected
