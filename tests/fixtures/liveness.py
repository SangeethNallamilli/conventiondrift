"""Is a process still running? A probe that never signals it (backlog "goneprobe").

Test tooling only. ``os.kill(pid, 0)`` is no probe on Windows: signal 0 is
``CTRL_C_EVENT``, so CPython calls ``GenerateConsoleCtrlEvent(0, pid)``, which takes a
process *group* id. For any other pid it fails with WinError 87. Before 3.12.9 and
3.13.2, CPython then falls through to ``OpenProcess`` and ``TerminateProcess(pid, 0)``:
it kills a live process and raises ``SystemError`` (gh-87128). Since gh-58689 it raises
``OSError`` 87 for a live process and a gone one alike. Either way, an
``OSError`` or ``SystemError`` from it says nothing about whether the process was gone.

Here Windows asks ``OpenProcess`` for a handle and waits on it for 0 ms; POSIX keeps
``os.kill(pid, 0)`` (no signal is sent) and counts a zombie as gone. An error the probe
can't read raises: it is never taken to mean "gone". A pid Windows or the kernel has
reused for a new process reads as running, so a test can only fail that way, never pass.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from pathlib import Path
from typing import Any

_SYNCHRONIZE = 0x00100000
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_PARAMETER = 87  # OpenProcess: no process has this pid
_WAIT_OBJECT_0 = 0x0
_WAIT_TIMEOUT = 0x102


def windows_running(pid: int, kernel32: Any, last_error: Any) -> bool:
    """Win32: True while ``pid`` runs. ``kernel32`` and ``last_error`` are parameters so
    the logic runs, with fakes, on every OS."""
    handle = kernel32.OpenProcess(_SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not handle:
        err = last_error()
        if err == _ERROR_INVALID_PARAMETER:
            return False
        if err == _ERROR_ACCESS_DENIED:
            return True  # it exists; we may not open it
        raise OSError(f"OpenProcess({pid}) failed: WinError {err}")
    try:
        state = kernel32.WaitForSingleObject(handle, 0)
        if state == _WAIT_TIMEOUT:
            return True
        if state == _WAIT_OBJECT_0:
            return False  # exited (the object lives on while handles to it remain)
        raise OSError(f"WaitForSingleObject({pid}) gave {state:#x}: WinError {last_error()}")
    finally:
        kernel32.CloseHandle(handle)


def posix_running(pid: int) -> bool:
    """POSIX: True while ``pid`` runs and is not a zombie (``/proc`` where there is one)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # it exists; it is not ours
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        # With a /proc (Linux) it ended since the kill; without one (macOS) the kill said
        # it runs, and a zombie there is reaped by launchd soon after its parent dies.
        return not Path("/proc/self").exists()
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def _kernel32() -> Any:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    return kernel32


def running(pid: int) -> bool:
    """True while ``pid`` runs, on this OS. Never signals or ends the process."""
    if sys.platform == "win32":
        return windows_running(pid, _kernel32(), ctypes.get_last_error)  # type: ignore[attr-defined,unused-ignore]
    else:
        return posix_running(pid)


def gone_within(pid: int, wait: float) -> bool:
    """True once ``pid`` has stopped running, polled for up to ``wait`` seconds."""
    deadline = time.monotonic() + wait
    while True:
        if not running(pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
