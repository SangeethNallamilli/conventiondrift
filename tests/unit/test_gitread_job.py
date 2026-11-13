"""Unit tests for the Windows job object that holds git's process tree (I-13 C3).

Windows is simulated through gitread's own view of ``os`` and a stub kernel32;
the real ``os`` and pathlib are untouched. One real test runs on every OS.
"""

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

JOB, PROCESS = 0x7001, 0x7002


class _OsAs:
    """gitread's view of ``os`` as another OS; the real ``os`` (and pathlib) is untouched."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


class _Kernel32:
    """Records every job call; ``fail`` names the one call that returns 0."""

    def __init__(self, fail: str = "") -> None:
        self.fail = fail
        self.calls: list[tuple[Any, ...]] = []
        self.closed: list[int] = []

    def _ok(self, name: str, result: int = 1) -> int:
        return 0 if self.fail == name else result

    def CreateJobObjectW(self, attributes: Any, name: Any) -> int:
        self.calls.append(("create", attributes, name))
        return self._ok("create", JOB)

    def SetInformationJobObject(self, handle: int, info_class: int, info: Any, size: int) -> int:
        flags = ctypes.cast(info, ctypes.POINTER(type(info._obj)))[0]  # the byref'd struct
        self.calls.append(("limits", handle, info_class, flags.BasicLimitInformation.LimitFlags))
        assert size == ctypes.sizeof(info._obj)
        return self._ok("limits")

    def OpenProcess(self, access: int, inherit: int, pid: int) -> int:
        self.calls.append(("open", access, inherit, pid))
        return self._ok("open", PROCESS)

    def AssignProcessToJobObject(self, job: int, process: int) -> int:
        self.calls.append(("assign", job, process))
        return self._ok("assign")

    def TerminateJobObject(self, handle: int, code: int) -> int:
        self.calls.append(("terminate", handle, code))
        if self.fail == "terminate":
            raise OSError("terminate failed")
        return 1

    def CloseHandle(self, handle: int) -> int:
        self.calls.append(("close", handle))
        self.closed.append(handle)
        return 1


class _Popen:
    pid = 4242


def _as_windows(monkeypatch: pytest.MonkeyPatch, kernel: Any) -> None:
    monkeypatch.setattr(gitread, "os", _OsAs("nt"))
    monkeypatch.setattr(gitread, "_kernel32", lambda: kernel)


def _assign(proc: Any) -> gitread._Job | None:
    return gitread._assign_job(proc)


def test_posix_never_makes_a_job(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_kernel() -> Any:
        raise AssertionError("kernel32 used on POSIX")

    monkeypatch.setattr(gitread, "os", _OsAs("posix"))
    monkeypatch.setattr(gitread, "_kernel32", no_kernel)
    assert _assign(_Popen()) is None


def test_windows_puts_git_in_a_kill_on_close_job(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = _Kernel32()
    _as_windows(monkeypatch, kernel)
    job = _assign(_Popen())
    assert job is not None
    flags = 0x2000 | 0x0800  # KILL_ON_JOB_CLOSE | BREAKAWAY_OK, by hand
    assert kernel.calls == [
        ("create", None, None),
        ("limits", JOB, 9, flags),  # JobObjectExtendedLimitInformation
        ("open", 0x0100 | 0x0001, 0, 4242),  # PROCESS_SET_QUOTA | PROCESS_TERMINATE
        ("assign", JOB, PROCESS),
        ("close", PROCESS),  # the process handle only; the job stays open
    ]
    job.close()
    assert kernel.closed == [PROCESS, JOB]


@pytest.mark.parametrize(
    ("fail", "closed"),
    [
        ("create", []),
        ("limits", [JOB]),
        ("open", [JOB]),
        ("assign", [PROCESS, JOB]),
    ],
)
def test_windows_job_failures_fall_back_and_leak_nothing(
    monkeypatch: pytest.MonkeyPatch, fail: str, closed: list[int]
) -> None:
    kernel = _Kernel32(fail=fail)
    _as_windows(monkeypatch, kernel)
    assert _assign(_Popen()) is None
    assert kernel.closed == closed  # each handle that was opened, exactly once


@pytest.mark.parametrize("error", [OSError("no kernel32"), AttributeError("no WinDLL")])
def test_windows_without_kernel32_falls_back(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def missing() -> Any:
        raise error

    monkeypatch.setattr(gitread, "os", _OsAs("nt"))
    monkeypatch.setattr(gitread, "_kernel32", missing)
    assert _assign(_Popen()) is None


@pytest.mark.parametrize("fail", ["", "terminate"])
def test_terminate_kills_the_job_then_closes_it_once(
    monkeypatch: pytest.MonkeyPatch, fail: str
) -> None:
    kernel = _Kernel32(fail=fail)
    job = gitread._Job(kernel, JOB)
    job.terminate()
    job.terminate()
    job.close()
    assert kernel.calls == [("terminate", JOB, 1), ("close", JOB)]


class _Proc:
    pid = 4242

    def __init__(self, events: list[str], root_dead: bool) -> None:
        self.events = events
        self.root_dead = root_dead

    def kill(self) -> None:
        self.events.append("kill")
        if self.root_dead:
            raise ProcessLookupError

    def wait(self, timeout: float | None = None) -> int:
        self.events.append("wait")
        return 0


class _RecordingJob:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def terminate(self) -> None:
        self.events.append("terminate")

    def close(self) -> None:
        self.events.append("close")


@pytest.mark.parametrize("root_dead", [False, True])
def test_kill_with_a_job_terminates_it_and_never_runs_taskkill(
    monkeypatch: pytest.MonkeyPatch, root_dead: bool
) -> None:
    monkeypatch.setattr(gitread, "os", _OsAs("nt"))

    def no_taskkill(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("taskkill on the job path")

    monkeypatch.setattr(subprocess, "run", no_taskkill)
    events: list[str] = []
    gitread._kill_tree(_Proc(events, root_dead), _RecordingJob(events))  # type: ignore[arg-type]
    assert events == ["terminate", "kill", "wait"]


def test_kill_with_a_real_job_object_closes_its_handle_before_reaping() -> None:
    kernel = _Kernel32()
    events: list[str] = []

    class _Watch(_Proc):
        def kill(self) -> None:
            events.append(f"kill after {kernel.calls}")

    gitread._kill_tree(_Watch(events, False), gitread._Job(kernel, JOB))  # type: ignore[arg-type]
    assert events == [f"kill after {[('terminate', JOB, 1), ('close', JOB)]}", "wait"]


def _seam(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace ``_assign_job`` with one that hands out a recording job."""
    events: list[str] = []
    monkeypatch.setattr(gitread, "_assign_job", lambda _proc: _RecordingJob(events))
    return events


def test_run_bounded_closes_the_job_after_a_clean_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events = _seam(monkeypatch)
    out = gitread._run_bounded(
        [sys.executable, "-c", "print('ok')"],
        cwd=tmp_path,
        env=dict(os.environ),
        label="log",
        max_stdout=64,
        timeout=20.0,
    )
    assert out.stdout.strip() == b"ok"
    assert events == ["close"]


def test_run_bounded_kills_through_the_job_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events = _seam(monkeypatch)
    with pytest.raises(ComponentError, match="git log timed out"):
        gitread._run_bounded(
            [sys.executable, "-c", "import time; time.sleep(20)"],
            cwd=tmp_path,
            env=dict(os.environ),
            label="log",
            max_stdout=64,
            timeout=0.3,
        )
    assert events == ["terminate"]


def test_batch_process_kills_through_its_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events = _seam(monkeypatch)
    process = gitread._start_batch(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        cwd=tmp_path,
        env=dict(os.environ),
        label="cat-file",
    )
    process.kill()
    assert events == ["terminate"]


def test_job_limits_layout() -> None:
    info = gitread._job_limits(0x2800)
    assert info.BasicLimitInformation.LimitFlags == 0x2800
    assert info.BasicLimitInformation.ActiveProcessLimit == 0
    # JOBOBJECT_EXTENDED_LIMIT_INFORMATION: 144 bytes on 64-bit, 112 on 32-bit.
    assert ctypes.sizeof(info) == {8: 144, 4: 112}[ctypes.sizeof(ctypes.c_void_p)]


class _Function:
    def __init__(self) -> None:
        self.restype: Any = None
        self.argtypes: Any = None


class _Dll:
    def __init__(self, name: str, *, use_last_error: bool) -> None:
        self.name = name
        self.use_last_error = use_last_error

    def __getattr__(self, attr: str) -> _Function:
        function = _Function()
        setattr(self, attr, function)
        return function


def test_kernel32_job_prototypes_are_handle_sized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "WinDLL", _Dll, raising=False)
    kernel = gitread._kernel32()
    handle = ctypes.c_void_p
    assert kernel.CreateJobObjectW.restype is handle
    assert kernel.OpenProcess.restype is handle
    assert kernel.CreateJobObjectW.argtypes == [handle, ctypes.c_wchar_p]
    assert kernel.SetInformationJobObject.argtypes == [
        handle,
        ctypes.c_int,
        handle,
        ctypes.c_uint32,
    ]
    assert kernel.AssignProcessToJobObject.argtypes == [handle, handle]
    assert kernel.TerminateJobObject.argtypes == [handle, ctypes.c_uint]


# --- one real run on every OS ------------------------------------------------------

_STILL_ACTIVE = 259
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_BREAKAWAY_FLAGS = _CREATE_BREAKAWAY_FROM_JOB | _CREATE_NEW_PROCESS_GROUP


def _windows_alive(pid: int) -> bool:
    """Win32 liveness: ``os.kill(pid, 0)`` would send Ctrl+C on Windows, never use it."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_uint32()
        ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return bool(ok) and code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def _posix_alive(pid: int) -> bool:
    """Running and not a zombie: /proc on Linux, ``/bin/ps`` elsewhere."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        try:
            return not stat.read_text().rsplit(")", 1)[1].split()[0].startswith("Z")
        except OSError:
            return False
    out = subprocess.run(  # noqa: S603 - fixed absolute argv, no shell
        ["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False
    )
    state = out.stdout.strip()
    return bool(state) and not state.startswith("Z")


def _alive(pid: int) -> bool:
    return _windows_alive(pid) if os.name == "nt" else _posix_alive(pid)


def _gone_soon(pid: int) -> bool:
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _tree_git(tmp_path: Path, *, escape: bool) -> list[str]:
    """A git that starts grandchildren holding its pipes, then exits.

    ``in_group`` prints past the cap after git has exited, so the kill comes when
    only grandchildren are left. ``new_group`` (Windows only) is merely a new
    process group, which stays in scope. With ``escape``, ``escaped`` leaves git's
    kill scope (Windows: breakaway from the job; POSIX: its own session).
    """
    code = (
        "import os, subprocess, sys\n"
        f"base = {str(tmp_path)!r}\n"
        "sleep = [sys.executable, '-c', 'import time; time.sleep(20)']\n"
        "pids = {}\n"
        f"if {escape!r}:\n"
        "    if os.name == 'nt':\n"
        f"        away = {{'creationflags': {_BREAKAWAY_FLAGS}}}\n"
        "    else:\n"
        "        away = {'start_new_session': True}\n"
        "    try:\n"
        "        pids['escaped'] = subprocess.Popen(sleep, **away).pid\n"
        "    except PermissionError:\n"
        "        open(os.path.join(base, 'denied'), 'w').write('denied')\n"
        "        sys.exit(0)\n"
        "if os.name == 'nt':\n"
        f"    group = {{'creationflags': {_CREATE_NEW_PROCESS_GROUP}}}\n"
        "    pids['new_group'] = subprocess.Popen(sleep, **group).pid\n"
        "late = 'import time; time.sleep(0.5); print(\"x\" * 64, flush=True); time.sleep(20)'\n"
        "pids['in_group'] = subprocess.Popen([sys.executable, '-c', late]).pid\n"
        "for name, pid in pids.items():\n"
        "    open(os.path.join(base, name + '.pid'), 'w').write(str(pid))\n"
    )
    return [sys.executable, "-c", code]


def _cap_after_git_exits(tmp_path: Path, *, escape: bool) -> tuple[float, dict[str, int]]:
    """Run the tree past the cap; the elapsed time and the grandchildren's pids."""
    begin = time.monotonic()
    try:
        gitread._run_bounded(
            _tree_git(tmp_path, escape=escape),
            cwd=tmp_path,
            env=dict(os.environ),
            label="log",
            max_stdout=3,
            timeout=10.0,
        )
    except ComponentError as exc:
        assert exc.args[-1] == "git log output too large"
    else:
        if os.name == "nt" and (tmp_path / "denied").exists():
            pytest.skip("the runner's own job forbids breakaway (ERROR_ACCESS_DENIED)")
        pytest.fail("the cap was not hit")
    return time.monotonic() - begin, {p.stem: int(p.read_text()) for p in tmp_path.glob("*.pid")}


def _clean_up(pids: dict[str, int]) -> None:
    for pid in pids.values():
        if _alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows
            except OSError:
                pass


def test_a_real_kill_after_git_exits_takes_the_in_group_tree(tmp_path: Path) -> None:
    elapsed, pids = _cap_after_git_exits(tmp_path, escape=False)
    try:
        assert elapsed < 4.5
        assert _gone_soon(pids["in_group"])
        if os.name == "nt":
            assert _gone_soon(pids["new_group"])  # a new process group alone is in scope
    finally:
        _clean_up(pids)


def test_a_real_kill_after_git_exits_spares_the_escaped(tmp_path: Path) -> None:
    elapsed, pids = _cap_after_git_exits(tmp_path, escape=True)
    try:
        assert elapsed < 4.5
        assert _gone_soon(pids["in_group"])
        if os.name == "nt":
            assert _gone_soon(pids["new_group"])
        assert _alive(pids["escaped"])
    finally:
        _clean_up(pids)


@pytest.mark.skipif(os.name != "nt", reason="real Windows job object")
def test_windows_git_is_really_in_a_kill_on_close_job() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    job = gitread._assign_job(proc)
    try:
        assert job is not None
        job.terminate()
        assert proc.wait(4.5) == 1  # TerminateJobObject's exit code
    finally:
        proc.kill()
        proc.wait(4.5)
