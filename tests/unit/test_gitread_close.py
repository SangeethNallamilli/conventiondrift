"""Unit tests for closing git's pipes without blocking on a process that holds them.

Windows is simulated through gitread's own view of ``os`` and a stub ``kernel32``;
the real ``os`` and pathlib are untouched.
"""

import ctypes
import os
import threading
import time
from typing import Any, cast

import pytest

from conventiondrift import gitread


class _OsAs:
    """gitread's view of ``os`` as another OS; the real ``os`` (and pathlib) is untouched."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


class _Clock:
    """A clock that moves only when a fake reader waits."""

    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class _Reader:
    """A reader thread stand-in that ends after ``cancels_to_end`` cancels (never if None)."""

    native_id = 777

    def __init__(self, clock: _Clock, *, alive: bool, cancels_to_end: int | None = None) -> None:
        self.clock = clock
        self.alive = alive
        self.cancels_to_end = cancels_to_end
        self.cancels = 0
        self.joins: list[float | None] = []

    def join(self, timeout: float | None = None) -> None:
        self.joins.append(timeout)
        self.clock.now += timeout or 0.0

    def is_alive(self) -> bool:
        return self.alive

    def cancelled(self) -> None:
        self.cancels += 1
        if self.cancels_to_end is not None and self.cancels >= self.cancels_to_end:
            self.alive = False


class _Kernel32:
    def __init__(self, reader: _Reader, handle: int = 0x5150) -> None:
        self.reader = reader
        self.handle = handle
        self.opened: list[tuple[int, int, int]] = []
        self.closed: list[int] = []

    def OpenThread(self, access: int, inherit: int, thread_id: int) -> int:
        self.opened.append((access, inherit, thread_id))
        return self.handle

    def CancelSynchronousIo(self, handle: int) -> int:
        assert handle == self.handle
        self.reader.cancelled()
        return 1

    def CloseHandle(self, handle: int) -> int:
        self.closed.append(handle)
        return 1


class _Raw:
    def __init__(self, block: threading.Event | None = None, error: Exception | None = None):
        self.block = block
        self.error = error
        self.closes = 0
        self.done = threading.Event()

    def close(self) -> None:
        self.closes += 1
        try:
            if self.block is not None:
                self.block.wait(10.0)
            if self.error is not None:
                raise self.error
        finally:
            self.done.set()


class _Pipe:
    def __init__(self, raw: _Raw | None) -> None:
        if raw is not None:
            self.raw = raw
        self.closes = 0

    def close(self) -> None:
        self.closes += 1


def _close(pipe: object, reader: _Reader) -> None:
    gitread._close_when_done(pipe, cast(threading.Thread, reader))


def _setup(
    monkeypatch: pytest.MonkeyPatch, name: str, *, alive: bool, cancels_to_end: int | None = None
) -> tuple[_Clock, _Reader, _Kernel32]:
    clock = _Clock()
    reader = _Reader(clock, alive=alive, cancels_to_end=cancels_to_end)
    kernel = _Kernel32(reader)
    monkeypatch.setattr(gitread, "os", _OsAs(name))
    monkeypatch.setattr(gitread, "_clock", clock)
    monkeypatch.setattr(gitread, "_kernel32", lambda: kernel)
    return clock, reader, kernel


@pytest.mark.parametrize("name", ["posix", "nt"])
def test_a_finished_reader_closes_the_pipe_itself(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    _, reader, kernel = _setup(monkeypatch, name, alive=False)
    raw = _Raw()
    pipe = _Pipe(raw)
    _close(pipe, reader)
    assert pipe.closes == 1 and raw.closes == 0
    assert reader.joins == [gitread._READER_JOIN_SECONDS]
    assert kernel.opened == []  # nothing to cancel


def test_posix_closes_the_raw_file_under_a_blocked_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    _, reader, kernel = _setup(monkeypatch, "posix", alive=True)
    raw = _Raw()
    pipe = _Pipe(raw)
    _close(pipe, reader)
    assert raw.closes == 1 and pipe.closes == 0
    assert kernel.opened == []  # POSIX never cancels reads


def test_windows_cancels_the_blocked_read_then_closes_the_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, reader, kernel = _setup(monkeypatch, "nt", alive=True, cancels_to_end=2)
    raw = _Raw()
    pipe = _Pipe(raw)
    _close(pipe, reader)
    assert kernel.opened == [(gitread._THREAD_TERMINATE, 0, 777)]
    assert reader.cancels == 2  # retried: the reader may be between two reads
    assert kernel.closed == [kernel.handle]  # the thread handle, exactly once
    assert pipe.closes == 1 and raw.closes == 0


def test_windows_cancelling_is_bounded_and_the_close_is_left_to_a_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock, reader, kernel = _setup(monkeypatch, "nt", alive=True)  # never ends
    start = clock.now
    raw = _Raw()
    pipe = _Pipe(raw)
    _close(pipe, reader)
    spent = clock.now - start
    bound = gitread._READER_JOIN_SECONDS + gitread._CANCEL_READ_SECONDS
    assert bound <= spent <= bound + gitread._CANCEL_POLL_SECONDS
    assert reader.joins[1:] == [gitread._CANCEL_POLL_SECONDS] * reader.cancels
    assert kernel.closed == [kernel.handle]
    assert raw.done.wait(5.0) and raw.closes == 1  # still closed: no leak
    assert pipe.closes == 0  # never the buffered close, which would block


def test_windows_close_returns_while_the_raw_close_is_still_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, reader, _ = _setup(monkeypatch, "nt", alive=True)
    release = threading.Event()
    raw = _Raw(block=release, error=OSError("closed late"))
    begin = time.monotonic()
    _close(_Pipe(raw), reader)
    assert time.monotonic() - begin < 1.0  # real time: the fake clock did the waiting
    assert not raw.done.is_set()
    release.set()  # the holder lets go; the late close and its error stay in the thread
    assert raw.done.wait(5.0) and raw.closes == 1


@pytest.mark.parametrize("failure", ["open fails", "no kernel32", "no thread id"])
def test_windows_cancel_failures_still_close_without_blocking(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    _, reader, kernel = _setup(monkeypatch, "nt", alive=True)
    if failure == "open fails":
        kernel.handle = 0
    elif failure == "no kernel32":

        def missing() -> Any:
            raise OSError("no kernel32")

        monkeypatch.setattr(gitread, "_kernel32", missing)
    else:

        def bad_id(*_a: Any) -> int:
            raise TypeError("native_id is None")

        monkeypatch.setattr(kernel, "OpenThread", bad_id)
    raw = _Raw()
    _close(_Pipe(raw), reader)
    assert reader.cancels == 0
    assert kernel.closed == []  # nothing opened, nothing to close
    assert raw.done.wait(5.0) and raw.closes == 1


@pytest.mark.parametrize("name", ["posix", "nt"])
def test_a_pipe_without_a_raw_file_is_left_alone(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    _, reader, _ = _setup(monkeypatch, name, alive=True)
    pipe = _Pipe(None)
    _close(pipe, reader)
    assert pipe.closes == 0


@pytest.mark.parametrize("error", [OSError("bad fd"), ValueError("closed")])
def test_posix_raw_close_errors_are_swallowed(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    _, reader, _ = _setup(monkeypatch, "posix", alive=True)
    raw = _Raw(error=error)
    _close(_Pipe(raw), reader)
    assert raw.closes == 1


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


def test_kernel32_uses_handle_sized_prototypes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "WinDLL", _Dll, raising=False)
    kernel = gitread._kernel32()
    assert kernel.name == "kernel32" and kernel.use_last_error is True
    assert kernel.OpenThread.restype is ctypes.c_void_p  # a HANDLE, not a 32-bit int
    assert kernel.OpenThread.argtypes == [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    assert kernel.CancelSynchronousIo.argtypes == [ctypes.c_void_p]
    assert kernel.CloseHandle.argtypes == [ctypes.c_void_p]


def test_a_real_blocked_reader_is_closed_promptly() -> None:
    """End to end on this OS (Windows CI cancels the read for real): a held pipe never stalls."""
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb")
    reader = threading.Thread(target=gitread._drain, args=(stream, -1, [], threading.Event()))
    reader.daemon = True
    reader.start()
    try:
        begin = time.monotonic()
        gitread._close_when_done(stream, reader)
        assert time.monotonic() - begin < gitread._READER_JOIN_SECONDS + 1.0
        assert stream.closed
    finally:
        os.close(write_fd)
        reader.join(5.0)
