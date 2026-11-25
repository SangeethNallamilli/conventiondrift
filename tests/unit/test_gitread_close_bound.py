"""D-TL-104: every step of gitread's close path is hard-bounded from the caller's side.

Windows 3.15 under coverage once spent an escaped grandchild's whole 20 s lifetime in a
kill (run 45564181345, 20.11 s against 4.5 s), with no stack to say where. The close
steps call things that are bounded only on paper: ``Thread.join(timeout)`` and
``is_alive()`` end in an untimed OS-level join once the reader starts to exit, and a
pipe close waits on a lock that a read blocked by the pipe holder still holds. Each
stand-in below blocks in one of those places until the "holder" lets go; the close
must return while it still holds, and the pipe must still end up closed.

No clock is read here: a step that waited for the holder would only return once
``_HOLD_SECONDS`` ran out, and the asserts that the holder is still holding would
fail. D-TL-25: the bounds come from gitread's own constants.
"""

import io
import os
import threading
from types import SimpleNamespace
from typing import Any, cast

import pytest

from conventiondrift import gitread

#: How long a stand-in pipe holder holds at most (a test that hung would end here).
_HOLD_SECONDS = 10.0
#: The close steps that can block on a holder; each one is a stand-in below.
BLOCKING_STEPS = ("reader join", "reader is_alive", "buffered close", "raw close")


class _OsAs:
    """gitread's view of ``os`` as another OS; the real ``os`` (and pathlib) is untouched."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


class _Hold:
    """A pipe holder: whatever waits on it blocks until :meth:`release` (bounded)."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.left = threading.Event()
        self._gone = threading.Event()

    def block(self) -> None:
        self.entered.set()
        try:
            assert self._gone.wait(_HOLD_SECONDS), "the holder was never released"
        finally:
            self.left.set()

    def release(self) -> None:
        self._gone.set()

    @property
    def holding(self) -> bool:
        return self.entered.is_set() and not self.left.is_set()


class _Reader:
    """A reader thread stand-in; ``blocks`` names the call that waits on the holder."""

    native_id = 777

    def __init__(self, hold: _Hold, blocks: str, *, alive: bool) -> None:
        self.hold = hold
        self.blocks = blocks
        self.alive = alive

    def join(self, timeout: float | None = None) -> None:
        if self.blocks == "reader join":
            self.hold.block()

    def is_alive(self) -> bool:
        if self.blocks == "reader is_alive":
            self.hold.block()
        return self.alive


class _Raw:
    def __init__(self, hold: _Hold, blocks: bool) -> None:
        self.hold = hold
        self.blocks = blocks
        self.closed = threading.Event()

    def close(self) -> None:
        if self.blocks:
            self.hold.block()
        self.closed.set()


class _Pipe:
    def __init__(self, raw: _Raw, hold: _Hold, blocks: bool) -> None:
        self.raw = raw
        self.hold = hold
        self.blocks = blocks
        self.closed = threading.Event()

    def close(self) -> None:
        if self.blocks:
            self.hold.block()
        self.closed.set()


def _no_cancel() -> Any:
    raise OSError("no kernel32 here")  # cancelling is test_gitread_close.py's subject


def _fast_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the close bounds to one cancel poll, so each case waits only that long."""
    monkeypatch.setattr(gitread, "_CLOSE_PIPE_SECONDS", gitread._CANCEL_POLL_SECONDS)
    monkeypatch.setattr(gitread, "_CLOSE_STDIN_SECONDS", gitread._CANCEL_POLL_SECONDS)


def _closed(stream: io.BufferedIOBase) -> bool:
    return stream.closed


def _cases() -> list[pytest.ParameterSet]:
    return [
        pytest.param(name, step, id=f"{name}-{step}")
        for name in ("posix", "nt")
        for step in BLOCKING_STEPS
    ]


@pytest.mark.parametrize(("name", "step"), _cases())
def test_a_close_step_blocked_by_a_holder_never_holds_the_caller(
    monkeypatch: pytest.MonkeyPatch, name: str, step: str
) -> None:
    monkeypatch.setattr(gitread, "os", _OsAs(name))
    monkeypatch.setattr(gitread, "_kernel32", _no_cancel)
    _fast_bound(monkeypatch)
    hold = _Hold()
    # A finished reader takes the buffered close; a live one the raw close.
    alive = step == "raw close"
    reader = _Reader(hold, step, alive=alive)
    raw = _Raw(hold, blocks=step == "raw close")
    pipe = _Pipe(raw, hold, blocks=step == "buffered close")
    try:
        gitread._close_when_done(pipe, cast(threading.Thread, reader))
        assert hold.entered.wait(_HOLD_SECONDS), f"the close never reached the {step}"
        assert hold.holding, f"the close waited for the holder at the {step}"
        assert not pipe.closed.is_set() and not raw.closed.is_set()
    finally:
        hold.release()
    # The abandoned close still finishes once the holder lets go: nothing leaks.
    closed = raw.closed if alive else pipe.closed
    assert closed.wait(_HOLD_SECONDS)


def test_a_real_buffered_pipe_locked_by_a_blocked_read_is_not_waited_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real ``BufferedReader`` lock: ``close()`` waits for a read inside the wrapper.

    The raw read blocks (a pipe holder that never writes) while the wrapper holds its
    lock; the reader stand-in says it is done, so the close takes ``stream.close()``,
    which before D-TL-104 waited on that lock for as long as the holder held.
    """
    _fast_bound(monkeypatch)
    hold = _Hold()

    class _HeldRaw(io.RawIOBase):
        def readable(self) -> bool:
            return True

        def readinto(self, buffer: Any) -> int:
            hold.block()
            return 0  # the holder exited: end of output

    stream = io.BufferedReader(_HeldRaw())
    pump = threading.Thread(target=stream.read1, args=(1,), daemon=True)
    pump.start()
    try:
        assert hold.entered.wait(_HOLD_SECONDS)  # the wrapper's lock is held from here
        gitread._close_when_done(stream, cast(threading.Thread, _Reader(hold, "", alive=False)))
        assert hold.holding and not _closed(stream)
    finally:
        hold.release()
        pump.join(_HOLD_SECONDS)
    assert not pump.is_alive()
    # The abandoned close takes the lock once the read returns, and closes the pipe.
    tick = threading.Event()  # never set: only paces the bounded poll
    for _ in range(int(_HOLD_SECONDS / gitread._CANCEL_POLL_SECONDS)):
        if _closed(stream):
            break
        tick.wait(gitread._CANCEL_POLL_SECONDS)
    assert _closed(stream)


def test_closing_stdin_held_by_a_grandchild_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    _fast_bound(monkeypatch)
    hold = _Hold()
    stdin = _Pipe(_Raw(hold, blocks=False), hold, blocks=True)
    process = object.__new__(gitread._BatchProcess)
    process._proc = cast(Any, SimpleNamespace(stdin=stdin))
    try:
        process.close_stdin()
        assert hold.entered.wait(_HOLD_SECONDS)
        assert hold.holding and not stdin.closed.is_set()
    finally:
        hold.release()
    assert stdin.closed.wait(_HOLD_SECONDS)


def test_a_prompt_step_runs_to_the_end_and_reports_done() -> None:
    ran: list[str] = []
    assert gitread._within(gitread._CLOSE_PIPE_SECONDS, lambda: ran.append("closed"))
    assert ran == ["closed"]


def test_a_finished_step_hands_its_error_to_the_caller() -> None:
    def fails() -> None:
        raise ValueError("raw close failed")

    with pytest.raises(ValueError, match="raw close failed"):
        gitread._within(gitread._CLOSE_PIPE_SECONDS, fails)


def test_an_abandoned_step_keeps_its_error_to_itself() -> None:
    hold = _Hold()
    caught: list[BaseException] = []

    def fails_late() -> None:
        hold.block()
        raise OSError("closed late")

    hook = threading.excepthook
    threading.excepthook = lambda args: caught.append(cast(BaseException, args.exc_value))
    try:
        assert not gitread._within(gitread._CANCEL_POLL_SECONDS, fails_late)
        assert hold.holding
    finally:
        hold.release()
        threading.excepthook = hook
    assert hold.left.wait(_HOLD_SECONDS)
    assert caught == []  # kept in the step, never an unhandled thread error


def test_the_close_bounds_cover_a_full_cancel() -> None:
    """A normal close (join, then the whole cancel window) finishes inside the bound."""
    full_cancel = (
        gitread._READER_JOIN_SECONDS + gitread._CANCEL_READ_SECONDS + gitread._CANCEL_POLL_SECONDS
    )
    assert gitread._CLOSE_PIPE_SECONDS > full_cancel
    assert gitread._CLOSE_STDIN_SECONDS >= gitread._CANCEL_READ_SECONDS
