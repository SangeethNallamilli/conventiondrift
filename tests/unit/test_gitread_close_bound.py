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

import builtins
import io
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_gitread_pipe_holders import PROMPT, TIMEOUT

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


def test_a_whole_kill_fits_the_pipe_holder_bound() -> None:
    """TE B2 on #93: the bounds themselves, not only stand-ins with a shrunk bound.

    A kill closes stdin and both pipes; ``PROMPT`` minus git's ``TIMEOUT`` is what the
    pipe-holder cases allow for that (test_gitread_pipe_holders.py).
    """
    whole_close = 2 * gitread._CLOSE_PIPE_SECONDS + gitread._CLOSE_STDIN_SECONDS
    assert whole_close < PROMPT - TIMEOUT


def test_the_close_worker_is_a_daemon_thread() -> None:
    """An abandoned close must never keep the interpreter from exiting (TE B2)."""
    seen: list[tuple[bool, int | None]] = []
    here = threading.get_ident()

    def record() -> None:
        thread = threading.current_thread()
        seen.append((thread.daemon, thread.ident))

    assert gitread._within(gitread._CLOSE_PIPE_SECONDS, record)
    assert len(seen) == 1
    daemon, ident = seen[0]
    assert daemon and ident != here


class _NoThreads:
    """gitread's view of ``threading`` when no thread can be started."""

    Event = threading.Event

    def __init__(self, error: BaseException | None) -> None:
        self.error = error
        self.made = 0

    def Thread(self, **_kwargs: Any) -> Any:  # stands in for the class
        self.made += 1
        outer = self

        class _Unstartable:
            daemon = True

            def start(self) -> None:
                if outer.error is not None:
                    raise outer.error

        return _Unstartable()


#: A subclass of RuntimeError from 3.13 on; RuntimeError itself before.
_FINALIZATION_ERROR: type[RuntimeError] = getattr(builtins, "PythonFinalizationError", RuntimeError)
#: How ``Thread.start()`` fails: at shutdown (3.12, then 3.13+), or the OS refuses (N2).
START_ERRORS: dict[str, Callable[[], BaseException]] = {
    "shutdown (3.12)": lambda: RuntimeError("can't create new thread at interpreter shutdown"),
    "shutdown (3.13+)": lambda: _FINALIZATION_ERROR(
        "can't create new thread at interpreter shutdown"
    ),
    "no thread to be had": lambda: RuntimeError("can't start new thread"),
}


@pytest.mark.parametrize("why", sorted(START_ERRORS))
def test_a_refused_thread_start_runs_the_fallback_and_never_raises(
    monkeypatch: pytest.MonkeyPatch, why: str
) -> None:
    threads = _NoThreads(START_ERRORS[why]())
    monkeypatch.setattr(gitread, "threading", threads)
    ran: list[str] = []
    assert not gitread._within(
        gitread._CLOSE_PIPE_SECONDS, lambda: ran.append("step"), lambda: ran.append("fallback")
    )
    assert threads.made == 1 and ran == ["fallback"]


def test_at_shutdown_no_thread_is_even_started(monkeypatch: pytest.MonkeyPatch) -> None:
    """3.11 at shutdown: ``Thread.start()`` waits forever for a thread that never runs."""
    threads = _NoThreads(AssertionError("Thread.start() during interpreter shutdown"))
    monkeypatch.setattr(gitread, "threading", threads)
    monkeypatch.setattr(gitread, "sys", SimpleNamespace(is_finalizing=lambda: True))
    ran: list[str] = []
    assert not gitread._within(
        gitread._CLOSE_PIPE_SECONDS, lambda: ran.append("step"), lambda: ran.append("fallback")
    )
    assert threads.made == 0 and ran == ["fallback"]


def test_a_failing_fallback_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitread, "threading", _NoThreads(RuntimeError("can't start new thread")))

    def fails() -> None:
        raise OSError("bad fd")

    assert not gitread._within(gitread._CLOSE_PIPE_SECONDS, lambda: None, fails)


class _Stream:
    def __init__(self) -> None:
        self.raw = SimpleNamespace(closes=0)
        self.raw.close = self._close_raw
        self.closes = 0

    def _close_raw(self) -> None:
        self.raw.closes += 1

    def close(self) -> None:
        self.closes += 1


@pytest.mark.parametrize("name", ["posix", "nt"])
def test_a_kill_without_threads_closes_what_cannot_block_and_never_raises(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """TE B1/N2: kill() reaches every close; none takes a lock a held read keeps."""
    monkeypatch.setattr(gitread, "os", _OsAs(name))
    monkeypatch.setattr(gitread, "threading", _NoThreads(RuntimeError("can't start new thread")))
    monkeypatch.setattr(gitread, "_kill_tree", lambda *_a: None)
    stdin, stdout, stderr = _Stream(), _Stream(), _Stream()
    process = object.__new__(gitread._BatchProcess)
    process._proc = cast(Any, SimpleNamespace(stdin=stdin, stdout=stdout, stderr=stderr))
    process._job = None
    process._stop = threading.Event()
    process._threads = cast(Any, [object(), object()])  # never joined: no thread to ask
    process.kill()
    assert stdin.raw.closes == 1  # nothing reads git's stdin in this process
    pipes = 0 if name == "nt" else 1  # Windows: even the raw close waits on a held read
    assert (stdout.raw.closes, stderr.raw.closes) == (pipes, pipes)
    assert stdin.closes == stdout.closes == stderr.closes == 0  # never the buffered close


def test_windows_raw_close_thread_refused_is_left_to_the_os(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gitread, "os", _OsAs("nt"))
    monkeypatch.setattr(gitread, "_kernel32", _no_cancel)
    monkeypatch.setattr(gitread, "threading", _NoThreads(RuntimeError("can't start new thread")))
    hold = _Hold()
    stream = _Stream()
    gitread._close_pipe(stream, cast(threading.Thread, _Reader(hold, "", alive=True)))
    assert stream.raw.closes == 0 and stream.closes == 0


#: TE's #93 B1 repro: a patches stream still open when the interpreter exits.
_EXIT_WITH_OPEN_STREAM = """
import sys
from conventiondrift.gitread import GitReader
repo, head = sys.argv[1], sys.argv[2]
stream = GitReader(repo).patches(None, head)
next(stream)
sys.exit(0)
"""


def _fixture_repo(tmp_path: Path) -> tuple[Path, str]:
    """Test helper only: a two-commit repo made with the test machine's git."""
    git = shutil.which("git")
    assert git is not None, "the subprocess case needs git on PATH"
    repo = tmp_path / "repo"
    repo.mkdir()
    env = dict(os.environ, HOME=str(tmp_path), GIT_CONFIG_NOSYSTEM="1")
    flags = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.autocrlf=false"]

    def run(*args: str) -> str:
        out = subprocess.run(  # noqa: S603 (resolved git, fixed argv)
            [git, *flags, *args], cwd=repo, env=env, capture_output=True, text=True, check=True
        )
        return out.stdout.strip()

    run("init", "-q")
    run("commit", "-q", "--allow-empty", "-m", "one")
    (repo / "f.txt").write_text("x\n", encoding="utf-8")
    run("add", "f.txt")
    run("commit", "-q", "-m", "two")
    return repo, run("rev-parse", "HEAD")


def test_an_open_patches_stream_at_interpreter_exit_closes_quietly(tmp_path: Path) -> None:
    """TE B1 on #93, end to end on this interpreter: no hang, no error at exit.

    The generator's ``finally`` (kill) runs while the interpreter shuts down, where
    3.11 hung in ``Thread.start()`` and 3.12+ raised out of ``kill()``.
    """
    repo, head = _fixture_repo(tmp_path)
    src = str(Path(gitread.__file__).resolve().parents[1])
    path = os.pathsep.join(p for p in (src, os.environ.get("PYTHONPATH")) if p)
    out = subprocess.run(  # noqa: S603 (this interpreter, fixed script)
        [sys.executable, "-c", _EXIT_WITH_OPEN_STREAM, str(repo), head],
        env=dict(os.environ, PYTHONPATH=path),
        capture_output=True,
        text=True,
        timeout=gitread.GIT_TIMEOUT_SECONDS,  # a hang ends here as TimeoutExpired
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert "Exception ignored" not in out.stderr
    assert "Traceback" not in out.stderr


def test_the_close_bounds_cover_a_full_cancel() -> None:
    """A normal close (join, then the whole cancel window) finishes inside the bound."""
    full_cancel = (
        gitread._READER_JOIN_SECONDS + gitread._CANCEL_READ_SECONDS + gitread._CANCEL_POLL_SECONDS
    )
    assert gitread._CLOSE_PIPE_SECONDS > full_cancel
    assert gitread._CLOSE_STDIN_SECONDS >= gitread._CANCEL_READ_SECONDS
