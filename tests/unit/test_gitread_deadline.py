"""One overall deadline for the patches stream (T-008, I-14 item 9 "Argv and stream details").

``patches`` gets ``GIT_TIMEOUT_SECONDS`` from spawn to exit. Each chunk wait and
the exit wait use the time left; running out kills git's tree and raises
``ComponentError("gitread")``. Expected values are written out by hand from that
rule: spawn at clock 1000.0 with the 60 s timeout means one deadline of 1060.0.
"""

import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError
from conventiondrift.gitread import GitReader

SHA, SHA2 = "a" * 40, "b" * 40
SPAWN = 1000.0
DEADLINE = 1060.0  # SPAWN + GIT_TIMEOUT_SECONDS (60), by hand


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()  # patches never reads it: _start_batch is replaced in every test
    return path


class _ScriptedLog:
    """A stand-in ``_BatchProcess`` on a fake clock.

    ``steps`` gives the seconds each chunk takes to arrive; ``exit_after`` the
    seconds git takes to exit after its last chunk. Like the real process it
    raises "timed out" if the wait would pass the deadline it was given.
    """

    def __init__(self, clock: list[float], steps: list[float], exit_after: float) -> None:
        self.clock, self.steps, self.exit_after = clock, list(steps), exit_after
        self.read_deadlines: list[float] = []
        self.wait_deadlines: list[float] = []
        self.killed = False

    def _advance(self, seconds: float, deadline: float) -> None:
        if self.clock[0] + seconds > deadline:
            self.clock[0] = deadline
            raise ComponentError("gitread", "git log timed out")
        self.clock[0] += seconds

    def close_stdin(self) -> None:
        pass

    def read_some(self, limit: int, deadline: float) -> bytes:
        self.read_deadlines.append(deadline)
        if not self.steps:
            return b""
        self._advance(self.steps.pop(0), deadline)
        return b"x"

    def wait(self, deadline: float) -> int:
        self.wait_deadlines.append(deadline)
        self._advance(self.exit_after, deadline)
        return 0

    def kill(self) -> None:
        self.killed = True


def _install(
    monkeypatch: pytest.MonkeyPatch, steps: list[float], exit_after: float
) -> _ScriptedLog:
    clock = [0.0]
    log = _ScriptedLog(clock, steps, exit_after)

    def start(argv: list[str], **kwargs: Any) -> _ScriptedLog:
        clock[0] = SPAWN
        return log

    monkeypatch.setattr(gitread, "_start_batch", start)
    monkeypatch.setattr(gitread, "_clock", lambda: clock[0])
    return log


def test_every_chunk_wait_and_the_exit_wait_share_one_deadline(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = _install(monkeypatch, steps=[10.0, 10.0, 10.0], exit_after=5.0)
    assert list(GitReader(repo).patches(SHA, SHA2)) == [b"x", b"x", b"x"]
    assert log.read_deadlines == [DEADLINE, DEADLINE, DEADLINE, DEADLINE]
    assert log.wait_deadlines == [DEADLINE]
    assert log.killed


def test_slow_chunks_each_under_the_timeout_add_up_to_a_timeout(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Five chunks of 20 s each: every one is under 60 s, together 100 s.
    # By hand: chunks land at 1020, 1040, 1060; the 4th would land at 1080 > 1060.
    log = _install(monkeypatch, steps=[20.0] * 5, exit_after=0.0)
    got: list[bytes] = []
    with pytest.raises(ComponentError) as info:
        for chunk in GitReader(repo).patches(SHA, SHA2):
            got.append(chunk)
    assert got == [b"x", b"x", b"x"]
    assert (info.value.component, info.value.message) == ("gitread", "git log timed out")
    assert log.killed and log.wait_deadlines == []


def test_the_exit_wait_gets_only_what_is_left(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 40 s of chunks leaves 20 s; an exit that takes 30 s is past the deadline
    # (a fresh 60 s exit wait would have allowed it).
    log = _install(monkeypatch, steps=[20.0, 20.0], exit_after=30.0)
    stream = GitReader(repo).patches(SHA, SHA2)
    assert [next(stream), next(stream)] == [b"x", b"x"]
    with pytest.raises(ComponentError, match=r"git log timed out"):
        next(stream)
    assert log.wait_deadlines == [DEADLINE] and log.killed


def test_an_exit_within_what_is_left_ends_the_stream(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = _install(monkeypatch, steps=[20.0, 20.0], exit_after=15.0)  # exits at 1055
    assert list(GitReader(repo).patches(SHA, SHA2)) == [b"x", b"x"]
    assert log.wait_deadlines == [DEADLINE]


def test_time_spent_by_the_consumer_counts(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _install(monkeypatch, steps=[1.0, 1.0], exit_after=0.0)
    stream = GitReader(repo).patches(SHA, SHA2)
    assert next(stream) == b"x"
    log.clock[0] += 59.0  # C8 holds the stream for 59 s: 1001 -> 1060
    with pytest.raises(ComponentError, match=r"git log timed out"):
        next(stream)
    assert log.read_deadlines == [DEADLINE, DEADLINE]


# --- the same rule against real processes (short real sleeps only) -------------


def _slow_git(chunks: int, gap: float) -> str:
    return (
        "import sys, time\n"
        f"for i in range({chunks}):\n"
        f"    time.sleep({gap}); sys.stdout.write('c%d;' % i); sys.stdout.flush()\n"
    )


def _real_start(monkeypatch: pytest.MonkeyPatch, script: str) -> list[Any]:
    real = gitread._start_batch
    started: list[Any] = []

    def start(argv: list[str], **kwargs: Any) -> Any:
        started.append(real([sys.executable, "-c", script], **kwargs))
        return started[-1]

    monkeypatch.setattr(gitread, "_start_batch", start)
    return started


def test_real_slow_chunks_time_out_on_the_overall_deadline(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 10 chunks 0.2 s apart (each well under the 0.7 s timeout; 2 s in all).
    started = _real_start(monkeypatch, _slow_git(10, 0.2))
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.7)
    got = b""
    begin = time.monotonic()
    with pytest.raises(ComponentError, match=r"git log timed out"):
        for chunk in GitReader(repo).patches(SHA, SHA2):
            got += chunk
    assert time.monotonic() - begin < 1.7
    assert 0 < got.count(b";") < 10
    assert started[0]._proc.returncode is not None  # killed and reaped


@pytest.mark.skipif(os.name == "nt", reason="POSIX process groups; Windows is stubbed")
def test_running_out_kills_the_whole_tree(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pidfile = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
        "sys.stdout.write('x'); sys.stdout.flush(); time.sleep(60)\n"
    )
    _real_start(monkeypatch, script)
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.8)
    with pytest.raises(ComponentError) as info:
        list(GitReader(repo).patches(SHA, SHA2))
    assert (info.value.component, info.value.message) == ("gitread", "git log timed out")
    assert _gone(int(pidfile.read_text()))


def _gone(pid: int) -> bool:
    for _ in _polls(5.0):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:
            if Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z":
                return True
        except OSError:
            pass
    return False


def _polls(total: float) -> Iterator[None]:
    end = time.monotonic() + total
    while time.monotonic() < end:
        yield
        time.sleep(0.05)
