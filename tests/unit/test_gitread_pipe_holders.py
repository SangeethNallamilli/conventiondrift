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

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX groups; Windows is stubbed")

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
    code = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'],"
        f" start_new_session={escapes})\n"
        f"open({str(tmp_path / 'grandchild.pid')!r}, 'w').write(str(child.pid))\n"
        f"sys.stdout.write({payload!r}); sys.stdout.flush()\n"
        + ("sys.exit(0)\n" if parent_exits else "time.sleep(20)\n")
    )
    return [sys.executable, "-c", code]


_HAS_PROC = Path("/proc/self/stat").exists()


def _state(pid: int, *, use_proc: bool = _HAS_PROC) -> str | None:
    """The process state letter(s), or None once the pid is gone.

    Linux reads /proc. macOS has no /proc, so it asks ``/bin/ps -o stat=``;
    reading /proc there always failed, so every pid looked dead (CON-10/11 #43).
    """
    if use_proc:
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            return None
    out = subprocess.run(  # noqa: S603 - fixed absolute argv, no shell
        ["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False
    )
    return out.stdout.strip() or None


def _alive(pid: int, *, use_proc: bool = _HAS_PROC) -> bool:
    """Running and not a zombie (a zombie still answers ``kill(pid, 0)``)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    state = _state(pid, use_proc=use_proc)
    return state is not None and not state.startswith("Z")


def test_alive_tells_running_zombie_and_reaped_apart() -> None:
    """The helper itself, with every probe this OS has (/proc and/or /bin/ps)."""
    probes = [use for use, ok in ((True, _HAS_PROC), (False, os.path.exists("/bin/ps"))) if ok]
    assert probes, "no way to read a process state on this OS"
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE
    )
    try:
        for use_proc in probes:
            assert _alive(child.pid, use_proc=use_proc), use_proc
        assert child.stdin is not None
        child.stdin.close()
        deadline = time.monotonic() + 5.0  # exited but not yet reaped: a zombie
        while any(_alive(child.pid, use_proc=u) for u in probes):
            assert time.monotonic() < deadline, "the exited child still looks alive"
            time.sleep(0.05)
        for use_proc in probes:
            assert _state(child.pid, use_proc=use_proc) is not None  # zombie, not gone
    finally:
        child.kill()
        child.wait()
    for use_proc in probes:
        assert not _alive(child.pid, use_proc=use_proc)


def _gone_soon(pid: int) -> bool:
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _use_fake(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> None:
    real = gitread._start_batch

    def start(_argv: list[str], **kwargs: Any) -> Any:
        return real(argv, **kwargs)

    monkeypatch.setattr(gitread, "_start_batch", start)
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", TIMEOUT)


def _repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    return path


# Each trigger drives one kill path; it gets the fake git argv and returns nothing.
def _run_bounded_timeout(tmp_path: Path, argv: list[str], _m: pytest.MonkeyPatch) -> None:
    with pytest.raises(ComponentError, match="git log timed out"):
        gitread._run_bounded(
            argv, cwd=tmp_path, env=dict(os.environ), label="log", max_stdout=4096, timeout=TIMEOUT
        )


def _run_bounded_cap(tmp_path: Path, argv: list[str], _m: pytest.MonkeyPatch) -> None:
    with pytest.raises(ComponentError, match="git log output too large"):
        gitread._run_bounded(
            argv, cwd=tmp_path, env=dict(os.environ), label="log", max_stdout=3, timeout=10.0
        )


def _reader_close(tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch, argv)
    reader = GitReader(_repo(tmp_path))
    reader._batch_process("--batch-check")
    time.sleep(0.3)  # let the grandchild start
    reader.close()


def _blob_failure(tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch, argv)
    with pytest.raises(ComponentError):  # the fake prints no header: timeout or bad output
        GitReader(_repo(tmp_path)).blob(SHA, 10)


def _patches_close(tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch, argv)
    stream = GitReader(_repo(tmp_path)).patches(SHA, SHA2)
    assert next(stream) == b"xxxxx"
    stream.close()


def _patches_timeout(tmp_path: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch, argv)
    with pytest.raises(ComponentError, match="git log timed out"):
        list(GitReader(_repo(tmp_path)).patches(SHA, SHA2))


Trigger = Callable[[Path, list[str], pytest.MonkeyPatch], None]
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


@pytest.mark.parametrize("kind", sorted(KINDS))
@pytest.mark.parametrize("path", sorted(TRIGGERS))
def test_a_pipe_holding_grandchild_never_stretches_a_kill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str, kind: str
) -> None:
    parent_exits, escapes = KINDS[kind]
    _, trigger, payload = TRIGGERS[path]
    argv = _fake_git(tmp_path, parent_exits, escapes, payload)
    begin = time.monotonic()
    try:
        trigger(tmp_path, argv, monkeypatch)
        assert time.monotonic() - begin < PROMPT
        pid = int((tmp_path / "grandchild.pid").read_text())
        if escapes:
            assert _alive(pid)  # outside git's group: not ours to kill, and not waited for
        else:
            assert _gone_soon(pid)  # the whole group is gone
    finally:
        pidfile = tmp_path / "grandchild.pid"
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
