"""blob() failure handling for the long-lived cat-file processes (T-008, I-14 item 9).

The rule ("Argv and stream details"): a well-formed ``<oid> missing`` reply leaves
both processes in step, so ``blob()`` raises ``ComponentError("gitread")`` and keeps
them. A timeout, a short read, a malformed header or an oid mismatch kills both
and raises, and every later call raises without restarting them.

D-TL-25: the failure cases are built from the four ruled classes, on each of the
two processes, and a test asserts that the cases cover every (class, process)
pair. Expected messages are written out by hand.
"""

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError
from conventiondrift.gitread import GitReader

GOOD = "c" * 40  # the fake answers this oid correctly: 3 bytes, "abc"
BAD = "d" * 40  # the fake answers this oid with the case's reply
OTHER = "e" * 40

#: The four ruled failure classes and the two processes they can happen on.
RULED_CLASSES = frozenset({"timeout", "short read", "malformed header", "oid mismatch"})
PROCESSES = frozenset({"--batch-check", "--batch"})
#: Messages, by hand: gitread's fixed texts for a timeout and for bad output.
TIMED_OUT = "git cat-file timed out"
BAD_OUTPUT = "unexpected git output"
STOPPED = "git cat-file stopped after an error"

#: (class, process, --batch-check reply to BAD, --batch reply to BAD, message).
#: "SLEEP" means the fake never answers. A reply without a final LF, or ending in
#: "|EXIT" (which is not sent), is followed by the fake exiting, so a read comes up
#: short instead of waiting. Where the failure is on --batch-check, the --batch
#: reply is what a lenient reader would accept, so a missed check shows up as a
#: returned blob instead of a later error.
CASES: list[tuple[str, str, str, str, str]] = [
    ("timeout", "--batch-check", "SLEEP", f"{BAD} blob 3\nabc\n", TIMED_OUT),
    ("timeout", "--batch", f"{BAD} blob 3\n", "SLEEP", TIMED_OUT),
    ("short read", "--batch-check", f"{BAD} blob 3", f"{BAD} blob 3\nabc\n", BAD_OUTPUT),
    ("short read", "--batch", f"{BAD} blob 3\n", f"{BAD} blob 3\nab\n|EXIT", BAD_OUTPUT),
    ("short read", "--batch", f"{BAD} blob 3\n", f"{BAD} blob 3", BAD_OUTPUT),
    (
        "malformed header",
        "--batch-check",
        f"{BAD} blob 3 extra\n",
        f"{BAD} blob 3 extra\nabc\n",
        BAD_OUTPUT,
    ),
    ("malformed header", "--batch-check", f"{BAD} blob three\n", "", BAD_OUTPUT),
    ("malformed header", "--batch-check", f"{BAD} missing please\n", "", BAD_OUTPUT),
    ("malformed header", "--batch", f"{BAD} blob 3\n", f"{BAD} blob 3 extra\nabc\n", BAD_OUTPUT),
    ("oid mismatch", "--batch-check", f"{OTHER} blob 3\n", f"{OTHER} blob 3\nabc\n", BAD_OUTPUT),
    ("oid mismatch", "--batch-check", f"{OTHER} missing\n", "", BAD_OUTPUT),
    ("oid mismatch", "--batch", f"{BAD} blob 3\n", f"{OTHER} blob 3\nabc\n", BAD_OUTPUT),
]


def test_cases_cover_every_ruled_class_on_both_processes() -> None:
    assert {(c[0], c[1]) for c in CASES} == {(k, p) for k in RULED_CLASSES for p in PROCESSES}


def _script(mode: str, check: str, batch: str) -> str:
    return (
        "import sys, time\n"
        f"MODE, CHECK, BATCH, GOOD = {mode!r}, {check!r}, {batch!r}, {GOOD!r}\n"
        "for line in sys.stdin:\n"
        "    oid = line.strip()\n"
        "    if oid == GOOD:\n"
        "        out = GOOD + ' blob 3\\n' + ('abc\\n' if MODE == '--batch' else '')\n"
        "    else:\n"
        "        out = CHECK if MODE == '--batch-check' else BATCH\n"
        "    if out == 'SLEEP':\n"
        "        time.sleep(30)\n"
        "    stop = out.endswith('|EXIT') or not out.endswith('\\n')\n"
        "    sys.stdout.buffer.write(out.removesuffix('|EXIT').encode())\n"
        "    sys.stdout.buffer.flush()  # binary: no newline translation on Windows\n"
        "    if stop:\n"
        "        sys.exit(0)\n"
    )


def _fake(monkeypatch: pytest.MonkeyPatch, check: str, batch: str) -> list[Any]:
    real = gitread._start_batch
    started: list[Any] = []

    def start(argv: list[str], **kwargs: Any) -> Any:
        mode = argv[-1]
        started.append(real([sys.executable, "-c", _script(mode, check, batch)], **kwargs))
        return started[-1]

    monkeypatch.setattr(gitread, "_start_batch", start)
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.5)
    return started


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()  # cat-file is faked; only the version check runs the real git
    return path


@pytest.mark.parametrize(
    ("klass", "process", "check", "batch", "message"),
    CASES,
    ids=[f"{c[0]}-{c[1]}-{i}" for i, c in enumerate(CASES)],
)
def test_each_failure_kills_both_processes_and_later_calls_raise_without_restart(
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    klass: str,
    process: str,
    check: str,
    batch: str,
    message: str,
) -> None:
    started = _fake(monkeypatch, check, batch)
    reader = GitReader(repo)
    assert reader.blob(GOOD, 10) == b"abc"  # both processes running
    assert len(started) == 2
    with pytest.raises(ComponentError) as info:
        reader.blob(BAD, 10)
    assert (info.value.component, info.value.message) == ("gitread", message)
    assert all(p._proc.returncode is not None for p in started)  # both killed and reaped
    for oid in (GOOD, BAD):  # later calls raise, and nothing restarts
        with pytest.raises(ComponentError) as later:
            reader.blob(oid, 10)
        assert (later.value.component, later.value.message) == ("gitread", STOPPED)
    reader.close()
    with pytest.raises(ComponentError, match=STOPPED):  # not even after close()
        reader.blob(GOOD, 10)
    assert len(started) == 2


def test_a_well_formed_missing_reply_keeps_both_processes(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = _fake(monkeypatch, f"{BAD} missing\n", "")
    reader = GitReader(repo)
    assert reader.blob(GOOD, 10) == b"abc"
    with pytest.raises(ComponentError) as info:
        reader.blob(BAD, 10)
    assert (info.value.component, info.value.message) == ("gitread", "object not found")
    assert all(p._proc.poll() is None for p in started)  # still running
    assert reader.blob(GOOD, 10) == b"abc"  # and still in step
    assert len(started) == 2
    reader.close()


def test_a_real_missing_object_keeps_both_real_processes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # noqa: S603, S607
    oid = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],  # noqa: S607
        input=b"ok",
        capture_output=True,
        check=True,
    ).stdout.decode()[:-1]
    reader = GitReader(repo)
    assert reader.blob(oid, 10) == b"ok"
    check, batch = reader._batch_check, reader._batch
    assert check is not None and batch is not None
    with pytest.raises(ComponentError) as info:
        reader.blob("f" * 40, 10)
    assert (info.value.component, info.value.message) == ("gitread", "object not found")
    assert check._proc.poll() is None and batch._proc.poll() is None
    assert reader._batch_check is check and reader._batch is batch  # not restarted
    assert reader.blob(oid, 10) == b"ok"
    reader.close()
