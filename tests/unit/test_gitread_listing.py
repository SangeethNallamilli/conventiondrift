"""Unit tests for conventiondrift.gitread, part 2 (T-008; DESIGN §3, INTERFACES I-11 C3).

Covers ``tree``, ``blob``, ``changed_files``, ``first_parent_chain`` and ``patches``
on real temporary git repositories, plus a stubbed bounded runner for malformed
output. Every git call must go through T-007's bounded runner with a cap.
"""

import dataclasses
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from tests.fixtures.gitrepo import SYMLINK_UNAVAILABLE_REASON, symlinks_available

from conventiondrift import gitread
from conventiondrift.errors import ComponentError, FileSkipped, GitUnavailable
from conventiondrift.gitread import GitReader

_REAL_RUN = subprocess.run
_GIT = shutil.which("git") or "git"
_TEST_GIT_FLAGS = ("-c", "core.autocrlf=false")
_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}
SHA = "ab" * 20
SHA2 = "cd" * 20
BAD_SHAS = ["", "HEAD", "A" * 40, "a" * 39, "--output=/tmp/x", "a" * 40 + "\n"]


def _git(repo: Path, *args: str, date: str | None = None) -> str:
    """Test helper only: set up fixture repos (not the code under test)."""
    env = dict(_ENV, HOME=str(repo))
    if date is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    out = _REAL_RUN(
        [_GIT, *_TEST_GIT_FLAGS, *args], cwd=repo, env=env, check=True, capture_output=True
    )
    return out.stdout.decode().strip()


def _write(repo: Path, rel: str, data: bytes | str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def _commit(repo: Path, msg: str = "c", date: str | None = None) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", msg, date=date)
    return _git(repo, "rev-parse", "HEAD")


def _require_symlinks() -> None:
    if not symlinks_available():
        pytest.skip(SYMLINK_UNAVAILABLE_REASON)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    return path


Call = dict[str, Any]


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Call]]:
    """Record every bounded or long-lived git start except the version check."""
    calls: list[Call] = []
    real = gitread._run_bounded
    real_start = gitread._start_batch

    def recorder(argv: list[str], **kwargs: Any) -> Any:
        if argv[1:] != ["--version"]:
            calls.append({"argv": list(argv), **kwargs})
        return real(argv, **kwargs)

    def start_recorder(argv: list[str], **kwargs: Any) -> Any:
        calls.append({"argv": list(argv), "batch": True, **kwargs})
        return real_start(argv, **kwargs)

    monkeypatch.setattr(gitread, "_run_bounded", recorder)
    monkeypatch.setattr(gitread, "_start_batch", start_recorder)
    yield calls


def _fake(monkeypatch: pytest.MonkeyPatch, *outputs: tuple[int, bytes]) -> list[Call]:
    """Stub the bounded runner: each git call (not the version check) gets the next output."""
    real = gitread._run_bounded
    queue = list(outputs)
    calls: list[Call] = []

    def fake(argv: list[str], **kwargs: Any) -> Any:
        if argv[1:] == ["--version"]:
            return real(argv, **kwargs)
        calls.append({"argv": list(argv), **kwargs})
        return gitread._Output(*queue.pop(0))

    monkeypatch.setattr(gitread, "_run_bounded", fake)
    return calls


def _fake_batch(monkeypatch: pytest.MonkeyPatch, script: str) -> list[list[str]]:
    """Make every long-lived git a Python process running ``script`` (stdin -> stdout)."""
    real_start = gitread._start_batch
    started: list[list[str]] = []

    def start(argv: list[str], **kwargs: Any) -> Any:
        started.append(list(argv))
        return real_start([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(gitread, "_start_batch", start)
    return started


def _sub_args(call: Call, sub: str) -> list[str]:
    argv: list[str] = call["argv"]
    return argv[argv.index(sub) + 1 :]


def _pinned(args: list[str]) -> list[str]:
    """``args`` with the one ``-O<abs path>`` folded back to ``-O<orderfile>``."""
    orders = [a for a in args if a.startswith("-O")]
    assert len(orders) == 1
    path = orders[0][2:]
    assert os.path.isabs(path) and os.path.basename(path) == "conventiondrift-orderfile"
    assert os.path.basename(os.path.dirname(path)).startswith("conventiondrift-home-")
    return ["-O<orderfile>" if a.startswith("-O") else a for a in args]


def _set_and_tail(args: list[str], revs: int) -> tuple[set[str], list[str]]:
    """I-14 item 9: options compare as a set (no repeats); ``--end-of-options`` and revs last."""
    options, tail = args[: -(revs + 1)], args[-(revs + 1) :]
    assert len(options) == len(set(options))
    return set(_pinned(options)), tail


def _no_host_path(exc: BaseException, repo: Path) -> None:
    assert str(repo) not in str(exc)
    assert str(repo.parent) not in str(exc)


# --- runner seam and allowlist --------------------------------------------------


def test_t007_runner_signatures_are_unchanged() -> None:
    # The TE's SR-013/SR-014 tests (PR #26) and I-14 item 8 pin these.
    import inspect

    assert list(inspect.signature(gitread._run_bounded).parameters) == [
        "argv", "cwd", "env", "label", "max_stdout", "timeout",
    ]  # fmt: skip
    assert list(inspect.signature(gitread._find_git).parameters) == ["repo_dir"]
    assert [f.name for f in dataclasses.fields(gitread._Output)] == ["returncode", "stdout"]


def test_new_options_are_allowlisted_and_nothing_wider() -> None:
    allow = gitread.OPTION_ALLOWLIST
    assert {"--batch-check", "--batch"} <= allow["cat-file"]
    assert "--batch-all-objects" not in allow["cat-file"]
    assert "--timestamp" in allow["rev-list"]
    assert "--name-status" in allow["diff-tree"]
    assert {"-m", "--root", "--format=%x00%H", "--no-show-signature", "--full-index"} <= allow[
        "log"
    ]
    assert "--reverse" not in allow["log"]
    for sub in ("log", "diff-tree"):
        assert not {"--ext-diff", "--textconv", "--output", "--follow"} & allow[sub]


# --- tree -----------------------------------------------------------------------


def test_tree_lists_every_file_with_mode_oid_and_size(repo: Path, spy: list[Call]) -> None:
    _write(repo, "a.py", "x = 1\n")
    _write(repo, "pkg/sub/b.py", b"")
    _write(repo, "run.sh", "#!/bin/sh\n")
    (repo / "run.sh").chmod(0o755)
    _git(repo, "add", "-A")
    _git(repo, "update-index", "--chmod=+x", "run.sh")  # the exec bit on every OS
    head = _commit(repo)
    entries = GitReader(repo).tree(head)
    assert [(e[0], e[2], e[3]) for e in entries] == [
        ("100644", 6, "a.py"),
        ("100644", 0, "pkg/sub/b.py"),
        ("100755", 10, "run.sh"),
    ]
    assert entries[0][1] == _git(repo, "rev-parse", f"{head}:a.py")
    assert _sub_args(spy[-1], "ls-tree") == [
        "-r", "-l", "-z", "--full-tree", "--end-of-options", head,
    ]  # fmt: skip
    assert spy[-1]["max_stdout"] == gitread.LISTING_MAX_BYTES
    assert spy[-1]["timeout"] == gitread.GIT_TIMEOUT_SECONDS


def test_tree_of_an_empty_commit_is_empty(repo: Path) -> None:
    assert GitReader(repo).tree(_commit(repo)) == []


def test_tree_keeps_symlinks_odd_names_and_gitlinks(repo: Path) -> None:
    """Symlink, gitlink, café, and space/tab names; these can be set up on Windows."""
    _require_symlinks()
    _git(repo, "config", "core.symlinks", "true")
    os.symlink("target", repo / "link")
    _write(repo, "sp ace.py", "")  # space; tab is rejected by Win32 (Invalid argument)
    _write(repo, "caf\xe9.py", "")
    _git(repo, "add", "-A")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{SHA},sub")
    _git(repo, "commit", "-q", "-m", "c")
    entries = {e[3]: e for e in GitReader(repo).tree(_git(repo, "rev-parse", "HEAD"))}
    assert entries["link"][0] == "120000" and entries["link"][2] == 6
    assert entries["sub"] == ("160000", SHA, None, "sub")
    assert "sp ace.py" in entries
    assert "caf\xe9.py" in entries


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "NTFS/Win32 forbids :, tab, newline, and a raw 0xff byte in file names, "
        "so the fixture can't be checked out"
    ),
)
def test_tree_keeps_ntfs_illegal_names(repo: Path) -> None:
    _write(repo, "sp ace\tand\nnewline.py", "")
    _write(repo, "x::warning::y.py", "")
    (repo / os.fsdecode(b"raw\xff.py")).write_bytes(b"")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")
    entries = {e[3]: e for e in GitReader(repo).tree(_git(repo, "rev-parse", "HEAD"))}
    assert "sp ace\tand\nnewline.py" in entries
    assert "x::warning::y.py" in entries
    assert "raw\udcff.py" in entries  # undecodable byte kept losslessly (surrogateescape)


@pytest.mark.parametrize("bad", BAD_SHAS)
def test_tree_refuses_a_bad_sha_before_running_git(repo: Path, spy: list[Call], bad: str) -> None:
    with pytest.raises(ComponentError, match="invalid object id"):
        GitReader(repo).tree(bad)
    assert spy == []


def test_tree_of_a_missing_commit_is_a_component_error(repo: Path) -> None:
    _commit(repo)
    with pytest.raises(ComponentError) as info:
        GitReader(repo).tree(SHA)
    assert info.value.component == "gitread"
    assert info.value.message == "git ls-tree failed (exit 128)"
    _no_host_path(info.value, repo)


def test_tree_over_the_listing_cap_is_a_component_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(20):
        _write(repo, f"f{i}.py", "")
    head = _commit(repo)
    monkeypatch.setattr(gitread, "LISTING_MAX_BYTES", 100)
    with pytest.raises(ComponentError, match="git ls-tree output too large"):
        GitReader(repo).tree(head)


@pytest.mark.parametrize(
    "stdout",
    [
        b"100644 blob " + SHA.encode() + b"       1\ta.py",  # no NUL terminator
        b"100644 blob " + SHA.encode() + b"       1\ta.py\0\0",  # empty record
        b"100644 tree " + SHA.encode() + b"       -\td\0",  # -r never lists trees
        b"100644 blob " + SHA.encode() + b"       -\ta.py\0",  # blob without a size
        b"160000 commit " + SHA.encode() + b"       5\tsub\0",  # gitlink with a size
        b"100644 blob " + SHA.upper().encode() + b"       1\ta.py\0",
        b"100644 blob " + SHA.encode() + b"       1\t\0",  # empty path
        b"10064 blob " + SHA.encode() + b" 1\ta.py\0",
    ],
)
def test_tree_rejects_malformed_listings(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake(monkeypatch, (0, stdout))
    with pytest.raises(ComponentError, match="unexpected git output"):
        GitReader(repo).tree(SHA)


# --- blob -----------------------------------------------------------------------


def _oid(repo: Path, data: bytes, name: str = "f.bin") -> str:
    _write(repo, name, data)
    _commit(repo)
    return _git(repo, "rev-parse", f"HEAD:{name}")


@pytest.mark.parametrize("data", [b"x = 1\n", b"", b"\x00\xff no newline", b"\n\n"])
def test_blob_returns_the_exact_bytes(repo: Path, data: bytes) -> None:
    reader = GitReader(repo)
    try:
        assert reader.blob(_oid(repo, data), 1 << 20) == data
    finally:
        reader.close()


def test_blob_at_exactly_the_limit_is_read(repo: Path) -> None:
    reader = GitReader(repo)
    assert reader.blob(_oid(repo, b"12345"), 5) == b"12345"
    reader.close()


def test_blob_reuses_one_process_per_mode_for_many_blobs(repo: Path, spy: list[Call]) -> None:
    oids = [_oid(repo, f"v{i}\n".encode() * (i + 1), f"f{i}.py") for i in range(12)]
    reader = GitReader(repo)
    try:
        for i, oid in enumerate(oids):
            assert reader.blob(oid, 1 << 20) == f"v{i}\n".encode() * (i + 1)
    finally:
        reader.close()
    assert [_sub_args(c, "cat-file") for c in spy] == [["--batch-check"], ["--batch"]]
    for call in spy:
        assert call["batch"] is True and call["label"] == "cat-file"
        assert all(oid not in arg for oid in oids for arg in call["argv"])  # ids on stdin
        assert "safe.bareRepository=explicit" in call["argv"]
        assert call["env"]["GIT_NO_LAZY_FETCH"] == "1"
        assert call["argv"][0] == gitread._find_git(repo).path


def test_blob_over_the_limit_never_asks_batch_for_the_body(repo: Path, spy: list[Call]) -> None:
    oid = _oid(repo, b"123456")
    reader = GitReader(repo)
    with pytest.raises(FileSkipped) as info:
        reader.blob(oid, 5)
    assert info.value.reason == "size limit"
    assert [_sub_args(c, "cat-file") for c in spy] == [["--batch-check"]]
    assert reader.blob(oid, 6) == b"123456"  # the check process is still in step
    reader.close()


def test_blob_with_a_zero_limit_reads_only_empty_blobs(repo: Path) -> None:
    reader = GitReader(repo)
    assert reader.blob(_oid(repo, b""), 0) == b""
    with pytest.raises(FileSkipped):
        reader.blob(_oid(repo, b"x", "g.bin"), 0)
    reader.close()


def test_blob_negative_limit_is_refused(repo: Path, spy: list[Call]) -> None:
    with pytest.raises(ComponentError, match="invalid size limit"):
        GitReader(repo).blob(SHA, -1)
    assert spy == []


@pytest.mark.parametrize("bad", BAD_SHAS)
def test_blob_refuses_a_bad_id_before_running_git(repo: Path, spy: list[Call], bad: str) -> None:
    with pytest.raises(ComponentError, match="invalid object id"):
        GitReader(repo).blob(bad, 10)
    assert spy == []


def test_blob_of_a_missing_object_keeps_the_processes(repo: Path, spy: list[Call]) -> None:
    oid = _oid(repo, b"ok")
    reader = GitReader(repo)
    with pytest.raises(ComponentError, match="object not found") as info:
        reader.blob(SHA, 10)
    _no_host_path(info.value, repo)
    assert reader.blob(oid, 10) == b"ok"
    assert len(spy) == 2  # one --batch-check, one --batch: nothing restarted
    reader.close()


def test_blob_of_a_tree_or_commit_is_refused(repo: Path) -> None:
    _write(repo, "d/f.py", "")
    head = _commit(repo)
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    reader = GitReader(repo)
    for oid in (head, tree):
        with pytest.raises(ComponentError, match="object is not a blob"):
            reader.blob(oid, 1 << 20)
    reader.close()


def _batch_script(check: str, batch: str) -> str:
    """A fake cat-file: --batch-check answers with ``check``, --batch with ``batch``."""
    return (
        "import sys\n"
        "mode = 'check' if len(sys.argv) < 2 else sys.argv[1]\n"
        f"CHECK, BATCH = {check!r}, {batch!r}\n"
        "for line in sys.stdin:\n"
        "    oid = line.strip()\n"
        "    out = CHECK if mode == 'check' else BATCH\n"
        "    sys.stdout.buffer.write(out.replace('OID', oid).encode('latin-1'))\n"
        "    sys.stdout.flush()\n"
        "    if 'EXIT' in out or not out.endswith('\\n'): sys.exit(0)\n"
    )


def _fake_cat_file(monkeypatch: pytest.MonkeyPatch, check: str, batch: str) -> list[list[str]]:
    real_start = gitread._start_batch
    started: list[list[str]] = []

    def start(argv: list[str], **kwargs: Any) -> Any:
        started.append(list(argv))
        mode = "check" if argv[-1] == "--batch-check" else "batch"
        script = _batch_script(check, batch)
        return real_start([sys.executable, "-c", script, mode], **kwargs)

    monkeypatch.setattr(gitread, "_start_batch", start)
    return started


@pytest.mark.parametrize(
    ("check", "batch"),
    [
        ("XX blob 3\n", ""),  # header for another object
        ("OID blob 3", ""),  # no newline, then end of output
        ("OID blob 3" + "x" * 5000 + "\n", ""),  # header over the 4096-byte cap
        ("OID tag-x 3\n", ""),
        ("", ""),  # check process ends without answering
        ("OID blob 3\n", ""),  # batch ends without answering
        ("OID blob 3\n", "OID blob 4\nabcd\n"),  # different header
        ("OID blob 3\n", "OID blob 3\nab"),  # short body, then end (process died)
        ("OID blob 3\n", "OID blob 3\nabcd"),  # no trailing LF
        ("OID blob 3\n", "OID blob 3\nabEXIT"),  # dies mid-body
    ],
)
def test_blob_protocol_errors_kill_both_processes(
    repo: Path, monkeypatch: pytest.MonkeyPatch, check: str, batch: str
) -> None:
    started = _fake_cat_file(monkeypatch, check, batch)
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 5.0)  # every case ends sooner
    reader = GitReader(repo)
    with pytest.raises(ComponentError) as info:
        reader.blob(SHA, 100)
    assert info.value.component == "gitread"
    assert "abc" not in info.value.message
    assert reader._batch_check is None and reader._batch is None
    reader.close()
    count = len(started)  # and a later call raises without restarting (I-14 item 9):
    with pytest.raises(ComponentError, match="git cat-file stopped after an error"):
        reader.blob(SHA, 100)
    assert len(started) == count


def test_blob_request_timeout_kills_both_processes(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = _fake_batch(monkeypatch, "import time; time.sleep(60)")
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.5)
    reader = GitReader(repo)
    begin = time.monotonic()
    with pytest.raises(ComponentError, match="git cat-file timed out"):
        reader.blob(SHA, 100)
    assert time.monotonic() - begin < 10
    assert reader._batch_check is None and len(started) == 1


def test_batch_send_to_an_exited_process_is_a_component_error(tmp_path: Path) -> None:
    proc = gitread._start_batch(
        [sys.executable, "-c", "pass"], cwd=tmp_path, env=dict(os.environ), label="cat-file"
    )
    assert proc.wait(time.monotonic() + 20) == 0
    with pytest.raises(ComponentError) as info:
        proc.send(b"x" * 200_000)  # past any pipe buffer, to a closed read end
    assert info.value.message == "git cat-file stopped"
    proc.kill()


def test_close_is_idempotent_and_safe_before_use(repo: Path) -> None:
    reader = GitReader(repo)
    reader.close()  # nothing started
    reader.close()
    oid = _oid(repo, b"data")
    assert reader.blob(oid, 10) == b"data"
    check, batch = reader._batch_check, reader._batch
    assert check is not None and batch is not None
    procs = [check._proc, batch._proc]
    reader.close()
    assert all(proc.returncode is not None for proc in procs)  # killed and reaped
    reader.close()
    assert reader.blob(oid, 10) == b"data"  # restarts lazily after close
    reader.close()


def test_batch_process_reports_eof_and_reads_lines(tmp_path: Path) -> None:
    proc = gitread._start_batch(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'ab\\ncdef')"],
        cwd=tmp_path,
        env=dict(os.environ),
        label="log",
    )
    deadline = time.monotonic() + 20
    assert proc.read_line(10, deadline) == b"ab\n"
    assert proc.read_some(2, deadline) == b"cd"
    assert proc.read_some(10, deadline) == b"ef"
    assert proc.read_some(10, deadline) == b""
    assert proc.read_some(10, deadline) == b""  # stays at end of output
    assert proc.wait(deadline) == 0
    proc.kill()
    proc.kill()


def test_start_batch_that_cannot_start_is_git_unavailable(tmp_path: Path) -> None:
    with pytest.raises(GitUnavailable):
        gitread._start_batch([str(tmp_path / "no-git")], cwd=tmp_path, env={}, label="cat-file")


def test_batch_pump_stops_when_killed_with_a_full_queue(tmp_path: Path) -> None:
    proc = gitread._start_batch(
        [sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536)"],
        cwd=tmp_path,
        env=dict(os.environ),
        label="log",
    )
    deadline = time.monotonic() + 20
    while proc._queue.qsize() < gitread._QUEUE_CHUNKS and time.monotonic() < deadline:
        time.sleep(0.01)
    proc.kill()
    assert all(not t.is_alive() for t in proc._threads)


def test_batch_wait_timeout_is_a_component_error(tmp_path: Path) -> None:
    proc = gitread._start_batch(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        cwd=tmp_path,
        env=dict(os.environ),
        label="log",
    )
    with pytest.raises(ComponentError, match="git log timed out"):
        proc.wait(time.monotonic() + 0.2)
    proc.kill()
    assert proc._proc.returncode is not None


# --- changed_files --------------------------------------------------------------


def test_changed_files_add_modify_delete_and_rename(repo: Path, spy: list[Call]) -> None:
    _write(repo, "keep.py", "1\n")
    _write(repo, "gone.py", "2\n")
    _write(repo, "old/name.py", "same content\n" * 5)
    base = _commit(repo)
    _write(repo, "keep.py", "1\n2\n")
    (repo / "gone.py").unlink()
    (repo / "new").mkdir()
    (repo / "old/name.py").rename(repo / "new/name.py")
    _write(repo, "added.py", "3\n")
    head = _commit(repo)
    assert sorted(GitReader(repo).changed_files(base, head), key=str) == sorted(
        [
            ("A", None, "added.py"),
            ("D", None, "gone.py"),
            ("M", None, "keep.py"),
            ("R", "old/name.py", "new/name.py"),
        ],
        key=str,
    )
    assert _set_and_tail(_sub_args(spy[-1], "diff-tree"), 2) == (
        {
            "-r", "-z", "--name-status", "--no-color", "--no-ext-diff", "--no-textconv",
            "-M50%", "-l1000", "--no-relative", "-O<orderfile>",
        },
        ["--end-of-options", base, head],
    )  # fmt: skip
    assert spy[-1]["max_stdout"] == gitread.LISTING_MAX_BYTES


def test_changed_files_rename_only_change_is_one_rename(repo: Path) -> None:
    _write(repo, "a/mod.py", "def f():\n    return 1\n")
    base = _commit(repo)
    _git(repo, "mv", "a", "b")
    head = _commit(repo)
    assert GitReader(repo).changed_files(base, head) == [("R", "a/mod.py", "b/mod.py")]


def test_changed_files_type_change(repo: Path) -> None:
    _require_symlinks()
    _git(repo, "config", "core.symlinks", "true")
    _write(repo, "x", "data")
    base = _commit(repo)
    (repo / "x").unlink()
    os.symlink("elsewhere", repo / "x")
    head = _commit(repo)
    assert GitReader(repo).changed_files(base, head) == [("T", None, "x")]


def test_changed_files_same_commit_is_empty(repo: Path) -> None:
    head = _commit(repo)
    assert GitReader(repo).changed_files(head, head) == []


def test_changed_files_copy_status_from_git_drops_the_score(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake(monkeypatch, (0, b"C075\0a.py\0b.py\0M\0c\xff.py\0"))
    assert GitReader(repo).changed_files(SHA, SHA2) == [
        ("C", "a.py", "b.py"),
        ("M", None, "c\udcff.py"),
    ]


@pytest.mark.parametrize(
    "stdout",
    [
        b"X\0a.py\0",  # unknown status
        b"R\0a.py\0b.py\0",  # rename without a score
        b"M100\0a.py\0",  # score on a plain status
        b"R100\0a.py\0",  # rename missing its new path
        b"M\0",  # status with no path
        b"M\0a.py",  # no NUL terminator
        b"a.py\0",
    ],
)
def test_changed_files_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake(monkeypatch, (0, stdout))
    with pytest.raises(ComponentError, match="unexpected git output"):
        GitReader(repo).changed_files(SHA, SHA2)


def test_changed_files_unknown_commit_is_a_component_error(repo: Path) -> None:
    head = _commit(repo)
    with pytest.raises(ComponentError, match=r"git diff-tree failed \(exit 128\)") as info:
        GitReader(repo).changed_files(SHA, head)
    _no_host_path(info.value, repo)


@pytest.mark.parametrize(("base", "head"), [("HEAD", SHA), (SHA, "--output=/tmp/x")])
def test_changed_files_refuses_bad_shas(repo: Path, spy: list[Call], base: str, head: str) -> None:
    with pytest.raises(ComponentError, match="invalid object id"):
        GitReader(repo).changed_files(base, head)
    assert spy == []


def test_changed_files_over_the_cap_is_a_component_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _commit(repo)
    for i in range(20):
        _write(repo, f"file_{i}.py", "")
    head = _commit(repo)
    monkeypatch.setattr(gitread, "LISTING_MAX_BYTES", 50)
    with pytest.raises(ComponentError, match="git diff-tree output too large"):
        GitReader(repo).changed_files(base, head)


# --- first_parent_chain ---------------------------------------------------------


def _history(repo: Path) -> dict[str, str]:
    """main: c1 - c2 - merge(c2, s1) - c3, with side branch s1 off c1."""
    shas = {"c1": _commit(repo, "c1", date="2026-01-01T00:00:00+05:00")}
    _git(repo, "checkout", "-q", "-b", "side")
    _write(repo, "side.py", "s\n")
    shas["s1"] = _commit(repo, "s1", date="2026-01-02T00:00:00Z")
    _git(repo, "checkout", "-q", "main")
    _write(repo, "main.py", "m\n")
    shas["c2"] = _commit(repo, "c2", date="2026-01-03T00:00:00Z")
    _git(repo, "merge", "-q", "--no-ff", "side", "-m", "merge", date="2026-01-04T00:00:00Z")
    shas["merge"] = _git(repo, "rev-parse", "HEAD")
    _write(repo, "main.py", "m\nn\n")
    shas["c3"] = _commit(repo, "c3", date="2026-01-05T00:00:00-08:00")
    return shas


def test_first_parent_chain_newest_first_with_utc_dates(repo: Path, spy: list[Call]) -> None:
    s = _history(repo)
    chain = GitReader(repo).first_parent_chain(s["c3"], 10)
    assert chain == [
        (s["c3"], datetime(2026, 1, 5, 8, tzinfo=UTC)),
        (s["merge"], datetime(2026, 1, 4, tzinfo=UTC)),
        (s["c2"], datetime(2026, 1, 3, tzinfo=UTC)),
        (s["c1"], datetime(2025, 12, 31, 19, tzinfo=UTC)),
    ]  # s1 is on the side branch, never walked
    assert all(when.tzinfo is UTC for _, when in chain)
    assert _sub_args(spy[-1], "rev-list") == [
        "--first-parent", "--max-count=10", "--timestamp", "--end-of-options", s["c3"],
    ]  # fmt: skip
    assert spy[-1]["max_stdout"] == 10 * gitread._CHAIN_LINE_MAX


def test_first_parent_chain_matches_commit_date(repo: Path) -> None:
    s = _history(repo)
    reader = GitReader(repo)
    for sha, when in reader.first_parent_chain(s["c3"], 10):
        assert reader.commit_date(sha) == when


def test_first_parent_chain_stops_at_the_limit(repo: Path) -> None:
    s = _history(repo)
    assert [sha for sha, _ in GitReader(repo).first_parent_chain(s["c3"], 2)] == [
        s["c3"],
        s["merge"],
    ]


@pytest.mark.parametrize("limit", [0, -1, gitread.MAX_COUNT_CAP + 1])
def test_first_parent_chain_limit_outside_the_cap_is_refused(
    repo: Path, spy: list[Call], limit: int
) -> None:
    with pytest.raises(ComponentError, match=r"outside the R2\.6 cap"):
        GitReader(repo).first_parent_chain(SHA, limit)
    assert spy == []


def test_first_parent_chain_at_the_cap_is_allowed(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _fake(monkeypatch, (0, b"1 " + SHA.encode() + b"\n"))
    assert GitReader(repo).first_parent_chain(SHA, gitread.MAX_COUNT_CAP) == [
        (SHA, datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC))
    ]
    assert f"--max-count={gitread.MAX_COUNT_CAP}" in calls[0]["argv"]


def test_first_parent_chain_accepts_pre_1970_dates(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake(monkeypatch, (0, b"-86400 " + SHA.encode() + b"\n"))
    assert GitReader(repo).first_parent_chain(SHA, 1) == [(SHA, datetime(1969, 12, 31, tzinfo=UTC))]


@pytest.mark.parametrize("bad", BAD_SHAS)
def test_first_parent_chain_refuses_a_bad_sha(repo: Path, spy: list[Call], bad: str) -> None:
    with pytest.raises(ComponentError, match="invalid object id"):
        GitReader(repo).first_parent_chain(bad, 5)
    assert spy == []


def test_first_parent_chain_unknown_commit_is_a_component_error(repo: Path) -> None:
    _commit(repo)
    with pytest.raises(ComponentError, match=r"git rev-list failed \(exit 128\)"):
        GitReader(repo).first_parent_chain(SHA, 5)


@pytest.mark.parametrize(
    "stdout",
    [
        b"",  # a commit always lists itself
        b"1 " + SHA.encode(),  # no newline
        b"1 " + SHA.encode() + b"\n1 " + SHA2.encode() + b"\n",  # more than the limit
        SHA.encode() + b"\n",  # no timestamp
        b"x " + SHA.encode() + b"\n",
        b"1 " + SHA.upper().encode() + b"\n",
        b"99999999999999999999 " + SHA.encode() + b"\n",  # past datetime's range
    ],
)
def test_first_parent_chain_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake(monkeypatch, (0, stdout))
    with pytest.raises(ComponentError, match="unexpected git output"):
        GitReader(repo).first_parent_chain(SHA, 1)


# --- patches --------------------------------------------------------------------


def _markers(text: bytes) -> list[str]:
    return [line[1:].decode() for line in text.split(b"\n") if line.startswith(b"\0")]


def test_patches_stream_newest_first_with_commit_markers(repo: Path, spy: list[Call]) -> None:
    s = _history(repo)
    stream = GitReader(repo).patches(s["c1"], s["c3"])
    assert spy == []  # git starts on the first next()
    chunks = list(stream)
    assert all(0 < len(c) <= gitread.PATCH_CHUNK_BYTES for c in chunks)
    text = b"".join(chunks)
    assert _markers(text) == [s["c3"], s["merge"], s["c2"]]  # newest first, c1 excluded
    marker = [b"\0" + s[k].encode() + b"\n" for k in ("c3", "merge", "c2")]
    # the merge diffs against its first parent: side.py arrives with the merge
    merge_part = text.split(marker[1])[1].split(marker[2])[0]
    assert b"+++ b/side.py\n" in merge_part and b"@@ -0,0 +1 @@\n+s\n" in merge_part
    assert b"@@ -1,0 +2 @@" in text.split(marker[0])[1].split(marker[1])[0]  # -U0
    assert b"merge" not in text.replace(marker[1], b"")  # no commit messages
    (call,) = spy
    assert call["batch"] is True and call["label"] == "log"
    assert _set_and_tail(_sub_args(call, "log"), 2) == (
        {
            "--first-parent", "--max-count=10000", "-m", "--root", "-p", "-U0", "--text",
            "--no-ext-diff", "--no-textconv", "--no-color", "--src-prefix=a/",
            "--dst-prefix=b/", "-M50%", "-l1000", "--full-index", "--diff-algorithm=myers",
            "--no-indent-heuristic", "--inter-hunk-context=0", "--no-relative",
            "--submodule=short", "--no-show-signature", "-O<orderfile>", "--format=%x00%H",
        },
        ["--end-of-options", s["c3"], "^" + s["c1"]],
    )  # fmt: skip


def test_patches_from_none_go_back_to_the_root(repo: Path, spy: list[Call]) -> None:
    s = _history(repo)
    text = b"".join(GitReader(repo).patches(None, s["c2"]))
    assert _markers(text) == [s["c2"], s["c1"]]  # c1 is the root commit: included
    assert _sub_args(spy[-1], "log")[-2:] == ["--end-of-options", s["c2"]]
    assert not any(a.startswith("^") for a in spy[-1]["argv"])


def test_patches_from_none_show_the_root_diff(repo: Path) -> None:
    _git(repo, "config", "log.showRoot", "false")  # --root wins over repo config
    _write(repo, "a.py", "first\n")
    root = _commit(repo)
    text = b"".join(GitReader(repo).patches(None, root))
    assert _markers(text) == [root]
    assert b"+++ b/a.py\n@@ -0,0 +1 @@\n+first\n" in text


def test_patches_chunks_are_at_most_one_mib(repo: Path) -> None:
    base = _commit(repo)
    _write(repo, "big.py", "".join(f"line_{i} = {i}\n" for i in range(150_000)))
    head = _commit(repo)
    chunks = list(GitReader(repo).patches(base, head))
    assert sum(map(len, chunks)) > 2 * gitread.PATCH_CHUNK_BYTES
    assert max(map(len, chunks)) <= gitread.PATCH_CHUNK_BYTES


def test_patches_chunk_cap_is_applied_to_buffered_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _commit(repo)
    _write(repo, "a.py", "x = 1\n" * 50)
    head = _commit(repo)
    monkeypatch.setattr(gitread, "PATCH_CHUNK_BYTES", 7)
    chunks = list(GitReader(repo).patches(base, head))
    assert max(map(len, chunks)) <= 7 and len(chunks) > 20


def test_patches_close_mid_stream_kills_git(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = _commit(repo)
    _write(repo, "big.py", "".join(f"v{i} = {i}\n" for i in range(300_000)))
    head = _commit(repo)
    started: list[Any] = []
    real_start = gitread._start_batch

    def start(argv: list[str], **kwargs: Any) -> Any:
        started.append(real_start(argv, **kwargs))
        return started[-1]

    monkeypatch.setattr(gitread, "_start_batch", start)
    stream = GitReader(repo).patches(base, head)
    first = next(stream)
    assert first.startswith(b"\0" + head.encode())
    (process,) = started
    stream.close()  # what C8 does at its 256 MiB cap
    assert process._proc.returncode is not None  # killed and reaped
    assert all(not t.is_alive() for t in process._threads)


def test_patches_never_print_a_hostile_commit_message(repo: Path) -> None:
    base = _commit(repo)
    _write(repo, "a.py", "x\n")
    head = _commit(repo, "subject\n\n" + SHA + "\ndiff --git a/evil b/evil\n+++ b/evil\n+1")
    text = b"".join(GitReader(repo).patches(base, head))
    assert b"evil" not in text and SHA.encode() not in text


def test_patches_show_a_rename_as_a_rename(repo: Path) -> None:
    _write(repo, "a.py", "same\n" * 4)
    base = _commit(repo)
    _git(repo, "mv", "a.py", "b.py")
    head = _commit(repo)
    text = b"".join(GitReader(repo).patches(base, head))
    assert b"rename from a.py\nrename to b.py\n" in text
    assert b"+same" not in text


def test_patches_ignore_repo_diff_config(repo: Path) -> None:
    _git(repo, "config", "diff.renames", "false")
    _write(repo, "a.py", "same\n" * 4)
    base = _commit(repo)
    _git(repo, "mv", "a.py", "b.py")
    head = _commit(repo)
    assert b"rename to b.py\n" in b"".join(GitReader(repo).patches(base, head))


def test_patches_of_an_empty_range_are_empty(repo: Path) -> None:
    head = _commit(repo)
    assert list(GitReader(repo).patches(head, head)) == []


def test_patches_failure_is_a_component_error(repo: Path) -> None:
    head = _commit(repo)
    with pytest.raises(ComponentError, match=r"git log failed \(exit 128\)") as info:
        list(GitReader(repo).patches(SHA, head))
    _no_host_path(info.value, repo)


def test_patches_waiting_too_long_for_a_chunk_is_a_component_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_batch(monkeypatch, "import time; time.sleep(60)")
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.5)
    with pytest.raises(ComponentError, match="git log timed out"):
        list(GitReader(repo).patches(SHA, SHA2))


def test_patches_waiting_too_long_for_the_exit_is_a_component_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_batch(
        monkeypatch,
        "import os, sys, time\nsys.stdout.write('x'); sys.stdout.flush()\n"
        "os.close(1); time.sleep(60)",
    )
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.5)
    stream = GitReader(repo).patches(SHA, SHA2)
    assert next(stream) == b"x"
    with pytest.raises(ComponentError, match="git log timed out"):
        next(stream)


@pytest.mark.parametrize(("a", "b"), [("HEAD", SHA), (SHA, "a" * 40 + "..HEAD")])
def test_patches_refuse_bad_shas(repo: Path, spy: list[Call], a: str, b: str) -> None:
    with pytest.raises(ComponentError, match="invalid object id"):
        GitReader(repo).patches(a, b)
    assert spy == []


def test_patches_in_a_missing_repo_dir_is_a_component_error(tmp_path: Path) -> None:
    with pytest.raises(ComponentError, match="repository directory not found"):
        next(GitReader(tmp_path / "gone").patches(None, SHA))


# --- every T-008 call is bounded ------------------------------------------------


def test_every_t008_call_goes_through_the_seam(repo: Path, spy: list[Call]) -> None:
    _write(repo, "a.py", "1\n")
    base = _commit(repo)
    _write(repo, "a.py", "2\n")
    head = _commit(repo)
    reader = GitReader(repo)
    oid = reader.tree(head)[0][1]
    reader.blob(oid, 10)
    reader.changed_files(base, head)
    reader.first_parent_chain(head, 5)
    list(reader.patches(base, head))
    reader.close()
    assert len(spy) == 6
    git = gitread._find_git(repo).path
    for call in spy:
        assert call["argv"][0] == git
        assert "safe.bareRepository=explicit" in call["argv"]
        assert call["env"]["GIT_NO_LAZY_FETCH"] == "1"
        if not call.get("batch"):
            assert call["timeout"] == gitread.GIT_TIMEOUT_SECONDS
            assert 0 < call["max_stdout"] <= gitread.LISTING_MAX_BYTES
