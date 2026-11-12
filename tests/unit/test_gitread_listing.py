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
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError, FileSkipped
from conventiondrift.gitread import GitReader

_REAL_RUN = subprocess.run
_GIT = shutil.which("git") or "git"
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
    out = _REAL_RUN([_GIT, *args], cwd=repo, env=env, check=True, capture_output=True)
    return out.stdout.decode().strip()


def _write(repo: Path, rel: str, data: bytes | str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def _commit(repo: Path, msg: str = "c", date: str | None = None) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", msg, date=date)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    return path


Call = dict[str, Any]


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Call]]:
    """Record every bounded git call except the version check, then run it."""
    calls: list[Call] = []
    real = gitread._run_bounded

    def recorder(argv: list[str], **kwargs: Any) -> Any:
        if argv[1:] != ["--version"]:
            calls.append({"argv": list(argv), **kwargs})
        return real(argv, **kwargs)

    real_input = gitread._run_bounded_input

    def input_recorder(argv: list[str], **kwargs: Any) -> Any:
        calls.append({"argv": list(argv), **kwargs})
        return real_input(argv, **kwargs)

    monkeypatch.setattr(gitread, "_run_bounded", recorder)
    monkeypatch.setattr(gitread, "_run_bounded_input", input_recorder)
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
    monkeypatch.setattr(gitread, "_run_bounded_input", fake)
    return calls


def _sub_args(call: Call, sub: str) -> list[str]:
    argv: list[str] = call["argv"]
    return argv[argv.index(sub) + 1 :]


def _no_host_path(exc: BaseException, repo: Path) -> None:
    assert str(repo) not in str(exc)
    assert str(repo.parent) not in str(exc)


# --- bounded runner with stdin --------------------------------------------------


def test_t007_runner_signatures_are_unchanged() -> None:
    # The TE's SR-013/SR-014 tests (PR #26) pin these; stdin needs its own helper.
    import inspect

    assert list(inspect.signature(gitread._run_bounded).parameters) == [
        "argv", "cwd", "env", "label", "max_stdout", "timeout",
    ]  # fmt: skip
    assert list(inspect.signature(gitread._find_git).parameters) == ["repo_dir"]
    assert [f.name for f in dataclasses.fields(gitread._Output)] == ["returncode", "stdout"]


def test_bounded_runner_feeds_stdin_through_a_pipe(tmp_path: Path) -> None:
    code = "import sys; sys.stdout.write(sys.stdin.read().upper())"
    out = gitread._run_bounded_input(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=dict(os.environ),
        label="cat-file",
        max_stdout=64,
        timeout=20.0,
        stdin=b"abc\n",
    )
    assert out == gitread._Output(0, b"ABC\n")


def test_bounded_runner_survives_a_process_that_ignores_stdin(tmp_path: Path) -> None:
    out = gitread._run_bounded_input(
        [sys.executable, "-c", "import os, sys; os.close(0); sys.exit(4)"],
        cwd=tmp_path,
        env=dict(os.environ),
        label="cat-file",
        max_stdout=64,
        timeout=20.0,
        stdin=b"x" * 64,
    )
    assert out.returncode == 4


def test_new_options_are_allowlisted_and_nothing_wider() -> None:
    allow = gitread.OPTION_ALLOWLIST
    assert {"--batch-check", "--batch"} <= allow["cat-file"]
    assert "--batch-all-objects" not in allow["cat-file"]
    assert "--timestamp" in allow["rev-list"]
    assert "--name-status" in allow["diff-tree"]
    assert {"-m", "-M", "--root", "--reverse", "--format=%x00%H"} <= allow["log"]
    for sub in ("log", "diff-tree"):
        assert not {"--ext-diff", "--textconv", "--output", "--follow"} & allow[sub]


# --- tree -----------------------------------------------------------------------


def test_tree_lists_every_file_with_mode_oid_and_size(repo: Path, spy: list[Call]) -> None:
    _write(repo, "a.py", "x = 1\n")
    _write(repo, "pkg/sub/b.py", b"")
    _write(repo, "run.sh", "#!/bin/sh\n")
    (repo / "run.sh").chmod(0o755)
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


@pytest.mark.skipif(os.name == "nt", reason="symlinks and odd names need a POSIX filesystem")
def test_tree_keeps_symlinks_odd_names_and_gitlinks(repo: Path) -> None:
    os.symlink("target", repo / "link")
    _write(repo, "sp ace\tand\nnewline.py", "")
    _write(repo, "caf\xe9.py", "")
    _write(repo, "x::warning::y.py", "")
    (repo / os.fsdecode(b"raw\xff.py")).write_bytes(b"")
    _git(repo, "add", "-A")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{SHA},sub")
    _git(repo, "commit", "-q", "-m", "c")
    entries = {e[3]: e for e in GitReader(repo).tree(_git(repo, "rev-parse", "HEAD"))}
    assert entries["link"][0] == "120000" and entries["link"][2] == 6
    assert entries["sub"] == ("160000", SHA, None, "sub")
    assert "sp ace\tand\nnewline.py" in entries
    assert "caf\xe9.py" in entries
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


def _oid(repo: Path, data: bytes) -> str:
    _write(repo, "f.bin", data)
    _commit(repo)
    return _git(repo, "rev-parse", "HEAD:f.bin")


@pytest.mark.parametrize("data", [b"x = 1\n", b"", b"\x00\xff no newline", b"\n\n"])
def test_blob_returns_the_exact_bytes(repo: Path, data: bytes) -> None:
    assert GitReader(repo).blob(_oid(repo, data), 1 << 20) == data


def test_blob_at_exactly_the_limit_is_read(repo: Path) -> None:
    assert GitReader(repo).blob(_oid(repo, b"12345"), 5) == b"12345"


def test_blob_passes_the_id_on_stdin_and_caps_the_body(repo: Path, spy: list[Call]) -> None:
    oid = _oid(repo, b"hello\n")
    GitReader(repo).blob(oid, 100)
    check, batch = spy
    assert _sub_args(check, "cat-file") == ["--batch-check"]
    assert _sub_args(batch, "cat-file") == ["--batch"]
    assert check["stdin"] == batch["stdin"] == oid.encode() + b"\n"
    assert all(oid not in arg for call in spy for arg in call["argv"])
    header = len(f"{oid} blob 6\n")
    assert check["max_stdout"] == gitread.SMALL_OUTPUT_MAX_BYTES
    assert batch["max_stdout"] == header + 6 + 1
    assert batch["timeout"] == gitread.GIT_TIMEOUT_SECONDS


def test_blob_over_the_limit_is_skipped_without_reading_the_body(
    repo: Path, spy: list[Call]
) -> None:
    oid = _oid(repo, b"123456")
    with pytest.raises(FileSkipped) as info:
        GitReader(repo).blob(oid, 5)
    assert info.value.reason == "size limit"
    assert [_sub_args(c, "cat-file") for c in spy] == [["--batch-check"]]


def test_blob_with_a_zero_limit_reads_only_empty_blobs(repo: Path) -> None:
    assert GitReader(repo).blob(_oid(repo, b""), 0) == b""
    with pytest.raises(FileSkipped):
        GitReader(repo).blob(_oid(repo, b"x"), 0)


def test_blob_negative_limit_is_refused(repo: Path, spy: list[Call]) -> None:
    with pytest.raises(ComponentError, match="invalid size limit"):
        GitReader(repo).blob(SHA, -1)
    assert spy == []


@pytest.mark.parametrize("bad", BAD_SHAS)
def test_blob_refuses_a_bad_id_before_running_git(repo: Path, spy: list[Call], bad: str) -> None:
    with pytest.raises(ComponentError, match="invalid object id"):
        GitReader(repo).blob(bad, 10)
    assert spy == []


def test_blob_of_a_missing_object_is_a_component_error(repo: Path) -> None:
    _commit(repo)
    with pytest.raises(ComponentError, match="unexpected git output") as info:
        GitReader(repo).blob(SHA, 10)
    _no_host_path(info.value, repo)


def test_blob_of_a_tree_or_commit_is_refused(repo: Path) -> None:
    _write(repo, "d/f.py", "")
    head = _commit(repo)
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    for oid in (head, tree):
        with pytest.raises(ComponentError, match="object is not a blob"):
            GitReader(repo).blob(oid, 1 << 20)


@pytest.mark.parametrize(
    "outputs",
    [
        [(128, b"")],
        [(0, SHA2.encode() + b" blob 3\n")],  # header for another object
        [(0, SHA.encode() + b" blob 3")],  # no newline
        [(0, SHA.encode() + b" blob 3\n"), (1, b"")],
        [(0, SHA.encode() + b" blob 3\n"), (0, SHA.encode() + b" blob 3\nab\n")],  # short
        [(0, SHA.encode() + b" blob 3\n"), (0, SHA.encode() + b" blob 4\nabc\n")],
        [(0, SHA.encode() + b" blob 3\n"), (0, SHA.encode() + b" blob 3\nabcd")],  # no LF
    ],
)
def test_blob_rejects_malformed_or_failed_cat_file(
    repo: Path, monkeypatch: pytest.MonkeyPatch, outputs: list[tuple[int, bytes]]
) -> None:
    _fake(monkeypatch, *outputs)
    with pytest.raises(ComponentError) as info:
        GitReader(repo).blob(SHA, 100)
    assert info.value.component == "gitread"
    assert "abc" not in info.value.message


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
            ("D", "gone.py", "gone.py"),
            ("M", "keep.py", "keep.py"),
            ("R", "old/name.py", "new/name.py"),
        ],
        key=str,
    )
    assert _sub_args(spy[-1], "diff-tree")[:3] == ["--no-ext-diff", "--no-textconv", "--no-color"]
    assert _sub_args(spy[-1], "diff-tree")[3:] == [
        "-r", "-M", "-z", "--name-status", "--end-of-options", base, head,
    ]  # fmt: skip
    assert spy[-1]["max_stdout"] == gitread.LISTING_MAX_BYTES


def test_changed_files_rename_only_change_is_one_rename(repo: Path) -> None:
    _write(repo, "a/mod.py", "def f():\n    return 1\n")
    base = _commit(repo)
    _git(repo, "mv", "a", "b")
    head = _commit(repo)
    assert GitReader(repo).changed_files(base, head) == [("R", "a/mod.py", "b/mod.py")]


@pytest.mark.skipif(os.name == "nt", reason="symlinks need a POSIX filesystem")
def test_changed_files_type_change(repo: Path) -> None:
    _write(repo, "x", "data")
    base = _commit(repo)
    (repo / "x").unlink()
    os.symlink("elsewhere", repo / "x")
    head = _commit(repo)
    assert GitReader(repo).changed_files(base, head) == [("T", "x", "x")]


def test_changed_files_same_commit_is_empty(repo: Path) -> None:
    head = _commit(repo)
    assert GitReader(repo).changed_files(head, head) == []


def test_changed_files_copy_status_from_git_drops_the_score(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake(monkeypatch, (0, b"C075\0a.py\0b.py\0M\0c\xff.py\0"))
    assert GitReader(repo).changed_files(SHA, SHA2) == [
        ("C", "a.py", "b.py"),
        ("M", "c\udcff.py", "c\udcff.py"),
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


def test_patches_stream_oldest_first_with_commit_markers(repo: Path, spy: list[Call]) -> None:
    s = _history(repo)
    stream = GitReader(repo).patches(s["c1"], s["c3"])
    assert isinstance(stream, Iterator)
    lines = list(stream)
    assert all(line.endswith(b"\n") for line in lines)
    markers = [line for line in lines if line.startswith(b"\0")]
    assert markers == [b"\0" + s[k].encode() + b"\n" for k in ("c2", "merge", "c3")]
    text = b"".join(lines)
    # the merge diffs against its first parent: side.py arrives with the merge
    merge_part = text.split(markers[1])[1].split(markers[2])[0]
    assert b"+++ b/side.py\n" in merge_part and b"@@ -0,0 +1 @@\n+s\n" in merge_part
    assert b"@@ -1,0 +2 @@" in text.split(markers[2])[1]  # -U0: no context lines
    assert b"merge" not in text.replace(markers[1], b"")  # no commit messages
    args = _sub_args(spy[-1], "log")
    assert args == [
        "--no-ext-diff", "--no-textconv", "--no-color",
        "--first-parent", "-m", "-p", "-U0", "-M", "--root", "--reverse",
        "--format=%x00%H", f"--max-count={gitread.MAX_COUNT_CAP}",
        "--end-of-options", f"{s['c1']}..{s['c3']}",
    ]  # fmt: skip
    assert spy[-1]["max_stdout"] == gitread.PATCH_BYTES_CAP
    assert spy[-1]["timeout"] == gitread.GIT_TIMEOUT_SECONDS


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


def test_patches_over_the_byte_cap_is_a_component_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _commit(repo)
    _write(repo, "big.py", "x = 1\n" * 200)
    head = _commit(repo)
    monkeypatch.setattr(gitread, "PATCH_BYTES_CAP", 256)
    with pytest.raises(ComponentError, match="git log output too large"):
        GitReader(repo).patches(base, head)


def test_patches_failure_is_a_component_error_before_any_line(repo: Path) -> None:
    head = _commit(repo)
    with pytest.raises(ComponentError, match=r"git log failed \(exit 128\)") as info:
        GitReader(repo).patches(SHA, head)
    _no_host_path(info.value, repo)


@pytest.mark.parametrize(("a", "b"), [("HEAD", SHA), (SHA, "a" * 40 + "..HEAD")])
def test_patches_refuse_bad_shas(repo: Path, spy: list[Call], a: str, b: str) -> None:
    with pytest.raises(ComponentError, match="invalid object id"):
        GitReader(repo).patches(a, b)
    assert spy == []


def test_patches_yield_a_last_unterminated_line(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake(monkeypatch, (0, b"a\n\nb"))
    assert list(GitReader(repo).patches(SHA, SHA2)) == [b"a\n", b"\n", b"b"]


# --- every T-008 call is bounded ------------------------------------------------


def test_every_t008_call_goes_through_the_bounded_runner(repo: Path, spy: list[Call]) -> None:
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
    assert len(spy) == 6
    for call in spy:
        assert call["timeout"] == gitread.GIT_TIMEOUT_SECONDS
        assert 0 < call["max_stdout"] <= gitread.PATCH_BYTES_CAP
        assert "safe.bareRepository=explicit" in call["argv"]
        assert call["env"]["GIT_NO_LAZY_FETCH"] == "1"
