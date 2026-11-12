"""Unit tests for conventiondrift.gitread, part 1 (T-007; DESIGN §3, INTERFACES I-11 C3).

Uses real temporary git repositories. The spec and security suites under
tests/spec/ and tests/security/ own the TRACEABILITY test ids; these are unit
tests of the runner and the first five operations.
"""

import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError, GitUnavailable, UnresolvableRevision
from conventiondrift.gitread import GitReader, is_valid_sha

# Saved before any test patches subprocess.run, so fixture setup is never spied on.
_REAL_RUN = subprocess.run
_GIT = shutil.which("git") or "git"

_TEST_GIT_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str, date: str | None = None) -> str:
    """Test helper only: set up fixture repos (not the code under test)."""
    env = dict(_TEST_GIT_ENV, HOME=str(repo))
    if date is not None:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    out = _REAL_RUN([_GIT, *args], cwd=repo, env=env, check=True, capture_output=True, text=True)
    return out.stdout.strip()


def _commit(repo: Path, msg: str, date: str | None = None) -> str:
    _git(repo, "commit", "-q", "--allow-empty", "-m", msg, date=date)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _commit(path, "first", date="2026-01-02T03:04:05+05:30")
    return path


Call = dict[str, Any]


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Call]]:
    """Record every subprocess.run call gitread makes, then delegate to the real one."""
    calls: list[Call] = []
    real = _REAL_RUN

    def recorder(*args: Any, **kwargs: Any) -> Any:
        env = kwargs.get("env") or {}
        home = env.get("HOME", "")
        calls.append(
            {
                "argv": list(args[0]),
                "kwargs": kwargs,
                "home_listing": os.listdir(home) if home and os.path.isdir(home) else None,
            }
        )
        return real(*args, **kwargs)

    monkeypatch.setattr(gitread.subprocess, "run", recorder)
    yield calls


def _fake_run(monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: bytes) -> None:
    def fake(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], returncode, stdout, b"")

    monkeypatch.setattr(gitread.subprocess, "run", fake)


HARDENING = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.untrackedCache=false",
    "-c", "diff.external=",
    "-c", "core.pager=cat",
    "-c", "protocol.allow=never",
    "-c", "log.showSignature=false",
]  # fmt: skip

BAD_SHAS = [
    "",
    "abc123",
    "a" * 39,
    "a" * 41,
    "a" * 63,
    "a" * 65,
    "A" * 40,
    "g" * 40,
    "a" * 40 + "\n",
    " " + "a" * 39,
    "--output=/tmp/x",
    "-" + "a" * 39,
    "HEAD",
    "a" * 39 + "\x00",
]


# --- SHA validation -------------------------------------------------------


@pytest.mark.parametrize("sha", ["0" * 40, "f" * 64, "0123456789abcdef" * 4, "deadbeef" * 5])
def test_is_valid_sha_accepts_40_and_64_lowercase_hex(sha: str) -> None:
    assert is_valid_sha(sha)


@pytest.mark.parametrize("sha", BAD_SHAS)
def test_is_valid_sha_rejects_everything_else(sha: str) -> None:
    assert not is_valid_sha(sha)


# --- the runner -----------------------------------------------------------


def test_every_call_uses_argv_list_fixed_flags_and_no_shell(repo: Path, spy: list[Call]) -> None:
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    reader.is_shallow()
    reader.has_object(head)
    reader.merge_base(head, head)
    reader.commit_date(head)
    assert len(spy) == 5
    for call in spy:
        argv = call["argv"]
        assert isinstance(call["argv"], list)
        assert os.path.isabs(argv[0])
        assert os.path.basename(argv[0]).startswith("git")
        assert argv[1 : 1 + len(HARDENING)] == HARDENING
        assert argv[1 + len(HARDENING)] in gitread.ALLOWED_SUBCOMMANDS
        assert call["kwargs"].get("shell", False) is False
        assert call["kwargs"]["stdin"] is subprocess.DEVNULL


def test_environment_is_fixed_and_nothing_else_leaks(
    repo: Path, spy: list[Call], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_DIR", "/nonexistent")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor'='touch /tmp/leak'")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "/bin/false")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(repo))
    monkeypatch.setenv("HOME", str(repo))
    assert is_valid_sha(GitReader(repo).resolve("HEAD"))
    env = spy[0]["kwargs"]["env"]
    assert env == {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "HOME": env["HOME"],
    }
    assert env["HOME"] != str(repo)
    assert spy[0]["home_listing"] == []
    assert not os.path.exists(env["HOME"])  # removed after the call


def test_environment_without_path_passes_no_path(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = gitread.shutil.which("git")
    assert git is not None
    monkeypatch.setattr(gitread.shutil, "which", lambda *_a, **_k: git)
    monkeypatch.delenv("PATH")
    seen: list[dict[str, str]] = []
    real = _REAL_RUN

    def recorder(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs["env"])
        return real(*args, **kwargs)

    monkeypatch.setattr(gitread.subprocess, "run", recorder)
    GitReader(repo).is_shallow()
    assert "PATH" not in seen[0]


def test_systemroot_passed_only_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("PATH", "/bin")
    monkeypatch.setattr(gitread.os, "name", "nt")
    nt_env = gitread._environment("/h")
    monkeypatch.setattr(gitread.os, "name", "posix")
    posix_env = gitread._environment("/h")
    assert nt_env == dict(gitread.FIXED_ENV, PATH="/bin", SYSTEMROOT=r"C:\Windows", HOME="/h")
    assert posix_env == dict(gitread.FIXED_ENV, PATH="/bin", HOME="/h")


def test_systemroot_absent_on_windows_is_not_invented(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SYSTEMROOT", raising=False)
    monkeypatch.setattr(gitread.os, "name", "nt")
    env = gitread._environment("/h")
    monkeypatch.setattr(gitread.os, "name", "posix")
    assert "SYSTEMROOT" not in env


def test_global_config_in_inherited_home_is_ignored(
    repo: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text("[core]\n\tfsmonitor = touch SENTINEL\n")
    monkeypatch.setenv("HOME", str(home))
    GitReader(repo).is_shallow()
    assert not (repo / "SENTINEL").exists()


def test_hostile_repo_config_runs_nothing(repo: Path, tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\ntouch {sentinel}\n")
    script.chmod(0o755)
    for hook in ("post-checkout", "pre-commit", "reference-transaction", "post-index-change"):
        (hooks / hook).write_text(f"#!/bin/sh\ntouch {sentinel}\n")
        (hooks / hook).chmod(0o755)
    with (repo / ".git" / "config").open("a") as cfg:
        cfg.write(
            f"[core]\n\tfsmonitor = {script}\n\thooksPath = {hooks}\n\tpager = {script}\n"
            f'[diff]\n\texternal = {script}\n[diff "x"]\n\ttextconv = {script}\n'
            f'[filter "x"]\n\tsmudge = {script}\n\tclean = {script}\n'
            f"[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {script}\n"
        )
    (repo / ".gitattributes").write_text("* diff=x filter=x\n")
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    assert reader.is_shallow() is False
    assert reader.has_object(head)
    assert reader.merge_base(head, head) == head
    reader.commit_date(head)
    assert not sentinel.exists()


@pytest.mark.parametrize(
    "sub",
    ["checkout", "fetch", "worktree", "blame", "config", "clone", "pull", "push", "gc",
     "update-ref", "filter-branch", "diff", "", "-c", "--exec-path", "rev-parse ", "REV-PARSE"],
)  # fmt: skip
def test_disallowed_subcommand_is_refused_before_running_git(
    repo: Path, spy: list[Call], sub: str
) -> None:
    with pytest.raises(ComponentError) as info:
        GitReader(repo)._run(sub, ["--end-of-options"])
    assert info.value.component == "gitread"
    assert spy == []


def test_allowlist_is_exactly_the_design_set() -> None:
    assert (
        frozenset(
            {
                "cat-file",
                "rev-parse",
                "rev-list",
                "merge-base",
                "ls-tree",
                "diff-tree",
                "log",
                "show",
            }
        )
        == gitread.ALLOWED_SUBCOMMANDS
    )


@pytest.mark.parametrize("sub", ["log", "show", "diff-tree"])
def test_diff_and_log_calls_get_no_ext_diff_no_textconv_no_color(
    repo: Path, spy: list[Call], sub: str
) -> None:
    head = GitReader(repo).resolve("HEAD")
    GitReader(repo)._run(sub, ["--end-of-options", head])
    argv = spy[-1]["argv"]
    i = argv.index(sub)
    assert argv[i + 1 : i + 4] == ["--no-ext-diff", "--no-textconv", "--no-color"]


def test_argument_with_nul_is_refused(repo: Path, spy: list[Call]) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo)._run("rev-parse", ["--verify", "HEAD\x00--output=x"])
    assert spy == []


def test_git_missing_raises_git_unavailable(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(repo / "no-such-dir"))
    with pytest.raises(GitUnavailable):
        GitReader(repo).is_shallow()


def test_git_that_cannot_start_raises_git_unavailable(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise PermissionError("exec")

    monkeypatch.setattr(gitread.subprocess, "run", boom)
    with pytest.raises(GitUnavailable):
        GitReader(repo).is_shallow()


def test_every_call_has_a_timeout_and_discards_stderr(repo: Path, spy: list[Call]) -> None:
    reader = GitReader(repo)
    head = reader.resolve("HEAD")
    reader.is_shallow()
    reader.has_object(head)
    reader.merge_base(head, head)
    reader.commit_date(head)
    assert len(spy) == 5
    for call in spy:
        kwargs = call["kwargs"]
        assert kwargs["timeout"] == gitread.GIT_TIMEOUT_SECONDS
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"] is subprocess.DEVNULL
        assert "capture_output" not in kwargs


def test_timeout_is_a_positive_bound_within_the_run_limit() -> None:
    # AC-N2.1: a whole B10k run finishes in under 60 s, so no single call may take longer.
    assert 0 < gitread.GIT_TIMEOUT_SECONDS <= 60


def test_timeout_is_a_component_error_with_fixed_text(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def hang(argv: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(
            argv, kwargs["timeout"], output=b"secret-out", stderr=b"fatal: secret-err"
        )

    monkeypatch.setattr(gitread.subprocess, "run", hang)
    with pytest.raises(ComponentError) as info:
        GitReader(repo).resolve("secret-ref-name")
    err = info.value
    assert err.component == "gitread"
    assert err.message == "git rev-parse timed out"
    assert err.__cause__ is None
    assert err.__suppress_context__ is True  # the argv (with the REV) is not chained
    for text in ("secret", "fatal", str(repo)):
        assert text not in str(err)


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell script as a fake git")
def test_hanging_git_is_killed_after_the_timeout(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_git = tmp_path / "bin" / "git"
    fake_git.parent.mkdir()
    fake_git.write_text("#!/bin/sh\nexec sleep 30\n")
    fake_git.chmod(0o755)
    monkeypatch.setattr(gitread.shutil, "which", lambda *_a, **_k: str(fake_git))
    monkeypatch.setattr(gitread, "GIT_TIMEOUT_SECONDS", 0.5)
    start = time.monotonic()
    with pytest.raises(ComponentError) as info:
        GitReader(repo).is_shallow()
    assert info.value.message == "git rev-parse timed out"
    assert time.monotonic() - start < 10


def test_missing_repo_dir_is_a_component_error(tmp_path: Path) -> None:
    with pytest.raises(ComponentError):
        GitReader(tmp_path / "missing").is_shallow()


def test_not_a_repository_is_a_component_error(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / ".git").write_text("not a gitdir\n")  # stops discovery of any outer repo
    with pytest.raises(ComponentError) as info:
        GitReader(plain).is_shallow()
    assert info.value.component == "gitread"


def test_error_message_never_quotes_input_or_stderr(repo: Path) -> None:
    with pytest.raises(UnresolvableRevision) as info:
        GitReader(repo).resolve("secret-ref-name")
    assert str(info.value) == "unresolvable revision"
    with pytest.raises(ComponentError) as info2:
        GitReader(repo).has_object("ab" * 19 + "zz")
    assert "zz" not in str(info2.value)
    assert "fatal" not in info2.value.message


# --- resolve --------------------------------------------------------------


def test_resolve_head_branch_and_annotated_tag(repo: Path) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "tag", "-a", "v1", "-m", "tag")
    reader = GitReader(repo)
    assert reader.resolve("HEAD") == head
    assert reader.resolve("main") == head
    assert reader.resolve("v1") == head  # peeled to the commit, not the tag object
    assert reader.resolve(head) == head


def test_resolve_uses_verify_end_of_options_and_commit_peel(repo: Path, spy: list[Call]) -> None:
    GitReader(repo).resolve("main")
    argv = spy[0]["argv"]
    assert argv[-4:] == ["rev-parse", "--verify", "--end-of-options", "main^{commit}"]


@pytest.mark.parametrize(
    "rev",
    ["--output={out}", "--git-dir={out}", "-o{out}", "--exec-path={out}",
     "$(touch {out})", "`touch {out}`", "x; touch {out}", "x && touch {out}", "x | tee {out}",
     "x > {out}", "unknown-branch", "", "HEAD\nHEAD", "HEAD HEAD"],
)  # fmt: skip
def test_resolve_rejects_option_injection_and_shell_metacharacters(
    repo: Path, tmp_path: Path, rev: str
) -> None:
    out = tmp_path / "pwned"
    with pytest.raises(UnresolvableRevision) as info:
        GitReader(repo).resolve(rev.format(out=out))
    assert str(info.value) == "unresolvable revision"
    assert not out.exists()


def test_resolve_rejects_nul_without_running_git(repo: Path, spy: list[Call]) -> None:
    with pytest.raises(UnresolvableRevision):
        GitReader(repo).resolve("HEAD\x00")
    assert spy == []


def test_resolve_rejects_a_tree(repo: Path) -> None:
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    with pytest.raises(UnresolvableRevision):
        GitReader(repo).resolve(tree)


@pytest.mark.parametrize(
    "stdout", [b"", b"HEAD\n", b"a" * 40 + b"\n" + b"b" * 40 + b"\n", b"A" * 40 + b"\n",
               b"a" * 40, b"a" * 40 + b"\n\n", b"\xff" * 40 + b"\n"],
)  # fmt: skip
def test_resolve_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake_run(monkeypatch, 0, stdout)
    with pytest.raises(UnresolvableRevision):
        GitReader(repo).resolve("HEAD")


# --- is_shallow -----------------------------------------------------------


def test_is_shallow_false_for_full_repo(repo: Path) -> None:
    assert GitReader(repo).is_shallow() is False


def test_is_shallow_true_for_depth_one_clone(repo: Path, tmp_path: Path) -> None:
    _commit(repo, "second")
    clone = tmp_path / "shallow"
    _git(tmp_path, "-c", "protocol.file.allow=always", "clone", "-q", "--depth", "1",
         f"file://{repo}", str(clone))  # fmt: skip
    assert GitReader(clone).is_shallow() is True


@pytest.mark.parametrize("stdout", [b"", b"yes\n", b"true", b"true\nfalse\n"])
def test_is_shallow_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake_run(monkeypatch, 0, stdout)
    with pytest.raises(ComponentError):
        GitReader(repo).is_shallow()


# --- has_object -----------------------------------------------------------


def test_has_object_present_and_absent(repo: Path) -> None:
    reader = GitReader(repo)
    assert reader.has_object(reader.resolve("HEAD")) is True
    assert reader.has_object("0123456789" * 4) is False


@pytest.mark.parametrize("sha", BAD_SHAS)
def test_has_object_rejects_bad_sha_without_running_git(
    repo: Path, spy: list[Call], sha: str
) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).has_object(sha)
    assert spy == []


def test_has_object_passes_sha_after_end_of_options(repo: Path, spy: list[Call]) -> None:
    GitReader(repo).has_object("ab" * 20)
    assert spy[0]["argv"][-4:] == ["cat-file", "-e", "--end-of-options", "ab" * 20]


def test_has_object_maps_other_exit_codes_to_component_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_run(monkeypatch, 128, b"")
    with pytest.raises(ComponentError):
        GitReader(repo).has_object("ab" * 20)


# --- merge_base -----------------------------------------------------------


def test_merge_base_of_diverged_branches(repo: Path) -> None:
    root = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "feature")
    feature = _commit(repo, "feature")
    _git(repo, "checkout", "-q", "main")
    main = _commit(repo, "main")
    assert GitReader(repo).merge_base(main, feature) == root


def test_merge_base_none_for_unrelated_histories(repo: Path) -> None:
    first = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--orphan", "other")
    other = _commit(repo, "orphan")
    assert GitReader(repo).merge_base(first, other) is None


def test_merge_base_argv_has_only_shas_after_end_of_options(repo: Path, spy: list[Call]) -> None:
    head = _git(repo, "rev-parse", "HEAD")
    GitReader(repo).merge_base(head, head)
    assert spy[0]["argv"][-4:] == ["merge-base", "--end-of-options", head, head]


@pytest.mark.parametrize("bad", BAD_SHAS)
def test_merge_base_rejects_bad_sha_either_side(repo: Path, spy: list[Call], bad: str) -> None:
    good = "ab" * 20
    for a, b in ((bad, good), (good, bad)):
        with pytest.raises(ComponentError):
            GitReader(repo).merge_base(a, b)
    assert spy == []


def test_merge_base_missing_object_is_a_component_error(repo: Path) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).merge_base("ab" * 20, "cd" * 20)


@pytest.mark.parametrize(
    ("code", "stdout"), [(0, b""), (0, b"zz\n"), (1, b"ab" * 20 + b"\n"), (0, b"ab" * 20)]
)
def test_merge_base_rejects_malformed_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, code: int, stdout: bytes
) -> None:
    _fake_run(monkeypatch, code, stdout)
    with pytest.raises(ComponentError):
        GitReader(repo).merge_base("ab" * 20, "cd" * 20)


# --- commit_date ----------------------------------------------------------


def test_commit_date_is_committer_date_with_offset(repo: Path) -> None:
    sha = _commit(repo, "dated", date="2025-06-07T08:09:10-04:00")
    got = GitReader(repo).commit_date(sha)
    assert got == datetime(2025, 6, 7, 12, 9, 10, tzinfo=UTC)
    assert got == datetime(2025, 6, 7, 8, 9, 10, tzinfo=timezone(timedelta(hours=-4)))
    assert got.tzinfo is UTC


def test_commit_date_argv(repo: Path, spy: list[Call]) -> None:
    sha = _git(repo, "rev-parse", "HEAD")
    GitReader(repo).commit_date(sha)
    argv = spy[0]["argv"]
    i = argv.index("log")
    assert argv[i:] == ["log", "--no-ext-diff", "--no-textconv", "--no-color",
                        "--no-walk", "--format=%cI", "--end-of-options", sha]  # fmt: skip


@pytest.mark.parametrize("sha", BAD_SHAS)
def test_commit_date_rejects_bad_sha(repo: Path, spy: list[Call], sha: str) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).commit_date(sha)
    assert spy == []


def test_commit_date_of_missing_commit_is_a_component_error(repo: Path) -> None:
    with pytest.raises(ComponentError):
        GitReader(repo).commit_date("ab" * 20)


@pytest.mark.parametrize(
    "stdout", [b"", b"yesterday\n", b"2025-06-07T08:09:10\n",
               b"2025-06-07T08:09:10Z\n2025-06-07T08:09:10Z\n", b"\xff\n"],
)  # fmt: skip
def test_commit_date_rejects_malformed_or_naive_output(
    repo: Path, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    _fake_run(monkeypatch, 0, stdout)
    with pytest.raises(ComponentError):
        GitReader(repo).commit_date("ab" * 20)
