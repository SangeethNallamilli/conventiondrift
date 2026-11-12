"""Self-tests for the fixture git builder: dates, merge base, shallow clones, determinism."""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from fixtures.gitrepo import (
    SYMLINK_UNAVAILABLE_REASON,
    GitRepo,
    base_git_env,
    days_before,
    git_date,
    recent_lines,
)

T = dt.datetime(2026, 6, 15, 12, 0, tzinfo=dt.UTC)


def _build(root: Path) -> GitRepo:
    r = GitRepo.init(root)
    r.commit_files("c1", {"a.py": "x = 1\n"}, date=days_before(T, 100))
    r.start_pr_branch("feature")
    r.commit_files("p1", {"a.py": "x = 1\ny = 2\n"}, date=T)
    r.advance_base("main", {"b.py": "z = 3\n"}, date=days_before(T, 1))
    return r


def test_git_date_exact_with_offset() -> None:
    d = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone(dt.timedelta(hours=-5)))
    assert git_date(d) == f"@{int(d.timestamp())} -0500"
    with pytest.raises(ValueError):
        git_date(dt.datetime(2026, 1, 1))  # naive dates are refused


def test_commit_dates_are_exactly_as_given(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    off = dt.timezone(dt.timedelta(hours=5, minutes=30))
    when = dt.datetime(2025, 3, 4, 5, 6, 7, tzinfo=off)
    sha = r.commit_files(
        "c", {"f.txt": "1\n"}, date=when, author_date=dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    )
    assert r.commit_date(sha) == when
    assert r.commit_date(sha).utcoffset() == dt.timedelta(hours=5, minutes=30)
    assert r.author_date(sha) == dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


def test_forged_dates_accepted(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    a = r.commit_files("future", {"f": "1\n"}, date="2099-01-01T00:00:00+00:00")
    b = r.commit_files("past", {"f": "2\n"}, date="1971-01-01T00:00:00+00:00")
    assert r.commit_date(a).year == 2099 and r.commit_date(b).year == 1971


def test_commit_requires_explicit_date(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    r.write("f", "1\n")
    with pytest.raises(ValueError):
        r.commit("no date", date=None)


def test_base_branch_always_ahead_of_merge_base(tmp_path: Path) -> None:
    r = _build(tmp_path / "r")
    pr = r.pull_request(number=3, base_branch="main", head_branch="feature")
    assert pr.merge_base != pr.base_tip
    assert pr.merge_base == r.rev_parse("feature~1")
    assert r.parents(pr.base_tip) == [pr.merge_base]
    payload = pr.event_payload()
    assert payload["pull_request"]["base"]["sha"] == pr.base_tip
    assert payload["pull_request"]["head"]["sha"] == pr.head


def test_pull_request_refuses_base_not_ahead(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    r.commit_files("c1", {"a": "1\n"}, date=days_before(T, 2))
    r.start_pr_branch("feature")
    r.commit_files("p1", {"a": "2\n"}, date=T)
    with pytest.raises(AssertionError, match="merge base"):
        r.pull_request(number=1, base_branch="main", head_branch="feature")


def test_github_merge_commit_parents(tmp_path: Path) -> None:
    r = _build(tmp_path / "r")
    pr = r.github_merge_commit(
        r.pull_request(number=5, base_branch="main", head_branch="feature"), date=T
    )
    assert r.parents(pr.merge_commit) == [pr.base_tip, pr.head]
    assert r.rev_parse("refs/pull/5/merge") == pr.merge_commit
    assert set(r.ls_files(pr.merge_commit)) == {"a.py", "b.py"}


@pytest.mark.parametrize("which", ["head", "merge"])
def test_shallow_clone_depth_1(tmp_path: Path, which: str) -> None:
    r = _build(tmp_path / "r")
    pr = r.github_merge_commit(
        r.pull_request(number=5, base_branch="main", head_branch="feature"), date=T
    )
    ref = "refs/heads/feature" if which == "head" else "refs/pull/5/merge"
    c = r.shallow_clone(tmp_path / "c", ref)
    assert c.is_shallow()
    checked = c.rev_parse("HEAD")
    assert checked == (pr.head if which == "head" else pr.merge_commit)
    assert not c.has_object(pr.merge_base)
    assert not c.has_object(pr.base_tip)
    if which == "merge":
        assert not c.has_object(pr.head)


def test_move_and_delete_tracked(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    r.commit_files("c1", {"a/x.py": "1\n", "b.py": "2\n"}, date=days_before(T, 5))
    r.move("a/x.py", "shared/x.py")
    r.delete("b.py")
    sha = r.commit("move", date=T)
    assert r.ls_files(sha) == ["shared/x.py"]
    status = r.git("diff-tree", "-r", "-M", "--name-status", f"{sha}~1", sha)
    assert "R100\ta/x.py\tshared/x.py" in status


def test_same_calls_same_shas(tmp_path: Path) -> None:
    a, b = _build(tmp_path / "a"), _build(tmp_path / "b")
    assert a.snapshot() == b.snapshot()


def test_oracle_first_parent_dates(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    r.commit_files("old", {"f.py": "a\nb\nc\n"}, date=days_before(T, 200))
    r.commit_files("edit middle", {"f.py": "a\nB\nc\nd\n"}, date=days_before(T, 10))
    r.move("f.py", "g.py")
    r.commit("rename", date=days_before(T, 5))
    r.commit_files("head", {"g.py": "a\nB\nc\nd\ne\n"}, date=T)
    assert recent_lines(r, "HEAD") == {"g.py": {2, 4, 5}}


def test_init_without_dash_b_for_old_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """git < 2.28 has no `git init -b`; the builder falls back to symbolic-ref."""
    from fixtures import gitrepo

    monkeypatch.setattr(gitrepo, "git_version", lambda: (2, 27, 0))
    r = gitrepo.GitRepo.init(tmp_path / "old", default_branch="trunk")
    r.commit_files("c", {"a.txt": "a\n"}, date="2026-01-01T00:00:00+00:00")
    assert r.current_branch() == "trunk"
    assert gitrepo.git_version() >= (1,)


def test_base_git_env_isolates_config_and_keeps_windows_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    monkeypatch.setenv("COMSPEC", r"C:\Windows\System32\cmd.exe")
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    monkeypatch.setenv("TMP", str(tmp_path / "tmp"))
    env = base_git_env(home)
    assert env["HOME"] == str(home)
    assert env["USERPROFILE"] == str(home)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    cfg = Path(env["GIT_CONFIG_GLOBAL"])
    assert cfg.is_file()
    assert cfg.read_text(encoding="utf-8") == ""
    assert cfg != Path(os.devnull)
    assert env["SYSTEMROOT"] == r"C:\Windows"
    assert env["WINDIR"] == r"C:\Windows"
    assert env["COMSPEC"].endswith("cmd.exe")
    assert env["PATH"] == os.environ.get("PATH", os.defpath)
    monkeypatch.delenv("PATH", raising=False)
    env_no_path = base_git_env(home)
    assert env_no_path["PATH"] == os.defpath


def test_executable_bit_is_recorded_in_the_index(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    r.write("script.sh", "#!/bin/sh\necho hi\n", executable=True)
    r.write("plain.txt", "nope\n")
    sha = r.commit("modes", date="2026-01-01T00:00:00+00:00")
    script = r.git("ls-tree", sha, "--", "script.sh")
    plain = r.git("ls-tree", sha, "--", "plain.txt")
    assert script.startswith("100755"), script
    assert plain.startswith("100644"), plain


def test_symlink_is_recorded_in_the_index(tmp_path: Path) -> None:
    r = GitRepo.init(tmp_path / "r")
    r.write("target.txt", "hello\n")
    r.symlink("the-link", "target.txt")
    sha = r.commit("link", date="2026-01-01T00:00:00+00:00")
    out = r.git("ls-tree", sha, "--", "the-link")
    assert out.startswith("120000"), out
    assert r.git("show", f"{sha}:the-link") == "target.txt"


def test_forced_symlink_unavailability_skips_only_symlink_cases(tmp_path: Path) -> None:
    """Monkeypatching the probe skips only symlink-specific cases, each with a reason."""
    if os.environ.get("CD_INNER_PYTEST") == "1":
        return
    plugin = tmp_path / "force_no_symlinks.py"
    plugin.write_text(
        "def pytest_configure():\n"
        "    from fixtures import gitrepo\n"
        "    gitrepo.symlinks_available = lambda: False\n",
        encoding="utf-8",
    )
    junit = tmp_path / "junit.xml"
    repo = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["CD_INNER_PYTEST"] = "1"
    env["PYTHONPATH"] = os.pathsep.join([str(plugin.parent), env.get("PYTHONPATH", "")]).rstrip(
        os.pathsep
    )
    proc = subprocess.run(  # noqa: S603 - argv list, no shell
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/fixtures/test_gitrepo.py",
            "tests/fixtures/test_builders.py",
            "tests/spec/test_cli_contract.py",
            "-k",
            "not test_forced_symlink_unavailability",
            "-p",
            "force_no_symlinks",
            "-p",
            "no:cacheprovider",
            "--junitxml",
            str(junit),
            "-q",
            "--tb=line",
        ],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert junit.is_file(), proc.stdout + proc.stderr
    skipped: list[tuple[str, str]] = []
    unexpected: list[str] = []
    failed: list[str] = []
    for case in ET.parse(junit).iter("testcase"):  # noqa: S314 - our own pytest junit
        name = case.get("name") or ""
        classname = case.get("classname") or ""
        node = f"{classname}::{name}"
        skip = case.find("skipped")
        if skip is not None:
            message = skip.get("message") or (skip.text or "")
            typ = skip.get("type") or ""
            if SYMLINK_UNAVAILABLE_REASON in message:
                skipped.append((node, message))
            elif "xfail" not in typ.lower() and "xfail" not in message.lower():
                unexpected.append(f"{node} typ={typ!r} ({message})")
        elif case.find("failure") is not None or case.find("error") is not None:
            failed.append(node)
    assert failed == [], f"inner run failures: {failed}\n{proc.stdout}\n{proc.stderr}"
    assert unexpected == [], f"non-symlink skips: {unexpected}"
    assert skipped, (
        "expected symlink tests to skip when the probe is forced off; "
        f"exit={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    )
    for node, message in skipped:
        test_name = node.rsplit("::", 1)[-1]
        assert "symlink" in test_name, f"non-symlink test skipped: {node} ({message})"
