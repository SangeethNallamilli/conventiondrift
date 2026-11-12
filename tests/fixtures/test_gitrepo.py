"""Self-tests for the fixture git builder: dates, merge base, shallow clones, determinism."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from fixtures.gitrepo import GitRepo, days_before, git_date, recent_lines

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
