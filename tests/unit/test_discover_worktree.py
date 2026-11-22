"""T-010b part 2 unit tests: scan-mode discovery of the working tree, ``.gitignore``,
user excludes in the walk, and changed/unchanged tracked files (DESIGN §12 A-3,
INTERFACES I-12, I-13 scan-walk rulings, I-14 ``scan_tracked``, D-TL-55)."""

from __future__ import annotations

import errno
import hashlib
import os
import subprocess
import sys
import time
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from tests.fixtures.gitrepo import GitRepo

import conventiondrift.discover.safefs as safefs
from conventiondrift.core import BasePhaseDone
from conventiondrift.discover import discover_tree, gitignore, scan
from conventiondrift.discover.globmatch import GlobSet
from conventiondrift.discover.scan import ScanDiscovery, discover_worktree, git_blob_id
from conventiondrift.errors import ComponentError, FileSkipped
from conventiondrift.gitread import GitReader
from conventiondrift.model import SkippedFile, TrackedState

PHASE = BasePhaseDone(base_config_known=True)
POSIX = os.name == "posix"
DAY = "2026-01-01T00:00:00+00:00"
AGENTS = "# Rules\n- Use x.\n"


def symlink(target: str | Path, link: Path, *, is_dir: bool = False) -> None:
    """As in test_worktree_walk.py: a failure only skips locally, never under CI."""
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except OSError as exc:
        message = f"failed to create symlink {link} -> {target}: {exc}"
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or sys.platform == "win32":
            pytest.fail(message)
        pytest.skip(message)


def write(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode() if isinstance(content, str) else content)


def blob40(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


class Head:
    """A stand-in C3 reader that serves only ``tree`` for ``HEAD``."""

    def __init__(self, entries: Sequence[tuple[str, str, int | None, str]]) -> None:
        self.entries = tuple(entries)
        self.asked: list[str] = []

    def tree(self, sha: str) -> Sequence[tuple[str, str, int | None, str]]:
        self.asked.append(sha)
        return self.entries

    def blob(self, oid: str, max_bytes: int) -> bytes:  # pragma: no cover - never called
        raise AssertionError("scan mode reads the working tree, never a HEAD blob")


def tracked(root: Path, *paths: str, mode: str = "100644") -> Head:
    return Head([(mode, blob40((root / p).read_bytes()), 1, p) for p in paths])


def run(root: Path, head: Head | None = None, **kw: object) -> ScanDiscovery:
    if head is None:
        return discover_worktree(PHASE, root, **kw)  # type: ignore[arg-type]
    return discover_worktree(PHASE, root, head, "f" * 40, **kw)  # type: ignore[arg-type]


def py_paths(result: ScanDiscovery) -> list[str]:
    return [f.path for f in result.discovery.py_files]


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[GitRepo]:
    fixture = GitRepo.init(tmp_path / "repo")
    yield fixture
    fixture.remove()


# ------------------------------------------------------------------ arguments


def test_needs_the_phase_token(tmp_path: Path) -> None:
    message = "^discover_worktree needs the BasePhaseDone token as its first argument$"
    with pytest.raises(TypeError, match=message):
        discover_worktree(object(), tmp_path)  # type: ignore[arg-type]


def test_git_and_head_sha_come_together(tmp_path: Path) -> None:
    message = "^discover_worktree needs both git and head_sha, or neither$"
    with pytest.raises(ValueError, match=message):
        discover_worktree(PHASE, tmp_path, Head([]))
    with pytest.raises(ValueError, match=message):
        discover_worktree(PHASE, tmp_path, None, "f" * 40)


def test_head_tree_is_read_once_for_the_given_sha(tmp_path: Path) -> None:
    head = Head([])
    discover_worktree(PHASE, tmp_path, head, "a" * 40)
    assert head.asked == ["a" * 40]


def test_an_unlistable_root_is_a_discover_error(tmp_path: Path) -> None:
    with pytest.raises(ComponentError) as caught:
        run(tmp_path / "missing")
    assert caught.value.component == "discover"


def test_a_git_error_propagates(tmp_path: Path) -> None:
    class Broken(Head):
        def tree(self, sha: str) -> Sequence[tuple[str, str, int | None, str]]:
            raise ComponentError("gitread", "boom")

    with pytest.raises(ComponentError) as caught:
        run(tmp_path, Broken([]))
    assert caught.value.component == "gitread"


@pytest.mark.parametrize(
    "oid",
    ["f" * 39, "f" * 41, "f" * 63, "f" * 65, "F" * 40, "g" * 40, "", "f" * 39 + "\n"],
)
def test_an_object_id_that_is_not_a_git_hash_is_a_discover_error(tmp_path: Path, oid: str) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": "x = 1\n"})
    with pytest.raises(ComponentError) as caught:
        run(tmp_path, Head([("100644", oid, 1, "a.py")]))
    assert caught.value.component == "discover"
    assert caught.value.message == "HEAD listed an object id that is not a git hash"
    assert str(tmp_path) not in str(caught.value)


def test_result_is_read_only_and_unhashable(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": "x = 1\n"})
    result = run(tmp_path, tracked(tmp_path, "a.py"))
    with pytest.raises(TypeError):
        result.scan_tracked["b.py"] = TrackedState("0" * 40, True)  # type: ignore[index]
    with pytest.raises(TypeError):
        result.stats["scan_walk_entries"] = 0  # type: ignore[index]
    with pytest.raises(TypeError):
        hash(result)


# ------------------------------------------------------------------ same rules as a tree


def test_matches_discover_tree_on_a_clean_checkout(repo: GitRepo) -> None:
    repo.commit_files(
        "c",
        {
            "AGENTS.md": AGENTS,
            "pkg/CLAUDE.md": AGENTS,
            "pkg/a.py": "x = 1\n",
            "pkg/gen.py": "# generated, do not edit\n",
            "b.py": "y = 2\n",
            "pyproject.toml": '[project]\nname = "p"\n',
            "venv/lib/c.py": "z = 3\n",
        },
        date=DAY,
    )
    git = GitReader(repo.path)
    try:
        head = git.resolve("HEAD")
        tree = discover_tree(PHASE, git, head)
        worktree = discover_worktree(PHASE, repo.path, git, head)
    finally:
        git.close()
    found = worktree.discovery
    assert [f.path for f in found.instruction_files] == [f.path for f in tree.instruction_files]
    assert found.py_files == tree.py_files
    assert found.manifest_files == tree.manifest_files
    assert found.entry_points == tree.entry_points
    assert found.skipped == tree.skipped
    assert found.notes == tree.notes
    assert set(worktree.scan_tracked) == {"b.py", "pkg/a.py"}
    assert all(state.unchanged for state in worktree.scan_tracked.values())


def test_paths_notes_come_through(tmp_path: Path) -> None:
    write(tmp_path, {"RULES.md": AGENTS})
    result = run(tmp_path, paths=["RULES.md", "gone.md", ".git/x.md"])
    assert [f.path for f in result.discovery.instruction_files] == ["RULES.md"]
    assert result.discovery.notes == ("`gone.md` was not found", "`.git/x.md` is always excluded")


def test_a_symlinked_python_file_in_scope_is_reported(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "t.txt": "x = 1\n"})
    symlink("t.txt", tmp_path / "l.py")
    symlink("t.txt", tmp_path / "l.txt")
    result = run(tmp_path)
    assert result.discovery.skipped == (SkippedFile("l.py", "symlink"),)  # ruling 6


def test_an_empty_file_fits_a_zero_byte_limit(tmp_path: Path) -> None:
    # Walk entries carry no size, so the limit is checked on the open file only.
    write(tmp_path, {"RULES.md": "", "a.py": ""})
    result = run(tmp_path, paths=["RULES.md"], max_file_bytes=0)
    assert py_paths(result) == ["a.py"]
    assert result.discovery.skipped == ()


def test_files_are_read_with_the_size_limit(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": "- Use x.\n", "a.py": "x = 1\n" * 10, "b.py": "x\n"})
    result = run(tmp_path, max_file_bytes=10)
    assert py_paths(result) == ["b.py"]
    assert result.discovery.skipped == (SkippedFile("a.py", "size limit"),)


def test_a_file_that_vanishes_after_the_walk_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": "x = 1\n"})
    real = safefs.walk_worktree

    def walk_then_delete(*a: object, **k: object) -> safefs.WalkResult:
        result = real(*a, **k)  # type: ignore[arg-type]
        (tmp_path / "a.py").unlink()
        return result

    monkeypatch.setattr(safefs, "walk_worktree", walk_then_delete)
    result = run(tmp_path)
    assert result.discovery.skipped == (SkippedFile("a.py", "unreadable"),)


def test_walk_limit_folders_are_merged_in_path_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(safefs, "WALK_MAX_DEPTH", 1)
    write(tmp_path, {"AGENTS.md": AGENTS, "a/deep/x.py": "", "c/deep/y.py": "", "b.py": "x\n"})
    symlink("b.py", tmp_path / "b2.py")
    result = run(tmp_path)
    assert result.discovery.skipped == (
        SkippedFile("a/deep", "walk limit"),
        SkippedFile("b2.py", "symlink"),
        SkippedFile("c/deep", "walk limit"),
    )
    assert result.stats["scan_walk_skipped"] == 3


@pytest.mark.skipif(not POSIX, reason="names that are not UTF-8 are POSIX only")
@pytest.mark.skipif(
    sys.platform == "darwin", reason="APFS rejects non-UTF-8 file names (EILSEQ, errno 92)"
)
def test_walk_limits_sort_with_names_that_are_not_utf8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(safefs, "WALK_MAX_DEPTH", 1)
    write(tmp_path, {"AGENTS.md": AGENTS, "a/deep/x.py": "", "z/deep/y.py": ""})
    with open(os.path.join(os.fsencode(tmp_path), b"m\xff.py"), "wb"):
        pass
    result = run(tmp_path)
    assert result.discovery.skipped == (
        SkippedFile("a/deep", "walk limit"),
        SkippedFile("mU+DCFF.py", "unsupported path"),
        SkippedFile("z/deep", "walk limit"),
    )


def test_the_walk_tree_reader_never_reads_a_hard_excluded_path(tmp_path: Path) -> None:
    write(tmp_path, {".git/x.py": "x = 1\n"})
    reader = scan._WalkTree(tmp_path, [], [])
    with pytest.raises(FileSkipped) as caught:
        reader.blob(".git/x.py", 100)
    assert caught.value.reason == "unreadable"


def test_the_walk_tree_reader_serves_walk_refusals(tmp_path: Path) -> None:
    reader = scan._WalkTree(tmp_path, ["a.py"], [SkippedFile("l.py", "symlink")])
    assert [e[3] for e in reader.tree("")] == ["a.py", "l.py"]
    with pytest.raises(FileSkipped) as caught:
        reader.blob("l.py", 100)
    assert caught.value.reason == "symlink"


# ------------------------------------------------------------------ .gitignore


def test_gitignore_drops_untracked_files(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "AGENTS.md": AGENTS,
            ".gitignore": "ignored.py\nscratch/\n",
            "ignored.py": "",
            "kept.py": "",
            "scratch/out.py": "",
            "sub/.gitignore": "local.py\n",
            "sub/local.py": "",
            "local.py": "",
            "zz/local.py": "",  # walked after sub/.gitignore is loaded
        },
    )
    result = run(tmp_path)
    assert py_paths(result) == ["kept.py", "local.py", "zz/local.py"]
    assert result.stats["gitignore_patterns_loaded"] == 3


def test_an_ignored_folder_is_not_entered(tmp_path: Path) -> None:
    # scratch/ is not a default exclude, so only .gitignore keeps the walk out of it.
    write(tmp_path, {".gitignore": "scratch/\n", "scratch/a/b.py": "", "x.py": ""})
    result = run(tmp_path)
    assert result.stats["scan_walk_entries"] == 3  # .gitignore, scratch, x.py


def test_ignored_special_files_and_links_are_not_reported(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, ".gitignore": "*.py\n", "t.txt": ""})
    symlink("t.txt", tmp_path / "l.py")
    assert run(tmp_path).discovery.skipped == ()


def test_folders_above_a_tracked_file_are_entered(tmp_path: Path) -> None:
    write(
        tmp_path,
        {"AGENTS.md": AGENTS, ".gitignore": "mid/\n", "a/mid/c/t.py": "", "a/mid/c/u.py": ""},
    )
    result = run(tmp_path, tracked(tmp_path, "a/mid/c/t.py"))
    assert py_paths(result) == ["a/mid/c/t.py"]


def test_tracked_files_are_kept_even_when_ignored(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "AGENTS.md": AGENTS,
            ".gitignore": "*.py\nlib/\n",
            "a.py": "x = 1\n",
            "b.py": "",
            "lib/t.py": "y = 2\n",
            "lib/u.py": "",
        },
    )
    result = run(tmp_path, tracked(tmp_path, "a.py", "lib/t.py"))
    assert py_paths(result) == ["a.py", "lib/t.py"]  # lib/u.py: untracked under ignored lib/
    assert dict(result.scan_tracked) == {
        "a.py": TrackedState(blob40(b"x = 1\n"), True),
        "lib/t.py": TrackedState(blob40(b"y = 2\n"), True),
    }


def test_paths_entries_are_never_dropped(tmp_path: Path) -> None:
    write(
        tmp_path,
        {".gitignore": "docs/\n*.md\n", "docs/deep/RULES.md": AGENTS, "docs/deep/x.py": ""},
    )
    result = run(tmp_path, paths=["docs/deep/RULES.md"], excludes=["docs/"])
    assert [f.path for f in result.discovery.instruction_files] == ["docs/deep/RULES.md"]
    assert py_paths(result) == []  # docs/ is still excluded for everything else


def test_a_bad_paths_entry_is_still_reported(tmp_path: Path) -> None:
    write(tmp_path, {".gitignore": "hidden/\n", "hidden/RULES.md": AGENTS})
    result = run(tmp_path, paths=["../x.md", "hidden/RULES.md"])
    assert result.discovery.skipped == (SkippedFile("../x.md", "outside repository"),)
    assert [f.path for f in result.discovery.instruction_files] == ["hidden/RULES.md"]


def test_an_ignored_pyvenv_cfg_still_marks_a_venv(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "AGENTS.md": AGENTS,
            ".gitignore": "pyvenv.cfg\n",
            "x/env/pyvenv.cfg": "",
            "x/env/m.py": "",
            "y.py": "",
        },
    )
    assert py_paths(run(tmp_path)) == ["y.py"]


def test_info_exclude_is_used_first(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "AGENTS.md": AGENTS,
            ".git/info/exclude": "*.py\n",
            ".gitignore": "!keep.py\n",
            "keep.py": "",
            "drop.py": "",
        },
    )
    result = run(tmp_path)
    assert py_paths(result) == ["keep.py"]
    assert result.stats["gitignore_patterns_loaded"] == 2


def test_info_exclude_of_a_gitlink_repo_is_not_read(tmp_path: Path) -> None:
    write(tmp_path / "real", {"info/exclude": "*.py\n"})
    root = tmp_path / "root"
    write(root, {"AGENTS.md": AGENTS, "a.py": "", ".git": f"gitdir: {tmp_path / 'real'}\n"})
    result = run(root)
    assert py_paths(result) == ["a.py"]
    assert result.stats["gitignore_patterns_loaded"] == 0


def test_a_symlinked_gitignore_is_not_used(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "patterns": "*.py\n", "a.py": ""})
    symlink("patterns", tmp_path / ".gitignore")
    result = run(tmp_path)
    assert py_paths(result) == ["a.py"]
    assert result.discovery.notes == ()
    assert result.stats["gitignore_patterns_loaded"] == 0


def test_an_oversize_gitignore_is_a_note(tmp_path: Path) -> None:
    big = b"*.py\n" + b"#" * (65_536 - 5)
    write(tmp_path, {"AGENTS.md": AGENTS, "sub/.gitignore": big, "sub/a.py": ""})
    assert py_paths(run(tmp_path)) == []  # exactly 64 KiB is read
    (tmp_path / "sub/.gitignore").write_bytes(big + b"#")
    result = run(tmp_path)
    assert py_paths(result) == ["sub/a.py"]
    assert result.discovery.notes == (
        "`sub/.gitignore` is over 64 KiB, so its patterns were not used",
    )
    assert result.stats["gitignore_patterns_loaded"] == 0


def test_an_oversize_info_exclude_is_a_note(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, ".git/info/exclude": b"#" * 65_537})
    assert run(tmp_path).discovery.notes == (
        "`.git/info/exclude` is over 64 KiB, so its patterns were not used",
    )


@pytest.mark.skipif(not POSIX, reason="FIFOs are POSIX only")
def test_a_special_info_exclude_is_silent(tmp_path: Path) -> None:
    (tmp_path / ".git" / "info").mkdir(parents=True)
    os.mkfifo(tmp_path / ".git" / "info" / "exclude")
    assert run(tmp_path).discovery.notes == ()


def test_the_pattern_cap_is_a_note_and_counted(tmp_path: Path) -> None:
    lines = "".join(f"p{i}\n" for i in range(1_999))
    write(tmp_path, {"AGENTS.md": AGENTS, ".gitignore": lines + "a.py\n", "a.py": ""})
    result = run(tmp_path)
    assert py_paths(result) == []
    assert result.discovery.notes == ()
    assert result.stats["gitignore_patterns_loaded"] == 2_000
    assert result.stats["gitignore_patterns_skipped"] == 0
    write(tmp_path, {"sub/.gitignore": "x\n", "sub/b.py": "", "sub/c.py": ""})
    (tmp_path / "sub/.gitignore").write_text("b.py\n")
    result = run(tmp_path)
    assert py_paths(result) == ["sub/b.py", "sub/c.py"]
    assert result.discovery.notes == (
        "only the first 2,000 .gitignore patterns were used; 1 more pattern was not",
    )
    (tmp_path / "sub/.gitignore").write_text("b.py\nc.py\n")
    result = run(tmp_path)
    assert result.discovery.notes == (
        "only the first 2,000 .gitignore patterns were used; 2 more patterns were not",
    )
    assert result.stats["gitignore_patterns_skipped"] == 2


def _budget(monkeypatch: pytest.MonkeyPatch, steps: int) -> None:
    for module in (gitignore, scan):
        monkeypatch.setattr(module, "GITIGNORE_MATCH_BUDGET", steps)
        monkeypatch.setattr(module, "GITIGNORE_MATCH_ALLOWANCE", 0)
        monkeypatch.setattr(module, "GITIGNORE_MATCH_ALLOWANCE_PER_CHAR", 0)


def test_the_match_budget_is_a_note_and_leaves_the_rest_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Walk order: .gitignore, AGENTS.md, a.py (7 steps each), then z1.py ... (19 each):
    # z3.py would take the work from 59 to 78.
    _budget(monkeypatch, 60)
    names = ["a.py", "z1.py", "z2.py", "z3.py", "z4.py", "z5.py"]
    write(tmp_path, {"AGENTS.md": AGENTS, ".gitignore": "z*\n", **dict.fromkeys(names, "")})
    result = run(tmp_path)
    assert py_paths(result) == ["a.py", "z3.py", "z4.py", "z5.py"]
    assert result.discovery.notes == (
        ".gitignore matching used up its budget (60 steps plus 0 per path checked"
        " and 0 per character of its name); "
        "the last 3 paths were not "
        "checked against .gitignore, so none of them was left out",
    )
    assert list(result.stats) == [  # no new I-12 counter
        "scan_walk_entries",
        "scan_walk_skipped",
        "gitignore_patterns_loaded",
        "gitignore_patterns_skipped",
    ]


def test_the_match_budget_note_for_one_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _budget(monkeypatch, 60)  # .gitignore and AGENTS.md 14, z1.py and z2.py 38, z3.py 19
    write(tmp_path, {"AGENTS.md": AGENTS, ".gitignore": "z*\n", "z1.py": "", "z2.py": ""})
    write(tmp_path, {"z3.py": ""})
    result = run(tmp_path)
    assert py_paths(result) == ["z3.py"]
    assert result.discovery.notes == (
        ".gitignore matching used up its budget (60 steps plus 0 per path checked"
        " and 0 per character of its name); "
        "the last path was not "
        "checked against .gitignore, so it was not left out",
    )


def test_a_normal_repo_gets_no_budget_note(tmp_path: Path) -> None:
    files: dict[str, str | bytes] = {f"pkg{i % 20}/m{i}.py": "" for i in range(2_000)}
    files.update({f"pkg{i}/__pycache__/m.pyc": "" for i in range(20)})
    ignore = "__pycache__/\n*.py[cod]\nbuild/\ndist/\n*.egg-info/\n.venv\n*.log\n"
    write(tmp_path, {"AGENTS.md": AGENTS, ".gitignore": ignore, "build/x.py": "", **files})
    result = run(tmp_path)
    assert len(py_paths(result)) == 2_000  # build/x.py and the .pyc files are left out
    assert result.discovery.notes == ()


def test_the_gitignore_reader_never_reads_under_a_hard_excluded_folder(tmp_path: Path) -> None:
    write(tmp_path, {".git/.gitignore": "*\n"})
    walk_filter = scan._ScanFilter(
        tmp_path,
        tracked=frozenset(),
        gitlinks=frozenset(),
        named=frozenset(),
        excludes=GlobSet([]),
    )
    walk_filter.enter(".git", [".gitignore"])
    assert walk_filter.rules.loaded == 0


# ------------------------------------------------------------------ excludes in the walk


def test_excluded_folders_are_not_entered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safefs, "WALK_MAX_DEPTH", 1)
    write(tmp_path, {"AGENTS.md": AGENTS, "out/deep/x.py": "", "out/y.py": "", "z.py": ""})
    result = run(tmp_path, excludes=["out/"])
    assert py_paths(result) == ["z.py"]
    assert result.discovery.skipped == ()  # out/deep is never reached, so no walk limit
    assert result.stats["scan_walk_entries"] == 3


def test_excluded_files_are_silent(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "x_test.py": "", "y.py": ""})
    assert py_paths(run(tmp_path, excludes=["*_test.py"])) == ["y.py"]


def test_default_excludes_apply(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, ".venv/a.py": "", "b.py": ""})
    result = run(tmp_path)
    assert py_paths(result) == ["b.py"]
    assert result.stats["scan_walk_entries"] == 3


def test_submodule_folders_are_not_entered(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "sub/x.py": "", "sub/.git": "gitdir: x\n"})
    result = run(tmp_path, Head([("160000", "a" * 40, None, "sub")]))
    assert py_paths(result) == []
    assert result.scan_tracked == {}
    assert result.stats["scan_walk_entries"] == 2


def test_a_submodule_named_as_a_file_path_is_not_tracked(tmp_path: Path) -> None:
    # A HEAD gitlink at a path the worktree holds as a .py file: not a tracked file.
    write(tmp_path, {"AGENTS.md": AGENTS, "s.py": "x\n"})
    result = run(tmp_path, Head([("160000", "a" * 40, None, "s.py")]))
    assert py_paths(result) == ["s.py"]
    assert result.scan_tracked == {}


# ------------------------------------------------------------------ changed / unchanged


def test_changed_unchanged_and_untracked(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "same.py": "a\n", "edit.py": "b\n", "new.py": "c\n"})
    head = Head(
        [
            ("100644", blob40(b"a\n"), 2, "same.py"),
            ("100755", blob40(b"old\n"), 4, "edit.py"),
            ("100644", blob40(b"gone\n"), 5, "gone.py"),
        ]
    )
    result = run(tmp_path, head)
    assert dict(result.scan_tracked) == {
        "edit.py": TrackedState(blob40(b"old\n"), False),
        "same.py": TrackedState(blob40(b"a\n"), True),
    }
    assert py_paths(result) == ["edit.py", "new.py", "same.py"]


def test_an_executable_file_can_be_unchanged(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": "a\n"})
    result = run(tmp_path, tracked(tmp_path, "a.py", mode="100755"))
    assert result.scan_tracked["a.py"].unchanged


def test_a_symlink_at_head_is_changed_even_with_equal_bytes(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": "target.py"})
    result = run(tmp_path, tracked(tmp_path, "a.py", mode="120000"))
    assert result.scan_tracked["a.py"] == TrackedState(blob40(b"target.py"), False)


def test_only_kept_python_files_are_in_scan_tracked(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "gen.py": "# Generated. Do not edit.\n", "x.txt": ""})
    result = run(tmp_path, tracked(tmp_path, "AGENTS.md", "gen.py", "x.txt"))
    assert result.scan_tracked == {}


def test_sha256_object_ids_are_compared_with_sha256(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": "a\n", "b.py": "b\n"})
    a256 = hashlib.sha256(b"blob 2\0a\n").hexdigest()
    head = Head([("100644", a256, 2, "a.py"), ("100644", "0" * 64, 2, "b.py")])
    result = run(tmp_path, head)
    assert dict(result.scan_tracked) == {
        "a.py": TrackedState(a256, True),
        "b.py": TrackedState("0" * 64, False),
    }


@pytest.mark.parametrize(
    ("worktree", "at_head", "unchanged"),
    [
        (b"a\r\nb\r\n", b"a\nb\n", True),  # core.autocrlf checkout of an LF blob
        (b"a\r\nb\n", b"a\nb\n", True),  # mixed line ends: each CRLF is read as LF
        (b"a\r\nb\r\n", b"a\r\nb\r\n", True),  # a CRLF blob, as it is
        (b"a\r\nb\r\n", b"a\nc\n", False),  # an edit is still an edit
        (b"a\nb\n", b"a\r\nb\r\n", False),  # only CRLF to LF, never LF to CRLF
        (b"a\rb\n", b"a\nb\n", False),  # a lone CR is not a line end
        (b"a\rb\r\nc\r\n", b"a\rb\nc\n", False),  # with a lone CR, git converts nothing
        (b"a\r\r\nb\n", b"a\r\nb\n", False),  # "\r\r\n" has a lone CR too
    ],
)
def test_crlf_line_ends_are_read_as_lf_when_the_bytes_differ(
    tmp_path: Path, worktree: bytes, at_head: bytes, unchanged: bool
) -> None:
    # D-TL-69 #2: git config is not read; a CRLF file is hashed again with LF.
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": worktree})
    result = run(tmp_path, Head([("100644", blob40(at_head), 1, "a.py")]))
    assert result.scan_tracked["a.py"] == TrackedState(blob40(at_head), unchanged)


def test_crlf_rehash_uses_the_head_hash(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": b"a\r\n"})
    a256 = hashlib.sha256(b"blob 2\0a\n").hexdigest()
    result = run(tmp_path, Head([("100644", a256, 1, "a.py")]))
    assert result.scan_tracked["a.py"] == TrackedState(a256, True)


def test_a_crlf_checkout_is_unchanged_as_git_says(repo: GitRepo) -> None:
    # D-TL-69 #2, against git itself: with core.autocrlf, git stores an LF blob for a
    # CRLF file (hash-object applies the same conversion as add) unless it has a lone
    # CR; that is HEAD's blob for a.py only. Here that is found without reading config.
    files = {"AGENTS.md": AGENTS, "a.py": "x\ny\n", "b.py": "p\n", "c.py": "c\rd\ne\n"}
    repo.commit_files("c", files, date=DAY)
    write(repo.path, {"a.py": b"x\r\ny\r\n", "b.py": b"q\r\n", "c.py": b"c\rd\r\ne\r\n"})
    for name, same in (("a.py", True), ("b.py", False), ("c.py", False)):
        stored = repo.git("-c", "core.autocrlf=true", "hash-object", name).strip()
        assert (stored == repo.git("rev-parse", f"HEAD:{name}").strip()) is same
    git = GitReader(repo.path)
    try:
        result = discover_worktree(PHASE, repo.path, git, git.resolve("HEAD"))
    finally:
        git.close()
    assert {p: s.unchanged for p, s in result.scan_tracked.items()} == {
        "a.py": True,
        "b.py": False,
        "c.py": False,  # a lone CR: git keeps the bytes as they are
    }


def test_against_real_git_status(repo: GitRepo) -> None:
    repo.commit_files(
        "c",
        {
            "AGENTS.md": AGENTS,
            ".gitignore": "*.log\nignored/\n",
            "same.py": "a\n",
            "edit.py": "b\n",
            "crlf.py": b"x\r\ny\r\n",
        },
        date=DAY,
    )
    write(
        repo.path,
        {"edit.py": "b2\n", "new.py": "n\n", "ignored/i.py": "", "x.log": "", "w.py": ""},
    )
    git = GitReader(repo.path)
    try:
        result = discover_worktree(PHASE, repo.path, git, git.resolve("HEAD"))
    finally:
        git.close()
    status = repo.git("status", "--porcelain", "--untracked-files=all")
    assert sorted(line.strip() for line in status.splitlines()) == [
        "?? new.py",
        "?? w.py",
        "M edit.py",
    ]
    assert {p: s.unchanged for p, s in result.scan_tracked.items()} == {
        "crlf.py": True,
        "edit.py": False,
        "same.py": True,
    }
    assert py_paths(result) == ["crlf.py", "edit.py", "new.py", "same.py", "w.py"]


def test_no_head_means_every_file_is_untracked(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, "a.py": ""})
    result = run(tmp_path)
    assert py_paths(result) == ["a.py"]
    assert result.scan_tracked == {}


# ------------------------------------------------------------------ git blob ids


def test_blob_ids_match_git_hash_object(tmp_path: Path) -> None:
    data = b"x = 1\r\n\x00\xff"
    (tmp_path / "f").write_bytes(data)
    proc = subprocess.run(
        ["git", "hash-object", "--no-filters", "f"],  # noqa: S607
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )
    assert git_blob_id(data, 40) == proc.stdout.decode().strip()


def test_blob_ids_for_sha256_repositories(tmp_path: Path) -> None:
    init = subprocess.run(  # noqa: S603 - argv list, no shell
        ["git", "init", "-q", "--object-format=sha256", str(tmp_path)],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if init.returncode != 0:  # pragma: no cover - git older than 2.29
        pytest.skip("this git cannot make a SHA-256 repository")
    (tmp_path / "f").write_bytes(b"")
    proc = subprocess.run(
        ["git", "hash-object", "--no-filters", "f"],  # noqa: S607
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )
    assert git_blob_id(b"", 64) == proc.stdout.decode().strip()


@pytest.mark.parametrize("length", [0, 39, 41, 63, 65])
def test_blob_ids_need_a_git_hash_length(length: int) -> None:
    with pytest.raises(ValueError, match=str(length)):
        git_blob_id(b"", length)


# ------------------------------------------------------------------ I-12 counters


def test_stats_are_exact_and_in_schema_order(tmp_path: Path) -> None:
    write(tmp_path, {"AGENTS.md": AGENTS, ".gitignore": "#c\nx\ny\n", "a/b.py": "", "x": ""})
    symlink("x", tmp_path / "l")
    result = run(tmp_path)
    assert list(result.stats.items()) == [
        ("scan_walk_entries", 6),  # AGENTS.md .gitignore a l x, then a/b.py (x is listed)
        ("scan_walk_skipped", 1),
        ("gitignore_patterns_loaded", 2),
        ("gitignore_patterns_skipped", 0),
    ]
    assert result.discovery.skipped == ()  # the symlink would not be analyzed (ruling 6)


# ------------------------------------------------------------------ A-3 condition 7

_NEAR_CAP_FILES = 20_000


@pytest.fixture(scope="module")
def near_cap_tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """20,000 files in 200 folders six deep, as in a large B10k-sized checkout."""
    root = tmp_path_factory.mktemp("near_cap")
    write(root, {"AGENTS.md": AGENTS})
    for d in range(200):
        folder = root.joinpath(*(f"d{d % 7}l{k}" for k in range(5)), f"leaf{d}")
        folder.mkdir(parents=True)
        for f in range(_NEAR_CAP_FILES // 200):
            (folder / f"mod_{f}.py").write_bytes(b"")
    (root / ".git" / "info").mkdir(parents=True)
    return root


# D-TL-72, D-TL-74a, D-TL-76: what the matcher guarantees, on every runner, is that its
# work counter stays within GITIGNORE_MATCH_BUDGET plus the allowance per path checked
# (which grows with its name); a check that starts inside the budget stops within its
# own start cost of the end. The wall-clock bound (hostile patterns at most double
# discovery, so the time they add must not pass the time with no patterns) is checked
# only on Linux, the ubuntu reference runner: a set that stays under the allowance pays
# it on every path, and how long a step takes next to a walk step differs by runner
# (macOS reached 1.07x at 03520df). The absolute B10k discovery budget (DESIGN §5) is
# the B10k benchmark job's to enforce.
_HOSTILE_LINES = 2_000


_REFERENCE_RUNNER = sys.platform == "linux"


def _assert_at_most_doubles(hostile: float, baseline: float) -> None:
    if not _REFERENCE_RUNNER:
        return  # D-TL-76: wall clock only on the reference runner
    assert hostile - baseline <= baseline, (
        f"hostile {hostile:.2f} s, no patterns {baseline:.2f} s: +{hostile - baseline:.2f} s"
    )


def _record_rules(monkeypatch: pytest.MonkeyPatch) -> list[gitignore.IgnoreRules]:
    """Every :class:`IgnoreRules` discovery makes from now on, in order."""
    made: list[gitignore.IgnoreRules] = []

    class Recorded(gitignore.IgnoreRules):
        def __init__(self) -> None:
            super().__init__()
            made.append(self)

    monkeypatch.setattr(scan, "IgnoreRules", Recorded)
    return made


def _assert_work_within_budget(rules: gitignore.IgnoreRules, longest: int) -> None:
    """D-TL-76: the work stays within the budget plus the allowance per path checked,
    past it only by what the last check paid before it could stop: its start cost, its
    candidates (L-76-1), one folder cut and one match step, for a path of at most
    ``longest`` components."""
    lookups = 2 * sum(map(len, rules._lengths.values()))
    gathered = len(rules._rules) // gitignore._CANDIDATES_PER_STEP
    last_check = (4 + longest + lookups + gathered) + (2 + 1 + longest) + 2
    assert rules._work <= rules._budget() + last_check, (
        f"work {rules._work:,}, budget {rules._budget():,} for {rules._checks:,} paths"
    )


def _set_patterns(root: Path, lines: Sequence[str]) -> None:
    """The same two files every run (only their content changes), each under 64 KiB."""
    (root / ".git" / "info" / "exclude").write_text("".join(lines[: len(lines) // 2]))
    (root / ".gitignore").write_text("".join(lines[len(lines) // 2 :]))


def _best_of_2(root: Path) -> tuple[float, ScanDiscovery]:
    best = float("inf")
    for _ in range(2):
        started = time.perf_counter()
        result = run(root)
        best = min(best, time.perf_counter() - started)
    return best, result


@pytest.fixture(scope="module")
def near_cap_baseline(near_cap_tree: Path) -> float:
    """Best of 2 discoveries of the tree with both pattern files present but empty,
    shared by every set on this tree."""
    _set_patterns(near_cap_tree, [])
    best, result = _best_of_2(near_cap_tree)
    assert len(py_paths(result)) == _NEAR_CAP_FILES
    assert result.discovery.notes == ()
    return best


# A-3 #7 (DESIGN §12, #76 B2 and M-76-1): a repo near the caps, with patterns the index
# can't narrow, takes at most twice as long to discover as the same tree with no patterns
# (best of 2 each; D-TL-74a). The 2,000-line sets run the budget out, so the time
# includes reaching it. With the D-TL-75 allowance of 256 per path plus 2 per character
# of its name (D-TL-76 addendum 2; about 274 a path here), the 77-line sets are the
# largest that never run it out on this tree, so they pay about all of it on every
# path: the worst case for this bound (CR's and TE's k=90-100 peak at the old 384; 76
# at 256 alone before L-76-1 charged the candidates gathered, 74 with that charge).
# The 100-line sets run it out past that peak.
@pytest.mark.timing
@pytest.mark.parametrize(
    ("line", "lines", "runs_out"),
    [
        ("[q]{}", _HOSTILE_LINES, True),  # TE
        ("[x]*{}*q/", _HOSTILE_LINES, True),  # CR
        ("**/*/**/*/**/*/**/*/**/*/**/*/**/[a-z]*q{}", _HOSTILE_LINES, True),  # SR, deep "**"
        ("[x]*{}*q", 77, False),  # CR's shape, the peak under the allowance (D-TL-75)
        ("[q]{}", 77, False),  # TE's shape, the peak under the allowance (D-TL-75)
        ("[x]*{}*q", 100, True),  # CR's shape, just past the peak
        ("[q]{}", 100, True),  # TE's shape, just past the peak
        ("[q]{}", _HOSTILE_LINES, False),  # SR's L-76-1 set: 1,999 of these, then "!*"
    ],
)
def test_hostile_patterns_add_little_to_discovering_a_repo_near_the_caps(
    near_cap_tree: Path,
    near_cap_baseline: float,
    monkeypatch: pytest.MonkeyPatch,
    line: str,
    lines: int,
    runs_out: bool,
) -> None:
    patterns = [line.format(i) + "\n" for i in range(lines)]
    if not runs_out and lines == _HOSTILE_LINES:
        # SR's L-76-1 set (D-TL-76 addendum): "!*" last is tried first and matches every
        # path in a few steps, but gathering and sorting all 2,000 candidates is paid
        # (L-76-1): about 286 steps a path, about 12 over its allowance here, so it runs
        # the base budget out only after about 240,000 paths, not on this tree.
        patterns[-1] = "!*\n"
    _set_patterns(near_cap_tree, patterns)
    made = _record_rules(monkeypatch)
    best, result = _best_of_2(near_cap_tree)
    assert len(made) == 2
    for rules in made:
        assert rules.exhausted is runs_out
        _assert_work_within_budget(rules, max(p.count("/") + 1 for p in py_paths(result)))
    _assert_at_most_doubles(best, near_cap_baseline)
    assert result.stats["gitignore_patterns_loaded"] == lines
    assert len(py_paths(result)) == _NEAR_CAP_FILES
    assert bool([n for n in result.discovery.notes if "budget" in n]) is runs_out


_DEEP_FOLDERS = 58  # with b<n>/leaf<n>/mod_<n>.py: 61 components, inside the 64 cap
_DEEP_FILES = 2_000  # enough paths to run the budget out


def _deep_tree(root: Path) -> None:
    """2,000 files under 58 folders of 200 characters each: paths of about 11,700
    characters, built with ``dir_fd`` because they are longer than ``PATH_MAX``."""
    write(root, {"AGENTS.md": AGENTS})
    (root / ".git" / "info").mkdir(parents=True)
    fd = os.open(root, os.O_RDONLY)
    try:
        for k in range(_DEEP_FOLDERS):
            name = f"{k:02d}" + "n" * 198
            os.mkdir(name, dir_fd=fd)
            inner = os.open(name, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = inner
        for b in range(4):
            os.mkdir(f"b{b}", dir_fd=fd)
        for d in range(20):
            leaf = f"b{d % 4}/leaf{d}"
            os.mkdir(leaf, dir_fd=fd)
            for f in range(_DEEP_FILES // 20):
                os.close(os.open(f"{leaf}/mod_{f}.py", os.O_CREAT | os.O_WRONLY, dir_fd=fd))
    finally:
        os.close(fd)


# The ubuntu and macOS CI legs must build the deep tree; only the git-minimum container
# (GIT_MIN_VERSION set, its filesystem refuses the names) and local runs may skip.
_MUST_BUILD_THE_DEEP_TREE = (
    bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    and sys.platform in ("linux", "darwin")
    and not os.environ.get("GIT_MIN_VERSION")
)


# #76 CR B2: the budget pays for path length, so 2,000 patterns tried on
# very long paths at most double discovery (D-TL-74a). POSIX only: the tree is built
# with dir_fd, and Windows needs long-path support for paths this long.
@pytest.mark.timing
@pytest.mark.skipif(not POSIX, reason="the deep tree is built with dir_fd (POSIX only)")
def test_hostile_patterns_add_little_on_very_long_paths(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path_factory.mktemp("deep")
    try:
        _deep_tree(root)
    except OSError as e:
        # #76 CR B1: some filesystems (the git-minimum container's) refuse a 200-character
        # name or a path this deep. That limit comes from the filesystem, not the OS, so
        # skip only on ENAMETOOLONG and let any other error fail the test.
        if e.errno != errno.ENAMETOOLONG:
            raise
        if _MUST_BUILD_THE_DEEP_TREE:
            raise  # #76 CR, D-TL-76 addendum 2: no skip on the ubuntu and macOS CI legs
        pytest.skip(f"this filesystem refuses the deep tree's names: {e}")
    _set_patterns(root, [])
    baseline, result = _best_of_2(root)
    assert len(py_paths(result)) == _DEEP_FILES
    assert max(len(p) for p in py_paths(result)) > 11_000
    assert result.discovery.notes == ()
    _set_patterns(root, ["[x]/[y]*\n"] * _HOSTILE_LINES)
    made = _record_rules(monkeypatch)
    best, result = _best_of_2(root)
    assert len(made) == 2
    for rules in made:
        assert rules.exhausted
        _assert_work_within_budget(rules, max(p.count("/") + 1 for p in py_paths(result)))
    _assert_at_most_doubles(best, baseline)
    assert result.stats["gitignore_patterns_loaded"] == _HOSTILE_LINES
    assert len(py_paths(result)) == _DEEP_FILES
    assert [n for n in result.discovery.notes if "budget" in n]


_LONG_NAME = 255  # NAME_MAX on Linux and macOS: the most per-character allowance a path gets
_LONG_NAME_LINES = 3  # "*[q]N": the largest set that never runs this tree's budget out


def _long_name_tree(root: Path) -> None:
    """20,000 files with 255-character names, laid out as the near-cap tree."""
    write(root, {"AGENTS.md": AGENTS})
    (root / ".git" / "info").mkdir(parents=True)
    for d in range(200):
        folder = root.joinpath(*(f"d{d % 7}l{k}" for k in range(5)), f"leaf{d}")
        folder.mkdir(parents=True)
        for f in range(_NEAR_CAP_FILES // 200):
            (folder / (f"mod_{f:03d}_".ljust(_LONG_NAME - 3, "m") + ".py")).write_bytes(b"")


# SR (L-76-1 follow-up, D-TL-77 #3): the allowance grows with the name, so a hostile set
# gets the most per path on 255-character names: up to 256 + 2 * 255 = 766 steps. "*[q]N"
# is tried on every name and its "*" scans all of it, so it costs the most per pattern;
# 3 of them are the largest set that never runs this tree's budget out (4 do: checked
# when the set was chosen), so they pay about all of the allowance on every path. Same
# bounds as the near-cap sets: the counter on every leg, at most double the time with
# no patterns on Linux. POSIX only: Windows needs long-path support for these paths.
@pytest.mark.timing
@pytest.mark.skipif(not POSIX, reason="paths with 255-character names need long-path support")
def test_hostile_patterns_add_little_on_the_longest_file_names(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path_factory.mktemp("long_names")
    try:
        _long_name_tree(root)
    except OSError as e:
        if e.errno != errno.ENAMETOOLONG or _MUST_BUILD_THE_DEEP_TREE:
            raise  # as for the deep tree: only git-minimum's container and local runs skip
        pytest.skip(f"this filesystem refuses 255-character names: {e}")
    _set_patterns(root, [])
    baseline, result = _best_of_2(root)
    assert len(py_paths(result)) == _NEAR_CAP_FILES
    assert {len(p.rpartition("/")[2]) for p in py_paths(result)} == {_LONG_NAME}
    assert result.discovery.notes == ()
    _set_patterns(root, [f"*[q]{i}\n" for i in range(_LONG_NAME_LINES)])
    made = _record_rules(monkeypatch)
    best, result = _best_of_2(root)
    assert len(made) == 2
    for rules in made:
        assert not rules.exhausted
        _assert_work_within_budget(rules, max(p.count("/") + 1 for p in py_paths(result)))
    _assert_at_most_doubles(best, baseline)
    assert len(py_paths(result)) == _NEAR_CAP_FILES
    assert result.stats["gitignore_patterns_loaded"] == _LONG_NAME_LINES
