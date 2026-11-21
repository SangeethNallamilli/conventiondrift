"""T-010b part 2 unit tests: scan-mode discovery of the working tree, ``.gitignore``,
user excludes in the walk, and changed/unchanged tracked files (DESIGN §12 A-3,
INTERFACES I-12, I-13 scan-walk rulings, I-14 ``scan_tracked``, D-TL-55)."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from tests.fixtures.gitrepo import GitRepo

import conventiondrift.discover.safefs as safefs
from conventiondrift.core import BasePhaseDone
from conventiondrift.discover import discover_tree, scan
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
