"""T-010a unit tests: C4 commit-tree discovery (DESIGN §10 S6, INTERFACES I-11 C4, I-13)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from tests.fixtures.gitrepo import SYMLINK_UNAVAILABLE_REASON, symlinks_available

import conventiondrift.discover as discover
from conventiondrift.core import BasePhaseDone
from conventiondrift.defaults import DEFAULT_EXCLUDES
from conventiondrift.discover import (
    MAX_INSTRUCTION_FILES,
    MAX_PY_FILES,
    discover_tree,
    instruction_scope,
    is_generated,
)
from conventiondrift.discover.safefs import AlwaysExcluded
from conventiondrift.errors import ComponentError, FileSkipped
from conventiondrift.gitread import GitReader
from conventiondrift.model import SkippedFile, SkipReason

SHA = "ab" * 20
PY = b"x = 1\n"
PHASE = BasePhaseDone(base_config_known=False)


class FakeGit:
    """The two C3 calls C4 makes, over an in-memory tree. Records every blob read."""

    def __init__(self, files: Mapping[str, bytes | tuple[str, bytes]]) -> None:
        self.files = {p: (v if isinstance(v, tuple) else ("100644", v)) for p, v in files.items()}
        self.blobs: list[str] = []

    def tree(self, sha: str) -> list[tuple[str, str, int | None, str]]:
        assert sha == SHA
        return [
            (mode, path, None if mode == "160000" else len(data), path)
            for path, (mode, data) in self.files.items()
        ]

    def blob(self, oid: str, max_bytes: int) -> bytes:
        self.blobs.append(oid)
        data = self.files[oid][1]
        if len(data) > max_bytes:
            raise FileSkipped("size limit")
        return data


def run(
    files: Mapping[str, bytes | tuple[str, bytes]],
    *,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    paths: Sequence[str] | None = None,
) -> discover.Discovery:
    return discover_tree(PHASE, FakeGit(files), SHA, excludes=excludes, paths=paths)


def names(found: discover.Discovery) -> tuple[list[str], list[str]]:
    return [f.path for f in found.instruction_files], [f.path for f in found.py_files]


@pytest.mark.parametrize(
    ("path", "scope"),
    [
        ("AGENTS.md", ""),
        ("a/AGENT.md", "a"),
        ("b/AGENTS.override.md", "b"),
        ("CLAUDE.md", ""),
        ("c/CLAUDE.local.md", "c"),
        ("d/e/GEMINI.md", "d/e"),
        (".claude/rules/x.md", ""),
        (".cursorrules", ""),
        (".cursor/rules/y.md", ""),
        (".cursor/rules/sub/z.mdc", ""),
        (".github/copilot-instructions.md", ""),
        (".github/instructions/w.md", ""),
        (".claude/rules/CLAUDE.md", ""),  # a root tool folder wins over the file name
        ("NOTES.md", None),
        (".claude/other.txt", None),
        (".cursor/rules/sub/q.txt", None),
        ("sub/.cursorrules", None),  # root only
        ("sub/.github/copilot-instructions.md", None),
        ("sub/.claude/rules/x.md", None),
        ("agents.md", None),  # case-sensitive
    ],
)
def test_s6_pattern_table_and_scopes(path: str, scope: str | None) -> None:
    assert instruction_scope(path) == scope


def test_discovers_every_pattern_and_no_decoys_sorted_by_path_bytes() -> None:
    files = {
        p: PY for p in ("zz/AGENTS.md", "AGENTS.md", ".cursorrules", "NOTES.md", "é/CLAUDE.md")
    }
    files["a.py"] = PY
    found = run(files)
    assert [f.path for f in found.instruction_files] == [
        ".cursorrules",
        "AGENTS.md",
        "zz/AGENTS.md",
        "é/CLAUDE.md",
    ]
    assert [f.scope_dir for f in found.instruction_files] == ["", "", "zz", "é"]
    assert not any(f.via_paths_input for f in found.instruction_files)
    assert found.skipped == () and found.notes == ()


def test_no_instruction_files_and_no_python_are_empty_results() -> None:
    assert run({"a.py": PY}) == discover.Discovery((), (), (), frozenset(), (), ())
    empty = run({"AGENTS.md": b"- Use httpx\n"})
    assert empty.py_files == () and len(empty.instruction_files) == 1


def test_python_files_are_kept_only_inside_an_instruction_scope() -> None:
    git = FakeGit(
        {
            "services/billing/CLAUDE.md": b"r",
            "services/billing/pay.py": PY,
            "services/billing/deep/x.py": PY,
            "services/web/app.py": PY,
            "services/billing2/o.py": PY,
            "tool.py": PY,
        }
    )
    found = discover_tree(PHASE, git, SHA)
    assert names(found)[1] == ["services/billing/deep/x.py", "services/billing/pay.py"]
    assert "services/web/app.py" not in git.blobs  # out of scope: never read
    root = run({"AGENTS.md": b"r", "a/b.py": PY, "c.py": PY})
    assert names(root)[1] == ["a/b.py", "c.py"]


@pytest.mark.parametrize(
    "path",
    [
        ".venv/lib/x.py",
        "venv/x.py",
        "a/.tox/x.py",
        ".nox/x.py",
        "vendor/x.py",
        "pkg/_vendor/x.py",
        "third_party/x.py",
        "build/x.py",
        "dist/x.py",
        "pkg.egg-info/x.py",
        "a/__pycache__/x.py",
        "site-packages/x.py",
        "migrations/0001.py",
        "app/migrations/0001.py",
        "x/alembic/versions/1.py",
        "m_pb2.py",
        "a/m_pb2_grpc.py",
        "env/lib/x.py",  # env/ holds pyvenv.cfg below
        ".git/x.py",
        "node_modules/p/x.py",
        "a/node_modules/p/x.py",
        "a/.GIT/x.py",
    ],
)
def test_default_excludes_and_hard_excludes_drop_python_silently(path: str) -> None:
    found = run({"AGENTS.md": b"r", "src/app.py": PY, path: PY, "env/pyvenv.cfg": b"home = /x\n"})
    assert names(found)[1] == ["src/app.py"]
    assert found.skipped == ()


def test_hard_excludes_survive_a_custom_exclude_set_and_are_never_read() -> None:
    git = FakeGit({"AGENTS.md": b"r", ".git/hooks/x.py": PY, "node_modules/AGENTS.md": b"r"})
    found = discover_tree(PHASE, git, SHA, excludes=())
    assert names(found) == (["AGENTS.md"], [])
    assert git.blobs == ["AGENTS.md"]  # SEC-T10: nothing under .git/ or node_modules/ is read


def test_a_given_exclude_set_replaces_the_defaults() -> None:
    files = {"AGENTS.md": b"r", "vendor/v.py": PY, "legacy/l.py": PY, "src/s.py": PY}
    assert names(run(files))[1] == ["legacy/l.py", "src/s.py"]
    assert names(run(files, excludes=["legacy/**"]))[1] == ["src/s.py", "vendor/v.py"]
    assert DEFAULT_EXCLUDES[0] == ".venv/"  # the default comes from defaults.py


def test_excludes_also_apply_to_auto_detected_instruction_files() -> None:
    found = run({"AGENTS.md": b"r", "vendor/x/CLAUDE.md": b"r", "legacy/GEMINI.md": b"r"})
    assert names(found)[0] == ["AGENTS.md", "legacy/GEMINI.md"]


def test_a_pyvenv_folder_at_the_repo_root_is_not_a_venv_exclusion() -> None:
    assert names(run({"AGENTS.md": b"r", "pyvenv.cfg": b"x", "a.py": PY}))[1] == ["a.py"]


@pytest.mark.parametrize(
    "head",
    [
        "# Generated by protoc. DO NOT EDIT.\n",
        "# This file is GENERATED\n# please\n# DO NOT EDIT\n",
        "\n\n\n\n# generated, do not edit\n",  # the 5th line
    ],
)
def test_generated_header_files_are_dropped_silently(head: str) -> None:
    found = run({"AGENTS.md": b"r", "g.py": (head + "x = 1\n").encode(), "ok.py": PY})
    assert names(found)[1] == ["ok.py"]
    assert found.skipped == ()


@pytest.mark.parametrize(
    "text",
    [
        "# generated only\nx = 1\n",
        "# do not edit only\nx = 1\n",
        "\n\n\n\n\n# generated, do not edit\n",  # the 6th line is too late
    ],
)
def test_generated_header_needs_both_phrases_in_the_first_five_lines(text: str) -> None:
    assert not is_generated(text)
    assert names(run({"AGENTS.md": b"r", "a.py": text.encode()}))[1] == ["a.py"]


def test_generated_header_is_python_only() -> None:
    header = b"<!-- generated, do not edit -->\n"
    assert names(run({"AGENTS.md": header}))[0] == ["AGENTS.md"]


def test_paths_input_names_the_only_instruction_files_and_scopes_to_the_repo() -> None:
    files = {"AGENTS.md": b"a", "docs/RULES.md": b"r", "src/x.py": PY, "docs/d.py": PY}
    found = run(files, paths=["docs/RULES.md"])
    assert [(f.path, f.scope_dir, f.via_paths_input) for f in found.instruction_files] == [
        ("docs/RULES.md", "", True)
    ]
    assert names(found)[1] == ["docs/d.py", "src/x.py"]  # whole repo, outside docs/ too
    assert run(files, paths=None).instruction_files[0].path == "AGENTS.md"
    assert run(files, paths=[]).instruction_files[0].path == "AGENTS.md"


def test_paths_entry_matching_an_s6_pattern_keeps_its_scope() -> None:
    found = run({"sub/AGENTS.md": b"r", "sub/a.py": PY, "b.py": PY}, paths=["./sub//AGENTS.md"])
    assert [(f.path, f.scope_dir) for f in found.instruction_files] == [("sub/AGENTS.md", "sub")]
    assert names(found)[1] == ["sub/a.py"]


def test_paths_entries_are_deduplicated_and_not_subject_to_excludes() -> None:
    found = run({"vendor/R.md": b"r", "x.py": PY}, paths=["vendor/R.md", "./vendor/R.md"])
    assert names(found)[0] == ["vendor/R.md"]


@pytest.mark.parametrize(
    "entry", [".git/config", "a/node_modules/R.md", ".GIT/x", "docs/GIT~1/x", "x/.git"]
)
def test_hard_excluded_paths_entry_is_a_note_not_a_skipped_file(entry: str) -> None:
    git = FakeGit({"AGENTS.md": b"r", entry.lstrip("./"): b"r"})
    found = discover_tree(PHASE, git, SHA, paths=[entry])
    assert found.notes == (AlwaysExcluded(entry).note,)
    assert found.notes == (f"`{entry}` is always excluded",)
    assert found.skipped == () and found.instruction_files == () and git.blobs == []


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("../x.md", "outside repository"),
        ("/etc/passwd", "outside repository"),
        ("a\\b.md", "outside repository"),
    ],
)
def test_bad_paths_entries_are_skipped_with_a_reason(entry: str, reason: SkipReason) -> None:
    found = run({"AGENTS.md": b"r"}, paths=[entry])
    assert found.skipped == (SkippedFile(entry, reason),)
    assert found.instruction_files == ()


def test_some_missing_paths_entries_get_a_not_found_note_and_the_rest_run() -> None:
    files = {"AGENTS.md": b"root", "docs/RULES.md": b"r", "x.py": PY}
    found = run(files, paths=["gone.md", "docs/RULES.md", "./docs//nope.md"])
    assert names(found) == (["docs/RULES.md"], ["x.py"])
    assert found.notes == ("`gone.md` was not found", "`docs/nope.md` was not found")
    assert found.skipped == ()


def test_all_paths_entries_missing_never_fall_back_to_auto_detection() -> None:
    files = {"AGENTS.md": b"root", "a/CLAUDE.md": b"r", "x.py": PY}
    git = FakeGit(files)
    found = discover_tree(PHASE, git, SHA, paths=["gone.md", "other.md"])
    assert found == discover.Discovery(
        (), (), (), frozenset(), (), ("`gone.md` was not found", "`other.md` was not found")
    )
    assert git.blobs == []  # nothing was read, not even the root AGENTS.md


def test_missing_and_hard_excluded_entries_each_get_their_own_note() -> None:
    found = run({"AGENTS.md": b"r"}, paths=[".git/config", "gone.md"])
    assert found.notes == ("`.git/config` is always excluded", "`gone.md` was not found")


def test_discovery_carries_empty_manifest_and_entry_point_fields_until_t010c() -> None:
    found = run({"AGENTS.md": b"r", "pyproject.toml": b"[project]\n", "a.py": PY})
    assert found.manifest_files == () and found.entry_points == frozenset()


def test_the_base_phase_token_is_required_and_changes_nothing() -> None:
    files = {"AGENTS.md": b"r", "a.py": PY}
    known = discover_tree(BasePhaseDone(base_config_known=True), FakeGit(files), SHA)
    assert known == run(files)
    with pytest.raises(TypeError):
        discover_tree(FakeGit(files), SHA)  # type: ignore[call-arg,arg-type]
    with pytest.raises(AttributeError):
        PHASE.base_config_known = True  # type: ignore[misc]  # frozen


def test_a_root_tool_folder_file_that_also_matches_a_name_is_one_whole_repo_file() -> None:
    files = {
        ".claude/rules/CLAUDE.md": b"r",
        ".cursor/rules/AGENTS.md": b"r",
        ".github/instructions/GEMINI.md": b"r",
        "sub/.claude/rules/CLAUDE.md": b"r",  # not a root tool folder: the name decides
        "a.py": PY,
        ".claude/x.py": PY,
    }
    found = run(files)
    assert [(f.path, f.scope_dir) for f in found.instruction_files] == [
        (".claude/rules/CLAUDE.md", ""),
        (".cursor/rules/AGENTS.md", ""),
        (".github/instructions/GEMINI.md", ""),
        ("sub/.claude/rules/CLAUDE.md", "sub/.claude/rules"),
    ]
    assert names(found)[1] == [".claude/x.py", "a.py"]
    assert len({f.path for f in found.instruction_files}) == len(found.instruction_files)


def test_a_non_root_pyvenv_folder_excludes_its_whole_subtree_and_the_root_one_does_not() -> None:
    files = {
        "AGENTS.md": b"r",
        "pyvenv.cfg": b"home = /x\n",  # the repo root: not a venv exclusion
        "a.py": PY,
        "tools/env/pyvenv.cfg": b"home = /x\n",
        "tools/env/bin/x.py": PY,
        "tools/env/lib/deep/er/y.py": PY,
        "tools/env/CLAUDE.md": b"r",
        "tools/other.py": PY,
        "tools/env2/z.py": PY,  # a sibling with a similar name is untouched
    }
    found = run(files)
    assert names(found) == (["AGENTS.md"], ["a.py", "tools/env2/z.py", "tools/other.py"])
    assert found.skipped == ()


def test_summary_note_text_is_stable_for_the_escaping_layer() -> None:
    # PLAN N3: T-023 escapes the raw path inside the backticks.
    found = run({"AGENTS.md": b"r"}, paths=["node_modules/a`b.md"])
    assert found.notes == ("`node_modules/a`b.md` is always excluded",)


@pytest.mark.parametrize(
    ("mode", "reason"),
    [("120000", "symlink"), ("100600", "special file"), ("040000", "special file")],
)
def test_symlinks_and_odd_modes_are_reported_only_for_files_that_would_be_analyzed(
    mode: str, reason: SkipReason
) -> None:
    git = FakeGit(
        {
            "AGENTS.md": b"r",
            "link.py": (mode, b"target"),
            "sub/CLAUDE.md": (mode, b"target"),
            "link.txt": (mode, b"target"),
            "vendor/x.py": (mode, b"t"),  # excluded: never reported
            "sub/mod": ("160000", b""),  # a submodule is ignored
        }
    )
    found = discover_tree(PHASE, git, SHA)
    assert found.skipped == (SkippedFile("link.py", reason), SkippedFile("sub/CLAUDE.md", reason))
    assert git.blobs == ["AGENTS.md"]


def test_oversize_binary_and_undecodable_files_are_skipped_before_or_after_reading() -> None:
    git = FakeGit(
        {
            "AGENTS.md": b"r",
            "big.py": b"x" * 2_000_000,
            "bin.py": b"a\x00b",
            "latin.py": b"# coding: undefined\n",
            "utf16.py": b"\xff\xfeh\x00",
            "bin/AGENTS.md": b"a\x00",
        }
    )
    found = discover_tree(PHASE, git, SHA)
    assert {(s.path, s.reason) for s in found.skipped} == {
        ("big.py", "size limit"),
        ("bin.py", "binary"),
        ("latin.py", "not decodable"),
        ("utf16.py", "not decodable"),
        ("bin/AGENTS.md", "binary"),
    }
    assert "big.py" not in git.blobs  # the tree size is checked before any read
    low = discover_tree(
        PHASE, FakeGit({"AGENTS.md": b"r", "a.py": b"x = 1\n" * 10}), SHA, max_file_bytes=16
    )
    assert low.skipped == (SkippedFile("a.py", "size limit"),)


def test_a_blob_that_grows_past_the_limit_is_still_skipped() -> None:
    class Lying(FakeGit):
        def tree(self, sha: str) -> list[tuple[str, str, int | None, str]]:
            return [(m, o, 1, p) for m, o, _, p in super().tree(sha)]

    found = discover_tree(PHASE, Lying({"AGENTS.md": b"r", "a.py": b"x" * 2_000_000}), SHA)
    assert found.skipped == (SkippedFile("a.py", "size limit"),)


def test_unsupported_tree_names_are_reported_only_when_they_would_be_analyzed() -> None:
    files = {"AGENTS.md": b"r", "a\\b.py": PY, "c\udc80.py": PY, "CON.py": PY, "d\\e.txt": PY}
    found = run(files)
    assert [(s.path, s.reason) for s in found.skipped] == [
        ("CON.py", "unsupported path"),
        ("a\\b.py", "unsupported path"),
        ("cU+DC80.py", "unsupported path"),
    ]
    assert names(found)[1] == []


def test_a_listed_colon_name_is_analyzed_on_posix_only(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {"AGENTS.md": b"r", "::warning::x.py": PY}
    assert names(run(files))[1] == ["::warning::x.py"]
    monkeypatch.setattr(os, "name", "nt")
    found = run(files)
    assert names(found)[1] == [] and found.skipped[0].reason == "unsupported path"


def test_an_unsupported_instruction_file_name_is_reported() -> None:
    found = run({"a\\b/AGENTS.md": b"r"})
    assert found.skipped == (SkippedFile("a\\b/AGENTS.md", "unsupported path"),)


def test_instruction_file_cap_keeps_the_first_200_by_path() -> None:
    assert (MAX_INSTRUCTION_FILES, MAX_PY_FILES) == (200, 100_000)
    files = {f"d{i:03}/AGENTS.md": b"r" for i in range(MAX_INSTRUCTION_FILES + 3)}
    found = run(files)
    assert len(found.instruction_files) == 200
    assert found.instruction_files[-1].path == "d199/AGENTS.md"
    assert [(s.path, s.reason) for s in found.skipped] == [
        (f"d{i}/AGENTS.md", "cap exceeded") for i in (200, 201, 202)
    ]
    capped = run({"AGENTS.md": b"r", "z/AGENTS.md": b"r"}, paths=["AGENTS.md", "z/AGENTS.md"])
    assert len(capped.instruction_files) == 2


def test_python_file_cap_keeps_the_first_by_path_and_never_reads_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(discover, "MAX_PY_FILES", 2)
    git = FakeGit({"AGENTS.md": b"r", "c.py": PY, "a.py": PY, "b.py": PY, "d.py": PY})
    found = discover_tree(PHASE, git, SHA)
    assert names(found)[1] == ["a.py", "b.py"]
    assert found.skipped == (
        SkippedFile("c.py", "cap exceeded"),
        SkippedFile("d.py", "cap exceeded"),
    )
    assert git.blobs == ["AGENTS.md", "a.py", "b.py"]


def test_a_dropped_generated_file_does_not_use_a_cap_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discover, "MAX_PY_FILES", 1)
    found = run({"AGENTS.md": b"r", "a.py": b"# generated, do not edit\n", "b.py": PY})
    assert names(found)[1] == ["b.py"] and found.skipped == ()


def test_a_git_failure_other_than_a_skip_fails_closed() -> None:
    class Broken(FakeGit):
        def blob(self, oid: str, max_bytes: int) -> bytes:
            raise ComponentError("gitread", "boom")

    with pytest.raises(ComponentError):
        discover_tree(PHASE, Broken({"AGENTS.md": b"r"}), SHA)


def test_discovery_is_deterministic_for_any_listing_order() -> None:
    files = {"b/AGENTS.md": b"r", "a/AGENTS.md": b"r", "b/x.py": PY, "a/x.py": PY}
    forward = run(files)
    backward = run(dict(reversed(list(files.items()))))
    assert forward == backward


# A real repository through C3: tree and blob, a symlink, and the hostile .git name.
_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(  # noqa: S603 - test fixture setup, fixed argv
        [shutil.which("git") or "git", *args],
        cwd=repo,
        env=dict(_ENV, HOME=str(repo)),
        check=True,
        capture_output=True,
    )
    return out.stdout.decode().strip()


def test_real_repository_through_gitread(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    layout = {
        "AGENTS.md": b"Use httpx\n",
        "pkg/CLAUDE.md": b"Use pytest\n",
        "pkg/a.py": PY,
        "vendor/v.py": PY,
        "pkg/pb_pb2.py": PY,
        ".github/instructions/w.md": b"x\n",
    }
    for rel, data in layout.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    if symlinks_available():
        (repo / "link.py").symlink_to("pkg/a.py")
    elif sys.platform != "win32":  # pragma: no cover
        pytest.skip(SYMLINK_UNAVAILABLE_REASON)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")
    reader = GitReader(repo)
    try:
        found = discover_tree(PHASE, reader, _git(repo, "rev-parse", "HEAD"))
    finally:
        reader.close()
    assert [(f.path, f.scope_dir) for f in found.instruction_files] == [
        (".github/instructions/w.md", ""),
        ("AGENTS.md", ""),
        ("pkg/CLAUDE.md", "pkg"),
    ]
    assert [f.path for f in found.py_files] == ["pkg/a.py"]
    assert found.skipped == ((SkippedFile("link.py", "symlink"),) if symlinks_available() else ())
