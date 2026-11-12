"""T-010b unit tests: the I-5 hard-exclusion name check (SR N4 on T-009, SC-2.43)."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest

import conventiondrift.discover.safefs as d
from conventiondrift.discover.safefs import (
    HARD_EXCLUDE_IGNORABLE,
    has_hard_excluded_component,
    is_hard_excluded,
    read_unless_hard_excluded,
)
from conventiondrift.errors import FileSkipped

EXCLUDED = [
    ".git",
    "node_modules",
    ".GIT",
    ".Git",
    "NODE_MODULES",
    "Node_Modules",
    # NTFS trailing dots and spaces, repeated and mixed (step 2).
    ".git.",
    ".GIT ",
    ".git. .",
    "node_modules...",
    # Ignorable code points (step 1), anywhere in the name.
    ".g\u200cit",
    "\ufeff.git",
    ".git\u200b",
    "node\ufeff_modules",
    "\u00adnode_modules",
    ".g\u034fi\u180bt",
    ".g\u202eit",
    ".gi\u2060t",
    ".gi\u206ft",
    ".git\ufe0f",
    # Ignorables are dropped before trailing dots/spaces are stripped.
    ".git.\u200b",
    # casefold, not lower: U+017F LATIN SMALL LETTER LONG S folds to "s".
    "node_module\u017f",
    # 8.3 short names (step 4).
    "git~1",
    "GIT~1",
    "git~12",
    "GI1A2B~1",
    "gi00ff~9",
    "NODE_M~1",
    "node_m~12",
    "NO1A2B~3",
    "GIT~1.",
]
NOT_EXCLUDED = [
    "git",
    ".gitignore",
    ".github",
    ".git-blame-ignore-revs",
    "x.git",
    "..git",
    "_git",
    "node_module",
    "node_modules2",
    "gitx~1",
    "git~0",
    "git~01",
    "git~",
    "git~1a",
    "gi1a2~1",
    "gi1a2b3~1",
    "gi1a2g~1",
    "node_m~0",
    "nodem~1",
    "no1a2~1",
    "xgit~1",
    "git~1\n",
    " .git",
    ".g it",
    # Not in HARD_EXCLUDE_IGNORABLE, so the name stays different.
    ".g\u200ait",
    ".g\u2028it",
    "",
    ".",
    "..",
]


@pytest.mark.parametrize("name", EXCLUDED, ids=ascii)
def test_hard_excluded_names(name: str) -> None:
    assert is_hard_excluded(name)


@pytest.mark.parametrize("name", NOT_EXCLUDED, ids=ascii)
def test_names_that_are_not_hard_excluded(name: str) -> None:
    assert not is_hard_excluded(name)


def test_ignorable_set_is_exactly_the_interfaces_list() -> None:
    cps = [0x00AD, 0x034F, *range(0x180B, 0x180F), *range(0x200B, 0x2010)]
    cps += [*range(0x202A, 0x202F), *range(0x2060, 0x2070), *range(0xFE00, 0xFE10), 0xFEFF]
    assert frozenset(map(chr, cps)) == HARD_EXCLUDE_IGNORABLE
    for ch in HARD_EXCLUDE_IGNORABLE:
        assert is_hard_excluded(f".g{ch}it"), hex(ord(ch))
        assert is_hard_excluded(f"node_modules{ch}"), hex(ord(ch))


# The I-5 required cases, as repo-relative paths.
REQUIRED = [
    "NODE_M~1/x.py",
    "git~1/config",
    "GI1A2B~1/HEAD",
    ".git./config",
    ".GIT /config",
    ".g\u200cit/config",
    "node\ufeff_modules/a.py",
    "src/.git",
    "a/b/.Git/HEAD",
    "pkg/node_modules/x/y.py",
]


@pytest.mark.parametrize("relpath", REQUIRED, ids=ascii)
def test_any_component_excludes_the_path(relpath: str) -> None:
    assert has_hard_excluded_component(relpath)


@pytest.mark.parametrize("relpath", ["gitx~1/a.py", "src/git/a.py", "a.py", "docs/.github/x.md"])
def test_paths_without_an_excluded_component(relpath: str) -> None:
    assert not has_hard_excluded_component(relpath)


def test_regexes_are_registered_and_fullmatch_only() -> None:
    assert len(d.REGEXES) == 2
    for pattern in d.REGEXES:
        assert "$" not in pattern.pattern
        assert not pattern.pattern.startswith("^")
    # Anchoring comes from fullmatch: a trailing newline never matches.
    assert not is_hard_excluded("git~1\n")
    assert not is_hard_excluded("node_m~1\n")


ADVERSARIAL = [
    "git~" + "1" * 100_000,
    "git~" + "1" * 100_000 + "x",
    "gi" + "a" * 100_000 + "~1",
    "node_m~" + "9" * 100_000 + "\n",
    "no" + "0" * 100_000,
    "~" * 100_000,
    ".git" + "." * 100_000 + "x",
    "\u200b" * 100_000 + ".git",
    ".git" + " ." * 50_000,
]


@pytest.mark.parametrize("text", ADVERSARIAL, ids=lambda t: f"{t[:6]!r}x{len(t)}")
def test_hard_exclude_regexes_and_check_are_linear(text: str) -> None:
    start = time.perf_counter()
    for pattern in d.REGEXES:
        pattern.fullmatch(text)
        pattern.search(text)
    is_hard_excluded(text)
    has_hard_excluded_component(f"{text}/{text}")
    assert time.perf_counter() - start < 2.0


# ---- reading a named path (config `paths:` entries, git-tree paths) ----------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n\tfsmonitor = evil\n")
    (tmp_path / "AGENTS.md").write_text("- Use httpx\n")
    return tmp_path


@pytest.mark.parametrize(
    "relpath", [".Git/config", ".git/config", "./.GIT/config", "x/../.git/config", "git~1/config"]
)
def test_paths_entry_naming_git_config_is_never_opened(
    repo: Path, relpath: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[object] = []
    real_open, real_lstat = os.open, os.lstat

    def spy_open(path: object, *a: object, **k: object) -> int:
        opened.append(path)
        return real_open(path, *a, **k)  # type: ignore[arg-type]

    def spy_lstat(path: object, *a: object, **k: object) -> os.stat_result:
        opened.append(path)
        return real_lstat(path, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "lstat", spy_lstat)
    try:
        got = read_unless_hard_excluded(repo, relpath, "config", origin="input")
    except FileSkipped as exc:  # ".." wins: "outside repository", still never opened
        assert relpath.startswith("x/..")
        assert exc.reason == "outside repository"
    else:
        assert got is None
    assert opened == []


def test_paths_entry_that_is_not_excluded_is_read(repo: Path) -> None:
    assert read_unless_hard_excluded(repo, "AGENTS.md", "instruction", origin="input") == (
        b"- Use httpx\n"
    )


def test_tree_origin_and_size_limit_pass_through(repo: Path) -> None:
    (repo / "big.md").write_bytes(b"x" * 2048)
    with pytest.raises(FileSkipped, match="size limit"):
        read_unless_hard_excluded(repo, "big.md", "instruction", origin="tree", max_file_bytes=1024)
    assert read_unless_hard_excluded(repo, "node_modules/x.py", "python", origin="tree") is None


def test_check_uses_only_the_relative_path_not_the_root(tmp_path: Path) -> None:
    # A checkout that itself lives under ".git" or "node_modules" is still read.
    root = tmp_path / "node_modules" / ".GIT" / "repo"
    root.mkdir(parents=True)
    (root / "AGENTS.md").write_text("- Use httpx\n")
    assert read_unless_hard_excluded(root, "AGENTS.md", "instruction", origin="tree")
    assert read_unless_hard_excluded(str(root), "AGENTS.md", "instruction", origin="input")


def test_no_dollar_anchor_in_safefs_source() -> None:
    src = Path(d.__file__).read_text(encoding="utf-8")
    for m in re.finditer(r're\.compile\((r?"[^"]*")', src):
        assert "$" not in m.group(1)
