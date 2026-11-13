"""T-010b unit tests: the I-5 hard-exclusion name check (SR N4 on T-009, SC-2.43).

D-TL-25: the positive and negative cases are generated from the code's own
constants (``_HARD_EXCLUDED_NAMES``, ``HARD_EXCLUDE_IGNORABLE``, the trailing
characters stripped and the short-name patterns in ``REGEXES``), and
``test_cases_cover_every_class`` fails if a class gains a member with no case.
"""

from __future__ import annotations

import os
import re
import time
import typing
from pathlib import Path

import pytest

import conventiondrift.discover.safefs as d
from conventiondrift.discover.safefs import (
    HARD_EXCLUDE_IGNORABLE,
    AlwaysExcluded,
    has_hard_excluded_component,
    is_hard_excluded,
    read_unless_hard_excluded,
)
from conventiondrift.errors import FileSkipped
from conventiondrift.model import SkippedFile

NAMES = sorted(d._HARD_EXCLUDED_NAMES)
IGNORABLE = sorted(HARD_EXCLUDE_IGNORABLE)
TRAILING = ". "  # I-5 step 2: NTFS drops trailing dots and spaces
# Short names per name, keyed like NAMES; each must fullmatch exactly one REGEXES entry.
SHORT = {
    ".git": ["git~1", "GIT~1", "git~12", "GI1A2B~1", "gi00ff~9", "GIT~1."],
    "node_modules": ["NODE_M~1", "node_m~12", "NO1A2B~3", "no00ff~9", "NODE_M~1 "],
}
SHORT_NEAR_MISS = {
    ".git": ["gitx~1", "git~0", "git~01", "git~", "git~1a", "gi1a2~1", "gi1a2b3~1", "gi1a2g~1"],
    "node_modules": ["node_m~0", "nodem~1", "no1a2~1", "node_mo~1", "no1a2b3~1", "xnode_m~1"],
}


def _case_variants(name: str) -> list[str]:
    return sorted({name.upper(), name.title(), name.swapcase(), name.capitalize()} - {name})


def _excluded_cases() -> list[str]:
    out: list[str] = []
    for name in NAMES:
        out.append(name)
        out += _case_variants(name)  # step 3
        out += [name + t for t in TRAILING] + [name + TRAILING * 3]  # step 2, repeated
        out += [name[:2] + ch + name[2:] for ch in IGNORABLE]  # step 1, every code point
        out += [ch + name.upper() + "." for ch in IGNORABLE[:1]]  # all three steps at once
        out.append(name + "." + IGNORABLE[0])  # ignorables go before the strip
        out += SHORT[name]
    out.append("node_module\u017f")  # casefold, not lower: U+017F folds to "s"
    return out


def _boundary_neighbours() -> list[str]:
    """Code points next to the ignorable set that are not in it."""
    cps = {ord(c) for c in HARD_EXCLUDE_IGNORABLE}
    return sorted(chr(n) for c in cps for n in (c - 1, c + 1) if n not in cps)


def _not_excluded_cases() -> list[str]:
    out: list[str] = ["", ".", "..", "git", ".gitignore", ".github", "..git", "x.git"]
    for name in NAMES:
        out += [
            name[:-1],
            name + "x",
            "x" + name,
            " " + name,
            name + "\n",
            name[:2] + " " + name[2:],
        ]
        out += [name[:2] + ch + name[2:] for ch in _boundary_neighbours()]
        out += SHORT_NEAR_MISS[name]
    return out


EXCLUDED = _excluded_cases()
NOT_EXCLUDED = _not_excluded_cases()


def test_cases_cover_every_class() -> None:
    assert set(NAMES) == {".git", "node_modules"} == set(SHORT) == set(SHORT_NEAR_MISS)
    for ch in HARD_EXCLUDE_IGNORABLE:
        assert any(ch in c for c in EXCLUDED), hex(ord(ch))
    for t in TRAILING:
        assert any(c.endswith(t) for c in EXCLUDED)
    shorts = [s.casefold().rstrip(TRAILING) for v in SHORT.values() for s in v]
    for pattern in d.REGEXES:  # each short-name pattern has plain and hashed positives
        assert sum(pattern.fullmatch(s) is not None for s in shorts) >= 4, pattern.pattern
        assert any(pattern.fullmatch(s) and s[2] in "0123456789abcdef" for s in shorts)
    assert len(_boundary_neighbours()) >= 2 * 8  # both edges of every range in the set
    assert not set(EXCLUDED) & set(NOT_EXCLUDED)


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
    # Bytes, not text: write_text would write CRLF on Windows (PR #23 windows-latest).
    (tmp_path / ".git" / "config").write_bytes(b"[core]\n\tfsmonitor = evil\n")
    (tmp_path / "AGENTS.md").write_bytes(b"- Use httpx\n")
    return tmp_path


NAMED = [f"{v}/config" for n in NAMES for v in [n, *_case_variants(n), *SHORT[n][:1]]]


def test_named_cases_include_the_tech_lead_case() -> None:
    assert ".Git/config" in NAMED
    assert set(NAMES) <= {r.split("/")[0] for r in NAMED}


@pytest.mark.parametrize("relpath", [*NAMED, "./.GIT/config", "x/../.git/config"], ids=ascii)
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
        assert isinstance(got, AlwaysExcluded)
    assert opened == []


def test_paths_entry_that_is_not_excluded_is_read(repo: Path) -> None:
    assert read_unless_hard_excluded(repo, "AGENTS.md", "instruction", origin="input") == (
        b"- Use httpx\n"
    )


def test_tree_origin_and_size_limit_pass_through(repo: Path) -> None:
    (repo / "big.md").write_bytes(b"x" * 2048)
    with pytest.raises(FileSkipped, match="size limit"):
        read_unless_hard_excluded(repo, "big.md", "instruction", origin="tree", max_file_bytes=1024)
    got = read_unless_hard_excluded(repo, "node_modules/x.py", "python", origin="tree")
    assert isinstance(got, AlwaysExcluded)
    assert got.path == "node_modules/x.py"


def test_check_uses_only_the_relative_path_not_the_root(tmp_path: Path) -> None:
    # A checkout that itself lives under ".git" or "node_modules" is still read.
    root = tmp_path / "node_modules" / ".GIT" / "repo"
    root.mkdir(parents=True)
    (root / "AGENTS.md").write_bytes(b"- Use httpx\n")
    assert read_unless_hard_excluded(root, "AGENTS.md", "instruction", origin="tree")
    assert read_unless_hard_excluded(str(root), "AGENTS.md", "instruction", origin="input")


def test_no_dollar_anchor_in_safefs_source() -> None:
    src = Path(d.__file__).read_text(encoding="utf-8")
    for m in re.finditer(r're\.compile\((r?"[^"]*")', src):
        assert "$" not in m.group(1)


# ---- I-13 ruling 1 / QA F3: the "`<path>` is always excluded" note --------------------


def test_paths_entry_note_comes_from_i13_text(repo: Path) -> None:
    """I-13 ruling 1: dropped with `` `<path>` is always excluded ``, never a SkippedFile."""
    relpath = ".git/config"
    got = read_unless_hard_excluded(repo, relpath, "config", origin="input")
    assert isinstance(got, AlwaysExcluded)
    # object: mypy proves the classes disjoint, but the test pins it at run time.
    assert not isinstance(typing.cast(object, got), (SkippedFile, FileSkipped))
    assert got.path == relpath
    # Expected wording is from I-13, not from AlwaysExcluded.note.
    assert got.note == "`" + relpath + "` is always excluded"


def test_paths_entry_note_uses_the_validated_path(repo: Path) -> None:
    got = read_unless_hard_excluded(repo, "./.GIT/config", "config", origin="input")
    assert isinstance(got, AlwaysExcluded)
    assert got.path == ".GIT/config"
    assert got.note == "`.GIT/config` is always excluded"


# ---- QA F5: casefold(), not lower(), per I-5 step 3 -----------------------------------


def test_casefold_not_lower_is_required_by_i5() -> None:
    """I-5 step 3 folds with ``str.casefold()``. U+017F (long s) casefolds to ``s``.

    ``node_module`` + U+017F therefore equals ``node_modules`` after casefold and is
    hard-excluded; ``str.lower()`` leaves U+017F in place and would miss it.
    """
    name = "node_module\u017f"
    assert name.casefold() == "node_modules"  # Unicode, not this module
    assert name.lower() != "node_modules"
    assert is_hard_excluded(name)
    # The I-5 step lives in the function body, not only in a docstring (a first-
    # occurrence replace of casefold() would otherwise hit the docstring and survive).
    import inspect

    body = inspect.getsource(is_hard_excluded).split('"""', 2)[-1]
    assert ".casefold()" in body
    assert ".lower()" not in body


# ---- SR L2: NTFS stream names are hard-excluded on every OS ---------------------------

# I-5 runs on the component after cutting at the first ':'.
STREAM_EXCLUDED = [
    ".git::$INDEX_ALLOCATION",
    ".git::$INDEX_ALLOCATION/config",
    ".GIT:stream",
    ".Git:stream/config",
    "node_modules:stream/x.py",
    "GIT~1::$DATA/config",
]
STREAM_NOT_EXCLUDED = [
    "file.py:stream",
    "gitx~1:x",
    "src/a.py::$DATA",
    "foo:bar",
]


@pytest.mark.parametrize("relpath", STREAM_EXCLUDED, ids=ascii)
def test_ntfs_stream_names_are_hard_excluded(relpath: str) -> None:
    assert has_hard_excluded_component(relpath)
    assert is_hard_excluded(relpath.split("/")[0])


@pytest.mark.parametrize("relpath", STREAM_NOT_EXCLUDED, ids=ascii)
def test_stream_suffix_does_not_exclude_an_ordinary_name(relpath: str) -> None:
    assert not has_hard_excluded_component(relpath)


def test_stream_named_read_is_never_opened(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    for relpath in (".git::$INDEX_ALLOCATION/config", ".GIT:stream"):
        # Tree names: on POSIX the I-5 match runs after cutting at ':'; on Windows
        # a tree name with ':' is already "unsupported path" (I-13) before the
        # match (SR L-B). Typed values with a ':' are "outside repository" (I-13)
        # everywhere. Either way the name is never opened or lstat-ed.
        tree_result = _tree_read_as(os.name, repo, relpath)
        if os.name == "nt":
            assert tree_result == "unsupported path"
        else:
            assert isinstance(tree_result, AlwaysExcluded)
            assert tree_result.note == "`" + relpath + "` is always excluded"
        with pytest.raises(FileSkipped) as exc:
            read_unless_hard_excluded(repo, relpath, "config", origin="input")
        assert exc.value.reason == "outside repository"
    assert opened == []


def _tree_read_as(name: str, repo: Path, relpath: str) -> AlwaysExcluded | str:
    """Read ``relpath`` as a tree name with ``os.name`` set to ``name`` only around the
    call (SR N-9: restored before any assert); a FileSkipped becomes its reason."""
    real = os.name
    os.name = name
    try:
        got = read_unless_hard_excluded(repo, relpath, "config", origin="tree")
    except FileSkipped as exc:
        return exc.reason
    finally:
        os.name = real
    assert isinstance(got, AlwaysExcluded)
    return got


@pytest.mark.parametrize("name", ["posix", "nt"])
def test_stream_named_tree_read_per_os_is_never_opened(
    name: str, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR L-B: both OS branches run on every runner. On "nt" the tree name is
    "unsupported path" (I-13); on "posix" it is AlwaysExcluded (I-5 after the ':' cut).
    Neither opens nor lstat-s anything."""
    touched: list[object] = []
    monkeypatch.setattr(os, "open", lambda p, *a, **k: touched.append(p))
    monkeypatch.setattr(os, "lstat", lambda p, *a, **k: touched.append(p))
    for relpath in (".git::$INDEX_ALLOCATION/config", ".GIT:stream"):
        got = _tree_read_as(name, repo, relpath)
        if name == "nt":
            assert got == "unsupported path"
        else:
            assert isinstance(got, AlwaysExcluded)
            assert got.note == "`" + relpath + "` is always excluded"
    assert touched == []


# ---- SR L1: the unguarded worktree read is private to safefs --------------------------


def test_unguarded_worktree_read_is_private_to_safefs() -> None:
    """Fail if any src module other than safefs references the unguarded read."""
    root = Path(d.__file__).resolve().parents[1]  # conventiondrift package
    pattern = re.compile(r"(?<![\w])_?read_worktree_file\b")
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "_vendor" in path.parts or path.name == "safefs.py":
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(path.as_posix())
    assert offenders == []
    src = Path(d.__file__).read_text(encoding="utf-8")
    assert re.search(r"^def _read_worktree_file\(", src, re.M)
    assert not re.search(r"^def read_worktree_file\(", src, re.M)
    assert "read_worktree_file" not in d.__all__
    assert hasattr(d, "_read_worktree_file")
    assert not hasattr(d, "read_worktree_file")
