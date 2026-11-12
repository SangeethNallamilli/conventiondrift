"""T-009 unit tests: repo-root containment on path strings (R2.1, AC-N3.8)."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from conventiondrift.discover.safefs import (
    REASON_OUTSIDE,
    REASON_UNSUPPORTED,
    PathOrigin,
    read_worktree_file,
    validate_relpath,
)
from conventiondrift.errors import FileSkipped

# The AC-N3.8 values, one per bullet (TRACEABILITY row AC-N3.8). For the
# `ignore` and `exclude` bullets the value checked is the path entry itself.
AC_N3_8_VALUES = {
    "../../etc/passwd": "../../etc/passwd",
    "../outside.yml": "../outside.yml",
    "/etc/hostname": "/etc/hostname",
    "..\\outside.yml": "..\\outside.yml",
    "C:\\outside.yml": "C:\\outside.yml",
    "ignore ../outside.md": "../outside.md",
    "exclude /etc/**": "/etc/**",
}

_opened: list[object] | None = None


def _audit(event: str, args: tuple[object, ...]) -> None:
    if _opened is not None and event == "open":
        _opened.append(args[0])


sys.addaudithook(_audit)


@pytest.fixture
def opened() -> Iterator[list[object]]:
    global _opened
    _opened = []
    try:
        yield _opened
    finally:
        _opened = None


@pytest.mark.parametrize("value", list(AC_N3_8_VALUES.values()), ids=list(AC_N3_8_VALUES))
def test_validate_relpath_rejects(value: str, tmp_path: Path, opened: list[object]) -> None:
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value)
    assert exc.value.reason == REASON_OUTSIDE
    with pytest.raises(FileSkipped) as exc2:
        read_worktree_file(tmp_path, value, "config", origin="input")
    assert exc2.value.reason == REASON_OUTSIDE
    assert opened == [], "nothing may be opened for a rejected path"


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "./",
        "//",
        "a/../b",
        "a/..",
        "..",
        "/",
        "//server/share",
        "a\x00b",
    ],
)
def test_reject_edge_forms(value: str) -> None:
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value)
    assert exc.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AGENTS.md", "AGENTS.md"),
        ("./AGENTS.md", "AGENTS.md"),
        ("src//pkg/./mod.py", "src/pkg/mod.py"),
        ("docs/", "docs"),
        ("legacy/**", "legacy/**"),
        ("..foo/b..ar", "..foo/b..ar"),  # dots inside a name are not a `..` segment
        (".hidden/.x", ".hidden/.x"),
        ("console.py", "console.py"),  # starts like CON, but is not a device name
        ("com10.py", "com10.py"),  # only COM1-COM9 are reserved
        ("lpt0/x.py", "lpt0/x.py"),
        ("connul/auxprn.py", "connul/auxprn.py"),
        ("a b/c d.py", "a b/c d.py"),  # inner spaces are fine, only a trailing one is not
        ("src/@someone/<b>x</b>.py", "src/@someone/<b>x</b>.py"),
        ("ünïcode/ファイル.py", "ünïcode/ファイル.py"),
    ],
)
def test_accept_and_normalize(value: str, expected: str) -> None:
    assert validate_relpath(value) == expected


BACKSLASH_OR_DRIVE = [
    "\\\\server\\share",
    "a\\b.py",
    "src\\pkg\\m.py",
    "src/a\\b.py",
    "c:/x.py",
    "Z:x",
    "a:b.py",  # single letter + ':' is a drive-relative path on Windows
    "c:x.py",
    # D-PM-28 #5 (SR-012 F5): every segment, not just the first.
    "src/c:x.py",
    "src/pkg/c:x.py",
    "ab:c.py",
    "src/a:b.py",
    "a.py:stream",  # NTFS alternate data stream
    "src/a.py::$DATA",
    "dir:x/a.py",
    # trailing dot or space, in any segment
    "a.",
    "a.py.",
    "src./a.py",
    "src/...",
    "a ",
    "src /a.py",
    "src/a.py ",
    # reserved device names, any case, with or without an extension, any segment
    *[
        n
        for d in ("CON", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9")
        for n in (d, d.lower())
    ],
    "nul.txt",
    "Com1.py",
    "lPt9.tar.gz",
    "src/CON",
    "src/aux.py",
    "con/x.py",
    "a/nul.d/b.py",
    "NUL .txt",  # Windows ignores the trailing space before the extension
]


@pytest.mark.parametrize("value", BACKSLASH_OR_DRIVE)
def test_backslash_or_drive_typed_value_is_outside_repository(value: str) -> None:
    """A value the user typed keeps AC-N3.8's reason (D-PM-28)."""
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value)
    assert exc.value.reason == REASON_OUTSIDE
    with pytest.raises(FileSkipped) as exc2:
        validate_relpath(value, "input")
    assert exc2.value.reason == REASON_OUTSIDE
    with pytest.raises(FileSkipped) as exc3:
        read_worktree_file(Path("/nonexistent"), value, "python", origin="input")
    assert exc3.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize("value", BACKSLASH_OR_DRIVE)
def test_backslash_or_drive_tree_name_is_unsupported_path(value: str) -> None:
    """A name found in the repo tree gets "unsupported path" (D-PM-28, I-13)."""
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, "tree")
    assert exc.value.reason == REASON_UNSUPPORTED
    with pytest.raises(FileSkipped) as exc2:
        read_worktree_file(Path("/nonexistent"), value, "python", origin="tree")
    assert exc2.value.reason == REASON_UNSUPPORTED


@pytest.mark.parametrize(
    "value",
    ["../a\\b.py", "../CON", "/src/c:x.py", "a/../nul", "/c:x.py", "a/../c:x.py", "a\\b\x00.py"],
)
def test_traversal_wins_over_unsupported_for_tree_names(value: str) -> None:
    """Traversal, absolute and NUL forms stay "outside repository" from any origin."""
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, "tree")
    assert exc.value.reason == REASON_OUTSIDE


def test_tree_origin_accepts_ordinary_names() -> None:
    assert validate_relpath("src/ab.py", "tree") == "src/ab.py"
    assert validate_relpath("./con_sole/x.py", "tree") == "con_sole/x.py"
    assert validate_relpath("src/./a.py", "tree") == "src/a.py"  # "." keeps its handling


def test_read_tree_name_with_backslash_is_unsupported(tmp_path: Path, opened: list[object]) -> None:
    (tmp_path / "a\\b.py").write_bytes(b"x = 1\n")
    opened.clear()
    with pytest.raises(FileSkipped) as exc:
        read_worktree_file(tmp_path, "a\\b.py", "python", origin="tree")
    assert exc.value.reason == REASON_UNSUPPORTED
    assert opened == [], "nothing may be opened for a rejected path"


@pytest.mark.parametrize("name", ["c:x.py", "nul.py", "a.py.", "x.py:s"])
def test_read_tree_name_in_later_segment_is_unsupported(
    tmp_path: Path, opened: list[object], name: str
) -> None:
    """``src/c:x.py`` and friends are caught past the first segment (D-PM-28 #5)."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / name).write_bytes(b"x = 1\n")
    opened.clear()
    cases: tuple[tuple[PathOrigin, str], ...] = (
        ("tree", REASON_UNSUPPORTED),
        ("input", REASON_OUTSIDE),
    )
    for origin, expected in cases:
        with pytest.raises(FileSkipped) as exc:
            read_worktree_file(tmp_path, f"src/{name}", "python", origin=origin)
        assert exc.value.reason == expected
    assert opened == [], "nothing may be opened for a rejected path"
