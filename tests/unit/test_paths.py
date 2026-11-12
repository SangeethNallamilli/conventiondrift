"""T-009 unit tests: repo-root containment on path strings (R2.1, AC-N3.8)."""

from __future__ import annotations

import os
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
        validate_relpath(value, origin="input")
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
@pytest.mark.parametrize("origin", ["input", "tree"])
def test_reject_edge_forms(value: str, origin: PathOrigin) -> None:
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin=origin)
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
@pytest.mark.parametrize("origin", ["input", "tree"])
def test_accept_and_normalize(value: str, expected: str, origin: PathOrigin) -> None:
    assert validate_relpath(value, origin=origin) == expected


# Skipped or rejected on every OS, for both origins (D-PM-28 #5 as narrowed, I-13).
ALWAYS_WINDOWS_ONLY = [
    "\\\\server\\share",
    "a\\b.py",
    "src\\pkg\\m.py",
    "src/a\\b.py",
    # trailing dot or space, in any segment
    "a.",
    "a.py.",
    "src./a.py",
    "src/...",
    "..foo/bar..",
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
    "src/c:x/nul.py",  # a device name still wins on POSIX next to a ':'
]

# A ':' in any segment: always rejected when typed; for a tree name, only on Windows.
COLON_FORMS = [
    ("c:/x.py", "c:/x.py"),
    ("Z:x", "Z:x"),
    ("a:b.py", "a:b.py"),  # single letter + ':' is a drive-relative path on Windows
    ("c:x.py", "c:x.py"),
    ("src/c:x.py", "src/c:x.py"),
    ("src/pkg/c:x.py", "src/pkg/c:x.py"),
    ("ab:c.py", "ab:c.py"),
    ("./src/a:b.py", "src/a:b.py"),
    ("a.py:stream", "a.py:stream"),  # NTFS alternate data stream
    ("src/a.py::$DATA", "src/a.py::$DATA"),
    ("dir:x/a.py", "dir:x/a.py"),
    ("src/::warning::%0A.py", "src/::warning::%0A.py"),  # the AC-N3.13 causing file
]
COLON_VALUES = [v for v, _ in COLON_FORMS]


@pytest.fixture(params=["posix", "nt"])
def os_name(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Run a validate_relpath test as if on POSIX and as if on Windows.

    Only pure string checks run under the patched name (no Path objects or file system).
    """
    monkeypatch.setattr(os, "name", request.param)
    return str(request.param)


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY + COLON_VALUES)
def test_windows_only_typed_value_is_outside_repository_on_every_os(
    value: str, os_name: str
) -> None:
    """A value the user typed keeps AC-N3.8's reason on every OS (D-PM-28)."""
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin="input")
    assert exc.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY)
def test_windows_only_tree_name_is_unsupported_on_every_os(value: str, os_name: str) -> None:
    """Backslash, trailing dot or space, and device names in the tree (D-PM-28, I-13)."""
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin="tree")
    assert exc.value.reason == REASON_UNSUPPORTED


@pytest.mark.parametrize("value", COLON_VALUES)
def test_colon_tree_name_is_unsupported_on_windows(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin="tree")
    assert exc.value.reason == REASON_UNSUPPORTED


@pytest.mark.parametrize(("value", "expected"), COLON_FORMS)
def test_colon_tree_name_is_analyzed_on_posix(
    value: str, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Linux and macOS a ':' is an ordinary name character (D-PM-28 narrowed, AC-N3.13)."""
    monkeypatch.setattr(os, "name", "posix")
    assert validate_relpath(value, origin="tree") == expected


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY + COLON_VALUES)
def test_read_rejects_typed_windows_only_value(value: str) -> None:
    with pytest.raises(FileSkipped) as exc:
        read_worktree_file("/nonexistent", value, "python", origin="input")
    assert exc.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY)
def test_read_skips_windows_only_tree_name(value: str) -> None:
    with pytest.raises(FileSkipped) as exc:
        read_worktree_file("/nonexistent", value, "python", origin="tree")
    assert exc.value.reason == REASON_UNSUPPORTED


@pytest.mark.parametrize(
    "value",
    ["../a\\b.py", "../CON", "/src/c:x.py", "a/../nul", "/c:x.py", "a/../c:x.py", "a\\b\x00.py"],
)
def test_traversal_wins_over_unsupported_for_tree_names(value: str) -> None:
    """Traversal, absolute and NUL forms stay "outside repository" from any origin."""
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin="tree")
    assert exc.value.reason == REASON_OUTSIDE


def test_tree_origin_accepts_ordinary_names() -> None:
    assert validate_relpath("src/ab.py", origin="tree") == "src/ab.py"
    assert validate_relpath("./con_sole/x.py", origin="tree") == "con_sole/x.py"
    assert validate_relpath("src/./a.py", origin="tree") == "src/a.py"  # "." keeps its handling


def test_origin_is_a_required_keyword() -> None:
    """Every caller must say where the path came from (D-PM-28, CR suggestion)."""
    with pytest.raises(TypeError):
        validate_relpath("a.py")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        validate_relpath("a.py", "tree")  # type: ignore[call-arg]


def test_read_tree_name_with_backslash_is_unsupported(tmp_path: Path, opened: list[object]) -> None:
    (tmp_path / "a\\b.py").write_bytes(b"x = 1\n")
    opened.clear()
    with pytest.raises(FileSkipped) as exc:
        read_worktree_file(tmp_path, "a\\b.py", "python", origin="tree")
    assert exc.value.reason == REASON_UNSUPPORTED
    assert opened == [], "nothing may be opened for a rejected path"


@pytest.mark.parametrize("name", ["nul.py", "a.py.", "a.py ", "Com1.py"])
def test_read_tree_name_in_later_segment_is_unsupported(
    tmp_path: Path, opened: list[object], name: str
) -> None:
    """Device names and trailing dots/spaces are caught past the first segment (D-PM-28 #5)."""
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


@pytest.mark.skipif(os.name == "nt", reason="':' cannot appear in a Windows file name")
@pytest.mark.parametrize("name", ["c:x.py", "x.py:s", "::warning::%0A.py"])
def test_read_colon_tree_name_on_posix(tmp_path: Path, opened: list[object], name: str) -> None:
    """``src/c:x.py`` is a normal file on POSIX: read for a tree name, refused when typed."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / name).write_bytes(b"x = 1\n")
    assert read_worktree_file(tmp_path, f"src/{name}", "python", origin="tree") == b"x = 1\n"
    opened.clear()
    with pytest.raises(FileSkipped) as exc:
        read_worktree_file(tmp_path, f"src/{name}", "python", origin="input")
    assert exc.value.reason == REASON_OUTSIDE
    assert opened == [], "nothing may be opened for a rejected path"
