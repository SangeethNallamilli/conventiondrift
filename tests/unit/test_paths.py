"""T-009 unit tests: repo-root containment on path strings (R2.1, AC-N3.8)."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from conventiondrift.discover import REASON_OUTSIDE, read_worktree_file, validate_relpath
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
def test_ac_n3_8_reject(value: str, tmp_path: Path, opened: list[object]) -> None:
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value)
    assert exc.value.reason == REASON_OUTSIDE
    with pytest.raises(FileSkipped) as exc2:
        read_worktree_file(tmp_path, value, "config")
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
        "\\\\server\\share",
        "a\\b.py",
        "c:/x.py",
        "Z:x",
        "a:b.py",  # single letter + ':' is a drive-relative path on Windows (open question)
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
        (
            "ab:c.py",
            "ab:c.py",
        ),  # ':' in names is legal (AC-N3.13); only `X:` drive prefixes are not
        ("src/a:b.py", "src/a:b.py"),  # a drive prefix only matters on the first segment
        ("..foo/bar..", "..foo/bar.."),  # dots inside a name are not a `..` segment
        ("src/@someone/<b>x</b>.py", "src/@someone/<b>x</b>.py"),
        ("ünïcode/ファイル.py", "ünïcode/ファイル.py"),
    ],
)
def test_accept_and_normalize(value: str, expected: str) -> None:
    assert validate_relpath(value) == expected
