"""T-009 unit tests: repo-root containment on path strings (R2.1, AC-N3.8)."""

from __future__ import annotations

import ntpath
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import conventiondrift.discover.safefs as safefs
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
        ("com0.py", "com0.py"),
        ("COM\u2074.py", "COM\u2074.py"),  # superscript 4: only 1-3 are reserved
        ("lpt\u2070", "lpt\u2070"),  # superscript 0
        ("conin.py", "conin.py"),  # CONIN$ needs the '$'
        ("CONIN$$.py", "CONIN$$.py"),
        ("conout$x/a.py", "conout$x/a.py"),
        ("$conin$.py", "$conin$.py"),
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
    # SR N2 (I-13): the rest of the Python 3.13 set, any case, with an extension
    *[
        n
        for d in (
            "CONIN$",
            "CONOUT$",
            *(f"{p}{c}" for p in ("COM", "LPT") for c in "\u00b9\u00b2\u00b3"),
        )
        for n in (d, d.lower(), d.title(), f"{d.lower()}.py", f"src/{d} .log", f"{d}.tar.gz")
    ],
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


# ---- SR N1 on T-009 (I-13): lone surrogates are rejected before any encoding ----------

LONE_SURROGATES = [
    "a\ud800.py",  # first surrogate
    "x/\udfff/y.py",  # last surrogate, in a folder segment
    "a\udc80.py",  # what surrogateescape (os.fsdecode) makes of the byte 0x80
    "src/caf\udce9.py",  # ... and of a Latin-1 0xE9
    "\udbff",  # a high surrogate alone as the whole name
    "\ud83d\ude00.py",  # a UTF-16 pair stays two lone code points in a Python str
]


@pytest.mark.parametrize("value", LONE_SURROGATES)
@pytest.mark.parametrize(
    ("origin", "expected"), [("tree", REASON_UNSUPPORTED), ("input", REASON_OUTSIDE)]
)
def test_lone_surrogate_split_by_origin(
    value: str, origin: PathOrigin, expected: str, os_name: str, opened: list[object]
) -> None:
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin=origin)
    assert exc.value.reason == expected
    with pytest.raises(FileSkipped) as exc2:  # never a UnicodeEncodeError
        read_worktree_file("/nonexistent", value, "python", origin=origin)
    assert exc2.value.reason == expected
    assert opened == [], "nothing may be opened for a rejected path"


@pytest.mark.parametrize("value", ["../\ud800.py", "/\udc80", "a\udc80\x00"])
def test_traversal_wins_over_lone_surrogate(value: str) -> None:
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin="tree")
    assert exc.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize("value", ["a\ud7ff.py", "a\ue000.py", "\U0001f600.py", "caf\xe9.py"])
@pytest.mark.parametrize("origin", ["input", "tree"])
def test_code_points_next_to_the_surrogate_range_are_fine(value: str, origin: PathOrigin) -> None:
    assert validate_relpath(value, origin=origin) == value


@pytest.mark.skipif(
    sys.platform != "linux", reason="needs a file system that takes non-UTF-8 names"
)
def test_real_non_utf8_tree_name_is_unsupported(tmp_path: Path, opened: list[object]) -> None:
    """A real file named with the byte 0xFF is listed as ``\\udcff`` and never opened."""
    fd = os.open(os.fsencode(tmp_path) + b"/a\xff.py", os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"x = 1\n")
    os.close(fd)
    (name,) = os.listdir(tmp_path)
    assert name == "a\udcff.py"
    opened.clear()
    with pytest.raises(FileSkipped) as exc:
        read_worktree_file(tmp_path, name, "python", origin="tree")
    assert exc.value.reason == REASON_UNSUPPORTED
    assert opened == [], "nothing may be opened for a rejected path"


# The Python 3.13 ``ntpath._reserved_names`` set, written out (SR N2, I-13).
PY313_DEVICE_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{c}" for c in "123456789\u00b9\u00b2\u00b3"]
    + [f"LPT{c}" for c in "123456789\u00b9\u00b2\u00b3"]
)


def test_device_names_match_python_313() -> None:
    assert len(PY313_DEVICE_NAMES) == 30
    assert safefs._DEVICE_NAMES == PY313_DEVICE_NAMES
    if sys.version_info >= (3, 13):  # the stdlib's own set, where it exists
        assert ntpath._reserved_names == PY313_DEVICE_NAMES  # type: ignore[attr-defined]


DEVICE_PROBES = [
    f"{stem}{tail}"
    for stem in (
        *PY313_DEVICE_NAMES,
        *(n.lower() for n in PY313_DEVICE_NAMES),
        "COM0",
        "COM10",
        "COM\u2074",
        "LPT\u2070",
        "CONIN",
        "CONOUT",
        "CONIN$$",
        "XCON",
        "CONX",
        "console",
    )
    for tail in ("", ".py", ".tar.gz", " .txt", "  .x", ".")
]


@pytest.mark.skipif(not hasattr(ntpath, "isreserved"), reason="ntpath.isreserved is 3.13+")
def test_tree_name_agrees_with_ntpath_isreserved(os_name: str) -> None:
    """Our device-name and trailing-dot checks say what Python 3.13's ``isreserved`` says."""
    for name in DEVICE_PROBES:
        reserved: bool = ntpath.isreserved(name)  # type: ignore[attr-defined,unused-ignore]
        try:
            validate_relpath(name, origin="tree")
        except FileSkipped as exc:
            assert exc.reason == REASON_UNSUPPORTED
            assert reserved, name
        else:
            assert not reserved, name


# ---- CR2 S4: an origin outside Literal["input", "tree"] gets the strict branch ---------

UNKNOWN_ORIGINS: list[object] = ["TREE", "Tree", "inputs", "", None, "tree ", 0]


@pytest.mark.parametrize("origin", UNKNOWN_ORIGINS)
@pytest.mark.parametrize(
    "value", ["c:x.py", "src/a.py:stream", "a\\b.py", "nul.txt", "a\udc80.py", "src/a.py."]
)
def test_unknown_origin_is_treated_as_typed(
    origin: object, value: str, monkeypatch: pytest.MonkeyPatch, opened: list[object]
) -> None:
    monkeypatch.setattr(os, "name", "posix")  # where a tree name with ':' would be accepted
    with pytest.raises(FileSkipped) as exc:
        validate_relpath(value, origin=origin)  # type: ignore[arg-type]
    assert exc.value.reason == REASON_OUTSIDE
    with pytest.raises(FileSkipped) as exc2:
        read_worktree_file("/nonexistent", value, "python", origin=origin)  # type: ignore[arg-type]
    assert exc2.value.reason == REASON_OUTSIDE
    assert opened == [], "nothing may be opened for a rejected path"


@pytest.mark.parametrize("origin", UNKNOWN_ORIGINS)
def test_unknown_origin_name_too_long_is_outside_repository(origin: object, tmp_path: Path) -> None:
    with pytest.raises(FileSkipped) as exc:
        read_worktree_file(tmp_path, "n" * 5000 + ".py", "python", origin=origin)  # type: ignore[arg-type]
    assert exc.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize("origin", UNKNOWN_ORIGINS)
def test_unknown_origin_still_accepts_ordinary_names(origin: object) -> None:
    assert validate_relpath("./src/a.py", origin=origin) == "src/a.py"  # type: ignore[arg-type]
