"""T-009 unit tests: repo-root containment on path strings (R2.1, AC-N3.8)."""

from __future__ import annotations

import contextlib
import ntpath
import os
import sys
import typing
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import conventiondrift.discover.safefs as safefs
from conventiondrift.discover.safefs import (
    REASON_OUTSIDE,
    REASON_UNSUPPORTED,
    PathOrigin,
    _read_worktree_file,
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
        _read_worktree_file(tmp_path, value, "config", origin="input")
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


# The Python 3.13 ``ntpath._reserved_names`` set, written out (SR N2, I-13).
PY313_DEVICE_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{c}" for c in "123456789\u00b9\u00b2\u00b3"]
    + [f"LPT{c}" for c in "123456789\u00b9\u00b2\u00b3"]
)


def _case_variants(name: str) -> tuple[str, ...]:
    """Upper, lower, title and mixed case (D-TL-25): matching must ignore case."""
    return tuple(dict.fromkeys((name, name.lower(), name.title(), name.title().swapcase())))


# D-TL-25: every reserved name in every case variant, bare and with extensions or a
# trailing-space stem, as a later segment, and as a folder. Built from the spec set
# above; test_device_names_match_python_313 ties that set to the code's.
DEVICE_NEGATIVES = [
    *(v for n in sorted(PY313_DEVICE_NAMES) for v in _case_variants(n)),
    *(
        form
        for n in sorted(PY313_DEVICE_NAMES)
        for form in (f"{n.lower()}.py", f"{n}.tar.gz", f"src/{n.title()} .log", f"{n}/x.py")
    ),
]


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
    # reserved device names: hand-picked shapes, then the full set (D-TL-25)
    "nul.txt",
    "Com1.py",
    "lPt9.tar.gz",
    "src/CON",
    "src/aux.py",
    "con/x.py",
    "a/nul.d/b.py",
    "NUL .txt",  # Windows ignores the trailing space before the extension
    "src/c:x/nul.py",  # a device name still wins on POSIX next to a ':'
    *DEVICE_NEGATIVES,
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
def os_name(request: pytest.FixtureRequest) -> str:
    """Run a validate_relpath test as if on POSIX and as if on Windows.

    The fixture only names the OS; :func:`_as_os` patches ``os.name`` around the
    call under test.
    """
    return str(request.param)


@contextlib.contextmanager
def _as_os(name: str) -> Iterator[None]:
    """Patch ``os.name`` only around the call under test, restoring it before any assert.

    On Python 3.11, a concrete ``Path`` built while ``os.name`` is patched (pytest
    builds them while reporting a failure) crashes the run with INTERNALERROR. So
    nothing here builds a Path, and a failing assert always runs with the real name.
    """
    real = os.name
    os.name = name
    try:
        yield
    finally:
        os.name = real


def _reason_as(name: str, fn: Callable[..., object], *args: object, **kw: object) -> str | None:
    """Call ``fn`` with ``os.name`` patched; return the skip reason, or None if it passed."""
    with _as_os(name):
        try:
            fn(*args, **kw)
        except FileSkipped as exc:
            return exc.reason
    return None


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY + COLON_VALUES)
def test_windows_only_typed_value_is_outside_repository_on_every_os(
    value: str, os_name: str
) -> None:
    """A value the user typed keeps AC-N3.8's reason on every OS (D-PM-28)."""
    assert _reason_as(os_name, validate_relpath, value, origin="input") == REASON_OUTSIDE


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY)
def test_windows_only_tree_name_is_unsupported_on_every_os(value: str, os_name: str) -> None:
    """Backslash, trailing dot or space, and device names in the tree (D-PM-28, I-13)."""
    assert _reason_as(os_name, validate_relpath, value, origin="tree") == REASON_UNSUPPORTED


@pytest.mark.parametrize("value", COLON_VALUES)
def test_colon_tree_name_is_unsupported_on_windows(value: str) -> None:
    assert _reason_as("nt", validate_relpath, value, origin="tree") == REASON_UNSUPPORTED


@pytest.mark.parametrize(("value", "expected"), COLON_FORMS)
def test_colon_tree_name_is_analyzed_on_posix(value: str, expected: str) -> None:
    """On Linux and macOS a ':' is an ordinary name character (D-PM-28 narrowed, AC-N3.13)."""
    with _as_os("posix"):
        got = validate_relpath(value, origin="tree")
    assert got == expected


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY + COLON_VALUES)
def test_read_rejects_typed_windows_only_value(value: str) -> None:
    with pytest.raises(FileSkipped) as exc:
        _read_worktree_file("/nonexistent", value, "python", origin="input")
    assert exc.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize("value", ALWAYS_WINDOWS_ONLY)
def test_read_skips_windows_only_tree_name(value: str) -> None:
    with pytest.raises(FileSkipped) as exc:
        _read_worktree_file("/nonexistent", value, "python", origin="tree")
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
        _read_worktree_file(tmp_path, "a\\b.py", "python", origin="tree")
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
            _read_worktree_file(tmp_path, f"src/{name}", "python", origin=origin)
        assert exc.value.reason == expected
    assert opened == [], "nothing may be opened for a rejected path"


@pytest.mark.skipif(os.name == "nt", reason="':' cannot appear in a Windows file name")
@pytest.mark.parametrize("name", ["c:x.py", "x.py:s", "::warning::%0A.py"])
def test_read_colon_tree_name_on_posix(tmp_path: Path, opened: list[object], name: str) -> None:
    """``src/c:x.py`` is a normal file on POSIX: read for a tree name, refused when typed."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / name).write_bytes(b"x = 1\n")
    assert _read_worktree_file(tmp_path, f"src/{name}", "python", origin="tree") == b"x = 1\n"
    opened.clear()
    with pytest.raises(FileSkipped) as exc:
        _read_worktree_file(tmp_path, f"src/{name}", "python", origin="input")
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
    assert _reason_as(os_name, validate_relpath, value, origin=origin) == expected
    # Never a UnicodeEncodeError: it would propagate out of _reason_as and fail the test.
    got = _reason_as(os_name, _read_worktree_file, "/nonexistent", value, "python", origin=origin)
    assert got == expected
    assert opened == [], "nothing may be opened for a rejected path"


def test_every_surrogate_code_point_is_rejected() -> None:
    """D-TL-25: the whole U+D800..U+DFFF range, alone and inside a name, both origins."""
    for cp in range(0xD800, 0xE000):
        for value in (chr(cp), f"src/a{chr(cp)}b.py"):
            with pytest.raises(FileSkipped) as exc:
                validate_relpath(value, origin="tree")
            assert exc.value.reason == REASON_UNSUPPORTED
            with pytest.raises(FileSkipped) as exc2:
                validate_relpath(value, origin="input")
            assert exc2.value.reason == REASON_OUTSIDE


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
        _read_worktree_file(tmp_path, name, "python", origin="tree")
    assert exc.value.reason == REASON_UNSUPPORTED
    assert opened == [], "nothing may be opened for a rejected path"


def test_device_names_match_python_313() -> None:
    assert len(PY313_DEVICE_NAMES) == 30
    assert safefs._DEVICE_NAMES == PY313_DEVICE_NAMES
    if sys.version_info >= (3, 13):  # the stdlib's own set, where it exists
        assert ntpath._reserved_names == PY313_DEVICE_NAMES  # type: ignore[attr-defined]


def test_device_negatives_cover_every_reserved_name_and_case() -> None:
    """D-TL-25: the negative parameters cover the whole set, in every case variant."""
    for name in PY313_DEVICE_NAMES:
        for variant in _case_variants(name):
            assert variant in ALWAYS_WINDOWS_ONLY, variant
        assert any(v.startswith(f"{name.lower()}.") for v in ALWAYS_WINDOWS_ONLY), name
    assert {v.upper() for v in _case_variants("conin$")} == {"CONIN$"}


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
        got = _reason_as(os_name, validate_relpath, name, origin="tree")
        assert got == (REASON_UNSUPPORTED if reserved else None), name


# ---- CR2 S4: an origin outside Literal["input", "tree"] gets the strict branch ---------

UNKNOWN_ORIGINS: list[object] = ["TREE", "Tree", "inputs", "", None, "tree ", 0]


def test_unknown_origins_are_outside_the_literal() -> None:
    """D-TL-25: the bad origins are built against PathOrigin itself, case variants included."""
    valid = set(typing.get_args(PathOrigin))
    assert valid == {"input", "tree"}
    assert not valid & set(UNKNOWN_ORIGINS)
    assert {"TREE", "Tree"} <= set(UNKNOWN_ORIGINS)  # case variants of "tree"


@pytest.mark.parametrize("origin", UNKNOWN_ORIGINS)
@pytest.mark.parametrize(
    "value", ["c:x.py", "src/a.py:stream", "a\\b.py", "nul.txt", "a\udc80.py", "src/a.py."]
)
def test_unknown_origin_is_treated_as_typed(
    origin: object, value: str, opened: list[object]
) -> None:
    # Simulated POSIX, where a tree name with ':' would be accepted.
    assert _reason_as("posix", validate_relpath, value, origin=origin) == REASON_OUTSIDE
    got = _reason_as("posix", _read_worktree_file, "/nonexistent", value, "python", origin=origin)
    assert got == REASON_OUTSIDE
    assert opened == [], "nothing may be opened for a rejected path"


@pytest.mark.parametrize("origin", UNKNOWN_ORIGINS)
def test_unknown_origin_name_too_long_is_outside_repository(origin: object, tmp_path: Path) -> None:
    with pytest.raises(FileSkipped) as exc:
        _read_worktree_file(tmp_path, "n" * 5000 + ".py", "python", origin=origin)  # type: ignore[arg-type]
    assert exc.value.reason == REASON_OUTSIDE


@pytest.mark.parametrize("origin", UNKNOWN_ORIGINS)
def test_unknown_origin_still_accepts_ordinary_names(origin: object) -> None:
    assert validate_relpath("./src/a.py", origin=origin) == "src/a.py"  # type: ignore[arg-type]


# ---- CR2 S3: real Windows behaviour, unskipped on the windows-latest leg -------------
# Real NTFS streams and real device names under the real ``os.name == "nt"``: nothing
# is patched. Each body sits under a ``sys.platform`` check so mypy checks it as
# Windows code (``mypy --platform win32``).

windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="real Windows behaviour; runs on windows-latest (CR2 S3)"
)


@windows_only
def test_windows_real_alternate_data_stream_is_never_opened(
    tmp_path: Path, opened: list[object]
) -> None:
    if sys.platform == "win32":  # mypy checks this block as Windows code
        assert os.name == "nt"
        main = tmp_path / "a.py"
        main.write_bytes(b"x = 1\n")
        with open(f"{main}:s", "wb") as h:  # a real NTFS alternate data stream
            h.write(b"secret = 1\n")
        with open(f"{main}:s", "rb") as h:
            assert h.read() == b"secret = 1\n", "the stream exists and is readable"
        assert main.read_bytes() == b"x = 1\n", "the main stream is untouched"
        opened.clear()
        for name in ("a.py:s", "a.py:s:$DATA", "a.py::$DATA", "c:a.py", "./a.py:s"):
            with pytest.raises(FileSkipped) as exc:
                _read_worktree_file(tmp_path, name, "python", origin="tree")
            assert exc.value.reason == REASON_UNSUPPORTED, name
            with pytest.raises(FileSkipped) as exc2:
                _read_worktree_file(tmp_path, name, "python", origin="input")
            assert exc2.value.reason == REASON_OUTSIDE, name
        assert opened == [], "no stream (or drive-relative path) may be opened"
        assert _read_worktree_file(tmp_path, "a.py", "python", origin="tree") == b"x = 1\n"
    else:  # the skipif keeps other platforms out
        pytest.fail("Windows-only")


# D-TL-25: every reserved name in every case, plus hand-picked shapes.
WINDOWS_DEVICE_PATHS = [
    *DEVICE_NEGATIVES,
    "NUL .txt",
    "src/NUL",
    "src/CONIN$",
    "src/con/x.py",
]


@windows_only
def test_windows_real_device_names_are_never_opened(tmp_path: Path, opened: list[object]) -> None:
    if sys.platform == "win32":  # mypy checks this block as Windows code
        assert os.name == "nt"
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "ok.py").write_bytes(b"x = 1\n")
        opened.clear()
        for name in WINDOWS_DEVICE_PATHS:
            with pytest.raises(FileSkipped) as exc:
                _read_worktree_file(tmp_path, name, "python", origin="tree")
            assert exc.value.reason == REASON_UNSUPPORTED, name
            with pytest.raises(FileSkipped) as exc2:
                _read_worktree_file(tmp_path, name, "config", origin="input")
            assert exc2.value.reason == REASON_OUTSIDE, name
        assert opened == [], "no device may be opened"
        # The folder itself is readable, so the refusals above come from the name check.
        assert _read_worktree_file(tmp_path, "src/ok.py", "python", origin="tree") == b"x = 1\n"
    else:  # the skipif keeps other platforms out
        pytest.fail("Windows-only")
