"""T-010a unit tests: the linear-time gitignore-style matcher (DESIGN §12 A-3 condition 4)."""

from __future__ import annotations

import random
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from conventiondrift.discover import globmatch
from conventiondrift.discover.globmatch import GlobSet, compile_glob


def hit(pattern: str, path: str, *, is_dir: bool = False) -> bool:
    return compile_glob(pattern).match(path, is_dir)


@pytest.mark.parametrize(
    ("pattern", "path", "is_dir", "expected"),
    [
        ("vendor/", "vendor", True, True),
        ("vendor/", "a/b/vendor", True, True),  # a single segment matches at any depth
        ("vendor/", "vendor", False, False),  # a trailing slash means folders only
        ("*.egg-info/", "x/pkg.egg-info", True, True),
        ("*_pb2.py", "a/b/x_pb2.py", False, True),
        ("*_pb2.py", "a/b/x_pb2.pyc", False, False),
        ("**/alembic/versions/", "alembic/versions", True, True),
        ("**/alembic/versions/", "a/b/alembic/versions", True, True),
        ("alembic/versions/", "a/alembic/versions", True, False),  # a middle slash anchors it
        ("legacy/**", "legacy/a.py", False, True),
        ("legacy/**", "legacy/x/y.py", False, True),
        ("legacy/**", "legacy", True, False),  # `x/**` needs at least one component
        ("a/**/b", "a/b", False, True),
        ("a/**/b", "a/x/y/b", False, True),
        ("a/**/b", "a/x/c", False, False),
        ("a/****/b", "a/x/b", False, True),  # runs of ** collapse
        ("**", "anything/at/all", False, True),
        ("/.cursorrules", ".cursorrules", False, True),
        ("/.cursorrules", "sub/.cursorrules", False, False),
        ("a?c", "abc", False, True),
        ("a?c", "a/c", False, False),  # ? never matches a slash
        ("a*c", "a/c", False, False),  # nor does *
        ("a**c", "abbc", False, True),  # ** inside a segment is a plain *
        ("[a-c]x", "bx", False, True),
        ("[!a-c]x", "bx", False, False),
        ("[^a-c]x", "dx", False, True),
        ("[]]x", "]x", False, True),  # a leading ] is literal
        ("[z-a]x", "bx", False, False),  # a reversed range matches nothing but its start
        ("[z-a]x", "zx", False, True),
        ("[c-a]x", "cx", False, True),
        ("[c-a]x", "ax", False, False),
        ("[!c-a]x", "cx", False, False),
        ("[a-c/]x", "ax", False, False),  # split on "/": unclosed, unlike git
        ("a/***/b", "a/x/y/b", False, False),  # a *** segment is one *, unlike git's **
        ("a/***/b", "a/x/b", False, True),
        ("[a\\]]x", "]x", False, True),
        ("[+-\\]]x", "]x", False, True),  # an escaped range end
        ("[a-\\]]x", "]x", False, False),  # that range is reversed
        ("[abx", "[abx", False, False),  # an unclosed [ matches nothing, as in git
        ("a[", "a[", False, False),
        ("[]a", "]a", False, False),  # a leading ] is literal, so this class is unclosed
        ("x/[a", "x/[a", False, False),
        ("[a-z", "[a-z", False, False),
        ("*[", "a[", False, False),
        ("[ab]x[", "ax[", False, False),
        ("a\\*b", "a*b", False, True),
        ("a\\*b", "aXb", False, False),
        ("a\\", "a\\", False, True),  # a trailing backslash is literal
        ("\\!x", "!x", False, True),
        ("*.PY", "a.py", False, False),  # case-sensitive
        ("", "a", False, False),
        ("/", "a", False, False),
        ("a", "", False, False),
    ],
)
def test_match(pattern: str, path: str, is_dir: bool, expected: bool) -> None:
    assert hit(pattern, path, is_dir=is_dir) is expected


def test_negated_flag_is_parsed_and_match_ignores_its_sign() -> None:
    glob = compile_glob("!keep.py")
    assert glob.negated and glob.match("a/keep.py")
    assert not compile_glob("keep.py").negated


def test_globset_excluded_folder_excludes_everything_below_it() -> None:
    excluded = GlobSet(["build/", "*.log"])
    assert excluded.excludes("build/x/y.py")
    assert excluded.excludes("a/build/y.py")
    assert excluded.excludes("a/b.log")
    assert not excluded.excludes("src/app.py")
    assert excluded.excludes("pkg", is_dir=True) is False
    assert excluded.excludes("build", is_dir=True)


def test_globset_last_match_wins_but_no_reinclude_below_an_excluded_folder() -> None:
    excluded = GlobSet(["*.log", "!keep.log", "build/", "!build/keep.py"])
    assert not excluded.excludes("keep.log")
    assert excluded.excludes("other.log")
    assert excluded.excludes("build/keep.py")  # the parent folder is excluded
    assert not GlobSet(["a/*", "!a/keep.py"]).excludes("a/keep.py")


def test_globset_caches_folder_verdicts() -> None:
    excluded = GlobSet(["vendor/"])
    assert excluded.excludes("vendor/a.py")
    assert excluded.excludes("vendor/b.py")
    assert excluded._folders == {"vendor": True}


# ReDoS (SR condition, Architect ruling 2026-11-12): hostile patterns against hostile
# names finish at once. A backtracking regex would take exponential time on these.
@pytest.mark.timing
@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        ("*a" * 40 + "b", "a" * 400),
        ("a*" * 40 + "b", "a" * 400),
        ("**/a/" * 30 + "b", "/".join(["a"] * 60)),
        ("/".join(["*a*a*a*a*a*b"] * 12), "/".join(["a" * 200] * 12)),
        ("[a-b]*" * 30 + "c", "ab" * 200),
        ("**/*" * 30 + "x", "/".join(["a"] * 64)),
    ],
)
def test_hostile_patterns_are_fast(pattern: str, path: str) -> None:
    glob = compile_glob(pattern)
    started = time.monotonic()
    assert glob.match(path) is False
    assert time.monotonic() - started < 2.0


@pytest.mark.timing
def test_matching_work_grows_polynomially_not_exponentially() -> None:
    # The same hostile shape at 2x the size must not cost anywhere near 2**n more.
    def cost(n: int) -> float:
        glob = compile_glob("*a" * n + "b")
        started = time.perf_counter()
        glob.match("a" * (10 * n))
        return time.perf_counter() - started

    small, large = cost(20), cost(40)
    assert large < max(small, 0.001) * 50


class _CountingStr(str):
    """A ``str`` that counts how often a character is read by index."""

    reads = 0

    def __getitem__(self, key):  # type: ignore[no-untyped-def]
        type(self).reads += 1
        return super().__getitem__(key)


def _compile_reads(pattern: str) -> int:
    _CountingStr.reads = 0
    globmatch._compile_segment(_CountingStr(pattern))
    return _CountingStr.reads


@pytest.mark.parametrize("unit", ["[", "[a-z", "[\\]", "[]", "[!", "[a-\\"])
def test_compiling_unclosed_classes_is_linear_not_quadratic(unit: str) -> None:
    # An operation count, not a clock: 4x the input may cost about 4x the reads, never 16x.
    small, large = _compile_reads(unit * 1000), _compile_reads(unit * 4000)
    assert small > 0
    assert large <= 5 * small


@pytest.mark.parametrize("unit", ["[", "[a-z", "[\\]"])
def test_hostile_unclosed_class_patterns_compile_and_match_nothing(unit: str) -> None:
    glob = compile_glob(unit * 20_000)
    assert not glob.match(unit) and not glob.match("a" * 50)


def test_closed_classes_still_compile_in_linear_reads() -> None:
    small, large = _compile_reads("[a-c]" * 1000), _compile_reads("[a-c]" * 4000)
    assert large <= 5 * small


def test_class_ranges_are_merged_and_sorted_when_built() -> None:
    cls = globmatch._Class(False, "q", [("x", "z"), ("a", "c"), ("b", "e"), ("f", "g"), ("z", "a")])
    assert (cls.los, cls.his) == (["a", "x"], ["g", "z"])  # overlapping and adjacent merge
    assert [ch for ch in "abcdefghijklmnopqrstuvwxyz" if cls.matches(ch)] == list("abcdefgqxyz")
    assert not cls.matches("A") and not cls.matches("\x00")
    assert globmatch._Class(True, "", [("a", "c")]).matches("d")


def test_class_matching_agrees_with_a_naive_scan_and_uses_a_bisect() -> None:
    rng = random.Random(20261118)  # noqa: S311 - a fixed-seed test generator
    for _ in range(300):
        ranges = [tuple(sorted(rng.sample("abcdefghij", 2))) for _ in range(rng.randint(0, 6))]
        ranges += [("j", "a")] * rng.randint(0, 1)  # reversed: empty
        singles = "".join(rng.sample("klmnop", rng.randint(0, 3)))
        negate = rng.random() < 0.5
        cls = globmatch._Class(negate, singles, ranges)  # type: ignore[arg-type]
        for ch in "abcdefghijklmnopq":
            naive = ch in singles or any(lo <= ch <= hi for lo, hi in ranges if lo <= hi)
            assert cls.matches(ch) == (naive != negate)
    many = globmatch._Class(False, "", [(chr(c), chr(c)) for c in range(0x100, 0x100 + 4000, 2)])
    assert len(many.los) == 2000 and many.matches(chr(0x100 + 3998)) and not many.matches("\u0101")


_GIT = shutil.which("git") or "git"


@pytest.mark.parametrize(
    ("pattern", "name"),
    [
        ("[abx", "[abx"),
        ("a[", "a["),
        ("a[b", "a[b"),
        ("[]", "[]"),
        ("[]a", "[]a"),
        ("[a-", "[a-"),
        ("[!", "[!"),
        ("a[b]", "ab"),  # closed: matches
        ("a\\[b", "a[b"),  # escaped: literal
        ("[]]a", "]a"),
        ("[c-a]x", "cx"),  # a reversed range still matches its start
        ("[c-a]x", "bx"),
        ("[c-a]x", "ax"),
        ("[z-a]x", "zx"),
    ],
)
def test_bracket_expressions_agree_with_git_check_ignore(
    tmp_path: Path, pattern: str, name: str
) -> None:
    (tmp_path / ".gitignore").write_bytes(pattern.encode() + b"\n")
    env = {"PATH": __import__("os").environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": str(tmp_path)}  # fmt: skip
    for args in (["init", "-q"], ["config", "core.excludesFile", ""]):
        subprocess.run([_GIT, *args], cwd=tmp_path, env=env, check=True, capture_output=True)  # noqa: S603
    out = subprocess.run(  # noqa: S603
        [_GIT, "check-ignore", "-q", "--no-index", "--", name],
        cwd=tmp_path, env=env, capture_output=True, check=False,
    )  # fmt: skip
    assert out.returncode in (0, 1)  # 0 ignored, 1 not ignored
    assert compile_glob(pattern).match(name) == (out.returncode == 0)


# ---- #76 B2 / M-76-1: the work count the .gitignore match budget pays from -----------

_NO_LIMIT = 1 << 40


@pytest.mark.parametrize(
    ("pattern", "path", "is_dir", "expected"),
    [
        ("/a", "a", False, (True, 3)),  # start, one component compared (1 + 1)
        ("a", "a", False, (True, 2)),  # one segment: only the last component, 1 step
        ("**/x", "a/b/x", False, (True, 2)),  # the same shape written with "**/"
        ("*.py", "x/m.py", False, (True, 7)),  # 6 steps inside "m.py": *, back up, 4 chars
        ("[q]1", "q1", False, (True, 4)),
        ("[q]1", "q1/x", False, (False, 3)),
        ("a/b", "a/c", False, (False, 5)),
        ("a/*/c", "a/b/c", True, (True, 9)),
        ("a/", "a", False, (False, 1)),  # a folder-only pattern on a file: no work
        ("a", "", False, (False, 1)),
    ],
)
def test_match_counted_answers_as_match_and_counts_steps(
    pattern: str, path: str, is_dir: bool, expected: tuple[bool, int]
) -> None:
    glob = compile_glob(pattern)
    assert glob.match_counted(path, is_dir, _NO_LIMIT) == expected
    assert glob.match(path, is_dir) is expected[0]


def test_a_one_segment_pattern_compares_only_the_last_component() -> None:
    glob = compile_glob("[q]1")
    shallow = glob.match_counted("q1", False, _NO_LIMIT)
    deep = glob.match_counted("/".join(["q1"] * 60), False, _NO_LIMIT)
    assert shallow == deep == (True, 4)
    assert not glob.match("q1/x")


@pytest.mark.parametrize(
    ("pattern", "path", "limit", "stopped", "full"),
    [
        ("*a" * 40 + "b", "a" * 400, 100, 101, 802),  # inside one component
        ("**/a/" * 30 + "b", "/".join(["a"] * 60), 10, 11, 211),  # across components
    ],
)
def test_match_counted_stops_just_past_its_limit(
    pattern: str, path: str, limit: int, stopped: int, full: int
) -> None:
    glob = compile_glob(pattern)
    assert glob.match_counted(path, False, limit) == (False, stopped)
    assert glob.match_counted(path, False, _NO_LIMIT) == (False, full)


def test_a_match_that_needs_more_than_its_limit_does_not_match() -> None:
    glob = compile_glob("a/*/c")
    assert glob.match_counted("a/b/c", False, _NO_LIMIT) == (True, 9)
    assert glob.match_counted("a/b/c", False, 8) == (True, 9)  # the last step may pass it
    assert glob.match_counted("a/b/c", False, 5) == (False, 6)  # stopped inside "*"
