"""T-010a unit tests: the linear-time gitignore-style matcher (DESIGN §12 A-3 condition 4)."""

from __future__ import annotations

import time

import pytest

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
        ("[z-a]x", "bx", False, False),  # a reversed range matches nothing
        ("[a\\]]x", "]x", False, True),
        ("[+-\\]]x", "]x", False, True),  # an escaped range end
        ("[a-\\]]x", "]x", False, False),  # that range is reversed
        ("[abx", "[abx", False, True),  # an unclosed [ is literal
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


def test_matching_work_grows_polynomially_not_exponentially() -> None:
    # The same hostile shape at 2x the size must not cost anywhere near 2**n more.
    def cost(n: int) -> float:
        glob = compile_glob("*a" * n + "b")
        started = time.perf_counter()
        glob.match("a" * (10 * n))
        return time.perf_counter() - started

    small, large = cost(20), cost(40)
    assert large < max(small, 0.001) * 50
