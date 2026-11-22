"""T-010b part 2 unit tests: ``.gitignore`` lines, precedence and the pattern cap
(DESIGN §12 A-3 condition 4, ``discover/gitignore.py``).

The expected verdicts of the git cases come from ``git check-ignore`` on a real
repository (``test_verdicts_agree_with_git_check_ignore``), so the parser is held to
git rather than to our reading of ``gitignore(5)``.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.fixtures.gitrepo import GitRepo

from conventiondrift.discover import gitignore
from conventiondrift.discover.gitignore import IgnoreRules, gitignore_patterns
from conventiondrift.discover.safefs import WALK_MAX_DEPTH


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[GitRepo]:
    fixture = GitRepo.init(tmp_path / "repo")
    yield fixture
    fixture.remove()


def rules(*files: tuple[str, bytes]) -> IgnoreRules:
    loaded = IgnoreRules()
    for base, data in files:
        loaded.add(base, data)
    return loaded


# ------------------------------------------------------------------ line rules


def test_caps_are_the_design_values() -> None:
    assert gitignore.GITIGNORE_MAX_BYTES == 65_536
    assert gitignore.GITIGNORE_MAX_PATTERNS == 2_000


def test_blank_lines_and_comments_are_not_patterns() -> None:
    assert gitignore_patterns(b"\n#c\n  \n\n#\na\n") == ["a"]


def test_escaped_hash_and_bang_are_patterns() -> None:
    assert gitignore_patterns(b"\\#h\n\\!n\n") == ["\\#h", "\\!n"]


def test_crlf_lines_lose_the_cr() -> None:
    assert gitignore_patterns(b"a\r\nb\r\n") == ["a", "b"]


def test_only_one_cr_before_the_newline_is_dropped() -> None:
    assert gitignore_patterns(b"a\r\r\n") == ["a\r"]


def test_last_line_without_newline_is_read() -> None:
    assert gitignore_patterns(b"a\nb") == ["a", "b"]


def test_bom_is_dropped_only_at_the_start() -> None:
    assert gitignore_patterns(b"\xef\xbb\xbfa\n\xef\xbb\xbfb\n") == ["a", "\ufeffb"]


def test_bom_before_a_comment_leaves_a_comment() -> None:
    assert gitignore_patterns(b"\xef\xbb\xbf#c\n") == []


@pytest.mark.parametrize(
    ("line", "pattern"),
    [
        (b"a  ", "a"),
        (b"a \r", "a"),
        (b"a\\ ", "a\\ "),
        (b"a\\  ", "a\\ "),
        (b"a b ", "a b"),
        (b"a\t", "a\t"),
        (b"a\\", "a\\"),
        (b"a\\\\ ", "a\\\\"),
        (b"\\ ", "\\ "),
        (b"a\\\\\\ ", "a\\\\\\ "),
        (b"a\\\\\\  ", "a\\\\\\ "),
        (b"a\t ", "a\t"),
        (b"a\\ b ", "a\\ b"),
        (b"aX ", "aX"),
    ],
)
def test_trailing_spaces_are_dropped_unless_escaped(line: bytes, pattern: str) -> None:
    assert gitignore_patterns(line) == [pattern]


def test_a_pattern_ending_in_a_lone_backslash_never_matches() -> None:
    loaded = rules(("", b"a\\\nb\\\\\\\nc\\\\\n"))
    assert (loaded.loaded, loaded.skipped) == (3, 0)  # counted toward the cap
    assert not loaded.ignored("a\\")
    assert not loaded.ignored("a")
    assert not loaded.ignored("b\\")
    assert not loaded.ignored("b\\\\")
    assert loaded.ignored("c\\")


def test_a_line_of_spaces_is_not_a_pattern() -> None:
    assert gitignore_patterns(b"   \n") == []


def test_bytes_that_are_not_utf8_are_kept() -> None:
    assert gitignore_patterns(b"\xff.py\n") == ["\udcff.py"]


# ------------------------------------------------------------------ precedence


def test_no_rules_ignore_nothing() -> None:
    assert not IgnoreRules().ignored("a/b.py")


def test_last_matching_pattern_wins() -> None:
    loaded = rules(("", b"*.py\n!keep.py\n"))
    assert loaded.ignored("x.py")
    assert not loaded.ignored("keep.py")
    assert rules(("", b"!keep.py\n*.py\n")).ignored("keep.py")


def test_a_nested_file_applies_only_under_its_folder() -> None:
    loaded = rules(("a", b"x.py\n/y.py\n"))
    assert loaded.ignored("a/x.py")
    assert loaded.ignored("a/b/x.py")
    assert loaded.ignored("a/y.py")
    assert not loaded.ignored("a/b/y.py")
    assert not loaded.ignored("x.py")
    assert not loaded.ignored("ab/x.py")
    assert not loaded.ignored("a")


def test_a_deeper_file_overrides_a_shallower_one() -> None:
    loaded = rules(("", b"*.py\n"), ("a", b"!*.py\n"))
    assert not loaded.ignored("a/x.py")
    assert loaded.ignored("b/x.py")


def test_nothing_under_an_ignored_folder_comes_back() -> None:
    loaded = rules(("", b"build/\n!build/keep.py\n"))
    assert loaded.ignored("build", is_dir=True)
    assert loaded.ignored("build/keep.py")
    assert loaded.ignored("build/deep/keep.py")


def test_every_folder_above_a_path_is_checked() -> None:
    # Only the middle folder is ignored; the file itself is re-included by name.
    loaded = rules(("", b"mid/\n!x.py\n"))
    assert loaded.ignored("a/mid/c/x.py")
    assert loaded.ignored("a/b/mid/c/d/x.py")
    assert not loaded.ignored("a/b/c/x.py")


def test_each_folder_verdict_is_worked_out_once(monkeypatch: pytest.MonkeyPatch) -> None:
    loaded = rules(("", b"*.tmp\n"))
    seen: list[str] = []
    real = loaded._verdict

    def spy(path: str, is_dir: bool) -> bool:
        seen.append(path)
        return real(path, is_dir)

    monkeypatch.setattr(loaded, "_verdict", spy)
    assert not loaded.ignored("a/b/x.py")
    assert not loaded.ignored("a/b/y.py")
    assert seen == ["a", "a/b", "a/b/x.py", "a/b/y.py"]


def test_a_folder_only_pattern_never_matches_a_file() -> None:
    loaded = rules(("", b"build/\n"))
    assert not loaded.ignored("build")
    assert loaded.ignored("build", is_dir=True)


def test_adding_patterns_drops_cached_folder_verdicts() -> None:
    loaded = rules(("", b"x\n"))
    assert not loaded.ignored("a/b.py")  # caches folder "a" as not ignored
    loaded.add("", b"a/\n")
    assert loaded.ignored("a/b.py")


def test_a_file_with_no_patterns_changes_nothing() -> None:
    loaded = rules(("", b"*.py\n"), ("a", b"# nothing\n"))
    assert loaded.ignored("a/x.py")


@pytest.mark.parametrize(
    ("pattern", "path", "ignored"),
    [
        ("gen_*", "d/gen_1", True),
        ("gen_*", "d/xgen_1", False),
        ("gen_*", "ge", False),
        ("*.pyc", "d/m.pyc", True),
        ("*.pyc", "d/m.pyc.bak", False),
        ("*.pyc", ".pyc", True),
        ("*.pyc", "pyc", False),
        ("a?c", "abc", True),
        ("a?c", "bbc", False),
        ("a*bc", "abc", True),
        ("a*bc", "ab", False),
        ("ab*c", "abxyc", True),
        ("ab*c", "abxy", False),
        ("[ab]x", "bx", True),
        ("[ab]x", "cx", False),
        ("x[ab]", "xa", True),
        ("x[ab]", "ya", False),
        ("\\*x", "*x", True),
        ("\\*x", "ax", False),
        ("*\\x", "ax", True),
        ("*a*b", "zab", True),
        ("?a?bc", "xaybc", True),
        ("?a?bc", "xaybd", False),
        ("*a*b", "zba", False),
        ("a?b*", "axbz", True),
        ("ab*cd", "abzzcd", True),
        ("dirX/", "dirX", False),
        ("*", "anything", True),
        ("**/m", "a/b/m", True),
        ("a/**", "a/b", True),
        ("d/", "x/d", False),
        ("!", "x", False),
    ],
)
def test_each_pattern_shape_matches_as_it_should(pattern: str, path: str, ignored: bool) -> None:
    # Covers every lookup the speed-up uses (name, start, end, tried everywhere).
    assert rules(("", pattern.encode())).ignored(path) is ignored


def test_lookup_keeps_load_order_across_kinds() -> None:
    # A name pattern, then an end pattern, then a start pattern, then one tried
    # everywhere: each later one overrides the earlier for the same path.
    loaded = IgnoreRules()
    loaded.add("", b"m.py\n")
    assert loaded.ignored("m.py")
    loaded.add("", b"!*.py\n")
    assert not loaded.ignored("m.py")
    loaded.add("", b"m*\n")
    assert loaded.ignored("m.py")
    loaded.add("", b"![lm].py\n")
    assert not loaded.ignored("m.py")
    loaded.add("", b"m.py\n")
    assert loaded.ignored("m.py")


def test_only_patterns_that_can_match_are_tried() -> None:
    loaded = rules(
        ("", b"foo\n*.pyc\ngen_*\n*\nab*cd\n[ab]x\ndirX/\n*a*b\n\\*q\n"),
    )
    # 0 foo (name), 1 *.pyc (end), 2 gen_* (start), 3 * (everywhere), 4 ab*cd (start,
    # the longer text wins a tie), 5 [ab]x (everywhere), 6 dirX/ (name dirX),
    # 7 *a*b (end b), 8 \*q (everywhere: an escape is not plain text)
    assert loaded._candidates("a/foo") == [8, 5, 3, 0]
    assert loaded._candidates("m.pyc") == [8, 5, 3, 1]
    assert loaded._candidates("xpyc") == [8, 5, 3]
    assert loaded._candidates("gen_1") == [8, 5, 3, 2]
    assert loaded._candidates("abzz") == [8, 5, 4, 3]
    assert loaded._candidates("zzcd") == [8, 5, 3]
    assert loaded._candidates("q/dirX") == [8, 6, 5, 3]
    assert loaded._candidates("zab") == [8, 7, 5, 3]
    assert loaded._candidates("b") == [8, 7, 5, 3]
    assert loaded._candidates("gen_") == [8, 5, 3, 2]
    assert loaded._candidates("p") == [8, 5, 3]


# ------------------------------------------------------------------ caps


def test_the_pattern_cap_counts_in_load_order_across_files() -> None:
    loaded = IgnoreRules()
    loaded.add("", b"".join(b"p%d\n" % i for i in range(1_999)))
    loaded.add("a", b"first\nsecond\nthird\n")
    assert (loaded.loaded, loaded.skipped) == (2_000, 2)
    assert loaded.ignored("a/first")
    assert not loaded.ignored("a/second")
    assert not loaded.ignored("a/third")


def test_exactly_the_cap_skips_nothing() -> None:
    loaded = rules(("", b"".join(b"p%d\n" % i for i in range(2_000))))
    assert (loaded.loaded, loaded.skipped) == (2_000, 0)
    assert loaded.ignored("p1999")


def test_comments_and_blank_lines_do_not_count() -> None:
    loaded = rules(("", b"#c\n\n   \na\n"))
    assert (loaded.loaded, loaded.skipped) == (1, 0)


# ------------------------------------------------------------------ against git

_GIT_CASES: dict[str, bytes] = {
    ".gitignore": (
        b"\xef\xbb\xbf*.log\r\n"
        b"!keep.log\n"
        b"build/\n"
        b"!build/keep.py\n"
        b"\\#hash\n"
        b"\\!bang\n"
        b"trail   \n"
        b"esc\\ \n"
        b"/rooted\n"
        b"**/deep/x\n"
        b"sub/*.tmp\n"
        b"gen_*\n"
        b"\xef\xbb\xbflate\n"
    ),
    "sub/.gitignore": b"!a.log\nlocal\n/only_here\n",
    "other/.gitignore": b"*\n!*.py\n!*/\n",
}
_GIT_PATHS = (
    "a.log",
    "keep.log",
    "sub/a.log",
    "sub/b.log",
    "build/keep.py",
    "build/x.py",
    "#hash",
    "!bang",
    "trail",
    "trail   ",
    "esc ",
    "esc",
    "rooted",
    "sub/rooted",
    "sub/local",
    "local",
    "sub/only_here",
    "sub/deeper/only_here",
    "q/deep/x",
    "sub/t.tmp",
    "sub/in/t.tmp",
    "gen_1",
    "sub/gen_2",
    "late",
    "\ufefflate",
    "other/x.txt",
    "other/x.py",
    "other/in/y.py",
    "other/in/y.txt",
)


def _git_ignored(repo: GitRepo, path: str) -> bool:
    proc = subprocess.run(  # noqa: S603 - argv list, no shell
        ["git", "check-ignore", "-q", "--no-index", "--", path],  # noqa: S607
        cwd=repo.path,
        env=repo.env(),
        capture_output=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return proc.returncode == 0


def test_verdicts_agree_with_git_check_ignore(repo: GitRepo) -> None:
    for rel, data in _GIT_CASES.items():
        target = repo.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    loaded = IgnoreRules()
    for rel in sorted(_GIT_CASES, key=lambda r: r.count("/")):  # parents first, like the walk
        loaded.add(rel.rpartition("/")[0], _GIT_CASES[rel])
    expected = {path: _git_ignored(repo, path) for path in _GIT_PATHS}
    assert {path: loaded.ignored(path) for path in _GIT_PATHS} == expected
    # The fixture must exercise both answers, or it proves nothing.
    assert set(expected.values()) == {True, False}


# ------------------------------------------------------------------ match budget (#76 B2)


def _budget(monkeypatch: pytest.MonkeyPatch, steps: int, allowance: int = 0) -> None:
    monkeypatch.setattr(gitignore, "GITIGNORE_MATCH_BUDGET", steps)
    monkeypatch.setattr(gitignore, "GITIGNORE_MATCH_ALLOWANCE", allowance)


def test_the_match_budget_is_the_chosen_value() -> None:
    assert gitignore.GITIGNORE_MATCH_BUDGET == 3_000_000
    assert gitignore.GITIGNORE_MATCH_ALLOWANCE == 256


def test_each_check_pays_its_lookups_tries_and_match_steps() -> None:
    loaded = rules(("", b"*.py\nb/\n"))  # two lookups: an end of length 3, a name of 1
    assert loaded.ignored("x.py")
    # 4 + 1 component split + 2 * 2 lookups + 2 for the try + 2 to cut the path to the
    # root .gitignore's folder (1 + 1 component) + 7 match steps
    assert loaded._work == 20
    loaded = rules(("", b"*.py\nb/\n"))
    assert loaded.ignored("a/x.py")
    assert loaded._work == 31  # the folder "a" (9, nothing to try) and the file (22)
    assert loaded.ignored("a/y.py")
    assert loaded._work == 53  # the cached folder verdict is not paid again


def test_the_budget_runs_out_and_nothing_more_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _budget(monkeypatch, 40)
    loaded = rules(("", b"*.py\n"))  # each check: 4 + 1 + 2 + 2 + 2 + 7 = 18
    assert [loaded.ignored(p) for p in ("a.py", "b.py")] == [True, True]
    assert (loaded._work, loaded.exhausted, loaded.unchecked) == (36, False, 0)
    assert not loaded.ignored("c.py")  # runs out before the match: 36 + 11 + 2
    assert (loaded._work, loaded.exhausted, loaded.unchecked) == (49, True, 1)
    assert not loaded.ignored("d.py")
    assert not loaded.ignored("e/f.py", is_dir=True)
    assert (loaded._work, loaded.unchecked) == (49, 3)  # no more work once spent


def test_exactly_the_budget_is_not_spent(monkeypatch: pytest.MonkeyPatch) -> None:
    _budget(monkeypatch, 36)
    loaded = rules(("", b"*.py\n"))
    assert loaded.ignored("a.py") and loaded.ignored("b.py")
    assert (loaded._work, loaded.exhausted, loaded.unchecked) == (36, False, 0)
    assert not loaded.ignored("c.py")
    assert loaded.exhausted


def test_the_budget_is_shared_by_every_gitignore_file(monkeypatch: pytest.MonkeyPatch) -> None:
    # One scan, one budget: adding a nested .gitignore does not start a new one.
    _budget(monkeypatch, 50)
    loaded = rules(("", b"*.py\n"))
    assert loaded.ignored("a.py") and loaded.ignored("b.py")
    assert loaded._work == 36
    loaded.add("sub", b"*.txt\n")
    assert not loaded.ignored("sub/c.py")  # its 31 steps would make 67 > 50
    assert (loaded.exhausted, loaded.unchecked) == (True, 1)
    alone = rules(("", b"*.py\n"), ("sub", b"*.txt\n"))
    assert alone.ignored("sub/c.py")
    assert alone._work == 31


def test_running_out_on_a_folder_leaves_the_path_in(monkeypatch: pytest.MonkeyPatch) -> None:
    # "a" costs 10; "a/b" would be ignored by "b/" but its check takes the work to 26.
    _budget(monkeypatch, 25)
    loaded = rules(("", b"*.py\nb/\n"))
    assert not loaded.ignored("a/b/x.py")
    assert (loaded._work, loaded.exhausted, loaded.unchecked) == (26, True, 1)
    _budget(monkeypatch, 26)
    loaded = rules(("", b"*.py\nb/\n"))
    assert loaded.ignored("a/b/x.py")
    assert (loaded._work, loaded.unchecked) == (26, 0)


def test_one_long_match_stops_at_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _budget(monkeypatch, 1_000)
    loaded = rules(("", ("*a" * 40 + "[b]").encode()))  # tried on every path
    assert not loaded.ignored("a" * 400)  # 4 + 1 + 2 + 2 + 802 match steps
    assert (loaded._work, loaded.exhausted) == (811, False)
    assert not loaded.ignored("a" * 400)  # stopped after 181 of its 802 steps
    assert (loaded._work, loaded.exhausted, loaded.unchecked) == (1_001, True, 1)


def test_long_paths_pay_for_their_components() -> None:
    # #76 CR B2: a path is split and cut once per check, and that is paid per component,
    # so a deep path costs more than a short one with the same patterns and name.
    def work(path: str) -> int:
        loaded = rules(("", b"".join(b"[x]/[y]%d*\n" % i for i in range(10))))
        assert not loaded._verdict(path, False)
        return loaded._work

    short = work("a/b.py")
    deep = work("/".join(["n" * 200] * 60) + "/b.py")
    assert short == 4 + 2 + 10 * 2 + (1 + 2) + 10 * 4  # each match: [x] fails on "a" in 4
    assert deep == short + 59 + 59  # 59 more components split, and 59 more cut


@pytest.mark.parametrize(
    "pattern",
    [
        b"[q]%d\n",  # TE: one class, tried on every path
        b"[x]*%d*q/\n",  # CR: folder-only, tried on every folder
        b"**/*/**/*/**/*/**/*/**/*/**/*/**/[a-z]*q%d\n",  # SR: deep "**"
    ],
)
def test_hostile_pattern_sets_spend_the_budget(
    pattern: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    _budget(monkeypatch, 1_000_000)
    loaded = IgnoreRules()
    loaded.add("", b"keep.py\n")
    loaded.add("", b"".join(pattern % i for i in range(1_999)))
    assert loaded.loaded == 2_000
    paths = [f"d{i}/e/f/g/h/keep.py" for i in range(200)]  # 6 checks each, none cached
    verdicts = [loaded.ignored(p) for p in paths]
    assert loaded.exhausted
    spent = verdicts.index(False)
    assert spent > 0 and not any(verdicts[spent:])  # ignored, then never again
    assert loaded.unchecked == len(paths) - spent
    assert loaded._work < 1_000_000 + 10  # a check stops within a few steps of the end


def test_the_allowance_grows_with_each_path_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    _budget(monkeypatch, 0, 18)  # each "*.py" check costs 18
    loaded = rules(("", b"*.py\n"))
    assert all(loaded.ignored("m.py") for _ in range(1_000))  # files are not cached
    assert (loaded._work, loaded.exhausted) == (18_000, False)
    _budget(monkeypatch, 0, 17)
    loaded = rules(("", b"*.py\n"))
    assert not loaded.ignored("m.py")
    assert loaded.exhausted


def test_unused_allowance_carries_over(monkeypatch: pytest.MonkeyPatch) -> None:
    _budget(monkeypatch, 0, 18)
    loaded = rules(("", b"*.py\n"))
    assert not any(loaded.ignored(f"m{i}.txt") for i in range(10))  # 7 each: nothing to try
    assert loaded._work == 70
    assert loaded.ignored("a/b/c/d/e/f/g/m.py")  # 32, plus 70 for its seven folders
    assert (loaded._work, loaded.exhausted) == (172, False)  # 18 * 11 = 198 allowed
    _budget(monkeypatch, 0, 18)
    fresh = rules(("", b"*.py\n"))
    assert not fresh.ignored("a/b/c/d/e/f/g/m.py")  # 102 is more than 18 on its own
    assert fresh.exhausted


def test_a_spent_budget_stays_spent(monkeypatch: pytest.MonkeyPatch) -> None:
    _budget(monkeypatch, 0, 17)
    loaded = rules(("", b"*.py\n"))
    assert not loaded.ignored("a.py")
    assert [loaded.ignored(f"{i}.txt") for i in range(100)] == [False] * 100
    assert (loaded.exhausted, loaded.unchecked, loaded._checks) == (True, 101, 1)


# GitHub's Python.gitignore (github/gitignore 7705c2c, CC0), its pattern lines in order.
_STOCK_PYTHON = (
    "__pycache__/",
    "*.py[codz]",
    "*$py.class",
    "*.so",
    ".Python",
    "build/",
    "develop-eggs/",
    "dist/",
    "downloads/",
    "eggs/",
    ".eggs/",
    "lib/",
    "lib64/",
    "parts/",
    "sdist/",
    "var/",
    "wheels/",
    "share/python-wheels/",
    "*.egg-info/",
    ".installed.cfg",
    "*.egg",
    "MANIFEST",
    "*.manifest",
    "*.spec",
    "pip-log.txt",
    "pip-delete-this-directory.txt",
    "htmlcov/",
    ".tox/",
    ".nox/",
    ".coverage",
    ".coverage.*",
    ".cache",
    "nosetests.xml",
    "coverage.xml",
    "*.cover",
    "*.py.cover",
    "*.lcov",
    ".hypothesis/",
    ".pytest_cache/",
    "cover/",
    "*.mo",
    "*.pot",
    "*.log",
    "local_settings.py",
    "db.sqlite3",
    "db.sqlite3-journal",
    "instance/",
    ".webassets-cache",
    ".scrapy",
    "docs/_build/",
    ".pybuilder/",
    "target/",
    ".ipynb_checkpoints",
    "profile_default/",
    "ipython_config.py",
    ".pdm-python",
    ".pdm-build/",
    ".pixi/*",
    "!.pixi/config.toml",
    "__pypackages__/",
    "celerybeat-schedule*",
    "celerybeat.pid",
    "*.rdb",
    "*.aof",
    "*.pid",
    "mnesia/",
    "rabbitmq/",
    "rabbitmq-data/",
    "activemq-data/",
    "*.sage.py",
    ".env",
    ".envrc",
    ".venv",
    "env/",
    "venv/",
    "ENV/",
    "env.bak/",
    "venv.bak/",
    "conda-meta/",
    ".spyderproject",
    ".spyproject",
    ".ropeproject",
    "/site",
    ".mypy_cache/",
    ".dmypy.json",
    "dmypy.json",
    ".pyre/",
    ".pytype/",
    "cython_debug/",
    ".abstra/",
    "tempCodeRunnerFile.py",
    ".ruff_cache/",
    ".pypirc",
    "marimo/_static/",
    "marimo/_lsp/",
    "__marimo__/",
    ".streamlit/secrets.toml",
)


def _stock_rules() -> IgnoreRules:
    return rules(("", "\n".join(_STOCK_PYTHON).encode()))


def _stock_walk(loaded: IgnoreRules, prefix: str, folders: int) -> int:
    """A synthetic walk as the scan does it: each folder is checked before the 99 files
    of common kinds in it. Returns how many entries were checked."""
    kinds = ("mod_{}.py", "test_{}.py", "{}.pyc", "README_{}.md", "data_{}.json", ".env{}")
    entries = 0
    for n in range(folders):
        folder = f"{prefix}src{n % 50}/pkg_{n % 7}/sub{n}"
        loaded.ignored(folder, is_dir=True)
        entries += 1
        for i in range(99):
            loaded.ignored(f"{folder}/{kinds[i % 6].format(i)}")
            entries += 1
    return entries


# D-TL-73, D-TL-75: at any depth the walk allows, a walk with GitHub's Python .gitignore
# spends less than the allowance per entry, so the base budget is never touched and it
# never runs out however many entries there are. One deep check alone may cost more
# than the allowance (about 350 steps at depth 64); unused allowance carries over.
@pytest.mark.parametrize("depth", [0, 8, 32, WALK_MAX_DEPTH - 3])  # + src/pkg/sub
@pytest.mark.parametrize("name_length", [8, 60])
def test_a_stock_python_walk_spends_less_than_its_allowance_at_any_depth(
    depth: int, name_length: int
) -> None:
    prefix = "".join(f"p{k:02d}{'q' * name_length}/" for k in range(depth))
    loaded = _stock_rules()
    entries = _stock_walk(loaded, prefix, 200)
    assert entries == 20_000
    assert depth + 3 <= WALK_MAX_DEPTH  # the deepest folder is inside the walk cap
    assert not loaded.exhausted
    assert loaded._work <= gitignore.GITIGNORE_MATCH_ALLOWANCE * entries


def test_the_stock_python_gitignore_never_runs_out_below_the_walk_cap() -> None:
    # D-TL-73: a synthetic walk of 500,000 entries (the A-3 walk cap): folders are
    # checked before what is in them, as the walk does, with files of common kinds.
    loaded = _stock_rules()
    assert len(_STOCK_PYTHON) == loaded.loaded == 97
    kinds = ("mod_{}.py", "test_{}.py", "{}.pyc", "README_{}.md", "data_{}.json", ".env{}")
    entries = 0
    ignored = 0
    for top in range(50):
        for sub in range(100):
            folder = f"src{top}/pkg_{sub % 7}/sub{sub}"
            loaded.ignored(folder, is_dir=True)
            entries += 1
            for i in range(99):
                ignored += loaded.ignored(f"{folder}/{kinds[i % 6].format(i)}")
                entries += 1
    assert entries == 500_000
    assert not loaded.exhausted and loaded.unchecked == 0
    assert ignored == 50 * 100 * 17  # the .pyc files
