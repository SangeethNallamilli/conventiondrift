"""Unit tests for the package-manager checker, conventiondrift.checkers.package_manager (T-019).

Covers AC-F3.9 (one site per evidence file or table, FEASIBILITY F-4), the package-manager
half of AC-F2.5, and the TOML hardening the Security Reviewer asked for: deep nesting, an
integer over the digit limit, and binary or non-UTF-8 manifests never raise. C4 lists such a
``pyproject.toml`` as ``"manifest parse error"`` (I-9); the checker gives it no sites. Counts
go through the real pool.
"""

import sys
from collections.abc import Callable, Mapping

import pytest
from checker_support import REGISTRY_UNDER_TEST, assert_linear, counts, default_is_script, rules_of
from test_discover_tree import PY, run

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.package_manager import PackageManagerChecker
from conventiondrift.checkers.package_manager.match import OPTIONS, match_rule
from conventiondrift.checkers.package_manager.sites import (
    LOCKFILES,
    PYPROJECT,
    REQUIREMENTS_OPTION,
    REQUIREMENTS_PREFIX,
    REQUIREMENTS_SUFFIX,
    TOOL_TABLES,
    header_line,
    manifest_sites,
    tool_tables,
)
from conventiondrift.checkers.pool import analyze
from conventiondrift.discover.entrypoints import LOCKFILE_NAMES, REASON_MANIFEST_PARSE
from conventiondrift.model import Counts, ManifestFile, RuleMatch, Site, SkippedFile, Verdict
from conventiondrift.policy.config import DEFAULT_CHECKERS, DEFAULT_THRESHOLDS
from conventiondrift.verdicts import decide

# Pinned so a silent edit of a constant fails (D-TL-25).
_OPTIONS = frozenset({"pip", "poetry", "uv", "pdm"})
_LOCKFILES = {"poetry.lock": "poetry", "uv.lock": "uv", "pdm.lock": "pdm"}


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...] = ()) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), len(preferred + prohibited))


def sites(files: Mapping[str, bytes]) -> list[Site]:
    """The checker's sites over ``files`` through the real pool, which validates each one."""
    result = analyze(
        [],
        checkers=REGISTRY_UNDER_TEST,
        is_script=default_is_script(),
        manifests=[ManifestFile(path, data) for path, data in files.items()],
        max_workers=1,
    )
    assert not result.failed
    return list(result.sites("package-manager"))


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = PackageManagerChecker()
    assert checker.id == "package-manager"
    assert checker.experimental is False
    assert checker.options == _OPTIONS == OPTIONS
    assert checker.inputs == frozenset({"manifest"})
    assert checker.ast_handlers() == {}


def test_the_checker_is_in_the_registry_and_on_by_default() -> None:
    assert any(isinstance(c, PackageManagerChecker) for c in REGISTRY)
    assert DEFAULT_CHECKERS["package-manager"].enabled is True


def test_the_checker_delegates_to_its_module_functions() -> None:
    checker = PackageManagerChecker()
    assert checker.match_rule("use uv for dependencies.") == match_rule("use uv for dependencies.")
    files = {"uv.lock": b"", "requirements.txt": b""}
    assert list(checker.manifest_sites(files)) == list(manifest_sites(files))


def test_the_constants_agree_with_each_other_and_with_c4() -> None:
    assert LOCKFILES == _LOCKFILES
    assert frozenset(LOCKFILES) == LOCKFILE_NAMES
    assert frozenset(LOCKFILES.values()) == TOOL_TABLES
    assert TOOL_TABLES | {REQUIREMENTS_OPTION} == OPTIONS
    assert (PYPROJECT, REQUIREMENTS_PREFIX, REQUIREMENTS_SUFFIX) == (
        "pyproject.toml",
        "requirements",
        ".txt",
    )


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "expected"),
    [
        ("use uv for dependencies.", match(("uv",))),  # AC-F2.5 line 8
        ("use poetry for dependencies.", match(("poetry",))),  # AC-F3.9
        ("use pip for dependencies.", match(("pip",))),
        ("use pdm for dependencies.", match(("pdm",))),
        ("use poetry for dependencies.".upper(), match(("poetry",))),
        ("never use pip, use uv.", match(("uv",), ("pip",))),
        ("prefer uv over pip.", match(("uv",), ("pip",))),
        ("use uv instead of pip.", match(("uv",), ("pip",))),
        ("use pdm, not poetry.", match(("pdm",), ("poetry",))),
        ("don't use pip.", match((), ("pip",))),
    ],
)
def test_match_rule_reads_the_polarity_of_each_mention(sentence: str, expected: RuleMatch) -> None:
    assert match_rule(sentence) == expected


@pytest.mark.parametrize(
    "sentence",
    [
        "use a lockfile.",
        "commit uv.lock.",  # a file name is one token
        "use pip-tools.",
        "use pipenv for dependencies.",
        "use " + " or ".join(sorted(OPTIONS)) + ".",  # preferring every option is no rule
        "",
    ],
)
def test_match_rule_does_not_map_what_it_cannot_read(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_match_rule_reads_against_the_pinned_option_set() -> None:
    # classify gets exactly the four managers: all four preferred, or all four forbidden, is
    # no rule, while any three still map (a smaller or larger set would change these).
    every = " or ".join(sorted(_OPTIONS))
    assert match_rule(f"use {every}.") is None
    assert match_rule(f"never use {every}.") is None
    for left_out in sorted(_OPTIONS):
        three = tuple(sorted(_OPTIONS - {left_out}))
        assert match_rule("use " + " or ".join(three) + ".") == match(three)


@pytest.mark.parametrize("option", sorted(OPTIONS))
def test_each_option_is_its_own_word(option: str) -> None:
    assert match_rule(f"use {option}.") == match((option,))


def test_it_takes_only_line_8_of_the_canonical_sentences_ac_f2_5() -> None:
    canonical = [
        "use logging, not print.",
        "use httpx for http calls.",
        "use pytest, not unittest.",
        "store money as integer cents.",
        "use f-strings for string formatting.",
        "do not use bare except.",
        "always use type hints.",
    ]
    assert [match_rule(s) for s in canonical] == [None] * len(canonical)
    assert match_rule("use uv for dependencies.") == match(("uv",))


def test_the_registry_maps_package_manager_rules_to_the_checker() -> None:
    text = "Use Poetry for dependencies.\nNever use pip, use uv.\n"
    assert rules_of(text) == [(1, "package-manager"), (2, "package-manager")]


# --- sites: AC-F3.9 -------------------------------------------------------------------------


def test_f3_9_uv_files_contradict_a_poetry_rule_and_name_uv_lock() -> None:
    found = sites({"pyproject.toml": b'[project]\nname = "x"\n\n[tool.uv]\n', "uv.lock": b""})
    assert found == [Site("pyproject.toml", 4, 0, "uv"), Site("uv.lock", 1, 0, "uv")]
    poetry = match_rule("use poetry for dependencies.")
    assert poetry is not None
    following, contradicting = counts(poetry, found)
    assert following == 0
    assert contradicting >= 1
    assert "uv.lock" in {s.file for s in found if s.option not in poetry.preferred}


@pytest.mark.parametrize(
    ("path", "option"),
    [*sorted(LOCKFILES.items()), (f"{REQUIREMENTS_PREFIX}{REQUIREMENTS_SUFFIX}", "pip")],
)
def test_f3_9_a_single_managers_files_follow_its_rule(path: str, option: str) -> None:
    found = sites({path: b"", "setup.py": b"", "setup.cfg": b""})
    rule = match_rule(f"use {option} for dependencies.")
    assert rule is not None
    following, contradicting = counts(rule, found)
    assert following >= 1
    assert contradicting == 0


@pytest.mark.parametrize(
    "path",
    [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements_test.txt",
        "sub/requirements.txt",
        "a/b/requirements.txt",  # only the final component is the name
    ],
)
def test_every_requirements_txt_is_a_pip_site(path: str) -> None:
    assert sites({path: b"httpx\n"}) == [Site(path, 1, 0, REQUIREMENTS_OPTION)]


@pytest.mark.parametrize(
    "path",
    [
        "setup.py",
        "setup.cfg",
        "requirements.in",
        "dev-requirements.txt",
        "Pipfile",
        "x.lock",
        "Pyproject.toml",  # the pyproject name is exact
        "pyproject.toml.bak",
        "old-pyproject.toml",
        "sub/pyproject.tom",
    ],
)
def test_other_files_are_not_evidence(path: str) -> None:
    assert list(manifest_sites({path: b"[tool.uv]\n"})) == []


@pytest.mark.parametrize("name", sorted(LOCKFILES))
def test_a_lockfile_is_evidence_without_being_parsed(name: str) -> None:
    for data in (b"", b"not toml [[[", b"\x00\xff binary", b"k = " + b"[" * 2000):
        assert sites({f"pkg/{name}": data}) == [Site(f"pkg/{name}", 1, 0, LOCKFILES[name])]


def test_a_lockfile_with_another_managers_table_inside_is_still_only_its_own_site() -> None:
    assert sites({"uv.lock": b"[tool.poetry]\n"}) == [Site("uv.lock", 1, 0, "uv")]


def test_sites_come_in_path_order_then_table_name_order() -> None:
    files = {
        "z/requirements.txt": b"",
        "pyproject.toml": b"[tool.uv]\n[tool.poetry]\n[tool.pdm]\n",
        "a/uv.lock": b"",
    }
    assert list(manifest_sites(files)) == [
        Site("a/uv.lock", 1, 0, "uv"),
        Site("pyproject.toml", 3, 0, "pdm"),
        Site("pyproject.toml", 2, 0, "poetry"),
        Site("pyproject.toml", 1, 0, "uv"),
        Site("z/requirements.txt", 1, 0, "pip"),
    ]


EVIDENCE_IN_ORDER = (
    ("uv.lock", b""),
    ("pyproject.toml", b"[tool.uv]\n"),
    ("sub/uv.lock", b""),
)


@pytest.mark.parametrize("count", range(1, len(EVIDENCE_IN_ORDER) + 1))
def test_one_to_three_sites_are_insufficient_data_at_the_default_minimum(count: int) -> None:
    # AC-F3.9 known v1 limit (D-PM-10): a repo's evidence rarely reaches min-sites.
    assert count < DEFAULT_THRESHOLDS.min_sites
    found = sites(dict(EVIDENCE_IN_ORDER[:count]))
    rule = match_rule("use uv for dependencies.")
    assert rule is not None
    following, contradicting = counts(rule, found)
    assert (following, contradicting) == (count, 0)
    overall = Counts(following=following, contradicting=contradicting, relevant=count)
    verdict = decide(verifiable=True, overall=overall, recent=None, thresholds=DEFAULT_THRESHOLDS)
    assert verdict is Verdict.INSUFFICIENT


@pytest.mark.parametrize("name", sorted(TOOL_TABLES))
def test_each_manager_table_is_a_site_at_its_header(name: str) -> None:
    data = f'[project]\nname = "x"\n[tool.{name}]\nk = 1\n'.encode()
    assert sites({"sub/pyproject.toml": data}) == [Site("sub/pyproject.toml", 3, 0, name)]


def test_all_three_tables_in_one_pyproject_are_three_sites() -> None:
    data = b"[tool.pdm]\n[tool.poetry.dependencies]\n[[tool.uv.index]]\nurl = 'x'\n"
    assert sites({"pyproject.toml": data}) == [
        Site("pyproject.toml", 1, 0, "pdm"),
        Site("pyproject.toml", 2, 0, "poetry"),
        Site("pyproject.toml", 3, 0, "uv"),
    ]


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("[tool.uv]\n", 1),
        ("\n\n  [ tool . uv ]\n", 3),
        ("x = 1\n[tool.uv.sources]\n", 2),
        ("x = 1\n[[tool.uv.index]]\n", 2),
        ('x = 1\n[tool."uv"]\n', 2),
        ("x = 1\n[tool.'uv']\n", 2),
        ("a = 1\r\nb = 2\r\n[tool.uv]\r\n", 3),
        ("# [tool.uv]\n[tool.uvx]\n[tool.uv-extra]\n[tool.uv]\n", 4),
        ("[tool]\nuv.k = 1\n", 1),  # dotted keys: no header, line 1
        ("tool = { uv = { k = 1 } }\n", 1),  # inline table: line 1
        ("x = 1\fy\n[tool.uv]\n", 2),  # only \n ends a line
    ],
)
def test_header_line_finds_the_first_table_header(text: str, line: int) -> None:
    assert header_line(text, "uv") == line


@pytest.mark.parametrize(
    ("data", "tables"),
    [
        (b"[tool.uv]\n", frozenset({"uv"})),
        (b"\xef\xbb\xbf[tool.uv]\n", frozenset({"uv"})),  # a UTF-8 BOM is allowed
        (b"[tool]\nuv.k = 1\npoetry = 1\n", frozenset({"uv"})),  # not a table: not evidence
        (b"tool = 1\n", frozenset()),
        (b"[project]\nname = 'x'\n", frozenset()),
        (b"[tool.black]\n", frozenset()),
        (b"", frozenset()),
    ],
)
def test_tool_tables_reads_only_manager_tables(data: bytes, tables: frozenset[str]) -> None:
    assert tool_tables(data) == tables


def test_a_dotted_key_table_is_a_site_at_line_1() -> None:
    assert sites({"pyproject.toml": b"[tool]\nuv.k = 1\n"}) == [Site("pyproject.toml", 1, 0, "uv")]


# --- hostile manifests never raise (SR; I-9 "manifest parse error") ----------------------


def _digit_limit() -> int:
    """The running interpreter's int-to-str digit limit (D-TL-25).

    Every supported Python (requires-python >= 3.11) has one, so there is no skip branch; it is
    only 0 when ``PYTHONINTMAXSTRDIGITS=0`` turns it off, which the suite does not support.
    """
    limit = sys.get_int_max_str_digits()
    assert limit > 0, "run the tests with the default int-to-str digit limit"
    return limit


def _nested(depth: int, opening: str, closing: str) -> bytes:
    return ("[tool.uv]\nk = " + opening * depth + "1" + closing * depth + "\n").encode()


HOSTILE: dict[str, Callable[[], bytes]] = {
    "arrays 1000 deep": lambda: _nested(1000, "[", "]"),
    "inline tables 1000 deep": lambda: _nested(1000, "{a=", "}"),
    "arrays past the recursion limit": lambda: _nested(sys.getrecursionlimit() * 2, "[", "]"),
    "integer over the digit limit": lambda: (
        "[tool.uv]\nk = " + "9" * (_digit_limit() + 1) + "\n"
    ).encode(),
    "malformed toml": lambda: b"[tool.uv\n",
    "binary (NUL)": lambda: b"[tool.uv]\n\x00\n",
    "latin-1": lambda: '[tool.uv]\nname = "caf\xe9"\n'.encode("latin-1"),
    "utf-16 with bom": lambda: "[tool.uv]\n".encode("utf-16"),
    "lone surrogate bytes": lambda: b"[tool.uv]\nk = '\xed\xa0\x80'\n",
}


@pytest.mark.parametrize("kind", HOSTILE)
def test_an_unreadable_pyproject_gives_no_sites_and_never_raises(kind: str) -> None:
    data = HOSTILE[kind]()
    assert tool_tables(data) is None
    assert list(manifest_sites({"pyproject.toml": data})) == []
    # The checker keeps working: the other manifests' sites are still reported.
    assert sites({"pyproject.toml": data, "uv.lock": b""}) == [Site("uv.lock", 1, 0, "uv")]


@pytest.mark.parametrize(
    "kind", ["arrays 1000 deep", "integer over the digit limit", "binary (NUL)", "latin-1"]
)
def test_c4_lists_an_unreadable_pyproject_as_skipped_and_the_checker_never_sees_it(
    kind: str,
) -> None:
    found = run({"AGENTS.md": b"r", "a.py": PY, "pyproject.toml": HOSTILE[kind](), "uv.lock": b""})
    assert [s.path for s in found.skipped] == ["pyproject.toml"]
    if kind in ("arrays 1000 deep", "integer over the digit limit"):
        assert found.skipped == (SkippedFile("pyproject.toml", REASON_MANIFEST_PARSE),)
    assert sites({m.path: m.data for m in found.manifest_files}) == [Site("uv.lock", 1, 0, "uv")]


# --- linear time (R2.5) ---------------------------------------------------------------------

HOSTILE_PYPROJECTS: dict[str, Callable[[int], bytes]] = {
    "near-miss headers": lambda n: b"[tool]\nuv.k = 1\n" + b"#[tool.uvx]\n" * (n // 12),
    "whitespace runs": lambda n: b"[tool]\nuv.k = 1\n" + b" " * (n // 2) + b"\n[" + b" " * (n // 2),
    "many keys": lambda n: b"[tool.uv]\n" + b"".join(b"k%d = 1\n" % i for i in range(n // 12)),
}


@pytest.mark.timing
@pytest.mark.parametrize("kind", HOSTILE_PYPROJECTS)
def test_manifest_sites_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    assert_linear(
        HOSTILE_PYPROJECTS[kind],
        lambda data: list(manifest_sites({"pyproject.toml": data})),
        label=kind,
    )
