"""Unit tests for manifest discovery and console-script entry points (T-010c, A-4)."""

from __future__ import annotations

import sys
import tomllib
from collections.abc import Callable

import pytest
from checker_support import LINEAR_SIZES, assert_linear
from test_discover_tree import PHASE, PY, SHA, FakeGit, names, run

from conventiondrift.core import BasePhaseDone
from conventiondrift.discover import discover_tree, is_manifest_name
from conventiondrift.discover.entrypoints import (
    LOCKFILE_NAMES,
    MANIFEST_NAMES,
    REASON_MANIFEST_PARSE,
    _mapping,
    entry_points_from_scripts,
    manifest_kind,
    project_dir,
    scripts_from_toml,
)
from conventiondrift.discover.entrypoints import (
    is_manifest_name as entrypoints_is_manifest_name,
)
from conventiondrift.discover.safefs import (
    FILE_MAX_BYTES,
    REASON_BINARY,
    REASON_NOT_DECODABLE,
    REASON_SIZE,
    REASON_SYMLINK,
)
from conventiondrift.model import ManifestFile, SkippedFile, SkipReason

# The inventory pinned so a silent edit of the constant fails (D-TL-25).
_MANIFEST_NAMES = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
    }
)
_LOCKFILE_NAMES = frozenset({"poetry.lock", "uv.lock", "pdm.lock"})


def _scripts(body: str) -> bytes:
    return f"[project.scripts]\ncli = {body}\n".encode()


def test_the_manifest_names_are_the_package_manager_inventory() -> None:
    assert MANIFEST_NAMES == _MANIFEST_NAMES
    assert LOCKFILE_NAMES == _LOCKFILE_NAMES
    assert LOCKFILE_NAMES <= MANIFEST_NAMES
    assert is_manifest_name is entrypoints_is_manifest_name


@pytest.mark.parametrize(
    "path",
    [
        "pyproject.toml",
        "pkg/pyproject.toml",
        "setup.py",
        "src/setup.cfg",
        "requirements.txt",
        "requirements-dev.txt",
        "reqs/requirements_test.txt",
        "poetry.lock",
        "uv.lock",
        "app/pdm.lock",
    ],
)
def test_each_inventory_name_is_a_manifest(path: str) -> None:
    assert is_manifest_name(path)
    assert manifest_kind(path) in {"manifest", "lockfile"}
    if path.rsplit("/", 1)[-1] in LOCKFILE_NAMES:
        assert manifest_kind(path) == "lockfile"
    else:
        assert manifest_kind(path) == "manifest"


def test_manifest_kind_uses_only_the_final_component() -> None:
    # A first-slash split would mis-classify a lock two folders down.
    assert manifest_kind("pkg/app/uv.lock") == "lockfile"
    assert manifest_kind("pkg/app/pyproject.toml") == "manifest"


@pytest.mark.parametrize(
    "path",
    [
        "AGENTS.md",
        "a.py",
        "Pipfile",
        "Pipfile.lock",
        "requirements.in",
        "Requirements.txt",  # names are case-sensitive, like S6
        "my-requirements.txt",
        "requirements.txt.bak",
        "requirements",
        "poetry.toml",
        "setup.pyi",
        "pyproject.tml",
    ],
)
def test_other_basenames_are_not_manifests(path: str) -> None:
    assert not is_manifest_name(path)


def test_every_inventory_name_in_scope_is_discovered_and_sorted() -> None:
    files: dict[str, bytes] = {
        "AGENTS.md": b"r",
        "zz/requirements-dev.txt": b"flask\n",
        "pyproject.toml": b"[project]\n",
        "setup.cfg": b"[metadata]\n",
        "setup.py": b"from setuptools import setup\n",
        "requirements.txt": b"httpx\n",
        "poetry.lock": b"[[package]]\n",
        "uv.lock": b"version = 1\n",
        "app/pdm.lock": b"# pdm\n",
        "NOTES.toml": b"[project]\n",
        "a.py": PY,
    }
    found = run(files)
    assert [m.path for m in found.manifest_files] == [
        "app/pdm.lock",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "setup.cfg",
        "setup.py",
        "uv.lock",
        "zz/requirements-dev.txt",
    ]
    assert all(
        isinstance(m, ManifestFile) and m.data == files[m.path] for m in found.manifest_files
    )
    # setup.py is also a .py file in scope, so it is kept as Python too (read as text for the
    # manifest, never executed).
    assert "setup.py" in names(found)[1]
    assert found.skipped == ()


def test_manifests_follow_instruction_scope_like_python_files() -> None:
    files = {
        "services/billing/CLAUDE.md": b"r",
        "services/billing/pyproject.toml": b"[project]\n",
        "services/billing/uv.lock": b"v\n",
        "services/web/pyproject.toml": b"[project]\n",
        "pyproject.toml": b"[project]\n",
        "services/billing/a.py": PY,
        "services/web/b.py": PY,
    }
    found = run(files)
    assert names(found) == (["services/billing/CLAUDE.md"], ["services/billing/a.py"])
    assert [m.path for m in found.manifest_files] == [
        "services/billing/pyproject.toml",
        "services/billing/uv.lock",
    ]


def test_default_excludes_and_hard_excludes_drop_manifests_silently() -> None:
    files = {
        "AGENTS.md": b"r",
        "pyproject.toml": b"[project]\n",
        "vendor/pyproject.toml": b"[project]\n",
        ".venv/pyproject.toml": b"[project]\n",
        "node_modules/pkg/pyproject.toml": b"[project]\n",
        ".git/pyproject.toml": b"[project]\n",
        "a.py": PY,
    }
    git = FakeGit(files)
    found = discover_tree(PHASE, git, SHA)
    assert [m.path for m in found.manifest_files] == ["pyproject.toml"]
    assert found.skipped == ()
    assert "vendor/pyproject.toml" not in git.blobs
    assert ".venv/pyproject.toml" not in git.blobs
    assert "node_modules/pkg/pyproject.toml" not in git.blobs
    assert ".git/pyproject.toml" not in git.blobs


def test_a_paths_given_instruction_set_still_discovers_in_scope_manifests() -> None:
    files = {
        "AGENTS.md": b"root",
        "docs/RULES.md": b"r",
        "docs/pyproject.toml": b"[project]\n",
        "pyproject.toml": b"[project]\n",
        "a.py": PY,
    }
    found = run(files, paths=["docs/RULES.md"])
    assert names(found) == (["docs/RULES.md"], ["a.py"])
    # AC-F9.2: a non-S6 paths entry scopes to the whole repo (A-6), so root and docs manifests.
    assert [m.path for m in found.manifest_files] == ["docs/pyproject.toml", "pyproject.toml"]


def test_console_scripts_resolve_under_the_manifest_folder_including_src() -> None:
    toml = b"""
[project.scripts]
rootmod = "pkg.cli:main"
pkgmod = "app.tool:run"
srcmod = "pack.cmd:main"
initmod = "ns.mod:main"
srcinit = "ns2.mod:main"
missing = "no.such:main"
notaref = "just_a_name"
"""
    files = {
        "AGENTS.md": b"r",
        "pyproject.toml": toml,
        "pkg/cli.py": PY,
        "src/pack/cmd.py": PY,
        "ns/mod/__init__.py": PY,
        "src/ns2/mod/__init__.py": PY,
        "other.py": PY,
    }
    found = run(files)
    assert found.entry_points == frozenset(
        {"pkg/cli.py", "src/pack/cmd.py", "ns/mod/__init__.py", "src/ns2/mod/__init__.py"}
    )
    # "app.tool" is not among the discovered files.
    assert "app/tool.py" not in found.entry_points


def test_a_nested_pyproject_resolves_only_under_its_folder() -> None:
    files = {
        "services/a/CLAUDE.md": b"r",
        "services/a/pyproject.toml": b'[project.scripts]\ncli = "pkg.cli:main"\n',
        "services/a/src/pkg/cli.py": PY,
        "pkg/cli.py": PY,  # same suffix, but outside the manifest folder and out of scope
        "services/a/other.py": PY,
    }
    found = run(files)
    assert found.entry_points == frozenset({"services/a/src/pkg/cli.py"})
    assert [m.path for m in found.manifest_files] == ["services/a/pyproject.toml"]


def test_poetry_string_and_callable_tables_are_both_read() -> None:
    toml = b"""
[tool.poetry.scripts]
plain = "pkg.a:main"
table = { callable = "pkg.b:main", extras = ["dev"] }
ignored = 1
empty = { extras = ["dev"] }
"""
    files = {
        "AGENTS.md": b"r",
        "pyproject.toml": toml,
        "pkg/a.py": PY,
        "pkg/b.py": PY,
        "pkg/c.py": PY,
    }
    found = run(files)
    assert found.entry_points == frozenset({"pkg/a.py", "pkg/b.py"})


def test_project_scripts_and_poetry_scripts_are_unioned() -> None:
    toml = b"""
[project.scripts]
one = "pkg.a:main"
[tool.poetry.scripts]
two = "pkg.b:main"
"""
    files = {"AGENTS.md": b"r", "pyproject.toml": toml, "pkg/a.py": PY, "pkg/b.py": PY}
    found = run(files)
    assert found.entry_points == frozenset({"pkg/a.py", "pkg/b.py"})


def test_a_module_py_is_preferred_over_its_package_init() -> None:
    files = {
        "AGENTS.md": b"r",
        "pyproject.toml": b'[project.scripts]\ncli = "pkg.mod:main"\n',
        "pkg/mod.py": PY,
        "pkg/mod/__init__.py": PY,
    }
    found = run(files)
    assert found.entry_points == frozenset({"pkg/mod.py"})


def test_a_toml_parse_error_skips_the_manifest_and_does_not_fail() -> None:
    files = {
        "AGENTS.md": b"r",
        "pyproject.toml": b"[project.scripts\ncli = broken\n",
        "pkg/cli.py": PY,
        "requirements.txt": b"httpx\n",
    }
    found = run(files)
    assert found.skipped == (SkippedFile("pyproject.toml", REASON_MANIFEST_PARSE),)
    assert [m.path for m in found.manifest_files] == ["requirements.txt"]
    assert found.entry_points == frozenset()
    assert names(found)[1] == ["pkg/cli.py"]


def test_malformed_script_values_are_ignored_on_a_well_formed_document() -> None:
    files = {
        "AGENTS.md": b"r",
        "pyproject.toml": b"[project.scripts]\ncli = 1\nname = { extras = [] }\n",
        "pkg/cli.py": PY,
    }
    found = run(files)
    assert [m.path for m in found.manifest_files] == ["pyproject.toml"]
    assert found.entry_points == frozenset()
    assert found.skipped == ()


def test_an_oversize_or_binary_or_symlink_manifest_is_skipped_with_its_reason() -> None:
    git = FakeGit(
        {
            "AGENTS.md": b"r",
            "pyproject.toml": b"x" * (FILE_MAX_BYTES + 1),
            "requirements.txt": b"a\x00b",
            "uv.lock": ("120000", b"target"),
            "setup.cfg": b"ok\n",
            "a.py": PY,
        }
    )
    found = discover_tree(PHASE, git, SHA)
    assert {(s.path, s.reason) for s in found.skipped} == {
        ("pyproject.toml", "size limit"),
        ("requirements.txt", "binary"),
        ("uv.lock", "symlink"),
    }
    assert [m.path for m in found.manifest_files] == ["setup.cfg"]
    assert "pyproject.toml" not in git.blobs
    assert "uv.lock" not in git.blobs


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (("120000", b"target"), REASON_SYMLINK),
        (b"x" * (FILE_MAX_BYTES + 1), REASON_SIZE),
        (b"a\x00b", REASON_BINARY),
        ("caf\u00e9\n".encode("latin-1"), REASON_NOT_DECODABLE),
    ],
    ids=["symlink", "size-limit", "binary", "latin-1"],
)
def test_a_setup_py_read_failure_is_skipped_once(
    payload: bytes | tuple[str, bytes], reason: SkipReason
) -> None:
    found = run({"AGENTS.md": b"r", "setup.py": payload, "a.py": PY})
    assert found.skipped == (SkippedFile("setup.py", reason),)
    assert found.manifest_files == ()
    assert "setup.py" not in names(found)[1]


def test_a_deep_in_scope_manifest_is_walk_limit_and_is_never_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from conventiondrift.discover import safefs

    monkeypatch.setattr(safefs, "WALK_MAX_DEPTH", 3)
    files = {
        "AGENTS.md": b"r",
        "a/b/c/e/pyproject.toml": b"[project]\n",
        "a/b/c/e/notes.txt": b"x",
        "a.py": PY,
    }
    git = FakeGit(files)
    found = discover_tree(PHASE, git, SHA)
    assert found.skipped == (SkippedFile("a/b/c/e/pyproject.toml", "walk limit"),)
    assert found.manifest_files == ()
    assert "a/b/c/e/pyproject.toml" not in git.blobs
    assert "a/b/c/e/notes.txt" not in git.blobs  # ruling 6: not a manifest, not reported


def test_an_out_of_scope_script_target_is_not_an_entry_point() -> None:
    # The module exists, but it is outside the instruction file's folder, so it is not
    # in py_files and cannot be resolved.
    files = {
        "services/a/CLAUDE.md": b"r",
        "services/a/pyproject.toml": b'[project.scripts]\ncli = "pkg.cli:main"\n',
        "pkg/cli.py": PY,
        "services/a/x.py": PY,
    }
    found = run(files)
    assert found.entry_points == frozenset()
    assert "pkg/cli.py" not in names(found)[1]


def test_scripts_from_toml_returns_false_only_for_unreadable_toml() -> None:
    assert scripts_from_toml("[project.scripts\n") is False
    assert scripts_from_toml("[project]\nname = 1\n") == []
    assert scripts_from_toml('[project.scripts]\ncli = "pkg.cli:main"\n') == ["pkg.cli:main"]


_NESTED_DEPTH = 1000


def _nested_array_toml(depth: int) -> str:
    return "k = " + "[" * depth + "1" + "]" * depth + "\n"


def _nested_inline_table_toml(depth: int) -> str:
    return "k = " + "{a=" * depth + "1" + "}" * depth + "\n"


def _tomllib_raises_recursion(text: str) -> bool:
    try:
        tomllib.loads(text)
    except RecursionError:
        return True
    except tomllib.TOMLDecodeError:
        return False
    return False


def _depths_for(builder: Callable[[int], str]) -> tuple[int, ...]:
    """About 1000, plus a deeper depth if this tomllib does not recurse at 1000."""
    depths = [_NESTED_DEPTH]
    if not _tomllib_raises_recursion(builder(_NESTED_DEPTH)):
        for depth in (sys.getrecursionlimit() + 200, sys.getrecursionlimit() * 2, 5000):
            if depth != _NESTED_DEPTH and _tomllib_raises_recursion(builder(depth)):
                depths.append(depth)
                break
    return tuple(depths)


def _assert_nested_pyproject_never_escapes(text: str) -> None:
    """A deeply nested document is a parse-error skip when tomllib recurses, and never raises."""
    result = scripts_from_toml(text)
    found = run({"AGENTS.md": b"r", "pyproject.toml": text.encode(), "a.py": PY})
    if result is False:
        assert found.skipped == (SkippedFile("pyproject.toml", REASON_MANIFEST_PARSE),)
        assert found.manifest_files == ()
        assert found.entry_points == frozenset()
        return
    assert result == []
    assert found.skipped == ()
    assert [m.path for m in found.manifest_files] == ["pyproject.toml"]


@pytest.mark.parametrize(
    "builder",
    [_nested_array_toml, _nested_inline_table_toml],
    ids=["arrays", "inline-tables"],
)
def test_a_pyproject_nested_about_1000_deep_is_skipped_not_raised(
    builder: Callable[[int], str],
) -> None:
    for depth in _depths_for(builder):
        _assert_nested_pyproject_never_escapes(builder(depth))


def _int_str_digit_limit() -> int:
    """0 when the interpreter has no limit or the limit is disabled."""
    getter = getattr(sys, "get_int_max_str_digits", None)
    if getter is None:
        return 0
    return int(getter())


def _assert_huge_int_pyproject_never_escapes(text: str, *, expect_skip: bool) -> None:
    """An oversized integer is a parse-error skip when the digit limit is active, never a raise."""
    result = scripts_from_toml(text)
    found = run({"AGENTS.md": b"r", "pyproject.toml": text.encode(), "a.py": PY})
    if expect_skip:
        assert result is False
        assert found.skipped == (SkippedFile("pyproject.toml", REASON_MANIFEST_PARSE),)
        assert found.manifest_files == ()
        assert found.entry_points == frozenset()
        return
    assert result == []
    assert found.skipped == ()
    assert [m.path for m in found.manifest_files] == ["pyproject.toml"]


def test_a_pyproject_with_an_integer_over_the_digit_limit_is_skipped_not_raised() -> None:
    # D-TL-25: the digit count is taken from the running interpreter's limit, not a magic 4301.
    limit = _int_str_digit_limit()
    digits = limit + 1 if limit > 0 else 4301
    _assert_huge_int_pyproject_never_escapes(
        "k = " + "9" * digits + "\n",
        expect_skip=limit > 0,
    )


def test_a_pyproject_with_a_5000_digit_integer_is_skipped_not_raised() -> None:
    limit = _int_str_digit_limit()
    _assert_huge_int_pyproject_never_escapes(
        "version = " + "1" * 5000 + "\n",
        expect_skip=0 < limit < 5000,
    )


def test_entry_points_from_scripts_skips_unresolvable_refs() -> None:
    py_paths = frozenset({"src/pkg/cli.py", "pkg/other.py"})
    assert entry_points_from_scripts(
        ["pkg.cli:main", "nope:main", "not a ref", "pkg.other:run"],
        py_paths,
        "pyproject.toml",
    ) == frozenset({"src/pkg/cli.py", "pkg/other.py"})
    assert project_dir("services/a/pyproject.toml") == "services/a"
    assert project_dir("pyproject.toml") == ""


@pytest.mark.timing
def test_script_resolution_is_linear_up_to_the_1_mib_cap() -> None:
    # One well-formed ref against a growing set of discovered paths: lookups are set membership.
    def make(n: int) -> tuple[list[str], frozenset[str]]:
        paths = frozenset(f"mod{i}/pkg/cli.py" for i in range(max(n, 1)))
        refs = ["pkg.cli:main"] * max(n, 1)
        return refs, paths | {"src/pkg/cli.py"}

    def run_it(pair: tuple[list[str], frozenset[str]]) -> int:
        return len(entry_points_from_scripts(pair[0], pair[1], "pyproject.toml"))

    assert_linear(make, run_it, sizes=LINEAR_SIZES, label="entry-points")


@pytest.mark.timing
def test_toml_script_parsing_is_linear_up_to_the_1_mib_cap() -> None:
    def make(n: int) -> str:
        # Repeat a valid table so the document grows with n; keep it valid TOML.
        row = 'cli{i} = "pkg.mod{i}:main"\n'
        # n is the size in bytes at LINEAR_SIZES (up to 1 MiB).
        body = ["[project.scripts]\n"]
        i = 0
        while sum(len(part) for part in body) < n:
            body.append(row.format(i=i))
            i += 1
        return "".join(body)

    def run_it(text: str) -> int:
        refs = scripts_from_toml(text)
        assert refs is not False
        return len(refs)

    assert_linear(make, run_it, sizes=LINEAR_SIZES, label="toml-scripts")


def test_invalid_module_object_refs_are_not_resolved() -> None:
    py_paths = frozenset({"cli.py", "pkg/cli.py"})
    assert (
        entry_points_from_scripts(
            [":main", ".:main", "pkg-name:main", "123bad:main", "pkg.:main"],
            py_paths,
            "pyproject.toml",
        )
        == frozenset()
    )


def test_a_mapping_guard_ignores_a_non_table() -> None:
    # tomllib always yields a dict; the helper still rejects a non-table value.
    assert _mapping(1, "project") == {}
    assert _mapping("tool", "poetry") == {}


def test_an_unsupported_manifest_path_is_skipped_and_not_kept() -> None:
    files = {"AGENTS.md": b"r", "CON/uv.lock": b"v\n", "a.py": PY}
    found = run(files)
    assert found.manifest_files == ()
    assert found.skipped == (SkippedFile("CON/uv.lock", "unsupported path"),)


def test_the_phase_token_is_still_required() -> None:
    files = {"AGENTS.md": b"r", "pyproject.toml": b"[project]\n"}
    assert discover_tree(BasePhaseDone(base_config_known=True), FakeGit(files), SHA).manifest_files
