"""Unit tests for conventiondrift.defaults (INTERFACES I-13 "C5 rulings (T-012, SE1)").

Expected values are copied from DESIGN §10, not from the code.
"""

import ast
from pathlib import Path

import pytest

import conventiondrift.defaults as defaults_module
from conventiondrift.defaults import DEFAULT_EXCLUDES
from conventiondrift.discover.globmatch import GlobSet


def test_default_excludes_cover_design_list_without_hard_excludes() -> None:
    # DESIGN §10 "Default excludes" glob entries; folder patterns match at any depth.
    design = {
        ".venv/", "venv/", ".tox/", ".nox/", "vendor/", "_vendor/", "third_party/",
        "build/", "dist/", "*.egg-info/", "__pycache__/", "site-packages/",
        "migrations/", "**/alembic/versions/", "*_pb2.py", "*_pb2_grpc.py",
    }  # fmt: skip
    assert set(DEFAULT_EXCLUDES) == design
    assert len(DEFAULT_EXCLUDES) == len(design)
    # I-13: hard excludes are applied by C4 and are not listed.
    assert not {".git/", "node_modules/"} & set(DEFAULT_EXCLUDES)


def test_defaults_module_imports_nothing_from_policy_or_discover() -> None:
    # Architect ruling: constants only, no imports from policy/ or discover/.
    tree = ast.parse(Path(defaults_module.__file__).read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert imported  # the walk saw the module's imports
    for name in imported:
        assert not name.startswith("conventiondrift"), name


def _inner_segments(pattern: str) -> list[str]:
    return [part for part in pattern.rstrip("/").split("/") if part]


def test_multi_segment_defaults_start_with_double_star() -> None:
    # Architect ruling (PLAN, "Architect rulings, 12:45 ET"): a single-segment pattern matches at
    # any depth; a multi-segment pattern needs a leading "**/" to do the same.
    multi = [p for p in DEFAULT_EXCLUDES if len(_inner_segments(p)) > 1]
    assert multi == ["**/alembic/versions/"]
    assert all(p.startswith("**/") for p in multi)


@pytest.mark.parametrize("pattern", DEFAULT_EXCLUDES)
def test_every_default_excludes_at_the_root_and_at_depth(pattern: str) -> None:
    name = pattern.rstrip("/").removeprefix("**/")
    # Turn the glob's wildcard into a concrete name; a trailing "/" means a folder.
    concrete = name.replace("*", "x")
    path = f"{concrete}/file.py" if pattern.endswith("/") else concrete
    excludes = GlobSet(DEFAULT_EXCLUDES)
    assert excludes.excludes(path)
    assert excludes.excludes(f"a/b/{path}")


@pytest.mark.parametrize(
    "path",
    [
        "migrations/0001_initial.py",
        "app/db/migrations/0001_initial.py",
        "alembic/versions/abc.py",
        "app/alembic/versions/abc.py",
        "a/b/c/alembic/versions/abc.py",
    ],
)
def test_migration_defaults_exclude(path: str) -> None:
    assert GlobSet(DEFAULT_EXCLUDES).excludes(path)


@pytest.mark.parametrize(
    "path",
    [
        "versions/abc.py",
        "alembic/env.py",
        "xalembic/versions/abc.py",
        "app/legacy_migrations/0001.py",
        "src/migration.py",
    ],
)
def test_migration_defaults_do_not_exclude_lookalikes(path: str) -> None:
    assert not GlobSet(DEFAULT_EXCLUDES).excludes(path)
