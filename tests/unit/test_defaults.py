"""Unit tests for conventiondrift.defaults (INTERFACES I-13 "C5 rulings (T-012, SE1)").

Expected values are copied from DESIGN §10, not from the code.
"""

import ast
from pathlib import Path

import conventiondrift.defaults as defaults_module
from conventiondrift.defaults import DEFAULT_EXCLUDES


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
