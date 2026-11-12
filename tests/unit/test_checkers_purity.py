"""Static purity ban for src/conventiondrift/checkers/ (INTERFACES I-10, ADR-0003; T-014).

Checkers and the C7 framework must not touch I/O or run code: nothing under
``checkers/`` may use ``exec``, ``eval``, ``compile``, ``importlib``,
``__import__``, ``subprocess``, ``socket``, ``open``, ``os`` or ``urllib``.
"""

import ast
from pathlib import Path

import pytest

# Written by hand from I-10 "Pure functions".
BANNED_CALLS = frozenset({"exec", "eval", "compile", "__import__", "open"})
BANNED_MODULES = frozenset({"importlib", "subprocess", "socket", "os", "urllib"})
I10_LIST = {
    "exec",
    "eval",
    "compile",
    "importlib",
    "__import__",
    "subprocess",
    "socket",
    "open",
    "os",
    "urllib",
}


def real_checkers_dir(test_file: str) -> Path:
    """The pristine ``src/conventiondrift/checkers`` for a test file at ``tests/unit/``.

    mutmut 3.x runs the suite from a ``mutants/`` copy of the project, so this
    file may itself sit under ``<project>/mutants/tests/unit/``. The last
    ``mutants`` segment is mutmut's copy root (a parent folder may share the
    name); dropping it gives the real tree, so the scan covers the real source
    and never the mutated copy (same mapping as #25 S2 in test_verdicts.py).
    The copy is used only when no pristine tree exists next to it.
    """
    root = Path(test_file).resolve().parents[2]
    found = root / "src" / "conventiondrift" / "checkers"
    parts = found.parts
    indexes = [i for i, part in enumerate(parts) if part == "mutants"]
    if not indexes:
        return found
    idx = indexes[-1]
    original = Path(*parts[:idx], *parts[idx + 1 :])
    return original if original.is_dir() else found


# Locate the real source tree from this test file, not from
# conventiondrift.checkers.__file__, which is the mutants/ copy under mutmut 3.x.
CHECKERS_DIR = real_checkers_dir(__file__)


def violations(source: str) -> list[str]:
    """Every banned use in ``source``: names (builtins) and imported modules."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name) and node.id in BANNED_CALLS:
            found.append(node.id)
        elif (
            isinstance(node, ast.Attribute)
            and node.attr in BANNED_CALLS
            and (isinstance(node.value, ast.Name) and node.value.id == "builtins")
        ):
            found.append(node.attr)
        elif isinstance(node, ast.Import):
            found.extend(
                a.name.split(".")[0] for a in node.names if a.name.split(".")[0] in BANNED_MODULES
            )
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if node.level == 0 and top in BANNED_MODULES:
                found.append(top)
            found.extend(a.name for a in node.names if a.name in BANNED_CALLS | BANNED_MODULES)
    return found


def test_the_ban_list_is_the_i10_list() -> None:
    assert BANNED_CALLS | BANNED_MODULES == I10_LIST


def test_the_scanned_checkers_directory_exists_and_is_not_empty() -> None:
    assert CHECKERS_DIR.is_dir()
    files = list(CHECKERS_DIR.rglob("*.py"))
    assert files


def _tree(base: Path) -> Path:
    test_file = base / "tests" / "unit" / "test_checkers_purity.py"
    checkers = base / "src" / "conventiondrift" / "checkers"
    test_file.parent.mkdir(parents=True)
    checkers.mkdir(parents=True)
    test_file.write_text("", encoding="utf-8")
    return test_file


def test_a_mutants_copy_maps_back_to_the_real_checkers_dir(tmp_path: Path) -> None:
    _tree(tmp_path / "proj")
    copied = _tree(tmp_path / "proj" / "mutants")
    expected = (tmp_path / "proj" / "src" / "conventiondrift" / "checkers").resolve()
    assert real_checkers_dir(str(copied)) == expected


def test_only_the_last_mutants_segment_is_mutmuts_copy_root(tmp_path: Path) -> None:
    _tree(tmp_path / "mutants" / "proj")
    copied = _tree(tmp_path / "mutants" / "proj" / "mutants")
    expected = (tmp_path / "mutants" / "proj" / "src" / "conventiondrift" / "checkers").resolve()
    assert real_checkers_dir(str(copied)) == expected


def test_a_plain_layout_is_used_as_it_is(tmp_path: Path) -> None:
    test_file = _tree(tmp_path / "proj")
    expected = (tmp_path / "proj" / "src" / "conventiondrift" / "checkers").resolve()
    assert real_checkers_dir(str(test_file)) == expected


def test_a_mutants_copy_without_a_pristine_tree_is_scanned_as_found(tmp_path: Path) -> None:
    copied = _tree(tmp_path / "proj" / "mutants")
    expected = (tmp_path / "proj" / "mutants" / "src" / "conventiondrift" / "checkers").resolve()
    assert real_checkers_dir(str(copied)) == expected


def test_checkers_package_has_no_banned_use() -> None:
    files = sorted(CHECKERS_DIR.rglob("*.py"))
    assert {p.name for p in files} >= {"__init__.py", "base.py", "walk.py", "pool.py"}
    bad = {
        str(p.relative_to(CHECKERS_DIR)): v
        for p in files
        if (v := violations(p.read_text("utf-8")))
    }
    assert bad == {}


# One planted use per banned item, each on its own (D-TL-25).
PLANTED = {
    "exec": "exec('x')",
    "eval": "eval('1')",
    "compile": "compile('1', 'f', 'eval')",
    "__import__": "__import__('json')",
    "open": "open('f')",
    "importlib": "import importlib.util",
    "subprocess": "from subprocess import run",
    "socket": "import socket",
    "os": "from os import path",
    "urllib": "import urllib.request",
}


def test_planted_cases_cover_the_ban_list() -> None:
    assert set(PLANTED) == I10_LIST


@pytest.mark.parametrize("name", sorted(PLANTED))
def test_each_banned_use_is_caught(name: str) -> None:
    assert violations(PLANTED[name]) == [name]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import builtins\nbuiltins.open('f')", ["open"]),
        ("from builtins import eval", ["eval"]),
        ("from . import os", ["os"]),
        ("f = exec", ["exec"]),
    ],
)
def test_indirect_forms_are_caught(source: str, expected: list[str]) -> None:
    assert violations(source) == expected


@pytest.mark.parametrize(
    "source",
    [
        "import re\nre.compile('x')",
        "import ast\nast.parse('1')",
        "x.open()",
        "import osx",
        "from .os_like import a",
    ],
)
def test_lookalikes_are_not_flagged(source: str) -> None:
    assert violations(source) == []
