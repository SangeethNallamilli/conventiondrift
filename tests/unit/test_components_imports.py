"""Static check: ``components.py`` imports no implementation package (I-13 C6 item 5).

The Protocols are the contract between components, so they may name only the shared types in
``model``. The ``Checker`` Protocol is defined in ``components`` (I-13 C6 item 8, moved by T-016),
so importing ``components`` never loads a checker. The types C6 hands out live in ``model``
with no re-export from ``rules``.
"""

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conventiondrift.rules import conflicts, extract, mapping

SRC = Path(__file__).resolve().parents[2] / "src" / "conventiondrift"
ALLOWED = frozenset({"conventiondrift.model"})
MOVED = ("Extraction", "FileRules", "ExtractedRule", "ConflictIndex")


def _first_party_imports(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names if a.name.split(".")[0] == "conventiondrift")
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                found.add("." * node.level + (node.module or ""))
            elif (node.module or "").split(".")[0] == "conventiondrift":
                found.add(node.module or "")
    return found


def test_components_imports_only_the_shared_types() -> None:
    imports = _first_party_imports((SRC / "components.py").read_text())
    assert imports  # the scanner found something to check
    assert imports <= ALLOWED, imports - ALLOWED


def test_components_gets_extraction_from_model() -> None:
    assert "Extraction" in (SRC / "components.py").read_text()
    assert "from conventiondrift.model import" in (SRC / "components.py").read_text()


def test_the_scanner_sees_every_form_of_import() -> None:
    source = (
        "import conventiondrift.rules.mapping\n"
        "import os\n"
        "from conventiondrift.rules import mapping\n"
        "from . import x\n"
        "from .rules.mapping import y\n"
    )
    assert _first_party_imports(source) == {
        "conventiondrift.rules.mapping",
        "conventiondrift.rules",
        ".",
        ".rules.mapping",
    }


def test_model_does_not_import_the_rules_package() -> None:
    imports = _first_party_imports((SRC / "model.py").read_text())
    assert not any(name.startswith("conventiondrift.rules") for name in imports)


@pytest.mark.parametrize("module", [mapping, extract, conflicts], ids=lambda m: m.__name__)
@pytest.mark.parametrize("name", MOVED)
def test_the_moved_types_are_not_re_exported(module: object, name: str) -> None:
    assert name not in module.__all__  # type: ignore[attr-defined]


def test_the_checker_protocol_is_defined_in_components_and_re_exported_by_base() -> None:
    from conventiondrift import components
    from conventiondrift.checkers import base

    assert components.Checker.__module__ == "conventiondrift.components"
    assert base.Checker is components.Checker
    assert "Checker" in base.__all__


def test_importing_components_loads_no_checker() -> None:
    code = (
        "import sys, conventiondrift.components\n"
        "print(sorted(m for m in sys.modules if m.startswith('conventiondrift.checkers')))"
    )
    env = {**os.environ, "PYTHONPATH": str(SRC.parent)}
    out = subprocess.run(  # noqa: S603 -- fixed argv, our own interpreter
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "[]"
