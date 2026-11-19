"""Static check: ``components.py`` imports no implementation package (I-13 C6 item 5).

The Protocols are the contract between components, so they may name only the shared types:
``model`` and the ``Checker`` Protocol's own module. The types C6 hands out live in ``model``
with no re-export from ``rules``.
"""

import ast
from pathlib import Path

import pytest

from conventiondrift.rules import conflicts, extract, mapping

SRC = Path(__file__).resolve().parents[2] / "src" / "conventiondrift"
ALLOWED = frozenset({"conventiondrift.model", "conventiondrift.checkers.base"})
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
