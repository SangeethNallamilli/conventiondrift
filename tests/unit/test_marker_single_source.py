"""One definition of the I-3 sticky-comment marker (dev review risk R5).

C11 writes the marker as line 1 of every comment body and C12 compares it to decide "is this our
comment". Two literals would drift silently — a comment written with one and checked with the
other is never recognised, so every run posts a duplicate sticky comment. The marker is defined
once in ``model`` and both sites bind that object; these tests fail if either site grows its own
copy, even one equal to today's value.
"""

import ast
from pathlib import Path

import pytest

from conventiondrift import github, model
from conventiondrift.render import comment

SRC = Path(__file__).resolve().parents[2] / "src" / "conventiondrift"
MARKER_LITERAL = "<!-- conventiondrift:sticky v1 -->"
SHARED_NAME = "STICKY_COMMENT_MARKER"
SITES = (("github.py", "MARKER"), ("render/comment.py", "STICKY_MARKER"))


def _module_binding(tree: ast.Module, name: str) -> ast.expr | None:
    """The value of the module-level assignment (plain or annotated) that binds ``name``."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return node.value
    return None


def _binds_the_shared_constant(path: Path, name: str) -> bool:
    """True only when ``name`` is bound to the imported ``model.STICKY_COMMENT_MARKER`` object."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    value = _module_binding(tree, name)
    if not isinstance(value, ast.Name) or value.id != SHARED_NAME:
        return False
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "conventiondrift.model"
        and any(alias.name == SHARED_NAME for alias in node.names)
        for node in tree.body
    )


def _files_holding_the_literal(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if MARKER_LITERAL in path.read_text(encoding="utf-8")
    }


def test_the_marker_literal_lives_only_in_model() -> None:
    """One definition in ``src``; a copy anywhere else fails here."""
    assert _files_holding_the_literal(SRC) == {"model.py"}


def test_the_value_is_pinned() -> None:
    assert model.STICKY_COMMENT_MARKER == MARKER_LITERAL


def test_both_sites_reference_the_single_constant() -> None:
    """Identity, not equality: a literal copy is a different object even with the same text."""
    assert github.MARKER is model.STICKY_COMMENT_MARKER
    assert comment.STICKY_MARKER is model.STICKY_COMMENT_MARKER


@pytest.mark.parametrize(("relative", "name"), SITES, ids=[site[0] for site in SITES])
def test_each_site_binds_the_name_from_model(relative: str, name: str) -> None:
    assert _binds_the_shared_constant(SRC / relative, name)


def test_the_shared_marker_is_used_for_the_identity_check() -> None:
    """C12's "is ours" test and C11's line 1 must be the same object, not two equal strings."""
    body = f"{comment.STICKY_MARKER}\n## conventiondrift"
    assert github.MARKER in body.splitlines()
    assert github.MARKER is comment.STICKY_MARKER


@pytest.mark.parametrize(
    "body",
    [
        f'MARKER: Final = "{MARKER_LITERAL}"',
        'MARKER: Final = "<!-- conventiondrift:sticky v2 -->"',
        'MARKER = "<!-- conventiondrift:sticky v1 -->"',
    ],
    ids=["same_text_copy", "mutated_copy", "plain_assignment"],
)
def test_a_site_copy_is_detected(tmp_path: Path, body: str) -> None:
    """The check above is not vacuous: any literal copy, mutated or not, is caught."""
    planted = tmp_path / "planted.py"
    planted.write_text(body + "\n", encoding="utf-8")
    assert not _binds_the_shared_constant(planted, "MARKER")


def test_the_literal_scanner_sees_a_planted_definition(tmp_path: Path) -> None:
    planted = tmp_path / "extra.py"
    planted.write_text(f'MARKER: Final = "{MARKER_LITERAL}"\n', encoding="utf-8")
    assert _files_holding_the_literal(tmp_path) == {"extra.py"}
