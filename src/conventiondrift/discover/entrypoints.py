"""Manifest names and console-script entry points (DESIGN §12 A-4, T-010c).

C4 discovers the package-manager manifest names at any depth, then parses
``[project.scripts]`` and ``[tool.poetry.scripts]`` from each ``pyproject.toml``
with stdlib ``tomllib``. Each ``pkg.mod:func`` is resolved to a discovered
``.py`` path under that manifest's folder (``pkg/mod.py``, ``pkg/mod/__init__.py``,
and the same two under ``src/``). A TOML parse error is ``"manifest parse error"``
and never fails the run.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from typing import Final, Literal

from conventiondrift.discover.safefs import FileKind

__all__ = [
    "LOCKFILE_NAMES",
    "MANIFEST_NAMES",
    "REASON_MANIFEST_PARSE",
    "entry_points_from_scripts",
    "is_manifest_name",
    "manifest_kind",
    "project_dir",
    "scripts_from_toml",
]

REASON_MANIFEST_PARSE: Final = "manifest parse error"
"""I-9 skip reason when ``tomllib`` cannot read a ``pyproject.toml`` (A-4)."""

LOCKFILE_NAMES: Final = frozenset({"poetry.lock", "uv.lock", "pdm.lock"})
"""Basenames of lockfiles listed by the package-manager ACs (AC-F3.9) and SPEC §9.2."""

MANIFEST_NAMES: Final = frozenset(
    {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        *LOCKFILE_NAMES,
    }
)
"""Exact basenames in the package-manager inventory (SPEC §9.2 item 3, AC-F3.9).

``requirements*.txt`` is matched separately: any basename that starts with
``requirements`` and ends with ``.txt``.
"""

_REQUIREMENTS_PREFIX: Final = "requirements"
_REQUIREMENTS_SUFFIX: Final = ".txt"


def is_manifest_name(path: str) -> bool:
    """Whether the repo-relative path's final component is a package-manager manifest name."""
    name = path.rsplit("/", 1)[-1]
    if name in MANIFEST_NAMES or name in LOCKFILE_NAMES:
        return True
    return name.startswith(_REQUIREMENTS_PREFIX) and name.endswith(_REQUIREMENTS_SUFFIX)


def manifest_kind(path: str) -> FileKind:
    """``lockfile`` for the lock basenames, ``manifest`` for every other A-4 name."""
    name = path.rsplit("/", 1)[-1]
    return "lockfile" if name in LOCKFILE_NAMES else "manifest"


def project_dir(path: str) -> str:
    """The folder that holds ``path``, or ``""`` at the repo root."""
    return path.rpartition("/")[0]


def scripts_from_toml(text: str) -> list[str] | Literal[False]:
    """The ``module:object`` refs in the two A-4 tables, or False when the TOML is unreadable.

    A well-formed document that has no scripts, or that has a table whose values are not
    refs, yields an empty list: only a ``tomllib`` failure is a parse error. A document
    nested deeply enough to make ``tomllib`` raise ``RecursionError``, or an integer
    whose digits exceed the interpreter's conversion limit (``ValueError``), is also
    unreadable. ``TOMLDecodeError`` is a ``ValueError`` subclass, so both are caught.
    """
    try:
        doc = tomllib.loads(text)
    except (ValueError, RecursionError):
        return False
    refs: list[str] = []
    refs.extend(_table_refs(_mapping(doc, "project"), "scripts"))
    tool = _mapping(doc, "tool")
    refs.extend(_poetry_refs(_mapping(tool, "poetry").get("scripts")))
    return refs


def entry_points_from_scripts(
    refs: Iterable[str], py_paths: frozenset[str], manifest_path: str
) -> frozenset[str]:
    """Discovered ``.py`` paths the script refs resolve to, under this manifest's folder."""
    root = project_dir(manifest_path)
    found: set[str] = set()
    for ref in refs:
        module = _module_of(ref)
        if module is None:
            continue
        for candidate in _candidates(module, root):
            if candidate in py_paths:
                found.add(candidate)
                break
    return frozenset(found)


def _mapping(value: object, key: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        return {}
    inner = value.get(key)
    return inner if isinstance(inner, dict) else {}


def _table_refs(table: Mapping[str, object], key: str) -> list[str]:
    raw = table.get(key)
    if not isinstance(raw, dict):
        return []
    refs: list[str] = []
    for value in raw.values():
        ref = _ref_of(value)
        if ref is not None:
            refs.append(ref)
    return refs


def _poetry_refs(raw: object) -> list[str]:
    """Poetry accepts a string or a table with a ``callable`` key for each script."""
    if not isinstance(raw, dict):
        return []
    refs: list[str] = []
    for value in raw.values():
        ref = _ref_of(value)
        if ref is not None:
            refs.append(ref)
    return refs


def _ref_of(value: object) -> str | None:
    if isinstance(value, str):
        ref = value.strip()
        return ref or None
    if isinstance(value, dict):
        raw = value.get("callable")
        if isinstance(raw, str):
            ref = raw.strip()
            return ref or None
    return None


def _module_of(ref: str) -> str | None:
    module, sep, _func = ref.partition(":")
    if not sep:
        return None
    module = module.strip()
    parts = module.split(".")
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return module


def _candidates(module: str, root: str) -> tuple[str, ...]:
    rel = module.replace(".", "/")
    tails = (f"{rel}.py", f"{rel}/__init__.py", f"src/{rel}.py", f"src/{rel}/__init__.py")
    if not root:
        return tails
    return tuple(f"{root}/{tail}" for tail in tails)
