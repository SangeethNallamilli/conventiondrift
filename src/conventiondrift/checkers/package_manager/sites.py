"""``manifest_sites`` for the package-manager checker (INTERFACES I-10; FEASIBILITY F-4).

One site is one evidence file or one evidence table (F-4, D-PM-10):

* a lockfile (``poetry.lock``, ``uv.lock``, ``pdm.lock``), at line 1: its presence is the
  evidence, so it is never parsed;
* a ``requirements*.txt`` file, at line 1, for pip;
* a manager table in ``pyproject.toml`` (``[tool.poetry]``, ``[tool.uv]``, ``[tool.pdm]``),
  at the line of its first table header, or line 1 when the table is written another way
  (dotted keys or an inline table).

``pyproject.toml`` is parsed with stdlib ``tomllib``. C4 already skips an undecodable,
binary or unparsable one as a ``SkippedFile`` (I-9 "manifest parse error", D-TL-65 #6),
and ``manifest_sites`` cannot report skips, so a file that still fails here gives no sites
and never raises: a deeply nested document (``RecursionError``), an integer longer than the
interpreter's digit limit (``ValueError``) and malformed TOML (``TOMLDecodeError``, also a
``ValueError``) are all caught. ``setup.py`` and ``setup.cfg`` are not evidence (F-4).
"""

import re
import tomllib
from collections.abc import Iterator, Mapping
from typing import Final

from conventiondrift.model import Site

__all__ = [
    "LOCKFILES",
    "PYPROJECT",
    "REQUIREMENTS_OPTION",
    "REQUIREMENTS_PREFIX",
    "REQUIREMENTS_SUFFIX",
    "TOOL_TABLES",
    "header_line",
    "manifest_sites",
    "tool_tables",
]

LOCKFILES: Final = {"poetry.lock": "poetry", "uv.lock": "uv", "pdm.lock": "pdm"}
"""Each lockfile basename and the manager it is evidence for."""

TOOL_TABLES: Final = frozenset({"poetry", "uv", "pdm"})
"""Manager tables under ``[tool]`` in ``pyproject.toml``; each name is also its option."""

PYPROJECT: Final = "pyproject.toml"
REQUIREMENTS_PREFIX: Final = "requirements"
REQUIREMENTS_SUFFIX: Final = ".txt"
REQUIREMENTS_OPTION: Final = "pip"

_HEADERS: Final = {
    name: re.compile(
        rf"""[ \t]*\[\[?[ \t]*tool[ \t]*\.[ \t]*(?:{name}|"{name}"|'{name}')[ \t]*[.\]]"""
    )
    for name in TOOL_TABLES
}
"""A ``[tool.<name>]``, ``[tool.<name>.x]`` or ``[[tool.<name>.x]]`` header at a line start.
Bounded runs only, matched once per line, so each line costs linear time (R2.5)."""


def tool_tables(data: bytes) -> frozenset[str] | None:
    """The manager tables under ``[tool]``, or None when the TOML is unreadable."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    try:
        doc = tomllib.loads(text)
    except (ValueError, RecursionError):
        return None
    tool = doc.get("tool")
    if not isinstance(tool, dict):
        return frozenset()
    return frozenset(name for name in TOOL_TABLES if isinstance(tool.get(name), dict))


def header_line(text: str, name: str) -> int:
    """The 1-based line of the first header of table ``tool.<name>``, else 1.

    Lines are split at ``\\n`` only, the TOML newline (``\\r\\n`` ends in it too).
    """
    pattern = _HEADERS[name]
    for number, line in enumerate(text.split("\n"), start=1):
        if pattern.match(line):
            return number
    return 1


def _pyproject_sites(path: str, data: bytes) -> Iterator[Site]:
    tables = tool_tables(data)
    if not tables:
        return
    text = data.decode("utf-8-sig")
    for name in sorted(tables):
        yield Site(path, header_line(text, name), 0, name)


def manifest_sites(files: Mapping[str, bytes]) -> Iterator[Site]:
    """Every evidence site in ``files`` ({repo-relative path: bytes}), in path order."""
    for path in sorted(files):
        name = path.rsplit("/", 1)[-1]
        if name in LOCKFILES:
            yield Site(path, 1, 0, LOCKFILES[name])
        elif name.startswith(REQUIREMENTS_PREFIX) and name.endswith(REQUIREMENTS_SUFFIX):
            yield Site(path, 1, 0, REQUIREMENTS_OPTION)
        elif name == PYPROJECT:
            yield from _pyproject_sites(path, files[path])
