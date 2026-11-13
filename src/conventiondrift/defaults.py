"""Shared default constants (Architect ruling, INTERFACES I-13 "C5 rulings (T-012, SE1)").

Constants only: this module imports nothing from ``policy/`` or ``discover/``, so
C4 (discovery, T-010a) and C5 (policy) can both import from it. The two content
rules (a folder holding ``pyvenv.cfg``, the generated-file header) and the hard
``.git/`` and ``node_modules/`` exclusions are not globs: C4 applies them in every
mode and they are not listed here (I-13 ``Policy.excludes``).
"""

from __future__ import annotations

from typing import Final

__all__ = ["DEFAULT_EXCLUDES"]

DEFAULT_EXCLUDES: Final = (
    ".venv/",
    "venv/",
    ".tox/",
    ".nox/",
    "vendor/",
    "_vendor/",
    "third_party/",
    "build/",
    "dist/",
    "*.egg-info/",
    "__pycache__/",
    "site-packages/",
    "migrations/",
    "**/alembic/versions/",
    "*_pb2.py",
    "*_pb2_grpc.py",
)
"""DESIGN §10 default excludes as gitignore-style globs; every folder matches at any depth."""
