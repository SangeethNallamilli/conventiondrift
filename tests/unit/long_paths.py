"""Trees with paths longer than ``PATH_MAX``, for tests (D-TL-78 #5, #76 B1, #77 B1).

Test tooling only. :func:`build_tree` makes every folder and file through ``dir_fd``,
one name at a time, so no path the OS is given is longer than one folder chain step or
one file's path below the chain, however deep the tree is. POSIX only (``dir_fd``).

One rule for filesystems that refuse such a tree (REVIEW-LOG, recurring #76 B1 and
#77 B1): the git-minimum container's filesystem stops at about 8,000 characters of path,
and some refuse 255-character names. :func:`build_or_skip` skips the test only on
``ENAMETOOLONG``, and only where :data:`MUST_BUILD_LONG_PATHS` is false: the
git-minimum container (``GIT_MIN_VERSION`` set) and local runs. On the ubuntu and macOS
CI legs, and for any other error, the test fails. A test that does not need to pass
8,000 characters should size its tree to clear ``PATH_MAX`` (4,096) and stay under
8,000 instead, so it runs everywhere.
"""

from __future__ import annotations

import errno
import os
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest

MUST_BUILD_LONG_PATHS = (
    bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    and sys.platform in ("linux", "darwin")
    and not os.environ.get("GIT_MIN_VERSION")
)
"""True on the ubuntu and macOS CI legs, which must build every long-path tree."""

CONTAINER_PATH_LIMIT = 8_000  # about where the git-minimum container's filesystem stops


def build_tree(root: Path, chain: Sequence[str], files: Iterable[str]) -> None:
    """Make the folders ``chain`` under ``root``, each inside the one before, then each
    of ``files`` (``/``-separated, relative to the last folder of the chain, folders
    made as needed) as an empty file."""
    fd = os.open(root, os.O_RDONLY)
    try:
        for name in chain:
            os.mkdir(name, dir_fd=fd)
            inner = os.open(name, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = inner
        made: set[str] = set()
        for rel in files:
            parts = rel.split("/")
            for k in range(1, len(parts)):
                folder = "/".join(parts[:k])
                if folder not in made:
                    os.mkdir(folder, dir_fd=fd)
                    made.add(folder)
            os.close(os.open(rel, os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=fd))
    finally:
        os.close(fd)


def build_or_skip(root: Path, chain: Sequence[str], files: Iterable[str]) -> None:
    """:func:`build_tree`, skipping the test only as the module docstring says."""
    try:
        build_tree(root, chain, files)
    except OSError as e:
        # The limit comes from the filesystem, not the OS, so only ENAMETOOLONG may skip.
        if e.errno != errno.ENAMETOOLONG or MUST_BUILD_LONG_PATHS:
            raise
        pytest.skip(f"this filesystem refuses the tree's long names or paths: {e}")
