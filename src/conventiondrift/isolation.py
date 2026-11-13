"""Worker isolation for C7's spawn pool (INTERFACES I-13 C7 ruling 8, ADR-0002 Amendment 4).

C7's pool processes must import only the installed package and the standard
library, never modules from the analyzed repository or the current folder.
Two layers check that:

* **Parent pre-check** (``pool_allowed``), before any process exists. Always:
  no ``sys.path`` entry may be ``""``, ``"."``, the current folder or the
  analyzed root (compared as resolved paths, see ``unsafe_path_entries``);
  spawn copies the parent's ``sys.path`` into each child. Then either
  ``sys.flags.isolated or sys.flags.safe_path`` holds, or the environment is
  honoured (no ``-E``) and ``PYTHONSAFEPATH`` is unset or exactly ``"1"`` and
  is then set for every child. Otherwise C7 runs the checkers inline.
* **Worker backstop** (``worker_backstop``), the pool initializer, which runs
  before any task is unpickled: it requires ``safe_path`` or ``isolated`` and
  the same clean ``sys.path``, and raises ``ComponentError("checkers")``
  otherwise.

This module lives outside ``checkers/`` because that package must not import
``os`` (I-10 purity). It imports only the stdlib and ``conventiondrift.errors``.
"""

import os
import sys
from collections.abc import Iterable, MutableMapping
from typing import Protocol

from conventiondrift.errors import ComponentError

SAFE_PATH_VAR = "PYTHONSAFEPATH"
"""The variable that gives every child Python 3.11+'s ``-P`` behaviour."""

SAFE_PATH_VALUE = "1"

BACKSTOP_MESSAGE = "worker isolation check failed"
"""The backstop's error text. It never names a path."""


class Flags(Protocol):
    """The parts of ``sys.flags`` the checks read."""

    @property
    def isolated(self) -> int: ...

    @property
    def safe_path(self) -> bool: ...

    @property
    def ignore_environment(self) -> int: ...


CURRENT_FOLDER_SPELLINGS = ("", os.curdir)
"""``sys.path`` entries that always mean the current folder (SR condition (a))."""

NUL = "\0"
"""Never part of a real path: a path holding one is refused before any
resolving, on every OS, since not every platform's ``realpath`` rejects it."""


def _strip_separators(path: str) -> str:
    """``path`` without trailing separators, except a root's own separator."""
    drive, rest = os.path.splitdrive(path)
    stripped = rest.rstrip(os.sep + (os.altsep or ""))
    return drive + (stripped or rest[:1])


def path_key(path: str) -> str:
    """The form two folders are compared in: realpath, then trailing separators
    stripped, then ``normcase`` (I-13 C7 ruling 8, SR condition (a))."""
    return os.path.normcase(_strip_separators(os.path.realpath(path)))


def unsafe_path_entries(entries: Iterable[object], cwd: str, root: str | None) -> bool:
    """Whether any entry is ``""``, ``"."``, the current folder or the analyzed root.

    Entries are compared by ``path_key``, so a relative path or a symlink to
    either folder counts too; as a backstop, an entry whose ``os.stat`` matches
    either folder's counts as well. An entry that isn't a ``str`` or can't be
    resolved, or that holds a NUL, counts as unsafe (fail closed); so does a NUL
    in ``cwd`` or ``root``, or a ``cwd`` or ``root`` that can't be resolved or
    stat-ed. An entry that can't be stat-ed (often one that doesn't exist) is
    judged by ``path_key`` alone: the backstop can only add a match.
    """
    folders = [cwd] if root is None else [cwd, root]
    if any(NUL in folder for folder in folders):
        return True
    try:
        banned = {path_key(folder) for folder in folders}
        banned_stats = [os.stat(folder) for folder in folders]
    except (OSError, ValueError):
        return True
    for entry in entries:
        if not isinstance(entry, str) or entry in CURRENT_FOLDER_SPELLINGS or NUL in entry:
            return True
        try:
            if path_key(entry) in banned:
                return True
        except (OSError, ValueError):
            return True
        try:
            entry_stat = os.stat(entry)
        except (OSError, ValueError):
            continue
        if any(os.path.samestat(entry_stat, folder) for folder in banned_stats):
            return True
    return False


def pool_allowed(
    root: str | None,
    *,
    flags: Flags = sys.flags,
    environ: MutableMapping[str, str] | None = None,
    path: Iterable[object] | None = None,
    cwd: str | None = None,
) -> bool:
    """The parent pre-check: whether C7 may start its spawn pool.

    First, always: no ``path`` entry may be unsafe (see ``unsafe_path_entries``);
    the flags below don't change what spawn copies into each child. Then, with
    ``-I`` or ``-P`` (``isolated``/``safe_path``) children inherit the flag, so
    the pool is allowed and ``environ`` is left alone. Otherwise the pool is
    allowed only when ``-E`` is off (children would ignore ``PYTHONSAFEPATH``)
    and ``PYTHONSAFEPATH`` is unset or exactly ``"1"`` (any other value, empty
    included, counts as unsafe); then ``PYTHONSAFEPATH=1`` is set in ``environ``
    and stays set afterwards. Any other case returns ``False`` and C7 runs inline.
    """
    entries = sys.path if path is None else path
    if unsafe_path_entries(entries, os.getcwd() if cwd is None else cwd, root):
        return False
    if flags.isolated or flags.safe_path:
        return True
    if flags.ignore_environment:
        return False
    env = os.environ if environ is None else environ
    if env.get(SAFE_PATH_VAR, SAFE_PATH_VALUE) != SAFE_PATH_VALUE:
        return False
    env[SAFE_PATH_VAR] = SAFE_PATH_VALUE
    return True


def safe_path_still_set(
    *, flags: Flags = sys.flags, environ: MutableMapping[str, str] | None = None
) -> bool:
    """Whether children started now would still get ``-P`` behaviour.

    C7 checks this when the pool closes, so a ``PYTHONSAFEPATH`` removed while
    the pool was alive (when it may have started a replacement worker) fails
    closed.
    """
    env = os.environ if environ is None else environ
    return bool(flags.isolated or flags.safe_path) or env.get(SAFE_PATH_VAR) == SAFE_PATH_VALUE


def check_worker(flags: Flags, path: Iterable[object], cwd: str, root: str | None) -> None:
    """The worker backstop's test; raises ``ComponentError("checkers")`` on failure."""
    if not (flags.safe_path or flags.isolated) or unsafe_path_entries(path, cwd, root):
        raise ComponentError("checkers", BACKSTOP_MESSAGE)


def worker_backstop(root: str | None) -> None:
    """Pool initializer: runs in each worker before it unpickles any task."""
    check_worker(sys.flags, sys.path, os.getcwd(), root)
