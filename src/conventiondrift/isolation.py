"""Worker isolation for C7's spawn pool (INTERFACES I-13 C7 ruling 8, ADR-0002 Amendment 4).

Spawn workers and the resource tracker start as ``python -c ...`` in the
parent's current folder. Without ``-I`` or ``-P`` that folder goes first on the
child's ``sys.path``, so files planted in an analyzed repo (``struct.py``,
``multiprocessing/``, ``concurrent/``...) would run in every worker (SR C-1 on
#31). Two layers stop that:

* **Parent pre-check** (``pool_allowed``), before any process exists: the pool
  runs only when ``sys.flags.isolated or sys.flags.safe_path``, or when the
  environment is honoured (no ``-E``), ``PYTHONSAFEPATH`` is set for every child,
  and no ``sys.path`` entry is ``""``, the current folder or the analyzed root
  (spawn copies the parent's ``sys.path`` into each child). Otherwise C7 runs
  the checkers inline.
* **Worker backstop** (``worker_backstop``), the pool initializer, which runs
  before any task is unpickled: it requires ``safe_path`` or ``isolated`` and
  the same clean ``sys.path``, and raises ``ComponentError("checkers")``
  otherwise.

This module lives outside ``checkers/`` because that package must not import
``os`` (I-10 purity). It imports only the stdlib and ``conventiondrift.errors``,
and children import it only after the pre-check has proved that no ``sys.path``
entry the repo controls comes before the installed package.
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


def _key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def unsafe_path_entries(entries: Iterable[object], cwd: str, root: str | None) -> bool:
    """Whether any entry is ``""``, the current folder or the analyzed root.

    Entries are compared as resolved, case-normalized paths, so ``"."``, a
    relative path or a symlink to the folder counts too. An entry that isn't a
    ``str`` or can't be resolved counts as unsafe (fail closed).
    """
    banned = {_key(cwd)} if root is None else {_key(cwd), _key(root)}
    for entry in entries:
        if not isinstance(entry, str) or entry == "":
            return True
        try:
            if _key(entry) in banned:
                return True
        except (OSError, ValueError):
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

    With ``-I`` or ``-P`` (``isolated``/``safe_path``) children inherit the flag,
    so the pool is allowed and ``environ`` is left alone. Otherwise the pool is
    allowed only when ``-E`` is off (children would ignore ``PYTHONSAFEPATH``)
    and no ``path`` entry is unsafe (see ``unsafe_path_entries``); then
    ``PYTHONSAFEPATH=1`` is set in ``environ`` and stays set afterwards. Any other
    case returns ``False`` and C7 runs inline.
    """
    if flags.isolated or flags.safe_path:
        return True
    if flags.ignore_environment:
        return False
    entries = sys.path if path is None else path
    if unsafe_path_entries(entries, os.getcwd() if cwd is None else cwd, root):
        return False
    (os.environ if environ is None else environ)[SAFE_PATH_VAR] = SAFE_PATH_VALUE
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
