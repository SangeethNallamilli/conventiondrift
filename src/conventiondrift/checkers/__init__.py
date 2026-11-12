"""C7 checkers: the fixed registry (INTERFACES I-10, I-11; ADR-0003; DESIGN §6, §12 A-1).

Checkers are registered only in ``REGISTRY``, a fixed tuple. There is no entry
point or plugin loading (SCOPE won't-have #6, THREAT-MODEL T-01). The eight
checkers are added here by T-016 to T-019.
"""

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import get_args

from conventiondrift.checkers.base import Checker
from conventiondrift.model import CheckerId

REGISTRY: tuple[Checker, ...] = ()
"""Every built-in checker. The order doesn't matter; the registry is iterated by id."""


def registry(checkers: Iterable[Checker] = REGISTRY) -> Mapping[str, Checker]:
    """The checker registry for ``Components.checkers``: read-only, keyed by id, sorted (I-11).

    Raises ``ValueError`` for an id that isn't an I-10 ``CheckerId`` or that
    appears twice.
    """
    known = frozenset(get_args(CheckerId))
    by_id: dict[str, Checker] = {}
    for checker in checkers:
        if checker.id not in known:
            raise ValueError("checker id is not an I-10 CheckerId")
        if checker.id in by_id:
            raise ValueError("checker id registered twice")
        by_id[checker.id] = checker
    return MappingProxyType(dict(sorted(by_id.items())))
