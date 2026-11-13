"""Unit tests for the fixed checker registry, conventiondrift.checkers (T-014)."""

from pathlib import Path
from types import MappingProxyType

import pytest
from checker_standins import CallChecker, ContextChecker, NodeCounter

from conventiondrift import checkers
from conventiondrift.checkers import REGISTRY, registry


def test_the_registry_is_a_fixed_tuple() -> None:
    # ADR-0003, DESIGN §6: no entry-point or plugin loading; checkers arrive with T-016..T-019.
    assert isinstance(REGISTRY, tuple)
    assert registry() == {}


def test_registry_is_read_only_keyed_by_id_and_sorted() -> None:
    made = registry([ContextChecker(), CallChecker("logging", frozenset({"print"})), NodeCounter()])
    assert isinstance(made, MappingProxyType)
    assert list(made) == ["logging", "string-format", "type-hints"]
    assert all(made[k].id == k for k in made)


def test_an_unknown_id_is_refused() -> None:
    with pytest.raises(ValueError, match="CheckerId"):
        registry([CallChecker("print", frozenset({"print"}))])  # type: ignore[arg-type]


def test_a_duplicate_id_is_refused() -> None:
    a = CallChecker("logging", frozenset({"print"}))
    with pytest.raises(ValueError, match="twice"):
        registry([a, CallChecker("logging", frozenset({"log"}))])


def test_the_package_loads_no_plugins() -> None:
    text = Path(checkers.__file__ or "").read_text("utf-8")
    for word in ("entry_points", "importlib", "pkg_resources", "__import__"):
        assert word not in text
