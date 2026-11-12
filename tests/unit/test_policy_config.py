"""Unit tests for conventiondrift.policy.config: defaults and the I-6 range backstop (T-012).

Expected values are copied from INTERFACES I-5/I-6 and DESIGN §10, not from the code.
"""

import dataclasses
from types import MappingProxyType
from typing import get_args

import pytest

from conventiondrift.model import CheckerId, CheckerPolicy, Thresholds
from conventiondrift.policy.config import (
    DEFAULT_CHECKERS,
    DEFAULT_HISTORY_DAYS,
    DEFAULT_LOGGING_SCRIPT_PATHS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_THRESHOLDS,
    HISTORY_DAYS_RANGE,
    THRESHOLD_RANGES,
    SideConfig,
    check_ranges,
)

# I-6: "holds ... 1..100", stale and migrating "each 0..100", "min-sites: 5 # 1..1000".
SPEC_RANGES = {
    "holds": ("thresholds.holds", 1, 100),
    "stale_overall": ("thresholds.stale.overall", 0, 100),
    "stale_recent": ("thresholds.stale.recent", 0, 100),
    "migrating_overall": ("thresholds.migrating.overall", 0, 100),
    "migrating_recent": ("thresholds.migrating.recent", 0, 100),
    "min_sites": ("thresholds.min-sites", 1, 1000),
}
SPEC_THRESHOLDS = Thresholds(
    holds=80, stale_overall=20, stale_recent=20, migrating_overall=50, migrating_recent=70,
    min_sites=5,
)  # fmt: skip


def test_defaults_match_i6() -> None:
    assert DEFAULT_THRESHOLDS == SPEC_THRESHOLDS
    assert DEFAULT_HISTORY_DAYS == 90
    assert HISTORY_DAYS_RANGE == (1, 3650)
    assert DEFAULT_MAX_FILE_BYTES == 1048576


def test_threshold_ranges_match_i6_and_cover_every_field() -> None:
    assert dict(THRESHOLD_RANGES) == SPEC_RANGES
    assert set(THRESHOLD_RANGES) == {f.name for f in dataclasses.fields(Thresholds)}


def test_default_checkers_match_i6() -> None:
    assert set(DEFAULT_CHECKERS) == set(get_args(CheckerId))
    assert {cid for cid, p in DEFAULT_CHECKERS.items() if not p.enabled} == {"money"}
    assert DEFAULT_LOGGING_SCRIPT_PATHS == (
        "**/tests/**", "**/test/**", "**/scripts/**", "**/bin/**",
        "**/test_*.py", "**/*_test.py", "**/conftest.py",
    )  # fmt: skip
    assert DEFAULT_CHECKERS["logging"].script_paths == DEFAULT_LOGGING_SCRIPT_PATHS
    assert all(p.script_paths == () for cid, p in DEFAULT_CHECKERS.items() if cid != "logging")
    with pytest.raises(TypeError):
        DEFAULT_CHECKERS["money"] = CheckerPolicy(True, ())  # type: ignore[index]


def test_side_config_checkers_are_read_only_copies() -> None:
    source: dict[CheckerId, CheckerPolicy] = {"money": CheckerPolicy(True, ())}
    config = SideConfig(checkers=source)
    assert isinstance(config.checkers, MappingProxyType)
    source.clear()
    assert dict(config.checkers) == {"money": CheckerPolicy(True, ())}


def test_check_ranges_keeps_a_valid_config_unchanged() -> None:
    config = SideConfig(thresholds=SPEC_THRESHOLDS, history_days=30)
    assert check_ranges(config) == (config, ())
    assert check_ranges(SideConfig()) == (SideConfig(), ())


def _edges(name: str) -> list[tuple[int, bool]]:
    _, low, high = THRESHOLD_RANGES[name]
    return [(low, True), (high, True), (low - 1, False), (high + 1, False), (-1, False),
            (10**9, False)]  # fmt: skip


@pytest.mark.parametrize(
    ("name", "value", "ok"),
    [(name, value, ok) for name in SPEC_RANGES for value, ok in _edges(name)],
)
def test_each_threshold_out_of_range_gets_its_default_and_a_note(
    name: str, value: int, ok: bool
) -> None:
    key, low, high = SPEC_RANGES[name]
    thresholds = dataclasses.replace(SPEC_THRESHOLDS, **{name: value})
    # Make every other field differ from its default so a reset of the whole block shows.
    others = {f: getattr(SPEC_THRESHOLDS, f) for f in SPEC_RANGES if f != name}
    others = {f: v + 1 for f, v in others.items()}
    thresholds = dataclasses.replace(thresholds, **others)
    fixed, notes = check_ranges(SideConfig(thresholds=thresholds))
    assert fixed.thresholds is not None
    for other, v in others.items():
        assert getattr(fixed.thresholds, other) == v
    if ok:
        assert getattr(fixed.thresholds, name) == value
        assert notes == ()
    else:
        assert getattr(fixed.thresholds, name) == getattr(SPEC_THRESHOLDS, name)
        assert len(notes) == 1
        assert key in notes[0]
        assert f"{low} to {high}" in notes[0]
        assert "default" in notes[0]


@pytest.mark.parametrize("name", sorted(SPEC_RANGES))
@pytest.mark.parametrize("value", [True, False])
def test_a_bool_is_not_an_integer_threshold(name: str, value: bool) -> None:
    thresholds = dataclasses.replace(SPEC_THRESHOLDS, **{name: value})
    fixed, notes = check_ranges(SideConfig(thresholds=thresholds))
    assert fixed.thresholds == SPEC_THRESHOLDS
    assert len(notes) == 1


def test_several_bad_thresholds_get_one_note_each() -> None:
    thresholds = dataclasses.replace(SPEC_THRESHOLDS, holds=150, min_sites=0, stale_recent=-1)
    fixed, notes = check_ranges(SideConfig(thresholds=thresholds))
    assert fixed.thresholds == SPEC_THRESHOLDS
    assert [n.split(" ")[0] for n in notes] == [
        "thresholds.holds",
        "thresholds.stale.recent",
        "thresholds.min-sites",
    ]


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        (HISTORY_DAYS_RANGE[0], True),
        (HISTORY_DAYS_RANGE[1], True),
        (HISTORY_DAYS_RANGE[0] - 1, False),
        (HISTORY_DAYS_RANGE[1] + 1, False),
        (-30, False),
        (True, False),
    ],
)
def test_history_days_out_of_range_gets_the_default(value: int, ok: bool) -> None:
    fixed, notes = check_ranges(SideConfig(history_days=value, thresholds=SPEC_THRESHOLDS))
    if ok:
        assert (fixed.history_days, notes) == (value, ())
    else:
        assert fixed.history_days == 90
        assert notes == ("history-days must be an integer from 1 to 3650; the default 90 is used",)
    assert fixed.thresholds == SPEC_THRESHOLDS
