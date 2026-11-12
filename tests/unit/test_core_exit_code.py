"""Unit tests for the pure I-4 exit-code policy in conventiondrift.core (T-006a)."""

import dataclasses
import itertools

import pytest

from conventiondrift.core import (
    AnalysisOutcome,
    RefusedTriggerOutcome,
    UsageErrorOutcome,
    exit_code,
)

FAIL_ON = ("none", "new-stale", "any-stale")


def _outcome(**changes: object) -> AnalysisOutcome:
    base = AnalysisOutcome(
        fail_on="none",
        head_only=False,
        new_stale_met=False,
        any_stale_met=False,
        internal_error=False,
    )
    return dataclasses.replace(base, **changes)  # type: ignore[arg-type]


def test_usage_error_exits_2() -> None:
    assert exit_code(UsageErrorOutcome()) == 2


def test_refused_trigger_exits_4() -> None:
    assert exit_code(RefusedTriggerOutcome()) == 4


@pytest.mark.parametrize(
    ("new_stale", "any_stale", "internal", "head_only"),
    list(itertools.product([False, True], repeat=4)),
)
def test_fail_on_none_always_exits_0(
    new_stale: bool, any_stale: bool, internal: bool, head_only: bool
) -> None:
    outcome = _outcome(
        fail_on="none",
        new_stale_met=new_stale,
        any_stale_met=any_stale,
        internal_error=internal,
        head_only=head_only,
    )
    assert exit_code(outcome) == 0


@pytest.mark.parametrize(
    ("new_stale", "any_stale", "expected"),
    [(False, False, 0), (False, True, 0), (True, True, 1), (True, False, 1)],
)
def test_new_stale_counts_only_new_stale(new_stale: bool, any_stale: bool, expected: int) -> None:
    outcome = _outcome(fail_on="new-stale", new_stale_met=new_stale, any_stale_met=any_stale)
    assert exit_code(outcome) == expected


@pytest.mark.parametrize(
    ("new_stale", "any_stale", "expected"),
    [(False, False, 0), (True, False, 0), (False, True, 1), (True, True, 1)],
)
def test_any_stale_counts_any_stale(new_stale: bool, any_stale: bool, expected: int) -> None:
    outcome = _outcome(fail_on="any-stale", new_stale_met=new_stale, any_stale_met=any_stale)
    assert exit_code(outcome) == expected


@pytest.mark.parametrize("fail_on", ["new-stale", "any-stale"])
@pytest.mark.parametrize("met", [False, True])
def test_internal_error_under_gating_exits_3_and_beats_1(fail_on: str, met: bool) -> None:
    outcome = _outcome(fail_on=fail_on, new_stale_met=met, any_stale_met=met, internal_error=True)
    assert exit_code(outcome) == 3


@pytest.mark.parametrize("fail_on", FAIL_ON)
def test_head_only_verdicts_never_fail(fail_on: str) -> None:
    outcome = _outcome(fail_on=fail_on, head_only=True, new_stale_met=True, any_stale_met=True)
    assert exit_code(outcome) == 0


@pytest.mark.parametrize(("fail_on", "expected"), [("none", 0), ("new-stale", 3), ("any-stale", 3)])
def test_head_only_internal_error_follows_sc_2_50(fail_on: str, expected: int) -> None:
    for met in (False, True):
        outcome = _outcome(
            fail_on=fail_on,
            head_only=True,
            internal_error=True,
            new_stale_met=met,
            any_stale_met=met,
        )
        assert exit_code(outcome) == expected


def test_outcomes_are_frozen_and_keyword_only() -> None:
    outcome = _outcome()
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.fail_on = "any-stale"  # type: ignore[misc]
    with pytest.raises(TypeError):
        AnalysisOutcome("none", False, False, False, False)  # type: ignore[call-arg]
    assert UsageErrorOutcome() == UsageErrorOutcome()
    assert RefusedTriggerOutcome() == RefusedTriggerOutcome()
