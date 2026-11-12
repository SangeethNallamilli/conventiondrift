"""Black-box AC-F4 (and AC-E.19, I-10, I-13) spec tests for T-021 / PR #25.

Expected results are taken from SPEC.md §5 (conventions and AC-F4.* / AC-E.19),
I-6 default thresholds, I-10 RuleMatch validity, and I-13 decide() guards /
C9 recent-field rulings. They are not taken from verdicts.py or from its
unit-test predicates.

ACs that need C8, C10, C11 or the Action (window dating, comments,
annotations, summary text) are listed in TRACEABILITY.md and are not claimed
here. T-021 / PR #25 is on main, so every case runs against
conventiondrift.verdicts for real; a failing case is a T-021 finding.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import replace

import pytest

from conventiondrift.model import Counts, Rule, RuleMatch, SideResult, Site, Thresholds, Verdict
from conventiondrift.verdicts import decide, side_result

# SPEC.md §5 conventions (defaults apply unless an AC states otherwise) and I-6:
# Holds: overall >= 80; Stale: overall < 20 and recent < 20;
# Migrating: overall < 50 and recent >= 70; minimum 5 sites.
DEFAULTS = Thresholds(
    holds=80,
    stale_overall=20,
    stale_recent=20,
    migrating_overall=50,
    migrating_recent=70,
    min_sites=5,
)

# I-13: decide() raises unless min_sites >= 1 and holds >= 1. The rejected
# domain is every integer below that floor. Include 0 and a negative so an
# `== 0` mutant of `< 1` cannot survive (D-TL-25).
GUARD_FLOOR = 1
BELOW_FLOOR = (GUARD_FLOOR - 1, -1, -7)
assert all(value < GUARD_FLOOR for value in BELOW_FLOOR)
assert 0 in BELOW_FLOOR and any(value < 0 for value in BELOW_FLOOR)

HTTP = frozenset({"requests", "httpx", "urllib3"})
USE_HTTPX = RuleMatch(preferred=frozenset({"httpx"}), prohibited=frozenset(), specificity=1)
RULE = Rule(
    id="AGENTS.md:3",
    file="AGENTS.md",
    line=3,
    also_at=(),
    text="Use httpx for HTTP calls",
    normalized_text="use httpx for http calls",
    checker="http-client",
    match=USE_HTTPX,
    scope_dir="",
    ignored=False,
    disabled=False,
)

H = Verdict.HOLDS
S = Verdict.STALE
M = Verdict.MIGRATING
C = Verdict.CONTESTED
INSUFF = Verdict.INSUFFICIENT
NV = Verdict.NOT_VERIFIABLE


def _counts(following: int, relevant: int) -> Counts:
    """Build a Counts whose parts add up: following + contradicting = relevant.

    That addition is the glossary (a site follows or it contradicts), not a
    code-side consistency predicate.
    """
    return Counts(following=following, contradicting=relevant - following, relevant=relevant)


def _verdict(
    overall: Counts,
    recent: Counts | None,
    thresholds: Thresholds = DEFAULTS,
    *,
    verifiable: bool = True,
) -> Verdict:
    return decide(verifiable=verifiable, overall=overall, recent=recent, thresholds=thresholds)


def _site(file: str, line: int, option: str) -> Site:
    return Site(file=file, line=line, col=0, option=option)


def _sites(options: Sequence[str], file: str = "src/a.py") -> list[Site]:
    return [_site(file, index + 1, option) for index, option in enumerate(options)]


def _side(
    sites: list[Site],
    recent_lines: Iterable[tuple[str, int]] | None,
    rule: Rule = RULE,
    thresholds: Thresholds = DEFAULTS,
    options: frozenset[str] = HTTP,
) -> SideResult:
    return side_result(
        rule, sites, options=options, recent_lines=recent_lines, thresholds=thresholds
    )


def _stand_in(preferred: frozenset[str], prohibited: frozenset[str]) -> RuleMatch:
    """I-10: plant a match C9 may still see after model.py starts rejecting it."""
    match = RuleMatch(preferred=frozenset({"httpx"}), prohibited=frozenset(), specificity=0)
    object.__setattr__(match, "preferred", preferred)
    object.__setattr__(match, "prohibited", prohibited)
    return match


# --- AC-F4.3 (REQ-7.4.2) -------------------------------------------------------


def test_ac_f4_3_holds_at_eighty_percent_even_with_zero_recent() -> None:
    """SPEC AC-F4.3: overall 80% (16/20) with recent 0% is Holds."""
    # Recent 0% is 0 following of a non-empty recent set (recent available).
    assert _verdict(_counts(16, 20), _counts(0, 5)) is H


def test_ac_f4_3_seventy_nine_percent_is_contested() -> None:
    """SPEC AC-F4.3: overall 79% (79/100) with recent 0% is Contested."""
    assert _verdict(_counts(79, 100), _counts(0, 5)) is C


# --- AC-F4.4 (REQ-7.4.3) -------------------------------------------------------


@pytest.mark.parametrize(
    ("overall", "recent", "expected"),
    [
        # Denominators of 10 give the AC's exact percentages and meet min 5 sites.
        (_counts(1, 10), _counts(1, 10), S),  # 10% / 10%
        (_counts(1, 10), _counts(2, 10), C),  # 10% / 20%
        (_counts(2, 10), _counts(0, 10), C),  # 20% / 0%
    ],
    ids=["10-and-10-stale", "10-and-20-contested", "20-and-0-contested"],
)
def test_ac_f4_4_stale_boundaries(overall: Counts, recent: Counts, expected: Verdict) -> None:
    """SPEC AC-F4.4: Stale only when overall 10% and recent 10%; the other two are Contested."""
    assert _verdict(overall, recent) is expected


# --- AC-F4.5 (REQ-7.4.4) -------------------------------------------------------


@pytest.mark.parametrize(
    ("overall", "recent", "expected"),
    [
        (_counts(4, 10), _counts(7, 10), M),  # 40% / 70%
        (_counts(5, 10), _counts(9, 10), C),  # 50% / 90%
        (_counts(40, 100), _counts(69, 100), C),  # 40% / 69%
    ],
    ids=["40-and-70-migrating", "50-and-90-contested", "40-and-69-contested"],
)
def test_ac_f4_5_migrating_boundaries(overall: Counts, recent: Counts, expected: Verdict) -> None:
    """SPEC AC-F4.5: Migrating at 40%/70%; Contested at 50%/90% and 40%/69%."""
    assert _verdict(overall, recent) is expected


# --- AC-F4.6 (REQ-7.4.5) -------------------------------------------------------


@pytest.mark.parametrize(
    ("overall", "recent"),
    [
        (_counts(6, 10), _counts(6, 10)),  # 60% / 60%
        (_counts(3, 10), _counts(4, 10)),  # 30% / 40%
    ],
    ids=["60-and-60", "30-and-40"],
)
def test_ac_f4_6_contested_fallthrough(overall: Counts, recent: Counts) -> None:
    """SPEC AC-F4.6: 60%/60% and 30%/40% are Contested."""
    assert _verdict(overall, recent) is C


# --- AC-F4.7 (REQ-7.4.6) and AC-E.19 (REQ-9.15) --------------------------------


def test_ac_f4_7_four_contradicting_sites_are_insufficient() -> None:
    """SPEC AC-F4.7: 4 relevant sites, all contradicting, is Insufficient data.

    "There is no warning" is a comment/annotation rule (glossary: only Stale
    warns). C9 has no comment sink, so this asserts the verdict is not Stale.
    """
    verdict = _verdict(_counts(0, 4), _counts(0, 4))
    assert verdict is INSUFF
    assert verdict is not S


def test_ac_f4_7_five_contradicting_sites_are_stale() -> None:
    """SPEC AC-F4.7: 5 relevant sites, all contradicting, is Stale."""
    assert _verdict(_counts(0, 5), _counts(0, 5)) is S


def test_ac_e_19_four_sites_are_insufficient_not_a_warning_verdict() -> None:
    """SPEC AC-E.19: after a PR, 4 contradicting sites are Insufficient data.

    The "no comment entry and no annotation" clause is C11 and is not asserted
    here. Insufficient data is not Stale, and only Stale warns (AC-F4.9).
    """
    verdict = _verdict(_counts(0, 4), None)
    assert verdict is INSUFF
    assert verdict is not S


# --- AC-F4.8 (REQ-7.4.7) -------------------------------------------------------


def test_ac_f4_8_unmatched_checker_is_not_verifiable() -> None:
    """SPEC AC-F4.8: a recognized rule that no checker matches is Not verifiable.

    I-13: a Not verifiable side has recent=None and reason=None.
    """
    rule = replace(RULE, checker=None, match=None)
    sites = _sites(["requests"] * 5)
    result = _side(sites, frozenset({("src/a.py", 1)}), rule=rule)
    assert result.verdict is NV
    assert result.recent is None
    assert result.recent_unavailable_reason is None


# --- AC-F4.10 (REQ-7.4.8 / SC-2.53), verdict and min-sites part only -----------

# SPEC.md AC-F4.10 (SC-2.53): "a rule has 4 relevant sites, all recent, with
# 1 following (overall 25%, recent 25%)". Under config "Holds 90, Stale 30/30,
# Migrating 60/60, minimum sites 3 and window 30 days", "the verdict is Stale
# (it would be Insufficient data under the defaults, since 4 is below the
# default minimum of 5)".
# 1 following / 4 relevant = 25%; all 4 are recent, so recent is also 1/4 = 25%.
# Window dating (history-days 30, and "a recent site 45 days old is excluded
# from recent adherence") is a C8 rule and is not asserted here.

AC_F4_10_COUNTS = _counts(1, 4)
AC_F4_10_CONFIG = Thresholds(
    holds=90,
    stale_overall=30,
    stale_recent=30,
    migrating_overall=60,
    migrating_recent=60,
    min_sites=3,
)


def test_ac_f4_10_four_recent_sites_one_following() -> None:
    """SPEC AC-F4.10 (SC-2.53): 4 relevant sites, all recent, 1 following.

    The same fixture is tested both ways. Under Holds 90, Stale 30/30,
    Migrating 60/60 and min-sites 3, 25%/25% is Stale. Under the defaults
    (I-6: min-sites 5) it is Insufficient data, because 4 < 5.
    """
    assert AC_F4_10_COUNTS.following == 1
    assert AC_F4_10_COUNTS.relevant == 4
    assert AC_F4_10_COUNTS.contradicting == 3
    assert _verdict(AC_F4_10_COUNTS, AC_F4_10_COUNTS, AC_F4_10_CONFIG) is S
    assert _verdict(AC_F4_10_COUNTS, AC_F4_10_COUNTS, DEFAULTS) is INSUFF


# --- AC-F4.12 (REQ-7.4.10) and AC-F4.13 (REQ-7.4.1), C9 verdict parts ----------


def test_ac_f4_12_overall_only_ten_percent_is_stale() -> None:
    """SPEC AC-F4.12: shallow / no recent, overall 10% and ≥5 sites is Stale."""
    assert _verdict(_counts(1, 10), None) is S


def test_ac_f4_12_overall_only_thirty_percent_is_contested() -> None:
    """SPEC AC-F4.12: shallow / no recent, overall 30% is Contested."""
    assert _verdict(_counts(3, 10), None) is C


@pytest.mark.parametrize(
    "following",
    [0, 1, 3, 4, 5, 8, 10],
    ids=lambda following: f"overall-{following}-of-10",
)
def test_ac_f4_12_overall_only_is_never_migrating(following: int) -> None:
    """SPEC AC-F4.12: with any overall adherence, no recent means never Migrating.

    4/10 would be Migrating if recent were 70%, so it is the interesting case.
    """
    assert _verdict(_counts(following, 10), None) is not M


def test_ac_f4_13_empty_window_ten_percent_is_stale_with_reason() -> None:
    """SPEC AC-F4.13: 10 sites, all outside the window, overall 10% is Stale.

    I-13 / I-9: recent is unavailable with reason "no relevant sites in the window".
    """
    # 1 httpx (follows) and 9 requests (contradict) → 10% overall.
    sites = _sites(["httpx"] + ["requests"] * 9)
    result = _side(sites, recent_lines=())
    assert result.verdict is S
    assert result.recent is None
    assert result.recent_unavailable_reason == "no relevant sites in the window"


def test_ac_f4_13_empty_window_thirty_percent_is_contested() -> None:
    """SPEC AC-F4.13: the same fixture at 30% overall is Contested."""
    sites = _sites(["httpx"] * 3 + ["requests"] * 7)
    result = _side(sites, recent_lines=())
    assert result.verdict is C
    assert result.recent is None
    assert result.recent_unavailable_reason == "no relevant sites in the window"


def test_ac_f4_12_shallow_reason_is_no_history() -> None:
    """I-13: a C8 failure / missing history is recent=None with reason 'no history'."""
    sites = _sites(["requests"] * 10)
    result = _side(sites, recent_lines=None)
    assert result.verdict is S
    assert result.recent is None
    assert result.recent_unavailable_reason == "no history"


# --- I-10 RuleMatch validity, C9 backstop (CR2 B1) -----------------------------


@pytest.mark.parametrize(
    "match",
    [
        _stand_in(preferred=frozenset(), prohibited=frozenset()),
        _stand_in(preferred=frozenset({"httpx"}), prohibited=frozenset({"httpx"})),
        RuleMatch(preferred=frozenset({"logging"}), prohibited=frozenset(), specificity=0),
        RuleMatch(preferred=frozenset(), prohibited=frozenset({"print"}), specificity=0),
    ],
    ids=["empty-union", "overlap", "preferred-outside-options", "prohibited-outside-options"],
)
def test_i10_invalid_match_is_not_verifiable(match: RuleMatch) -> None:
    """I-10: an invalid match is Not verifiable in C9, never Holds.

    The four classes are the I-10 conditions: empty preferred union prohibited,
    non-empty preferred intersection prohibited, and either set not a subset of options.
    """
    rule = replace(RULE, match=match)
    result = _side(_sites(["requests"] * 5), recent_lines=None, rule=rule)
    assert result.verdict is NV
    assert result.verdict is not H
    assert result.recent is None
    assert result.recent_unavailable_reason is None


# --- I-13 decide() guards (CR2 S1) ---------------------------------------------


@pytest.mark.parametrize("min_sites", BELOW_FLOOR, ids=lambda value: f"min_sites={value}")
def test_i13_decide_rejects_min_sites_below_one(min_sites: int) -> None:
    """I-13: decide() raises ValueError when min_sites < 1, even if verifiable is False."""
    thresholds = replace(DEFAULTS, min_sites=min_sites)
    with pytest.raises(ValueError):
        _verdict(_counts(0, 0), None, thresholds)
    with pytest.raises(ValueError):
        _verdict(_counts(0, 0), None, thresholds, verifiable=False)


@pytest.mark.parametrize("holds", BELOW_FLOOR, ids=lambda value: f"holds={value}")
def test_i13_decide_rejects_holds_below_one(holds: int) -> None:
    """I-13: decide() raises ValueError when holds < 1, even if verifiable is False."""
    thresholds = replace(DEFAULTS, holds=holds)
    with pytest.raises(ValueError):
        _verdict(_counts(10, 10), None, thresholds)
    with pytest.raises(ValueError):
        _verdict(_counts(10, 10), None, thresholds, verifiable=False)


@pytest.mark.parametrize(
    "overall",
    [
        Counts(following=-1, contradicting=6, relevant=5),  # following < 0
        Counts(following=6, contradicting=-1, relevant=5),  # following > relevant
    ],
    ids=["following-below-zero", "following-above-relevant"],
)
def test_i13_decide_rejects_following_outside_zero_to_relevant(overall: Counts) -> None:
    """I-13: decide() raises ValueError unless 0 <= following <= relevant."""
    with pytest.raises(ValueError):
        _verdict(overall, None)
    with pytest.raises(ValueError):
        _verdict(overall, None, verifiable=False)


def test_i13_decide_accepts_following_boundaries() -> None:
    """I-13: following == 0 and following == relevant are allowed counts."""
    assert _verdict(_counts(0, 5), None) is S
    assert _verdict(_counts(5, 5), None) is H
