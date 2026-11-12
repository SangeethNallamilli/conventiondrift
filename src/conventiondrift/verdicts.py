"""C9 verdict engine: counts plus thresholds give one verdict per rule per side.

Pure (DESIGN §1, I-11 C9): no I/O, no subprocess, no clock, and it never raises
for any input the model types allow. Everything is integer math on site counts;
percentages exist only for display and are computed by C11 (I-9, I-13 ``Counts``).

The algorithm is DESIGN §10 S1, applied in its fixed order:

1. No checker, or ambiguous: Not verifiable.
2. ``relevant < min-sites``: Insufficient data.
3. ``overall >= holds``: Holds.
4. Recent available (at least one recent relevant site):
   Stale if ``overall < stale.overall`` and ``recent < stale.recent``;
   else Migrating if ``overall < migrating.overall`` and ``recent >= migrating.recent``;
   else Contested.
5. Recent unavailable: Stale if ``overall < stale.overall``, else Contested.
   Migrating is unreachable here, because it needs recent adherence (AC-F4.12).

Threshold validation (``stale.overall <= migrating.overall <= holds`` and
``stale.recent <= migrating.recent``, falling back to defaults) is C5's job; C9
applies whatever ``Thresholds`` it is given.
"""

from collections.abc import Iterable, Sequence
from collections.abc import Set as AbstractSet
from typing import Literal

from conventiondrift.model import (
    Counts,
    Rule,
    RuleMatch,
    SideResult,
    Site,
    SiteResult,
    Thresholds,
    Verdict,
)

__all__ = ["decide", "follows", "pct_ge", "side_result"]

RecentUnavailableReason = Literal["no history", "no relevant sites in the window"]


def pct_ge(following: int, relevant: int, threshold: int) -> bool:
    """True when ``following / relevant`` is at least ``threshold`` percent.

    Exact integer form from S1 and I-9: ``following*100 >= threshold*relevant``.
    With ``relevant == 0`` this is ``0 >= 0``, i.e. True; step 2 normally stops an
    empty count before any threshold is compared.
    """
    return following * 100 >= threshold * relevant


def follows(option: str, match: RuleMatch) -> bool:
    """I-10: a site follows when its option is preferred, or, when nothing is
    preferred, when its option is not prohibited. Otherwise it contradicts."""
    if match.preferred:
        return option in match.preferred
    return option not in match.prohibited


def decide(
    *,
    verifiable: bool,
    overall: Counts,
    recent: Counts | None,
    thresholds: Thresholds,
) -> Verdict:
    """Apply S1 in its fixed order.

    ``recent`` is None when recent adherence is unavailable (no history, or no
    relevant site in the window). A ``Counts`` with zero relevant sites is treated
    the same way, since S1 defines "available" as at least one recent relevant site.
    """
    t = thresholds
    if not verifiable:
        return Verdict.NOT_VERIFIABLE
    if overall.relevant < t.min_sites:
        return Verdict.INSUFFICIENT
    if pct_ge(overall.following, overall.relevant, t.holds):
        return Verdict.HOLDS
    overall_below_stale = not pct_ge(overall.following, overall.relevant, t.stale_overall)
    if recent is None or recent.relevant < 1:
        return Verdict.STALE if overall_below_stale else Verdict.CONTESTED
    if overall_below_stale and not pct_ge(recent.following, recent.relevant, t.stale_recent):
        return Verdict.STALE
    if not pct_ge(overall.following, overall.relevant, t.migrating_overall) and pct_ge(
        recent.following, recent.relevant, t.migrating_recent
    ):
        return Verdict.MIGRATING
    return Verdict.CONTESTED


def _count(results: Sequence[SiteResult]) -> Counts:
    following = sum(1 for r in results if r.follows)
    return Counts(
        following=following, contradicting=len(results) - following, relevant=len(results)
    )


def side_result(
    rule: Rule,
    sites: Iterable[Site],
    *,
    options: AbstractSet[str],
    recent_lines: Iterable[tuple[str, int]] | None,
    thresholds: Thresholds,
) -> SideResult:
    """Build the C9 ``SideResult`` for one rule on one side.

    - ``sites``: this checker's sites on this side that fall inside the rule's
      scope. C9 counts every site it is given; T-028 filters by ``scope_dir``
      (I-13).
    - ``options``: the checker's ``options`` (I-10). Only sites whose option is in
      it are relevant; any other site is dropped.
    - ``recent_lines``: the ``(file, line)`` pairs C8 dated as recent on this side,
      or None when recent adherence is unavailable for the run (head-only mode, no
      ``HEAD`` in scan mode, or a C8 failure). A C8 failure is reported here as
      ``recent=None`` with reason ``"no history"``; the cause appears only in the
      Internal error section (I-13).
    - ``thresholds``: the effective, already validated thresholds.

    A rule with no checker or no match (no mapping, or an ambiguous one) is
    Not verifiable, carries no sites, and has ``recent=None`` and
    ``recent_unavailable_reason=None``, because recent does not apply (I-13).
    Disabled rules are dropped by T-028 before C9; an ignored rule gets its
    normal verdict.
    """
    # I-13: C9 is pure and counts every site it is given. T-028 filters sites
    # by scope_dir, and drops disabled rules, before C9. An ignored rule still
    # gets its normal verdict here (it only stops counting for fail-on).
    match = rule.match if rule.checker is not None else None
    results: list[SiteResult] = []
    if match is not None:
        # Build the lookup set once, and only when we will walk sites (SR F2, CR2 N2).
        recent_set = frozenset(recent_lines) if recent_lines is not None else None
        for s in sites:
            if s.option in options:
                recent = recent_set is not None and (s.file, s.line) in recent_set
                results.append(SiteResult(site=s, follows=follows(s.option, match), recent=recent))
    results.sort(key=lambda r: (r.site.file, r.site.line, r.site.col, r.site.option))

    overall = _count(results)
    recent_counts: Counts | None = None
    reason: RecentUnavailableReason | None
    if match is None:
        # I-13: recent does not apply to a Not verifiable side.
        reason = None
    elif recent_lines is None:
        # I-13: a C8 failure (and head-only / no HEAD) is "no history" here.
        # The cause of a C8 failure appears only in the Internal error section.
        reason = "no history"
    else:
        in_window = _count([r for r in results if r.recent])
        if in_window.relevant:
            recent_counts = in_window
            reason = None
        else:
            reason = "no relevant sites in the window"
    verdict = decide(
        verifiable=match is not None, overall=overall, recent=recent_counts, thresholds=thresholds
    )
    return SideResult(
        verdict=verdict,
        sites=tuple(results),
        overall=overall,
        recent=recent_counts,
        recent_unavailable_reason=reason,
    )
