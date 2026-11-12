"""Entrypoint core (DESIGN §12 A-1). T-006a: the pure I-4 exit-code policy.

``run()`` and the pipeline arrive with T-006a's remaining parts and T-028. The
callers (C1, C2, T-028) reduce a run to one of the outcomes below; this module
only maps it to an exit status, following INTERFACES I-4 "Exit codes", DESIGN
§4 and SC-2.50 (D-PM-30).
"""

from dataclasses import dataclass
from typing import Literal

EXIT_OK = 0
EXIT_FAIL_ON_MET = 1
EXIT_USAGE = 2
EXIT_INTERNAL_ERROR = 3
EXIT_REFUSED_TRIGGER = 4


@dataclass(frozen=True, slots=True)
class UsageErrorOutcome:
    """The run stopped on a usage error (I-4 exit 2), e.g. an unresolvable revision."""


@dataclass(frozen=True, slots=True)
class RefusedTriggerOutcome:
    """The Action refused its trigger, ``pull_request_target`` (I-4 exit 4)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalysisOutcome:
    """A run that got past argument and trigger checks.

    ``new_stale_met`` and ``any_stale_met`` say whether the I-4 "What counts"
    condition for each mode holds; callers compute them (scan mode never meets
    ``new-stale``). ``internal_error`` is true when any ``InternalError`` was
    recorded.
    """

    fail_on: Literal["none", "new-stale", "any-stale"]
    head_only: bool
    new_stale_met: bool
    any_stale_met: bool
    internal_error: bool


RunOutcome = UsageErrorOutcome | RefusedTriggerOutcome | AnalysisOutcome


def exit_code(outcome: RunOutcome) -> int:
    """Map a run outcome to its I-4 exit status (0/1/2/3/4; 3 beats 1)."""
    if isinstance(outcome, UsageErrorOutcome):
        return EXIT_USAGE
    if isinstance(outcome, RefusedTriggerOutcome):
        return EXIT_REFUSED_TRIGGER
    if outcome.fail_on == "none":
        return EXIT_OK
    if outcome.internal_error:
        # Head-only runs too (SC-2.50, D-PM-30): an internal error under a gating mode is 3.
        return EXIT_INTERNAL_ERROR
    if outcome.head_only:
        # Head-only verdicts never fail the run (AC-F4.11, AC-E.7).
        return EXIT_OK
    met = outcome.new_stale_met if outcome.fail_on == "new-stale" else outcome.any_stale_met
    return EXIT_FAIL_ON_MET if met else EXIT_OK
