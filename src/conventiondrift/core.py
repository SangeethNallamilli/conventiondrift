"""Entrypoint core (DESIGN §12 A-1; INTERFACES I-2, I-4, I-14).

T-006a ships the ``run()`` skeleton, the pure I-4 exit-code policy, the
exception-to-``InternalError`` helper and the ``fail-on`` fallback used when an
error happens before policy loads. The pipeline itself is T-028; writing the
Internal error section is T-006b.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, get_args

from conventiondrift.components import Components
from conventiondrift.errors import ComponentError
from conventiondrift.model import InternalError

FailOn = Literal["none", "new-stale", "any-stale"]
_FAIL_ON_VALUES: tuple[FailOn, ...] = get_args(FailOn)

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
    """A run that got past argument and trigger checks."""

    fail_on: FailOn
    """The effective ``fail-on`` (I-4 B7)."""
    head_only: bool
    new_stale_met: bool
    """I-4 "What counts" for ``new-stale``; T-028 sets ``Result.counts.new_stale > 0``."""
    any_stale_met: bool
    """I-4 "What counts" for ``any-stale``; T-028 sets ``Result.counts.stale > 0``."""
    internal_error: bool
    """True when any ``InternalError`` was recorded."""


RunOutcome = UsageErrorOutcome | RefusedTriggerOutcome | AnalysisOutcome
"""``RefusedTriggerOutcome`` is only ever built when ``entry == "action"`` (I-2, I-4)."""


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


_COMPONENT = re.compile(r"[a-z][a-z0-9_]*(:[a-z0-9_-]+)?")


def internal_error(exc: BaseException) -> InternalError:
    """The reportable form of a caught exception (I-14 Q6, sanitizing).

    Only the component name and the exception class are used; the exception's
    own message (including ``ComponentError.message``) is never written. A class
    name that isn't an ASCII identifier becomes ``Exception``; a component that
    doesn't match the I-14 pattern becomes ``core``.
    """
    component = exc.component if isinstance(exc, ComponentError) else "core"
    if not _COMPONENT.fullmatch(component):
        component = "core"
    name = type(exc).__name__
    if not (name.isascii() and name.isidentifier()):
        name = "Exception"
    return InternalError(
        component,
        f"{name}: this part of the analysis could not finish; details are withheld",
    )


def error_fail_on(
    explicit: str | None, base_config: FailOn | None, *, config_known_present: bool = False
) -> FailOn:
    """``fail-on`` for a run that failed before policy loaded (I-14 Q5, D-PM-32, SR-015).

    The explicit input or flag when present and valid wins. Otherwise the base
    config's value if it was already read. Otherwise, if the policy-side tree is
    known to contain a config file that wasn't read, ``new-stale``, so the run
    fails closed with exit 3; that value is an internal gate only, never a
    configured ``fail-on``. Otherwise ``none``.
    """
    for value in _FAIL_ON_VALUES:
        if explicit == value:
            return value
    if base_config is not None:
        return base_config
    if config_known_present:
        return "new-stale"
    return "none"


@dataclass(slots=True)
class RunContext:
    """What the pipeline has learned so far that error handling needs (I-14 Q5).

    The pipeline (T-028, T-029, T-031) records the raw explicit ``fail-on`` and
    the base config's ``fail-on`` here as soon as it reads them. T-028 sets
    ``config_known_present`` from base-side data only (D-PM-32).
    """

    explicit_fail_on: str | None = None
    base_fail_on: FailOn | None = None
    config_known_present: bool = False
    internal_errors: tuple[InternalError, ...] = ()


def _pipeline(
    argv: list[str],
    env: Mapping[str, str],
    entry: Literal["action", "cli"],
    components: Components,
    context: RunContext,
) -> RunOutcome:
    """The C3-to-C12 pipeline (DESIGN §2). Arrives with T-028."""
    raise NotImplementedError


def run(
    argv: list[str],
    env: Mapping[str, str],
    *,
    entry: Literal["action", "cli"],
    components: Components | None = None,
) -> int:
    """The single entrypoint for ``conventiondrift.action`` and ``conventiondrift.cli`` (I-2).

    ``entry`` is passed by the caller and never inferred from ``env``. Every
    ``BaseException`` from the pipeline (including ``SystemExit``,
    ``GeneratorExit`` and ``asyncio.CancelledError``) becomes an ``InternalError``
    and the run exits per I-4 with the ``fail-on`` known so far (I-14, SR F3).
    Only ``KeyboardInterrupt`` propagates.
    """
    context = RunContext()
    try:
        outcome = _pipeline(argv, env, entry, components or Components(), context)
    except KeyboardInterrupt:
        raise
    # I-14, SR F3: argument parsing never raises SystemExit, so any BaseException here came
    # from a component and must not pass the gate. Only KeyboardInterrupt propagates.
    except BaseException as exc:  # noqa: BLE001 -- I-14, SR F3: all but KeyboardInterrupt become an InternalError
        context.internal_errors += (internal_error(exc),)
        outcome = AnalysisOutcome(
            fail_on=error_fail_on(
                context.explicit_fail_on,
                context.base_fail_on,
                config_known_present=context.config_known_present,
            ),
            # Head-only isn't known yet when the error is caught. It doesn't matter: exit_code()
            # returns 0 for "none" and 3 for an internal error under a gating mode before it
            # looks at head_only (SC-2.50), so either value gives the same exit code.
            head_only=False,
            new_stale_met=False,
            any_stale_met=False,
            internal_error=True,
        )
    return exit_code(outcome)
