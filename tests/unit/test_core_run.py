"""Unit tests for run(), the InternalError helper and error-time fail-on (T-006a, I-2, I-14)."""

from collections.abc import Mapping
from typing import Any

import pytest

from conventiondrift import core
from conventiondrift.components import Components
from conventiondrift.core import (
    AnalysisOutcome,
    RefusedTriggerOutcome,
    RunContext,
    RunOutcome,
    UsageErrorOutcome,
    error_fail_on,
    internal_error,
    run,
)
from conventiondrift.errors import ComponentError, GitUnavailable
from conventiondrift.model import InternalError

PLANTED = "ghp_FAKE0000planted/src/secret.py contents"
SUFFIX = ": this part of the analysis could not finish; details are withheld"


def test_component_error_keeps_its_component_and_withholds_its_message() -> None:
    error = internal_error(ComponentError("checker:logging", PLANTED))
    assert error == InternalError("checker:logging", "ComponentError" + SUFFIX)
    assert PLANTED not in error.message


@pytest.mark.parametrize(
    "exc", [ValueError(PLANTED), KeyError(PLANTED), GitUnavailable(PLANTED), RuntimeError()]
)
def test_other_exceptions_are_reported_as_core(exc: Exception) -> None:
    error = internal_error(exc)
    assert error == InternalError("core", type(exc).__name__ + SUFFIX)
    assert PLANTED not in error.message


def test_exact_message_text() -> None:
    assert internal_error(RuntimeError()).message == (
        "RuntimeError: this part of the analysis could not finish; details are withheld"
    )


@pytest.mark.parametrize(
    ("explicit", "base", "expected"),
    [
        ("new-stale", "any-stale", "new-stale"),
        ("any-stale", None, "any-stale"),
        ("none", "any-stale", "none"),
        (None, "new-stale", "new-stale"),
        ("bogus", "any-stale", "any-stale"),
        ("NEW-STALE", None, "none"),
        ("", None, "none"),
        (None, None, "none"),
    ],
)
def test_error_fail_on_order(explicit: str | None, base: Any, expected: str) -> None:
    assert error_fail_on(explicit, base) == expected


class _Recorder:
    """Stands in for the T-028 pipeline and records what run() passed it."""

    def __init__(self, result: RunOutcome | BaseException, **context: Any) -> None:
        self.result = result
        self.context_updates = context
        self.calls: list[tuple[Any, ...]] = []
        self.context: RunContext | None = None

    def __call__(
        self,
        argv: list[str],
        env: Mapping[str, str],
        entry: str,
        components: Components,
        context: RunContext,
    ) -> RunOutcome:
        self.calls.append((argv, env, entry, components))
        self.context = context
        for name, value in self.context_updates.items():
            setattr(context, name, value)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (UsageErrorOutcome(), 2),
        (RefusedTriggerOutcome(), 4),
        (
            AnalysisOutcome(
                fail_on="any-stale",
                head_only=False,
                new_stale_met=False,
                any_stale_met=True,
                internal_error=False,
            ),
            1,
        ),
    ],
)
def test_run_maps_the_pipeline_outcome(
    monkeypatch: pytest.MonkeyPatch, outcome: RunOutcome, expected: int
) -> None:
    pipeline = _Recorder(outcome)
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run(["check"], {}, entry="action") == expected
    assert pipeline.context is not None
    assert pipeline.context.internal_errors == ()


@pytest.mark.parametrize("entry", ["action", "cli"])
def test_run_passes_entry_through_and_never_reads_it_from_env(
    monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    pipeline = _Recorder(UsageErrorOutcome())
    monkeypatch.setattr(core, "_pipeline", pipeline)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request"}
    run(["x"], env, entry=entry)  # type: ignore[arg-type]
    assert pipeline.calls[0][:3] == (["x"], env, entry)


def test_run_uses_default_components_or_the_given_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = _Recorder(UsageErrorOutcome())
    monkeypatch.setattr(core, "_pipeline", pipeline)
    run([], {}, entry="cli")
    assert pipeline.calls[0][3] == Components()
    given = Components(github_base_url="http://127.0.0.1:1")
    run([], {}, entry="cli", components=given)
    assert pipeline.calls[1][3] is given


def test_run_requires_entry() -> None:
    with pytest.raises(TypeError):
        run([], {})  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        ({}, 0),
        ({"explicit_fail_on": "new-stale"}, 3),
        ({"explicit_fail_on": "none", "base_fail_on": "any-stale"}, 0),
        ({"base_fail_on": "any-stale"}, 3),
        ({"explicit_fail_on": "invalid", "base_fail_on": "new-stale"}, 3),
        ({"explicit_fail_on": "invalid"}, 0),
    ],
)
def test_run_reports_a_raising_pipeline_with_the_fail_on_known_so_far(
    monkeypatch: pytest.MonkeyPatch, context: dict[str, Any], expected: int
) -> None:
    pipeline = _Recorder(ComponentError("render", PLANTED), **context)
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="action") == expected
    assert pipeline.context is not None
    assert pipeline.context.internal_errors == (InternalError("render", "ComponentError" + SUFFIX),)


def test_run_reports_non_component_exceptions_as_core(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = _Recorder(ValueError(PLANTED), explicit_fail_on="any-stale")
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="cli") == 3
    assert pipeline.context is not None
    assert pipeline.context.internal_errors == (InternalError("core", "ValueError" + SUFFIX),)


@pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_run_does_not_swallow_base_exceptions(
    monkeypatch: pytest.MonkeyPatch, exc_type: type[BaseException]
) -> None:
    monkeypatch.setattr(core, "_pipeline", _Recorder(exc_type()))
    with pytest.raises(exc_type):
        run([], {}, entry="cli")


def test_unwired_pipeline_is_an_internal_error() -> None:
    # Until T-028 lands the pipeline is not wired, and run() reports that as a core error.
    assert run(["check"], {}, entry="cli") == 0
    with pytest.raises(NotImplementedError):
        core._pipeline([], {}, "cli", Components(), RunContext())


def test_run_context_defaults() -> None:
    context = RunContext()
    assert (context.explicit_fail_on, context.base_fail_on, context.internal_errors) == (
        None,
        None,
        (),
    )
