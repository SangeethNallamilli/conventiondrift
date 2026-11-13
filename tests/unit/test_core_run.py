"""Unit tests for run(), the InternalError helper and error-time fail-on (T-006a, I-2, I-14)."""

import asyncio
import inspect
from collections.abc import Callable, Mapping
from typing import Any, Literal, get_args

import pytest

from conventiondrift import core
from conventiondrift.components import Components
from conventiondrift.core import (
    AnalysisOutcome,
    FailOn,
    RefusedTriggerOutcome,
    RunContext,
    RunOutcome,
    UsageErrorOutcome,
    error_fail_on,
    internal_error,
    run,
)
from conventiondrift.errors import ComponentError, GitTooOld, GitUnavailable
from conventiondrift.model import CheckerId, InternalError

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


@pytest.mark.parametrize(
    "component",
    ["core", "render", "git_reader", "a1:b_2", *(f"checker:{cid}" for cid in get_args(CheckerId))],
)
def test_valid_components_are_kept(component: str) -> None:
    assert internal_error(ComponentError(component, PLANTED)).component == component


@pytest.mark.parametrize(
    "component",
    [
        "",
        "Core",
        "1core",
        "_core",
        "checker:",
        "a:b:c",
        "checker:Logging",
        "core\n",
        "core x",
        "ćore",
        "checker:a b",
        "-core",
        "core-x:logging",
        "checker:HTTP-client",
    ],
)
def test_invalid_components_become_core(component: str) -> None:
    assert internal_error(ComponentError(component, PLANTED)).component == "core"


@pytest.mark.parametrize("component", ["checker:http-client-", "checker:a--b"])
def test_trailing_and_doubled_suffix_hyphens_are_kept(component: str) -> None:
    # I-14's suffix class [a-z0-9_-]+ allows these, so they pass through unchanged.
    assert internal_error(ComponentError(component, PLANTED)).component == component


@pytest.mark.parametrize(
    "name",
    [
        "Ërror",
        "Bad Name",
        "Bad\nName",
        "1Error",
        "",
        "a-b",
        "Bad\u202eError",  # Cf: right-to-left override (bidi)
        "Bad\u200bError",  # Cf: zero-width space
    ],
)
def test_class_names_that_are_not_ascii_identifiers_become_exception(name: str) -> None:
    exc = type(name, (Exception,), {})()
    assert internal_error(exc) == InternalError("core", "Exception" + SUFFIX)


def test_system_exit_and_generator_exit_are_reported_by_class_name() -> None:
    assert internal_error(SystemExit(0)).message == "SystemExit" + SUFFIX
    assert internal_error(GeneratorExit()).message == "GeneratorExit" + SUFFIX


def test_exact_message_text() -> None:
    assert internal_error(RuntimeError()).message == (
        "RuntimeError: this part of the analysis could not finish; details are withheld"
    )


def test_git_too_old_uses_the_fixed_public_text() -> None:
    error = internal_error(GitTooOld())
    assert error == InternalError("gitread", "git 2.30 or newer is required")


def test_component_error_and_git_unavailable_still_withhold_details() -> None:
    hidden = "git found only in the repository, workspace or current folder"
    assert internal_error(ComponentError("gitread", hidden)) == InternalError(
        "gitread", "ComponentError" + SUFFIX
    )
    assert hidden not in internal_error(ComponentError("gitread", hidden)).message
    unavailable = internal_error(GitUnavailable("git executable not found at /home/x/secret"))
    assert unavailable == InternalError("core", "GitUnavailable" + SUFFIX)
    assert "git executable not found" not in unavailable.message
    assert "/home/x/secret" not in unavailable.message


@pytest.mark.parametrize(
    ("explicit", "base", "expected"),
    [
        ("new-stale", "any-stale", "new-stale"),
        ("any-stale", None, "any-stale"),
        ("none", "any-stale", "none"),
        (None, "new-stale", "new-stale"),
        ("bogus", "any-stale", "any-stale"),
        ("NEW-STALE", None, "new-stale"),  # SR F1: an invalid explicit value fails closed
        ("", None, "none"),
        (None, None, "none"),
    ],
)
def test_error_fail_on_order(explicit: str | None, base: Any, expected: str) -> None:
    # No keyword: config_known_present defaults to False, the pre-D-PM-32 behaviour.
    assert error_fail_on(explicit, base) == expected
    assert error_fail_on(explicit, base, config_known_present=False) == expected


@pytest.mark.parametrize(
    ("explicit", "base", "expected"),
    [
        # (a) an explicit valid value wins even when a config is known to exist.
        ("none", None, "none"),
        ("any-stale", None, "any-stale"),
        ("none", "any-stale", "none"),
        # the base config's value wins over known-present, including "none".
        (None, "none", "none"),
        (None, "any-stale", "any-stale"),
        ("bogus", "none", "none"),
        # (b) known present, nothing read: fail closed with the internal gate.
        (None, None, "new-stale"),
        ("bogus", None, "new-stale"),
    ],
)
def test_error_fail_on_with_config_known_present(
    explicit: str | None, base: Any, expected: str
) -> None:
    assert error_fail_on(explicit, base, config_known_present=True) == expected


INVALID_EXPLICIT = [
    "bogus",
    "NEW-STALE",
    "NONE",
    "None",
    "Any-Stale",
    " none",
    "none ",
    "none\n",
    "none\x00",
    "n\u043ene",  # "none" with a Cyrillic small o (U+043E)
    "\uff4e\uff4f\uff4e\uff45",  # fullwidth "none" (U+FF4E U+FF4F U+FF4E U+FF45)
]


def test_invalid_explicit_has_a_case_only_variant_of_every_value() -> None:
    # D-TL-25: values are matched exactly, with no case folding (I-14 SR F1), so every
    # valid value needs a case-only look-alike here; this kills a casefold() mutant.
    valid = set(get_args(FailOn))
    case_only = {v.casefold() for v in INVALID_EXPLICIT if v not in valid}
    assert valid <= case_only


@pytest.mark.parametrize("explicit", INVALID_EXPLICIT)
def test_invalid_explicit_fail_on_fails_closed(explicit: str) -> None:
    # SR F1: with no base value and no known config, an invalid explicit value is new-stale.
    assert error_fail_on(explicit, None) == "new-stale"
    assert error_fail_on(explicit, None, config_known_present=False) == "new-stale"


@pytest.mark.parametrize("explicit", INVALID_EXPLICIT)
def test_invalid_explicit_fail_on_exits_3_through_run(
    monkeypatch: pytest.MonkeyPatch, explicit: str
) -> None:
    pipeline = _Recorder(RuntimeError(), explicit_fail_on=explicit)
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="cli") == 3
    assert pipeline.context is not None
    assert pipeline.context.internal_errors == (InternalError("core", "RuntimeError" + SUFFIX),)


def test_empty_explicit_fail_on_still_counts_as_unset() -> None:
    assert error_fail_on("", None) == "none"
    assert error_fail_on("", None, config_known_present=True) == "new-stale"


@pytest.mark.parametrize("base", ["none", "new-stale", "any-stale"])
@pytest.mark.parametrize("explicit", ["bogus", "none ", "n\u043ene"])
def test_valid_base_value_beats_an_invalid_explicit_value(explicit: str, base: Any) -> None:
    assert error_fail_on(explicit, base) == base


def test_config_known_present_is_keyword_only_and_off_by_default() -> None:
    param = inspect.signature(error_fail_on).parameters["config_known_present"]
    assert (param.kind, param.default) == (inspect.Parameter.KEYWORD_ONLY, False)
    with pytest.raises(TypeError):
        error_fail_on(None, None, True)  # type: ignore[call-arg]


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
    monkeypatch: pytest.MonkeyPatch, entry: Literal["action", "cli"]
) -> None:
    pipeline = _Recorder(UsageErrorOutcome())
    monkeypatch.setattr(core, "_pipeline", pipeline)
    env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request"}
    run(["x"], env, entry=entry)
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
    with pytest.raises(TypeError):
        run([], {}, "cli")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        ({}, 0),
        ({"explicit_fail_on": "new-stale"}, 3),
        ({"explicit_fail_on": "none", "base_fail_on": "any-stale"}, 0),
        ({"base_fail_on": "any-stale"}, 3),
        ({"explicit_fail_on": "invalid", "base_fail_on": "new-stale"}, 3),
        ({"explicit_fail_on": "invalid"}, 3),  # SR F1
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


@pytest.mark.parametrize("exc", [SystemExit(0), SystemExit(), SystemExit(1), GeneratorExit()])
@pytest.mark.parametrize(("fail_on", "expected"), [("none", 0), ("new-stale", 3), ("any-stale", 3)])
def test_component_system_exit_and_generator_exit_become_internal_errors(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException, fail_on: str, expected: int
) -> None:
    # A component's SystemExit(0) must never pass the gate (I-14).
    pipeline = _Recorder(exc, explicit_fail_on=fail_on)
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="action") == expected
    assert pipeline.context is not None
    assert pipeline.context.internal_errors == (InternalError("core", type(exc).__name__ + SUFFIX),)


@pytest.mark.parametrize("exc_type", [SystemExit, GeneratorExit])
def test_component_exit_under_any_stale_fails_closed_and_withholds_its_argument(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    exc_type: type[SystemExit | GeneratorExit],
) -> None:
    zero = _Recorder(exc_type(0), explicit_fail_on="any-stale")
    monkeypatch.setattr(core, "_pipeline", zero)
    assert run([], {}, entry="action") == 3

    pipeline = _Recorder(exc_type("ghp_FAKE /home/x"), explicit_fail_on="any-stale")
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="cli") == 3
    assert pipeline.context is not None
    (error,) = pipeline.context.internal_errors
    assert error == InternalError("core", exc_type.__name__ + SUFFIX)
    out, err = capsys.readouterr()
    for planted in ("ghp_FAKE", "/home/x"):
        assert planted not in error.message
        assert planted not in error.component
        assert planted not in out
        assert planted not in err


def test_run_git_too_old_debug_data_is_never_shown(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    version = "git version 2.29.0"
    host_path = "/home/x/secret"
    planted = f"{version} at {host_path}"
    try:
        raise RuntimeError(planted)
    except RuntimeError as cause:
        exc = GitTooOld()
        exc.__cause__ = cause
        exc.__context__ = cause
        exc.add_note(planted)
        exc.found_version = version  # type: ignore[attr-defined]
        exc.host_path = host_path  # type: ignore[attr-defined]

    pipeline = _Recorder(exc, explicit_fail_on="any-stale")
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="cli") == 3
    assert pipeline.context is not None
    (error,) = pipeline.context.internal_errors
    assert error == InternalError("gitread", "git 2.30 or newer is required")
    out, err = capsys.readouterr()
    for part in (version, host_path, planted):
        assert part not in error.message
        assert part not in error.component
        assert part not in out
        assert part not in err


def test_run_keeps_internal_errors_recorded_before_a_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    earlier = InternalError("checker:logging", "ComponentError" + SUFFIX)
    pipeline = _Recorder(
        ComponentError("render", PLANTED), internal_errors=(earlier,), explicit_fail_on="new-stale"
    )
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="action") == 3
    assert pipeline.context is not None
    assert pipeline.context.internal_errors == (
        earlier,
        InternalError("render", "ComponentError" + SUFFIX),
    )


GHP_FAKE = "ghp_FAKE0123456789"
HOST_PATH = "/home/runner/secret/x"


class Boom(BaseException):
    """A bare BaseException subclass a component might raise."""


Bóom = type("Bóom", (BaseException,), {})


@pytest.mark.parametrize(
    ("make", "name"),
    [
        (lambda: asyncio.CancelledError(GHP_FAKE, HOST_PATH), "CancelledError"),
        (lambda: Boom(GHP_FAKE, HOST_PATH), "Boom"),
        (lambda: Bóom(GHP_FAKE, HOST_PATH), "Exception"),
    ],
    ids=["CancelledError", "Boom", "non-ascii-name"],
)
@pytest.mark.parametrize(("fail_on", "expected"), [("none", 0), ("new-stale", 3), ("any-stale", 3)])
def test_run_turns_any_base_exception_into_an_internal_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make: Callable[[], BaseException],
    name: str,
    fail_on: str,
    expected: int,
) -> None:
    # SR F3: every BaseException except KeyboardInterrupt is caught and fails closed.
    pipeline = _Recorder(make(), explicit_fail_on=fail_on)
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="action") == expected
    assert pipeline.context is not None
    (error,) = pipeline.context.internal_errors
    assert error == InternalError("core", name + SUFFIX)
    out, err = capsys.readouterr()
    for planted in (GHP_FAKE, HOST_PATH):
        for text in (error.component, error.message, out, err):
            assert planted not in text


def test_run_lets_keyboard_interrupt_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        core, "_pipeline", _Recorder(KeyboardInterrupt(), explicit_fail_on="any-stale")
    )
    with pytest.raises(KeyboardInterrupt):
        run([], {}, entry="cli")


def test_unwired_pipeline_is_an_internal_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Until T-028 lands the pipeline is not wired, and run() reports that as a core error.
    contexts: list[RunContext] = []

    def _captured() -> RunContext:
        contexts.append(RunContext())
        return contexts[-1]

    monkeypatch.setattr(core, "RunContext", _captured)
    assert run(["check"], {}, entry="cli") == 0
    assert [c.internal_errors for c in contexts] == [
        (InternalError("core", "NotImplementedError" + SUFFIX),)
    ]
    with pytest.raises(NotImplementedError):
        core._pipeline([], {}, "cli", Components(), RunContext())


def test_run_context_defaults() -> None:
    context = RunContext()
    assert (
        context.explicit_fail_on,
        context.base_fail_on,
        context.config_known_present,
        context.internal_errors,
    ) == (None, None, False, ())


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        ({"config_known_present": True}, 3),
        ({"config_known_present": False}, 0),
        ({}, 0),
        ({"config_known_present": True, "explicit_fail_on": "none"}, 0),
        ({"config_known_present": True, "base_fail_on": "none"}, 0),
        ({"config_known_present": True, "base_fail_on": "any-stale"}, 3),
    ],
)
def test_run_uses_config_known_present_for_an_early_crash(
    monkeypatch: pytest.MonkeyPatch, context: dict[str, Any], expected: int
) -> None:
    pipeline = _Recorder(RuntimeError(PLANTED), **context)
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry="action") == expected
    assert pipeline.context is not None
    # The internal error is recorded either way, so exit 0 still writes the section.
    assert pipeline.context.internal_errors == (InternalError("core", "RuntimeError" + SUFFIX),)


@pytest.mark.parametrize("entry", ["action", "cli"])
def test_internal_gate_is_not_presented_as_a_configured_fail_on(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    entry: Literal["action", "cli"],
) -> None:
    # D-PM-32 case (b): "new-stale" is an internal gate only. Nothing in src renders a
    # fail-on or policy source yet; the renderer task owns the summary wording.
    pipeline = _Recorder(RuntimeError(), config_known_present=True)
    monkeypatch.setattr(core, "_pipeline", pipeline)
    assert run([], {}, entry=entry) == 3
    assert pipeline.context is not None
    (error,) = pipeline.context.internal_errors
    out, err = capsys.readouterr()
    for text in (error.component, error.message, out, err):
        assert "fail-on" not in text
        assert "new-stale" not in text
