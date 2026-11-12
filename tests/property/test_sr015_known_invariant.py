"""SR-015 invariance: once the base-config gate is 'known', it stays closed.

I-14 / D-PM-32 / SR-015 condition 1: 'known' comes only from base-side data.
Once RunContext.config_known_present is set, run() must exit 3 on an early
crash, whatever argv, env or head-side data say.

The field is also set-once: a later write of False must not open the gate
(CR1: a stand-in that cleared it got exit 0). Those two assertions are T-028
behaviour and are strict xfails until T-028 lands.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, Literal, cast, get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conventiondrift import core
from conventiondrift.core import FailOn, RunContext, run

PLANTED = "ghp_FAKE0000 /home/runner/key.pem planted-token"

# AC-F9.1 / I-4 / I-6: the three legal fail-on values. Pin the code's FailOn
# literal to that list (D-TL-25) so a drifted constant fails this module.
SPEC_FAIL_ON: tuple[str, ...] = ("none", "new-stale", "any-stale")
assert get_args(FailOn) == SPEC_FAIL_ON

XFAIL_T028 = pytest.mark.xfail(strict=True, reason="needs T-028 set-once config_known_present")

argv_strat = st.lists(
    st.sampled_from(
        [
            "check",
            "--fail-on",
            "none",
            "new-stale",
            "any-stale",
            "bogus",
            "--fail-on=none",
            "--head",
            "origin/pr",
            "--base",
            "main",
            "--config",
            "head/.conventiondrift.yml",
        ]
    ),
    max_size=6,
)
env_strat = st.fixed_dictionaries(
    {
        "INPUT_FAIL_ON": st.sampled_from(["none", "new-stale", "any-stale", "bogus", ""]),
        "INPUT_CONFIG": st.sampled_from([".conventiondrift.yml", "head/.conventiondrift.yml", ""]),
        "GITHUB_EVENT_PATH": st.sampled_from(["", "fake-event.json"]),
    }
)
head_strat = st.fixed_dictionaries(
    {
        "head_config": st.sampled_from(["fail-on: none\n", "fail-on: any-stale\n", ""]),
        "head_sha": st.sampled_from(["deadbeef", ""]),
    }
)


@pytest.fixture(autouse=True)
def _restore_pipeline() -> Iterator[None]:
    original = core._pipeline
    try:
        yield
    finally:
        core._pipeline = original


def _install_pipeline(update: Mapping[str, Any], *, then_clear: bool = False) -> None:
    def pipeline(
        argv: list[str],
        env: Mapping[str, str],
        entry: Literal["action", "cli"],
        components: object,
        context: RunContext,
        update: Mapping[str, Any] = update,
        then_clear: bool = then_clear,
    ) -> object:
        del argv, env, entry, components
        for key, value in update.items():
            # Only assign declared RunContext fields; head-side extras stay off the context.
            if hasattr(type(context), key) or key in RunContext.__slots__:
                setattr(context, key, value)
        if then_clear:
            context.config_known_present = False
        raise RuntimeError(PLANTED)

    core._pipeline = pipeline  # type: ignore[assignment]


@settings(max_examples=40, deadline=None)
@given(argv=argv_strat, env=env_strat, head=head_strat, entry=st.sampled_from(["action", "cli"]))
def test_known_gate_stays_closed_against_argv_env_and_head(
    argv: list[str], env: dict[str, str], head: dict[str, str], entry: str
) -> None:
    # Head-side data is supplied only via argv/env-like inputs, never as the source of 'known'.
    _install_pipeline({"config_known_present": True})
    combined_env = {**env, "CD_HEAD_CONFIG": head["head_config"], "CD_HEAD_SHA": head["head_sha"]}
    entry_kind = cast(Literal["action", "cli"], entry)
    rc = run(list(argv), combined_env, entry=entry_kind)
    assert rc == 3


@XFAIL_T028
def test_config_known_present_is_set_once() -> None:
    """Once True, the flag must not be writable back to False (CR1 / SR-015 / T-028)."""
    context = RunContext()
    context.config_known_present = True
    with pytest.raises((AttributeError, TypeError, ValueError)):
        context.config_known_present = False
    assert context.config_known_present is True


@XFAIL_T028
def test_clearing_known_after_set_must_not_open_the_gate() -> None:
    """CR1 repro: a stand-in that cleared the flag must not flip the early-crash exit to 0."""
    _install_pipeline({"config_known_present": True}, then_clear=True)
    rc = run([], {}, entry="action")
    assert rc == 3, (
        "SR-015: once config_known_present was set, an early crash must exit 3; "
        f"clearing the flag opened the gate (exit {rc})"
    )
