"""Unit tests for conventiondrift.policy.build_policy (T-012; I-4 B7, I-5, I-7, DESIGN §10 B7).

Expected answers come from SPEC AC-F9.x, INTERFACES I-4/I-5/I-7/I-14 and D-PM-12.
"""

import dataclasses
from collections.abc import Mapping
from typing import Any, get_args

import pytest

from conventiondrift import core, policy
from conventiondrift.core import FailOn
from conventiondrift.model import CheckerPolicy, IgnoreEntry, Thresholds
from conventiondrift.policy import (
    DEFAULT_CONFIG_PATH,
    Inputs,
    PolicySide,
    build_policy,
    config_path,
)
from conventiondrift.policy.config import DEFAULT_EXCLUDES, HISTORY_DAYS_RANGE, SideConfig

FAIL_ON: tuple[FailOn, ...] = get_args(FailOn)
M = "<!-- conventiondrift: ignore -->"
DEFAULT_T = Thresholds(80, 20, 20, 50, 70, 5)  # I-6 defaults
T_20 = dataclasses.replace(DEFAULT_T, stale_overall=20, stale_recent=20)
T_5 = dataclasses.replace(DEFAULT_T, stale_overall=5, stale_recent=5)
RULES = b"# Rules\n- Use httpx for HTTP calls\n"
RULES_IGNORED = b"# Rules\n- Use httpx for HTTP calls " + M.encode() + b"\n"


def side(config: SideConfig | None = None, files: Mapping[str, bytes] | None = None) -> PolicySide:
    return PolicySide(config=config, instruction_files={"AGENTS.md": RULES, **(files or {})})


def bool_inputs(name: str, value: str | None) -> Inputs:
    return Inputs(comment=value) if name == "comment" else Inputs(sarif=value)


def compare(inputs: Inputs, base: PolicySide, head: PolicySide) -> Any:
    return build_policy("compare", inputs, base=base, head=head)


# --- effective fail-on and policy source -----------------------------------------------


def test_fail_on_values_are_the_three_spec_values() -> None:
    assert set(FAIL_ON) == {"none", "new-stale", "any-stale"}


@pytest.mark.parametrize("explicit", [*FAIL_ON, None, ""])
@pytest.mark.parametrize("base_value", [*FAIL_ON, None])
@pytest.mark.parametrize("head_value", [*FAIL_ON, None])
def test_effective_fail_on_is_input_else_base_config_else_none(
    explicit: str | None, base_value: FailOn | None, head_value: FailOn | None
) -> None:
    # I-4 B7 / AC-F9.15: the input wins, else the base config, else none; head never decides.
    expected = explicit or base_value or "none"
    result = compare(
        Inputs(fail_on=explicit),
        side(SideConfig(fail_on=base_value)),
        side(SideConfig(fail_on=head_value)),
    )
    assert result.effective_fail_on == expected
    assert result.gated is (expected != "none")
    assert result.source == ("base" if expected != "none" else "head")


@pytest.mark.parametrize("explicit", ["bogus", "None", "none ", "NEW-STALE", "Any-Stale"])
def test_invalid_explicit_fail_on_fails_closed(explicit: str) -> None:
    # I-14 SR F1: a non-empty invalid explicit value never opens the gate.
    result = compare(Inputs(fail_on=explicit), side(), side())
    assert result.effective_fail_on == "new-stale"
    assert result.source == "base"


def test_fail_on_reuses_core_error_fail_on(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, ...]] = []

    def spy(explicit: str | None, base_config: FailOn | None, **kw: Any) -> FailOn:
        calls.append((explicit, base_config, kw))
        return "any-stale"

    monkeypatch.setattr(policy, "error_fail_on", spy)
    result = compare(Inputs(fail_on="x"), side(SideConfig(fail_on="none")), side())
    assert calls == [("x", "none", {})]
    assert result.effective_fail_on == "any-stale"
    assert getattr(policy, "error_fail_on") is spy  # noqa: B009
    assert core.error_fail_on is not spy


@pytest.mark.parametrize("mode", ["head-only", "scan"])
@pytest.mark.parametrize("config_fail_on", [*FAIL_ON, None])
def test_single_side_modes_take_policy_from_the_analyzed_tree(
    mode: Any, config_fail_on: FailOn | None
) -> None:
    # I-4: scan mode uses the flag, else the working-tree config; head-only uses the
    # analyzed commit (I-7, D-PM-22). Either way the source is that tree, reported as head.
    result = build_policy(
        mode,
        Inputs(),
        head=side(
            SideConfig(fail_on=config_fail_on, thresholds=T_5), files={"AGENTS.md": RULES_IGNORED}
        ),
    )
    assert result.effective_fail_on == (config_fail_on or "none")
    assert result.source == "head"
    assert result.thresholds == T_5
    assert result.markers == {"AGENTS.md": ((2, False),)}
    assert result.after_merge_notes == ()


@pytest.mark.parametrize(
    ("mode", "with_base"), [("compare", False), ("head-only", True), ("scan", True)]
)
def test_base_side_is_required_in_compare_mode_only(mode: Any, with_base: bool) -> None:
    with pytest.raises(ValueError, match="base side"):
        build_policy(mode, Inputs(), head=side(), base=side() if with_base else None)


# --- AC-F9.12 to AC-F9.15 -------------------------------------------------------------


def test_ac_f9_12_gated_run_uses_base_policy_and_notes_each_change() -> None:
    base = side(SideConfig(thresholds=T_20))
    head = side(
        SideConfig(
            thresholds=T_5,
            checkers={"http-client": CheckerPolicy(enabled=False, script_paths=())},
            ignores=(IgnoreEntry(file="AGENTS.md", line=2, text=None),),
        )
    )
    result = compare(Inputs(fail_on="new-stale"), base, head)
    assert result.source == "base"
    assert result.thresholds == T_20
    assert result.checkers["http-client"].enabled is True
    assert result.ignores == ()
    joined = "\n".join(result.after_merge_notes)
    for key in ("thresholds", "checkers.http-client", "ignore"):
        assert key in joined
    assert len(result.after_merge_notes) == 3
    assert all("takes effect after merge" in n for n in result.after_merge_notes)


def test_ac_f9_13_new_inline_ignore_is_not_applied_when_gated() -> None:
    result = compare(Inputs(fail_on="new-stale"), side(), side(files={"AGENTS.md": RULES_IGNORED}))
    assert result.markers == {}
    assert len(result.after_merge_notes) == 1
    assert "AGENTS.md" in result.after_merge_notes[0]
    assert "takes effect after merge" in result.after_merge_notes[0]


def test_ac_f9_14_ungated_run_uses_head_policy_without_notes() -> None:
    base = side(SideConfig(thresholds=T_20))
    head = side(
        SideConfig(thresholds=T_5), files={"AGENTS.md": b"- Use httpx\n" + M.encode() + b"\n"}
    )
    result = compare(Inputs(), base, head)
    assert result.effective_fail_on == "none"
    assert result.source == "head"
    assert result.thresholds == T_5
    assert result.markers == {"AGENTS.md": ((2, True),)}
    assert result.after_merge_notes == ()


def test_ac_f9_15_base_fail_on_wins_and_the_change_is_noted() -> None:
    result = compare(
        Inputs(), side(SideConfig(fail_on="new-stale")), side(SideConfig(fail_on="none"))
    )
    assert result.effective_fail_on == "new-stale"
    assert len(result.after_merge_notes) == 1
    assert "fail-on" in result.after_merge_notes[0]


def test_ac_f9_15_input_fail_on_beats_config_and_suppresses_its_note() -> None:
    base = side(SideConfig(fail_on="new-stale"))
    head = side(SideConfig(fail_on="none"))
    assert compare(Inputs(fail_on="none"), base, head).source == "head"
    gated = compare(Inputs(fail_on="any-stale"), base, head)
    assert gated.effective_fail_on == "any-stale"
    assert gated.after_merge_notes == ()


def test_no_notes_when_policies_resolve_equal() -> None:
    # No config on base and a config that spells out every default on head: no difference.
    explicit = SideConfig(fail_on="new-stale", history_days=90, thresholds=DEFAULT_T,
                          max_file_bytes=1048576)  # fmt: skip
    result = compare(Inputs(fail_on="new-stale"), side(None), side(explicit))
    assert result.after_merge_notes == ()


def test_every_policy_difference_gets_a_note_in_fixed_order() -> None:
    base = side(SideConfig(fail_on="new-stale"))
    head = side(
        SideConfig(
            fail_on="any-stale",
            history_days=30,
            thresholds=T_5,
            exclude=("legacy/**",),
            max_file_bytes=4096,
            checkers={
                "money": CheckerPolicy(True, ()),
                "logging": CheckerPolicy(True, ("scripts/**",)),
            },
            ignores=(IgnoreEntry(None, None, "use httpx"),),
        ),
        files={"AGENTS.md": RULES_IGNORED, "CLAUDE.md": M.encode()},
    )
    notes = compare(Inputs(), base, head).after_merge_notes
    keys = ["fail-on", "history-days", "thresholds", "exclude", "limits.max-file-bytes",
            "checkers.logging", "checkers.money", "ignore", "markers in AGENTS.md",
            "markers in CLAUDE.md"]  # fmt: skip
    assert len(notes) == len(keys)
    for note, key in zip(notes, keys, strict=True):
        assert f" {key} " in f"{note} ".replace(";", " ")


def test_history_days_input_suppresses_its_config_note() -> None:
    base = side(SideConfig(fail_on="new-stale"))
    head = side(SideConfig(fail_on="new-stale", history_days=30))
    assert compare(Inputs(history_days="45"), base, head).after_merge_notes == ()
    assert len(compare(Inputs(), base, head).after_merge_notes) == 1


def test_head_range_errors_compare_as_defaults() -> None:
    base = side(SideConfig(fail_on="new-stale"))
    head = side(
        SideConfig(fail_on="new-stale", thresholds=dataclasses.replace(DEFAULT_T, holds=150))
    )
    result = compare(Inputs(), base, head)
    assert result.after_merge_notes == ()
    # Head's notes don't apply when base policy is used.
    assert result.notes == ()


# --- precedence and inputs -------------------------------------------------------------


def test_defaults_without_any_config_or_input() -> None:
    result = compare(Inputs(), side(None), side(None))
    assert (result.history_days, result.thresholds, result.max_file_bytes) == (
        90,
        DEFAULT_T,
        1048576,
    )
    assert (result.comment, result.sarif, result.paths) == (True, True, None)
    assert result.excludes == DEFAULT_EXCLUDES
    assert {cid for cid, p in result.checkers.items() if not p.enabled} == {"money"}
    assert result.notes == ()


def test_config_beats_defaults_and_input_beats_config() -> None:
    cfg = SideConfig(
        history_days=30, max_file_bytes=4096, checkers={"money": CheckerPolicy(True, ())}
    )
    result = compare(Inputs(), side(None), side(cfg))
    assert (result.history_days, result.max_file_bytes) == (30, 4096)
    assert result.checkers["money"].enabled is True
    assert compare(Inputs(history_days="45"), side(None), side(cfg)).history_days == 45


@pytest.mark.parametrize(
    "value",
    [str(HISTORY_DAYS_RANGE[0]), str(HISTORY_DAYS_RANGE[1]), "090", "30"],
)
def test_valid_history_days_input(value: str) -> None:
    result = compare(Inputs(history_days=value), side(), side())
    assert (result.history_days, result.notes) == (int(value), ())


@pytest.mark.parametrize(
    "value",
    [
        str(HISTORY_DAYS_RANGE[0] - 1),
        str(HISTORY_DAYS_RANGE[1] + 1),
        "-5", "+5", " 30", "30 ", "3_0", "\u0663\u0660", "abc", "1.5", "1e2",
        "99999999999999999999",
    ],
)  # fmt: skip
@pytest.mark.parametrize("config_days", [None, 30])
def test_invalid_history_days_input_gets_a_note_and_the_fallback(
    value: str, config_days: int | None
) -> None:
    # DESIGN §4: note in summary, default used (the next value in precedence order).
    result = compare(Inputs(history_days=value), side(), side(SideConfig(history_days=config_days)))
    assert result.history_days == (config_days or 90)
    # Fixed text: the input value is never echoed.
    assert result.notes == ("history-days input must be an integer from 1 to 3650; it was ignored",)


@pytest.mark.parametrize("name", ["comment", "sarif"])
@pytest.mark.parametrize(
    ("value", "expected"), [("true", True), ("false", False), ("", True), (None, True)]
)
def test_valid_bool_inputs(name: str, value: str | None, expected: bool) -> None:
    result = compare(bool_inputs(name, value), side(), side())
    assert (getattr(result, name), result.notes) == (expected, ())


@pytest.mark.parametrize("name", ["comment", "sarif"])
@pytest.mark.parametrize(
    "value", ["True", "FALSE", "yes", "no", "1", "0", "false ", " true", "off"]
)
def test_invalid_bool_input_gets_a_note_and_the_default(name: str, value: str) -> None:
    result = compare(bool_inputs(name, value), side(), side())
    assert getattr(result, name) is True  # I-5 default
    # Fixed text: the input value is never echoed.
    assert result.notes == (f"{name} input must be true or false; the default true is used",)


def test_notes_order_inputs_then_config_then_ranges() -> None:
    cfg = SideConfig(thresholds=dataclasses.replace(DEFAULT_T, holds=0), notes=("unknown key foo",))
    result = compare(Inputs(history_days="x", comment="x", sarif="x"), side(), side(cfg))
    assert [n.split(" ")[0] for n in result.notes] == [
        "history-days", "comment", "sarif", "unknown", "thresholds.holds",
    ]  # fmt: skip
    assert result.thresholds == DEFAULT_T


def test_policy_side_range_backstop_sr_f1() -> None:
    # SR F1 on #25: out-of-range thresholds never reach C9, even on the gated base side.
    bad = dataclasses.replace(DEFAULT_T, holds=150, min_sites=0)
    result = compare(Inputs(fail_on="new-stale"), side(SideConfig(thresholds=bad)), side())
    assert result.thresholds == DEFAULT_T
    assert len(result.notes) == 2


# --- excludes, paths, config path, markers ---------------------------------------------


def test_ac_f9_3_exclude_input_replaces_defaults_and_config_adds_on_top() -> None:
    cfg = SideConfig(exclude=("legacy/**", "gen/"))
    result = compare(Inputs(exclude=("old/**", "gen/")), side(), side(cfg))
    assert result.excludes == ("old/**", "gen/", "legacy/**")
    without_input = compare(Inputs(), side(), side(cfg))
    assert without_input.excludes == (*DEFAULT_EXCLUDES, "legacy/**", "gen/")


def test_empty_exclude_input_counts_as_not_given() -> None:
    assert compare(Inputs(exclude=()), side(), side()).excludes == DEFAULT_EXCLUDES


def test_hard_excludes_are_never_listed_even_if_configured_away() -> None:
    # SC-2.43: .git/ and node_modules/ are C4's; Policy.excludes lists only effective globs.
    result = compare(Inputs(exclude=("src/",)), side(), side())
    assert result.excludes == ("src/",)


def test_paths_input() -> None:
    assert compare(Inputs(paths=("docs/RULES.md",)), side(), side()).paths == ("docs/RULES.md",)
    assert compare(Inputs(paths=()), side(), side()).paths is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, DEFAULT_CONFIG_PATH), ("", DEFAULT_CONFIG_PATH), ("ci/cd.yml", "ci/cd.yml")],
)
def test_ac_f9_7_config_path(value: str | None, expected: str) -> None:
    assert DEFAULT_CONFIG_PATH == ".conventiondrift.yml"
    assert config_path(Inputs(config=value)) == expected


def test_markers_come_from_the_policy_side_with_alone_flags() -> None:
    base_doc = b"- Use httpx " + M.encode() + b"\n  " + M.encode() + b"\n- Use pytest\n"
    base = side(files={"AGENTS.md": base_doc})
    head = side()
    gated = compare(Inputs(fail_on="any-stale"), base, head)
    assert gated.markers == {"AGENTS.md": ((1, False), (2, True))}
    assert compare(Inputs(), base, head).markers == {}


def test_unchanged_markers_apply_without_a_note_when_gated() -> None:
    both = {"AGENTS.md": RULES_IGNORED}
    result = compare(Inputs(fail_on="new-stale"), side(files=both), side(files=both))
    assert result.markers == {"AGENTS.md": ((2, False),)}
    assert result.after_merge_notes == ()


def test_invalid_explicit_fail_on_does_not_hide_the_config_fail_on_note() -> None:
    # I-14 SR F1 order: the base config's value beats an invalid explicit value, so a
    # config fail-on change still takes effect after merge.
    base = side(SideConfig(fail_on="any-stale"))
    result = compare(Inputs(fail_on="bogus"), base, side(SideConfig(fail_on="none")))
    assert result.effective_fail_on == "any-stale"
    assert len(result.after_merge_notes) == 1
    assert "fail-on" in result.after_merge_notes[0]


@pytest.mark.parametrize("fail_on", ["new-stale", "any-stale"])
@pytest.mark.parametrize("base_files", [{}, {"AGENTS.md": RULES}, {"AGENTS.md": b""}])
def test_sr32_c1_head_only_marker_has_no_effect_when_gated(
    fail_on: str, base_files: dict[str, bytes]
) -> None:
    # SR #32 C-1: a gated run's markers come from the base side only, with no fallback
    # to head, even when base has no instruction file or no marker in it.
    base = PolicySide(config=None, instruction_files=base_files)
    head = PolicySide(
        config=None, instruction_files={"AGENTS.md": RULES_IGNORED, "CLAUDE.md": M.encode()}
    )
    result = compare(Inputs(fail_on=fail_on), base, head)
    assert result.source == "base"
    assert result.markers == {}
    assert len(result.after_merge_notes) == 2
