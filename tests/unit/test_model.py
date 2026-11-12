"""Unit tests for the boundary types in conventiondrift.model (T-005; I-10, I-11, I-13)."""

import dataclasses
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, get_args, get_type_hints

import pytest

from conventiondrift import model
from conventiondrift.model import (
    Alternative,
    CausingFile,
    CheckerId,
    CheckerPolicy,
    Conflict,
    Counts,
    FileContext,
    IgnoreEntry,
    InstructionFile,
    InternalError,
    ManifestFile,
    Policy,
    PyFile,
    ReportCounts,
    Result,
    Rule,
    RuleMatch,
    RuleResult,
    SideResult,
    Site,
    SiteResult,
    SkippedFile,
    Suggestion,
    Thresholds,
    Verdict,
    Window,
)

CHECKER_IDS: tuple[CheckerId, ...] = get_args(CheckerId)
MATCH = RuleMatch(preferred=frozenset({"httpx"}), prohibited=frozenset({"requests"}), specificity=2)
SITE = Site(file="src/a.py", line=12, col=4, option="requests")
RULE = Rule(
    id="AGENTS.md:9",
    file="AGENTS.md",
    line=9,
    also_at=(20,),
    text="Use httpx, not requests",
    normalized_text="use httpx, not requests",
    checker="http-client",
    match=MATCH,
    scope_dir="",
    ignored=False,
    disabled=False,
)
THRESHOLDS = Thresholds(
    holds=80,
    stale_overall=20,
    stale_recent=20,
    migrating_overall=50,
    migrating_recent=70,
    min_sites=5,
)
LOGGING = CheckerPolicy(enabled=True, script_paths=("**/tests/**",))
POLICY = Policy(
    effective_fail_on="new-stale",
    gated=True,
    source="base",
    history_days=90,
    thresholds=THRESHOLDS,
    excludes=("legacy/**",),
    max_file_bytes=1048576,
    checkers=MappingProxyType(
        {cid: LOGGING if cid == "logging" else CheckerPolicy(True, ()) for cid in CHECKER_IDS}
    ),
    ignores=(IgnoreEntry(file="AGENTS.md", line=9, text=None),),
    markers=MappingProxyType({"AGENTS.md": (4,)}),
    paths=None,
    comment=True,
    sarif=True,
    after_merge_notes=(),
    notes=("n",),
)
SIDE = SideResult(
    verdict=Verdict.STALE,
    sites=(SiteResult(site=SITE, follows=False, recent=True),),
    overall=Counts(following=0, contradicting=1, relevant=1),
    recent=None,
    recent_unavailable_reason="no history",
)
SUGGESTION = Suggestion(
    kind="replace",
    named_option="httpx",
    alternatives=(Alternative(option="requests", sites=40),),
    new_text="Use requests, not httpx",
)
RULE_RESULT = RuleResult(
    rule_id="AGENTS.md:9",
    base_rule=None,
    head_rule=RULE,
    base=None,
    head=SIDE,
    conflict_with=("CLAUDE.md:3",),
    case="stale-rule-added",
    causing_files=(CausingFile(file="src/a.py", following_delta=-3, contradicting_delta=3),),
    suggestion=SUGGESTION,
)
WINDOW = Window(
    end=datetime(2026, 11, 12, 9, 0, tzinfo=UTC), days=90, available=True, unavailable_reason=None
)
RESULT = Result(
    mode="compare",
    base_sha="a" * 40,
    head_sha="b" * 40,
    head_only_reason=None,
    window=WINDOW,
    policy=POLICY,
    instruction_files=(),
    skipped_files=(SkippedFile(path="x.py", reason="binary"),),
    rule_results=(RULE_RESULT,),
    conflicts=(),
    unattached_markers=(("AGENTS.md", 30),),
    internal_errors=(InternalError(component="checker:logging", message="Internal error"),),
    counts=ReportCounts(stale=1, new_stale=1, rules_changed=1, rules_unchanged=0),
    notes=(),
    analyzer_python="3.13.5",
)

# One sample per model type, with the field names I-13 gives it, in order.
SAMPLES: dict[str, tuple[Any, tuple[str, ...]]] = {
    "RuleMatch": (MATCH, ("preferred", "prohibited", "specificity")),
    "Site": (SITE, ("file", "line", "col", "option")),
    "FileContext": (
        FileContext(
            path="t/test_a.py", is_test_file=True, is_script=False, main_guard_spans=((3, 5),)
        ),
        ("path", "is_test_file", "is_script", "main_guard_spans"),
    ),
    "InstructionFile": (
        InstructionFile(
            path="docs/RULES.md", data=b"- Use httpx", scope_dir="", via_paths_input=True
        ),
        ("path", "data", "scope_dir", "via_paths_input"),
    ),
    "PyFile": (PyFile(path="src/a.py", data=b"import httpx\n"), ("path", "data")),
    "ManifestFile": (ManifestFile(path="uv.lock", data=b"version = 1\n"), ("path", "data")),
    "SkippedFile": (SkippedFile(path="src/b.py", reason="syntax error"), ("path", "reason")),
    "Thresholds": (
        THRESHOLDS,
        (
            "holds",
            "stale_overall",
            "stale_recent",
            "migrating_overall",
            "migrating_recent",
            "min_sites",
        ),
    ),
    "CheckerPolicy": (LOGGING, ("enabled", "script_paths")),
    "IgnoreEntry": (
        IgnoreEntry(file=None, line=None, text="use requests"),
        ("file", "line", "text"),
    ),
    "Policy": (
        POLICY,
        (
            "effective_fail_on",
            "gated",
            "source",
            "history_days",
            "thresholds",
            "excludes",
            "max_file_bytes",
            "checkers",
            "ignores",
            "markers",
            "paths",
            "comment",
            "sarif",
            "after_merge_notes",
            "notes",
        ),
    ),
    "Rule": (
        RULE,
        (
            "id",
            "file",
            "line",
            "also_at",
            "text",
            "normalized_text",
            "checker",
            "match",
            "scope_dir",
            "ignored",
            "disabled",
        ),
    ),
    "Conflict": (
        Conflict(rules=("AGENTS.md:3", "CLAUDE.md:3"), checker="http-client"),
        ("rules", "checker"),
    ),
    "Counts": (SIDE.overall, ("following", "contradicting", "relevant")),
    "SiteResult": (SIDE.sites[0], ("site", "follows", "recent")),
    "SideResult": (
        SIDE,
        ("verdict", "sites", "overall", "recent", "recent_unavailable_reason"),
    ),
    "CausingFile": (
        RULE_RESULT.causing_files[0],
        ("file", "following_delta", "contradicting_delta"),
    ),
    "Alternative": (SUGGESTION.alternatives[0], ("option", "sites")),
    "Suggestion": (SUGGESTION, ("kind", "named_option", "alternatives", "new_text")),
    "RuleResult": (
        RULE_RESULT,
        (
            "rule_id",
            "base_rule",
            "head_rule",
            "base",
            "head",
            "conflict_with",
            "case",
            "causing_files",
            "suggestion",
        ),
    ),
    "Window": (WINDOW, ("end", "days", "available", "unavailable_reason")),
    "InternalError": (RESULT.internal_errors[0], ("component", "message")),
    "ReportCounts": (RESULT.counts, ("stale", "new_stale", "rules_changed", "rules_unchanged")),
    "Result": (
        RESULT,
        (
            "mode",
            "base_sha",
            "head_sha",
            "head_only_reason",
            "window",
            "policy",
            "instruction_files",
            "skipped_files",
            "rule_results",
            "conflicts",
            "unattached_markers",
            "internal_errors",
            "counts",
            "notes",
            "analyzer_python",
        ),
    ),
}
# Policy holds read-only mappings (MappingProxyType), which are not hashable,
# so Policy and Result (which holds a Policy) are not hashable either.
UNHASHABLE = {"Policy", "Result"}


def test_every_model_dataclass_has_a_sample() -> None:
    defined = {n for n, v in vars(model).items() if dataclasses.is_dataclass(v)}
    assert defined == set(SAMPLES)


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_fields_match_contract(name: str) -> None:
    sample, expected = SAMPLES[name]
    assert type(sample) is getattr(model, name)
    assert tuple(f.name for f in dataclasses.fields(sample)) == expected


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_is_frozen_and_slotted(name: str) -> None:
    sample, fields = SAMPLES[name]
    assert type(sample).__slots__ == fields
    assert not hasattr(sample, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(sample, fields[0], None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        delattr(sample, fields[0])
    with pytest.raises((AttributeError, TypeError)):
        sample.extra = 1


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_equal_copies_are_equal(name: str) -> None:
    sample, _ = SAMPLES[name]
    copy = dataclasses.replace(sample)
    assert copy is not sample
    assert copy == sample


@pytest.mark.parametrize("name", sorted(set(SAMPLES) - UNHASHABLE))
def test_equal_copies_hash_equal(name: str) -> None:
    sample, _ = SAMPLES[name]
    copy = dataclasses.replace(sample)
    assert hash(copy) == hash(sample)
    assert len({sample, copy}) == 1


@pytest.mark.parametrize("name", sorted(UNHASHABLE))
def test_types_holding_read_only_mappings_are_unhashable(name: str) -> None:
    sample, _ = SAMPLES[name]
    with pytest.raises(TypeError):
        hash(sample)


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_changing_a_field_breaks_equality(name: str) -> None:
    sample, fields = SAMPLES[name]
    for field in fields:
        value = getattr(sample, field)
        assert dataclasses.replace(sample, **{field: _different(value)}) != sample, field


def _different(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "x"
    if isinstance(value, bytes):
        return value + b"x"
    if isinstance(value, tuple):
        return (*value, value[0]) if value else ("x",)
    if isinstance(value, frozenset):
        return value | {"x"}
    if value is None:
        return "x"
    return None


def test_policy_mappings_are_read_only() -> None:
    assert set(POLICY.checkers) == set(CHECKER_IDS)
    with pytest.raises(TypeError):
        POLICY.checkers["logging"] = CheckerPolicy(False, ())  # type: ignore[index]
    with pytest.raises(TypeError):
        POLICY.markers["AGENTS.md"] = ()  # type: ignore[index]


def test_not_verifiable_rule_has_no_checker_or_match() -> None:
    rule = dataclasses.replace(RULE, checker=None, match=None)
    assert (rule.checker, rule.match) == (None, None)


def test_rule_result_side_may_be_missing() -> None:
    removed = dataclasses.replace(
        RULE_RESULT, base_rule=RULE, head_rule=None, base=SIDE, head=None, case="removed"
    )
    assert removed.head_rule is None
    assert removed.head is None


def test_checker_ids_are_the_eight_fixed_ids() -> None:
    assert CHECKER_IDS == (
        "logging",
        "http-client",
        "test-framework",
        "money",
        "string-format",
        "exceptions",
        "type-hints",
        "package-manager",
    )


def test_skip_reasons_are_the_report_list() -> None:
    assert get_args(model.SkipReason) == (
        "syntax error",
        "not decodable",
        "binary",
        "size limit",
        "symlink",
        "outside repository",
        "syntax newer than analyzer",
        "special file",
        "cap exceeded",
        "walk limit",
        "manifest parse error",
    )


def test_cases() -> None:
    assert get_args(model.Case) == (
        "made-stale-by-code",
        "stale-rule-added",
        "fixed",
        "pre-existing-stale",
        "removed",
    )


@pytest.mark.parametrize(
    ("cls", "field", "values"),
    [
        (Policy, "effective_fail_on", ("none", "new-stale", "any-stale")),
        (Policy, "source", ("base", "head")),
        (Suggestion, "kind", ("replace", "tie", "remove-or-rewrite", "none")),
        (Result, "mode", ("compare", "head-only", "scan")),
        (
            Result,
            "head_only_reason",
            ("shallow clone", "missing object", "no merge base", type(None)),
        ),
        (
            SideResult,
            "recent_unavailable_reason",
            ("no history", "no relevant sites in the window", type(None)),
        ),
    ],
)
def test_literal_fields(cls: type, field: str, values: tuple[Any, ...]) -> None:
    hint = get_type_hints(cls)[field]
    flat: list[Any] = []
    for arg in get_args(hint):
        flat.extend(get_args(arg) or (arg,))
    assert tuple(flat) == values


def test_verdict_values_are_the_report_strings() -> None:
    assert [v.value for v in Verdict] == [
        "Holds",
        "Stale",
        "Migrating",
        "Contested",
        "Insufficient data",
        "Not verifiable",
    ]
    assert Verdict("Insufficient data") is Verdict.INSUFFICIENT
    assert str(Verdict.NOT_VERIFIABLE) == "Not verifiable"


def test_unknown_verdict_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a valid Verdict"):
        Verdict("holds")


def test_missing_field_is_rejected() -> None:
    with pytest.raises(TypeError):
        Site(file="a.py", line=1, col=0)  # type: ignore[call-arg]
