"""Unit tests for the immutable boundary types in conventiondrift.model (T-005, I-10, I-11)."""

import dataclasses
from typing import Any, get_args

import pytest

from conventiondrift import model
from conventiondrift.model import (
    Alternative,
    CausingFile,
    CheckerId,
    Conflict,
    FileContext,
    InstructionFile,
    Policy,
    PyFile,
    Result,
    Rule,
    RuleMatch,
    RuleResult,
    Site,
    SkippedFile,
    Suggestion,
    Verdict,
)

MATCH = RuleMatch(preferred=frozenset({"httpx"}), prohibited=frozenset({"requests"}), specificity=2)
RULE = Rule(
    id="AGENTS.md:9",
    file="AGENTS.md",
    line=9,
    also_at=(20,),
    text="Use httpx, not requests",
    checker="http-client",
    match=MATCH,
    scope_dir="",
    ignored=False,
)
POLICY = Policy(effective_fail_on="none", source="head", after_merge_notes=(), notes=("n",))
SUGGESTION = Suggestion(
    kind="replace",
    named_option="httpx",
    alternatives=(Alternative(option="requests", sites=40),),
    new_text="Use requests, not httpx",
)
RULE_RESULT = RuleResult(
    case="made-stale-by-code",
    causing_files=(CausingFile(file="src/a.py", following_delta=-3, contradicting_delta=3),),
    suggestion=SUGGESTION,
)

# One sample per boundary type, and the field names each contract gives it.
SAMPLES: dict[str, tuple[Any, tuple[str, ...]]] = {
    "InstructionFile": (InstructionFile(path="AGENTS.md", data=b"- Use httpx"), ("path", "data")),
    "PyFile": (PyFile(path="src/a.py", data=b"import httpx\n"), ("path", "data")),
    "SkippedFile": (SkippedFile(path="src/b.py", reason="syntax error"), ("path", "reason")),
    "Policy": (POLICY, ("effective_fail_on", "source", "after_merge_notes", "notes")),
    "RuleMatch": (MATCH, ("preferred", "prohibited", "specificity")),
    "Site": (
        Site(file="src/a.py", line=12, col=4, option="requests"),
        ("file", "line", "col", "option"),
    ),
    "FileContext": (
        FileContext(path="tests/test_a.py", is_test_file=True, is_script=False),
        ("path", "is_test_file", "is_script"),
    ),
    "Rule": (
        RULE,
        ("id", "file", "line", "also_at", "text", "checker", "match", "scope_dir", "ignored"),
    ),
    "Conflict": (
        Conflict(rules=("AGENTS.md:3", "CLAUDE.md:3"), checker="http-client"),
        ("rules", "checker"),
    ),
    "CausingFile": (
        RULE_RESULT.causing_files[0],
        ("file", "following_delta", "contradicting_delta"),
    ),
    "Alternative": (Alternative(option="httpx", sites=40), ("option", "sites")),
    "Suggestion": (SUGGESTION, ("kind", "named_option", "alternatives", "new_text")),
    "RuleResult": (RULE_RESULT, ("case", "causing_files", "suggestion")),
    "Result": (
        Result(
            policy=POLICY,
            instruction_files=(),
            skipped_files=(SkippedFile(path="x.py", reason="binary"),),
            rule_results=(RULE_RESULT,),
            conflicts=(),
        ),
        ("policy", "instruction_files", "skipped_files", "rule_results", "conflicts"),
    ),
}


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_fields_match_contract(name: str) -> None:
    sample, expected = SAMPLES[name]
    assert type(sample) is getattr(model, name)
    assert tuple(f.name for f in dataclasses.fields(sample)) == expected


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_is_frozen(name: str) -> None:
    sample, fields = SAMPLES[name]
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(sample, fields[0], None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        delattr(sample, fields[0])


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_equal_copies_are_equal_and_hash_equal(name: str) -> None:
    sample, _ = SAMPLES[name]
    copy = dataclasses.replace(sample)
    assert copy is not sample
    assert copy == sample
    assert hash(copy) == hash(sample)
    assert len({sample, copy}) == 1


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_changing_a_field_breaks_equality(name: str) -> None:
    sample, fields = SAMPLES[name]
    first = getattr(sample, fields[0])
    other = dataclasses.replace(sample, **{fields[0]: _different(first)})
    assert other != sample


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
    return None


def test_rule_match_may_be_empty() -> None:
    match = RuleMatch(preferred=frozenset(), prohibited=frozenset({"print"}), specificity=1)
    assert match.preferred == frozenset()


def test_not_verifiable_rule_has_no_checker_or_match() -> None:
    rule = dataclasses.replace(RULE, checker=None, match=None)
    assert rule.checker is None
    assert rule.match is None
    assert rule != RULE


def test_sites_order_and_compare_by_value() -> None:
    a = Site(file="a.py", line=1, col=0, option="print")
    assert a == Site(file="a.py", line=1, col=0, option="print")
    assert a != Site(file="a.py", line=1, col=1, option="print")


def test_checker_ids_are_the_eight_fixed_ids() -> None:
    assert get_args(CheckerId) == (
        "logging",
        "http-client",
        "test-framework",
        "money",
        "string-format",
        "exceptions",
        "type-hints",
        "package-manager",
    )


def test_verdict_values_are_the_report_strings() -> None:
    assert [v.value for v in Verdict] == [
        "Holds",
        "Stale",
        "Migrating",
        "Contested",
        "Insufficient data",
        "Not verifiable",
    ]
    assert Verdict("Insufficient data") is Verdict.INSUFFICIENT_DATA
    assert str(Verdict.NOT_VERIFIABLE) == "Not verifiable"


def test_unknown_verdict_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a valid Verdict"):
        Verdict("holds")


def test_missing_field_is_rejected() -> None:
    with pytest.raises(TypeError):
        Site(file="a.py", line=1, col=0)  # type: ignore[call-arg]


def test_literal_value_sets() -> None:
    assert get_args(model.FailOn) == ("none", "new-stale", "any-stale")
    assert get_args(model.PolicySource) == ("base", "head")
    assert get_args(model.Case) == (
        "made-stale-by-code",
        "stale-rule-added",
        "fixed",
        "pre-existing-stale",
        "removed",
    )
    assert get_args(model.SuggestionKind) == ("replace", "tie", "remove-or-rewrite", "none")
