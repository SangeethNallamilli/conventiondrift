"""Unit tests for the boundary types in conventiondrift.model (T-005; I-10, I-11, I-13)."""

import dataclasses
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Literal, get_args, get_type_hints

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

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
# Policy and Result are frozen but unhashable by design (I-13, code review A1);
# every other type is hashable.
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
def test_policy_and_result_are_unhashable(name: str) -> None:
    sample, _ = SAMPLES[name]
    with pytest.raises(TypeError):
        hash(sample)


# Changes that would break an I-13 invariant get a valid alternative instead.
OVERRIDES: dict[tuple[str, str], dict[str, Any]] = {
    ("Policy", "gated"): {"gated": False, "effective_fail_on": "none"},
    ("Policy", "checkers"): {
        "checkers": {cid: CheckerPolicy(enabled=False, script_paths=()) for cid in CHECKER_IDS}
    },
    ("Policy", "markers"): {"markers": {}},
    ("Conflict", "rules"): {"rules": ("AGENTS.md:1", "AGENTS.md:2")},
    ("RuleResult", "head_rule"): {"head_rule": dataclasses.replace(RULE, line=10)},
}


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_changing_a_field_breaks_equality(name: str) -> None:
    sample, fields = SAMPLES[name]
    for field in fields:
        changes = OVERRIDES.get((name, field), {field: _different(getattr(sample, field))})
        assert dataclasses.replace(sample, **changes) != sample, field


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


def test_unhashable_types_declare_hash_none() -> None:
    assert all(cls.__hash__ is None for cls in (Policy, Result))


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
        "unsupported path",
        "unreadable",
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
        (Window, "unavailable_reason", ("no history", "internal error", type(None))),
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


# --- I-13 invariants checked in __post_init__ -------------------------------------------


def test_policy_wraps_mappings_in_read_only_copies() -> None:
    checkers = {cid: CheckerPolicy(enabled=True, script_paths=()) for cid in CHECKER_IDS}
    markers = {"AGENTS.md": (4,)}
    policy = dataclasses.replace(POLICY, checkers=checkers, markers=markers)
    assert isinstance(policy.checkers, MappingProxyType)
    assert isinstance(policy.markers, MappingProxyType)
    checkers.clear()
    markers["CLAUDE.md"] = (1,)
    assert set(policy.checkers) == set(CHECKER_IDS)
    assert dict(policy.markers) == {"AGENTS.md": (4,)}


@pytest.mark.parametrize("missing", CHECKER_IDS)
def test_policy_rejects_a_missing_checker_id(missing: CheckerId) -> None:
    checkers = {cid: p for cid, p in POLICY.checkers.items() if cid != missing}
    with pytest.raises(ValueError, match="exactly the 8 checker ids"):
        dataclasses.replace(POLICY, checkers=checkers)


@pytest.mark.parametrize("extra", ["print", "Logging", "logging ", ""])
def test_policy_rejects_an_extra_checker_key(extra: str) -> None:
    checkers: dict[Any, CheckerPolicy] = dict(POLICY.checkers)
    checkers[extra] = CheckerPolicy(enabled=True, script_paths=())
    with pytest.raises(ValueError, match="exactly the 8 checker ids"):
        dataclasses.replace(POLICY, checkers=checkers)


def test_policy_rejects_a_swapped_checker_key() -> None:
    checkers: dict[Any, CheckerPolicy] = {
        cid: p for cid, p in POLICY.checkers.items() if cid != "money"
    }
    checkers["print"] = CheckerPolicy(enabled=False, script_paths=())
    with pytest.raises(ValueError, match="exactly the 8 checker ids"):
        dataclasses.replace(POLICY, checkers=checkers)


@pytest.mark.parametrize(
    ("fail_on", "gated", "ok"),
    [
        ("none", False, True),
        ("new-stale", True, True),
        ("any-stale", True, True),
        ("none", True, False),
        ("new-stale", False, False),
        ("any-stale", False, False),
    ],
)
def test_policy_gated_matches_fail_on(
    fail_on: Literal["none", "new-stale", "any-stale"], gated: bool, ok: bool
) -> None:
    if ok:
        policy = dataclasses.replace(POLICY, effective_fail_on=fail_on, gated=gated)
        assert policy.gated is gated
    else:
        with pytest.raises(ValueError, match="gated"):
            dataclasses.replace(POLICY, effective_fail_on=fail_on, gated=gated)


def test_window_end_may_be_none_or_aware() -> None:
    assert dataclasses.replace(WINDOW, end=None).end is None
    assert WINDOW.end is not None


def test_window_rejects_naive_end() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        dataclasses.replace(WINDOW, end=datetime(2026, 11, 12, 9, 0))


def test_conflict_rules_must_be_sorted() -> None:
    assert Conflict(rules=("A.md:1", "A.md:1"), checker="money").rules == ("A.md:1", "A.md:1")
    with pytest.raises(ValueError, match=r"Conflict\.rules must be sorted"):
        Conflict(rules=("CLAUDE.md:3", "AGENTS.md:3"), checker="http-client")


def _site_result(file: str, line: int, col: int, option: str) -> SiteResult:
    return SiteResult(site=Site(file, line, col, option), follows=True, recent=False)


SORTED_SITES = (
    _site_result("a.py", 1, 0, "print"),
    _site_result("a.py", 1, 0, "print"),
    _site_result("a.py", 1, 2, "logging"),
    _site_result("a.py", 1, 2, "print"),
    _site_result("a.py", 3, 0, "logging"),
    _site_result("b.py", 1, 0, "logging"),
)


@pytest.mark.parametrize("sites", [(), SORTED_SITES[:1], SORTED_SITES])
def test_side_result_accepts_sorted_sites(sites: tuple[SiteResult, ...]) -> None:
    assert dataclasses.replace(SIDE, sites=sites).sites == sites


@pytest.mark.parametrize(
    "pair",
    [
        ("b.py", 1, 0, "x", "a.py", 9, 9, "z"),  # file out of order
        ("a.py", 2, 0, "x", "a.py", 1, 9, "z"),  # line out of order
        ("a.py", 1, 5, "x", "a.py", 1, 4, "z"),  # col out of order
        ("a.py", 1, 0, "print", "a.py", 1, 0, "logging"),  # option out of order
    ],
)
def test_side_result_rejects_unsorted_sites(pair: tuple[Any, ...]) -> None:
    first, second = _site_result(*pair[:4]), _site_result(*pair[4:])
    with pytest.raises(ValueError, match=r"SideResult\.sites must be sorted"):
        dataclasses.replace(SIDE, sites=(first, second))


def _rule_result(file: str, line: int, *, side: str = "head") -> RuleResult:
    rule = dataclasses.replace(RULE, id=f"{file}:{line}", file=file, line=line)
    if side == "head":
        return dataclasses.replace(RULE_RESULT, rule_id=rule.id, head_rule=rule, base_rule=None)
    return dataclasses.replace(RULE_RESULT, rule_id=rule.id, head_rule=None, base_rule=rule)


def test_result_accepts_rule_results_sorted_by_head_else_base_rule() -> None:
    ordered = (
        _rule_result("AGENTS.md", 3),
        _rule_result("AGENTS.md", 7, side="base"),
        _rule_result("AGENTS.md", 10),
        _rule_result("CLAUDE.md", 1, side="base"),
    )
    assert dataclasses.replace(RESULT, rule_results=ordered).rule_results == ordered
    assert dataclasses.replace(RESULT, rule_results=()).rule_results == ()


def test_result_head_rule_wins_over_base_rule_for_order() -> None:
    late_base = dataclasses.replace(RULE, file="Z.md", line=99)
    both = dataclasses.replace(_rule_result("AGENTS.md", 5), base_rule=late_base)
    ordered = (both, _rule_result("AGENTS.md", 6))
    assert dataclasses.replace(RESULT, rule_results=ordered).rule_results == ordered


@pytest.mark.parametrize(
    "results",
    [
        (("CLAUDE.md", 1, "head"), ("AGENTS.md", 9, "head")),  # file out of order
        (("AGENTS.md", 9, "head"), ("AGENTS.md", 2, "base")),  # line out of order
    ],
)
def test_result_rejects_unsorted_rule_results(results: tuple[tuple[str, int, str], ...]) -> None:
    rule_results = tuple(_rule_result(f, n, side=side) for f, n, side in results)
    with pytest.raises(ValueError, match=r"Result\.rule_results must be sorted"):
        dataclasses.replace(RESULT, rule_results=rule_results)


@pytest.mark.parametrize(("base_rule", "head_rule"), [(RULE, None), (None, RULE), (RULE, RULE)])
def test_rule_result_accepts_at_least_one_rule(
    base_rule: Rule | None, head_rule: Rule | None
) -> None:
    result = dataclasses.replace(RULE_RESULT, base_rule=base_rule, head_rule=head_rule)
    assert (result.base_rule, result.head_rule) == (base_rule, head_rule)


def test_rule_result_rejects_neither_rule() -> None:
    with pytest.raises(ValueError, match="at least one of base_rule/head_rule"):
        dataclasses.replace(RULE_RESULT, head_rule=None, base_rule=None)


def test_skipped_file_accepts_unreadable() -> None:
    assert SkippedFile(path="src/gone.py", reason="unreadable").reason == "unreadable"


def test_policy_allows_script_paths_only_for_logging() -> None:
    assert POLICY.checkers["logging"].script_paths == ("**/tests/**",)
    no_paths = {cid: CheckerPolicy(enabled=True, script_paths=()) for cid in CHECKER_IDS}
    assert dataclasses.replace(POLICY, checkers=no_paths).checkers["logging"].script_paths == ()


@pytest.mark.parametrize("checker", [cid for cid in CHECKER_IDS if cid != "logging"])
def test_policy_rejects_script_paths_on_other_checkers(checker: CheckerId) -> None:
    checkers = dict(POLICY.checkers)
    checkers[checker] = CheckerPolicy(enabled=True, script_paths=("**/bin/**",))
    with pytest.raises(ValueError, match="script_paths"):
        dataclasses.replace(POLICY, checkers=checkers)


@pytest.mark.parametrize("scope_dir", ["", "src", "src/billing", "a/b/c", "src.d"])
def test_rule_accepts_scope_dir_without_edge_slashes(scope_dir: str) -> None:
    assert dataclasses.replace(RULE, scope_dir=scope_dir).scope_dir == scope_dir


@pytest.mark.parametrize("scope_dir", ["/", "/src", "src/", "/src/", "src/billing/", "//"])
def test_rule_rejects_scope_dir_with_edge_slash(scope_dir: str) -> None:
    with pytest.raises(ValueError, match="leading or trailing slash"):
        dataclasses.replace(RULE, scope_dir=scope_dir)


# --- I-10 RuleMatch validity (CR2 B1 on #25) ----------------------------------------


def test_rule_match_rejects_empty_preferred_and_prohibited() -> None:
    with pytest.raises(ValueError, match="must not both be empty"):
        RuleMatch(preferred=frozenset(), prohibited=frozenset(), specificity=1)


@pytest.mark.parametrize(
    ("preferred", "prohibited"),
    [
        (frozenset({"httpx"}), frozenset({"httpx"})),
        (frozenset({"httpx", "requests", "urllib"}), frozenset({"requests", "urllib", "aiohttp"})),
    ],
)
def test_rule_match_rejects_overlapping_preferred_and_prohibited(
    preferred: frozenset[str], prohibited: frozenset[str]
) -> None:
    with pytest.raises(ValueError, match="must be disjoint"):
        RuleMatch(preferred=preferred, prohibited=prohibited, specificity=1)


def test_rule_match_accepts_only_preferred() -> None:
    match = RuleMatch(preferred=frozenset({"httpx"}), prohibited=frozenset(), specificity=1)
    assert match.preferred == frozenset({"httpx"})
    assert match.prohibited == frozenset()


def test_rule_match_accepts_only_prohibited() -> None:
    match = RuleMatch(preferred=frozenset(), prohibited=frozenset({"print"}), specificity=1)
    assert match.preferred == frozenset()
    assert match.prohibited == frozenset({"print"})


def test_rule_match_accepts_disjoint_nonempty_sets() -> None:
    match = RuleMatch(
        preferred=frozenset({"httpx"}), prohibited=frozenset({"requests"}), specificity=2
    )
    assert match == MATCH


def test_rule_match_error_does_not_echo_option_values() -> None:
    hostile = "untrusted-option<SECRET>"
    with pytest.raises(ValueError) as excinfo:
        RuleMatch(preferred=frozenset({hostile}), prohibited=frozenset({hostile}), specificity=0)
    assert hostile not in str(excinfo.value)


# D-TL-25: the two I-10 invalid classes, using the same union and intersection
# checks as RuleMatch.__post_init__.
def _rule_match_invalid_class(preferred: frozenset[str], prohibited: frozenset[str]) -> str | None:
    if not (preferred | prohibited):
        return "empty_union"
    if preferred & prohibited:
        return "overlap"
    return None


_RULEMATCH_INVALID_CLASSES = frozenset({"empty_union", "overlap"})
_RULEMATCH_INVALID_MATCH = {
    "empty_union": "must not both be empty",
    "overlap": "must be disjoint",
}

# replace() a valid MATCH (preferred={httpx}, prohibited={requests}) into each class.
_REPLACE_INVALID_CASES: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    ("empty_union", frozenset(), frozenset()),
    ("overlap", MATCH.preferred, frozenset({"httpx"})),
)

# Explicit property inputs so both invalid classes are always drawn, plus valid cases.
_PROPERTY_EXAMPLES: tuple[tuple[frozenset[str], frozenset[str], int], ...] = (
    (frozenset(), frozenset(), 0),
    (frozenset({"a"}), frozenset({"a"}), 1),
    (frozenset({"a", "b"}), frozenset({"b", "c"}), 2),
    (frozenset({"a"}), frozenset(), 1),
    (frozenset(), frozenset({"b"}), 1),
    (frozenset({"a"}), frozenset({"b"}), 2),
)

_OPTION_SETS = st.frozensets(st.sampled_from(("a", "b", "c", "d")), max_size=4)


def test_rule_match_replace_cases_cover_invalid_classes() -> None:
    covered = set()
    for invalid_class, preferred, prohibited in _REPLACE_INVALID_CASES:
        assert _rule_match_invalid_class(preferred, prohibited) == invalid_class
        covered.add(invalid_class)
    assert covered == _RULEMATCH_INVALID_CLASSES


@pytest.mark.parametrize(("invalid_class", "preferred", "prohibited"), _REPLACE_INVALID_CASES)
def test_rule_match_replace_rejects_invalid_state(
    invalid_class: str, preferred: frozenset[str], prohibited: frozenset[str]
) -> None:
    with pytest.raises(ValueError, match=_RULEMATCH_INVALID_MATCH[invalid_class]):
        dataclasses.replace(MATCH, preferred=preferred, prohibited=prohibited)


def test_rule_match_property_examples_cover_invalid_classes() -> None:
    covered = {
        cls
        for preferred, prohibited, _ in _PROPERTY_EXAMPLES
        if (cls := _rule_match_invalid_class(preferred, prohibited)) is not None
    }
    assert covered == _RULEMATCH_INVALID_CLASSES


@given(
    preferred=_OPTION_SETS,
    prohibited=_OPTION_SETS,
    specificity=st.integers(min_value=-100, max_value=100),
)
@example(preferred=frozenset(), prohibited=frozenset(), specificity=0)
@example(preferred=frozenset({"a"}), prohibited=frozenset({"a"}), specificity=1)
@example(preferred=frozenset({"a", "b"}), prohibited=frozenset({"b", "c"}), specificity=2)
@example(preferred=frozenset({"a"}), prohibited=frozenset(), specificity=1)
@example(preferred=frozenset(), prohibited=frozenset({"b"}), specificity=1)
@example(preferred=frozenset({"a"}), prohibited=frozenset({"b"}), specificity=2)
@settings(max_examples=80, deadline=None, derandomize=True)
def test_rule_match_constructs_iff_union_nonempty_and_disjoint(
    preferred: frozenset[str], prohibited: frozenset[str], specificity: int
) -> None:
    invalid_class = _rule_match_invalid_class(preferred, prohibited)
    if invalid_class is None:
        match = RuleMatch(preferred=preferred, prohibited=prohibited, specificity=specificity)
        assert match.preferred == preferred
        assert match.prohibited == prohibited
        assert match.specificity == specificity
    else:
        assert invalid_class in _RULEMATCH_INVALID_CLASSES
        with pytest.raises(ValueError, match=_RULEMATCH_INVALID_MATCH[invalid_class]):
            RuleMatch(preferred=preferred, prohibited=prohibited, specificity=specificity)
