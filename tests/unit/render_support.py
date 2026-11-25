"""Builders for the C11 JSON and SARIF unit tests (T-026). Test-only; never shipped."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from types import MappingProxyType
from typing import get_args

from conventiondrift.model import (
    Alternative,
    Case,
    CausingFile,
    CheckerId,
    CheckerPolicy,
    Conflict,
    Counts,
    InstructionFile,
    InternalError,
    Policy,
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

SHA = "a" * 40
HEAD_SHA = "b" * 40
NONE_SUGGESTION = Suggestion("none", None, (), None)


def policy(*, notes: tuple[str, ...] = (), source: str = "base") -> Policy:
    checkers = {cid: CheckerPolicy(cid != "money", ()) for cid in get_args(CheckerId)}
    return Policy(
        effective_fail_on="none",
        gated=False,
        source=source,  # type: ignore[arg-type]
        history_days=90,
        thresholds=Thresholds(80, 20, 20, 50, 70, 5),
        excludes=(),
        max_file_bytes=1048576,
        checkers=MappingProxyType(checkers),
        ignores=(),
        markers=MappingProxyType({}),
        paths=None,
        comment=True,
        sarif=True,
        after_merge_notes=(),
        notes=notes,
    )


def side(
    following: int,
    relevant: int,
    *,
    verdict: Verdict = Verdict.STALE,
    recent: Counts | None = None,
    sites: tuple[SiteResult, ...] = (),
) -> SideResult:
    return SideResult(
        verdict=verdict,
        sites=sites,
        overall=Counts(following, relevant - following, relevant),
        recent=recent,
        recent_unavailable_reason=None if recent is not None else "no history",
    )


def site(file: str, line: int, col: int, option: str, *, follows: bool) -> SiteResult:
    return SiteResult(Site(file, line, col, option), follows=follows, recent=False)


def rule(
    text: str = "Use requests for HTTP calls",
    *,
    file: str = "AGENTS.md",
    line: int = 9,
    also_at: tuple[int, ...] = (),
    checker: CheckerId | None = "http-client",
    preferred: frozenset[str] = frozenset({"requests"}),
    prohibited: frozenset[str] = frozenset(),
    ignored: bool = False,
    disabled: bool = False,
) -> Rule:
    match = RuleMatch(preferred, prohibited, 1) if checker is not None else None
    return Rule(
        id=f"{file}:{line}",
        file=file,
        line=line,
        also_at=also_at,
        text=text,
        normalized_text=text.lower(),
        checker=checker,
        match=match,
        scope_dir="",
        ignored=ignored,
        disabled=disabled,
    )


def item(
    the_rule: Rule | None = None,
    *,
    case: Case | None = "made-stale-by-code",
    base: SideResult | None = None,
    head: SideResult | None = None,
    omit_base: bool = False,
    omit_head: bool = False,
    conflict_with: tuple[str, ...] = (),
    conflict_total: int = 0,
    conflict_incomplete: bool = False,
    causing: tuple[CausingFile, ...] = (),
    suggestion: Suggestion = NONE_SUGGESTION,
) -> RuleResult:
    the_rule = the_rule or rule()
    return RuleResult(
        rule_id=the_rule.id,
        base_rule=None if omit_base else the_rule,
        head_rule=None if omit_head else the_rule,
        base=None if omit_base else (base or side(30, 40, verdict=Verdict.HOLDS)),
        head=None if omit_head else (head or side(3, 40)),
        conflict_with=conflict_with,
        conflict_with_total=conflict_total,
        conflict_incomplete=conflict_incomplete,
        case=case,
        causing_files=causing,
        suggestion=suggestion,
    )


def result(
    rule_results: Sequence[RuleResult] = (),
    *,
    mode: str = "compare",
    base_sha: str | None = SHA,
    head_only_reason: str | None = None,
    window: Window | None = None,
    the_policy: Policy | None = None,
    instruction_paths: Sequence[str] = ("AGENTS.md",),
    skipped: Sequence[SkippedFile] = (),
    conflicts: tuple[Conflict, ...] = (),
    errors: tuple[InternalError, ...] = (),
    counts: ReportCounts | None = None,
    notes: tuple[str, ...] = (),
    markers: tuple[tuple[str, int], ...] = (),
    analyzer_python: str = "3.12.7",
) -> Result:
    return Result(
        mode=mode,  # type: ignore[arg-type]
        base_sha=base_sha,
        head_sha=HEAD_SHA,
        head_only_reason=head_only_reason,  # type: ignore[arg-type]
        window=window
        or Window(end=None, days=90, available=False, unavailable_reason="no history"),
        policy=the_policy or policy(),
        instruction_files=tuple(InstructionFile(p, b"# r\n", "", False) for p in instruction_paths),
        skipped_files=tuple(skipped),
        rule_results=tuple(rule_results),
        conflicts=conflicts,
        unattached_markers=markers,
        internal_errors=errors,
        counts=counts or ReportCounts(0, 0, 0, 0, 0, 0),
        notes=notes,
        analyzer_python=analyzer_python,
    )


def window_at(end: datetime) -> Window:
    return Window(end=end, days=90, available=True, unavailable_reason=None)


def replace(new_text: str | None, *alternatives: tuple[str, int]) -> Suggestion:
    return Suggestion(
        "replace", "requests", tuple(Alternative(o, n) for o, n in alternatives), new_text
    )
