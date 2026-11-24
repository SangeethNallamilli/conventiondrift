"""C11 job-summary Markdown, fixed summaries, and the error-only policy-source line."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from conventiondrift.fallback import _safe
from conventiondrift.model import Conflict, Result, Rule, RuleResult, SkippedFile
from conventiondrift.render.context import RenderContext
from conventiondrift.render.display import display_rule, summary_side, verdict_label
from conventiondrift.render.escape import md
from conventiondrift.render.findings import omitted_finding_count
from conventiondrift.render.strings import (
    HEADING,
    INTERNAL_ERROR_HEADING,
    NO_INSTRUCTION_FILES,
    NO_PR_BODY,
    NO_PYTHON_FILES,
    PRT_BODY,
    PRT_HEADING,
    analyzed_line,
    analyzer_python_line,
    conflict_incomplete_note,
    conflicts_unlisted_line,
    disabled_checker_line,
    error_policy_source_line,
    fetch_hint,
    gating_line,
    head_only_why,
    internal_error_line,
    mode_line,
    no_comparison_sentence,
    not_annotated_line,
    partners_phrase,
    policy_source_line,
    pre_existing_line,
    read_only_line,
    scan_new_stale_line,
    unattached_marker_line,
    window_anchor_line,
    window_unavailable,
)

if TYPE_CHECKING:
    from conventiondrift.core import RunContext

__all__ = ["render_error_summary", "render_fixed_summary", "render_summary"]

_SECTION = {
    "rules": "## Rules",
    "not-verifiable": "## Not verifiable",
    "skipped": "## Skipped files",
    "ignored": "## Ignored",
    "conflicts": "## Conflicting rules",
    "removed": "## Removed",
    "notes": "## Notes",
    "after-merge": "## Takes effect after merge",
    "head-only": "## Head-only report",
    "window": "## Recent window",
}


def render_fixed_summary(kind: str) -> str:
    """A short job summary when there is no ``Result`` (D-TL-85)."""
    if kind == "no_pr":
        return f"{HEADING}\n\n{NO_PR_BODY}\n"
    if kind == "pull_request_target":
        return f"{PRT_HEADING}\n\n{PRT_BODY}\n"
    raise ValueError(f"unknown fixed summary kind: {kind}")


def render_error_summary(ctx: RunContext) -> str:
    """The I-14 error-only policy-source line; T-028 places it (D-TL-85 #5)."""
    return (
        error_policy_source_line(
            ctx.explicit_fail_on,
            config_known_present=ctx.config_known_present,
        )
        + "\n"
    )


def render_summary(result: Result, context: RenderContext) -> str:
    """The job-summary Markdown for one ``Result`` plus ``RenderContext``."""
    parts: list[str] = [f"{HEADING}\n\n{mode_line(context.mode)}"]
    if context.mode == "head-only":
        parts.append(_head_only_block(result, context))
    elif context.window_anchor is not None or result.window.unavailable_reason is not None:
        parts.append(_window_block(result, context))
    parts.append(_meta_lines(context))
    if context.read_only_reason is not None:
        parts.append(read_only_line(context.read_only_reason))
    if context.mode == "scan":
        parts.append(scan_new_stale_line())
    flags = _discovery_flags(result, context)
    if flags:
        parts.append(flags)
    kept, removed, ignored, not_verifiable = _classify(result.rule_results)
    if kept:
        parts.append(_bullets(_SECTION["rules"], [_rule_bullet(item, context) for item in kept]))
    if not_verifiable:
        parts.append(
            _bullets(_SECTION["not-verifiable"], [_brief_bullet(item) for item in not_verifiable])
        )
    if result.skipped_files:
        parts.append(
            _bullets(_SECTION["skipped"], [_skipped_bullet(item) for item in result.skipped_files])
        )
    preexisting = sum(1 for item in result.rule_results if item.case == "pre-existing-stale")
    if preexisting:
        parts.append(pre_existing_line(preexisting))
    if ignored:
        parts.append(_bullets(_SECTION["ignored"], [_brief_bullet(item) for item in ignored]))
    conflict_lines = _conflict_bullets(result)
    if conflict_lines:
        parts.append(_bullets(_SECTION["conflicts"], conflict_lines))
    if removed:
        parts.append(_bullets(_SECTION["removed"], [_removed_bullet(item) for item in removed]))
    notes = _notes_lines(result)
    if notes:
        parts.append(_bullets(_SECTION["notes"], notes))
    if result.policy.after_merge_notes:
        parts.append(
            _bullets(
                _SECTION["after-merge"], [md(note) for note in result.policy.after_merge_notes]
            )
        )
    trailing = _trailing_lines(result, context)
    if trailing:
        parts.append("\n\n".join(trailing))
    return _join(parts)


def _join(parts: Sequence[str]) -> str:
    return "\n\n".join(part for part in parts if part) + "\n"


def _bullets(heading: str, lines: Sequence[str]) -> str:
    return heading + "\n\n" + "\n".join(f"- {line}" for line in lines)


def _head_only_block(result: Result, context: RenderContext) -> str:
    sentences = [no_comparison_sentence()]
    why = head_only_why(result.head_only_reason)
    if why is not None:
        sentences.append(why)
    sentences.append(fetch_hint(markdown=True))
    kind = context.head_kind or "checkout"
    sha = md(context.analyzed_sha)
    body = [
        " ".join(sentences),
        "",
        analyzed_line(sha, kind, markdown=True),
        "",
        gating_line(markdown=True),
    ]
    return _SECTION["head-only"] + "\n\n" + "\n".join(body)


def _window_block(result: Result, context: RenderContext) -> str:
    if context.window_anchor is not None:
        anchor = context.window_anchor
        # In Markdown the SHA is a code span; the sentence template wraps it as-is.
        body = window_anchor_line(
            anchor.days,
            anchor.iso,
            md(anchor.sha),
            mode=context.mode if context.mode != "head-only" else "compare",
        )
    else:
        reason = result.window.unavailable_reason or "no history"
        body = window_unavailable(reason)
    return _SECTION["window"] + "\n\n" + body


def _meta_lines(context: RenderContext) -> str:
    python = analyzer_python_line(md(context.analyzer_python))
    policy = policy_source_line(context.policy_source)
    return f"{python}\n\n{policy}"


def _discovery_flags(result: Result, context: RenderContext) -> str:
    lines: list[str] = []
    if not context.python_files_found:
        lines.append(NO_PYTHON_FILES)
    if not result.instruction_files:
        lines.append(NO_INSTRUCTION_FILES)
    return "\n\n".join(lines)


def _classify(
    rule_results: Sequence[RuleResult],
) -> tuple[
    tuple[RuleResult, ...], tuple[RuleResult, ...], tuple[RuleResult, ...], tuple[RuleResult, ...]
]:
    kept: list[RuleResult] = []
    removed: list[RuleResult] = []
    ignored: list[RuleResult] = []
    not_verifiable: list[RuleResult] = []
    for item in rule_results:
        if item.case == "removed":
            removed.append(item)
            continue
        kept.append(item)
        rule = display_rule(item)
        if rule.ignored:
            ignored.append(item)
        head = item.head
        if head is not None and str(head.verdict.value) == "Not verifiable":
            not_verifiable.append(item)
        elif (
            item.head is None
            and item.base is not None
            and str(item.base.verdict.value) == "Not verifiable"
        ):
            not_verifiable.append(item)
    return tuple(kept), tuple(removed), tuple(ignored), tuple(not_verifiable)


def _rule_bullet(item: RuleResult, context: RenderContext) -> str:
    lead = _brief_bullet(item)
    if context.mode in {"head-only", "scan"}:
        side = item.head or item.base
        if side is None:
            raise RuntimeError("rule has no side to render")
        return f"{lead} — {summary_side(side)}"
    parts: list[str] = []
    if item.head is not None:
        parts.append(f"head {summary_side(item.head)}")
    if item.base is not None:
        parts.append(f"base {summary_side(item.base)}")
    elif item.head is None:
        parts.append("base none")
    return f"{lead} — {'; '.join(parts)}"


def _brief_bullet(item: RuleResult) -> str:
    rule = display_rule(item)
    return f"{md(rule.file)} line {rule.line}: {md(rule.text)}"


def _removed_bullet(item: RuleResult) -> str:
    lead = _brief_bullet(item)
    if item.base is None:
        return f"{lead} — removed"
    return f"{lead} — removed; base {summary_side(item.base)}"


def _skipped_bullet(item: SkippedFile) -> str:
    return f"{md(item.path)}: {item.reason}"


def _conflict_bullets(result: Result) -> list[str]:
    by_id = {item.rule_id: item for item in result.rule_results}
    listed_ids: set[str] = set()
    lines: list[str] = []
    for pair in result.conflicts:
        lines.append(_pair_bullet(pair, by_id))
        listed_ids.update(pair.rules)
    for item in result.rule_results:
        if item.conflict_with_total > 0 and item.rule_id not in listed_ids:
            lines.append(_single_conflict_bullet(item))
    return lines


def _pair_bullet(pair: Conflict, by_id: dict[str, RuleResult]) -> str:
    left = by_id.get(pair.rules[0])
    right = by_id.get(pair.rules[1])
    left_rule = display_rule(left) if left is not None else _missing_rule(pair.rules[0])
    right_rule = display_rule(right) if right is not None else _missing_rule(pair.rules[1])
    head = (
        f"{verdict_label(left.head if left else None)} / "
        f"{verdict_label(right.head if right else None)}"
    )
    base = (
        f"{verdict_label(left.base if left else None)} / "
        f"{verdict_label(right.base if right else None)}"
    )
    return (
        f"{md(left_rule.file)} line {left_rule.line}: {md(left_rule.text)} ({pair.checker}) and "
        f"{md(right_rule.file)} line {right_rule.line}: {md(right_rule.text)} — "
        f"head {head}; base {base}"
    )


def _missing_rule(rule_id: str) -> Rule:
    """A stand-in when a conflict id is not in ``rule_results`` (should not happen)."""
    file, _, line_s = rule_id.rpartition(":")
    line = int(line_s) if line_s.isdigit() else 0
    return Rule(
        id=rule_id,
        file=file or rule_id,
        line=line,
        also_at=(),
        text="",
        normalized_text="",
        checker=None,
        match=None,
        scope_dir="",
        ignored=False,
        disabled=False,
    )


def _single_conflict_bullet(item: RuleResult) -> str:
    lead = _brief_bullet(item)
    partners = partners_phrase(item.conflict_with_total, incomplete=item.conflict_incomplete)
    head = verdict_label(item.head)
    base = verdict_label(item.base)
    return f"{lead} — {partners}; head {head}; base {base}"


def _notes_lines(result: Result) -> list[str]:
    lines = [md(note) for note in result.notes]
    lines.extend(md(note) for note in result.policy.notes)
    for path, line in result.unattached_markers:
        lines.append(unattached_marker_line(md(path), line))
    for checker_id, policy in sorted(result.policy.checkers.items()):
        if not policy.enabled:
            lines.append(disabled_checker_line(checker_id))
    return lines


def _trailing_lines(result: Result, context: RenderContext) -> list[str]:
    lines: list[str] = []
    if result.counts.conflicts_unlisted:
        lines.append(conflicts_unlisted_line(result.counts.conflicts_unlisted))
    if result.counts.conflicts_incomplete:
        lines.append(conflict_incomplete_note(result.counts.conflicts_incomplete))
    if context.mode == "compare":
        omitted = omitted_finding_count(result.rule_results)
        if omitted:
            lines.append(not_annotated_line(omitted))
    if result.internal_errors:
        body = [INTERNAL_ERROR_HEADING, ""]
        for error in result.internal_errors:
            component, message = _safe(error)
            body.append(internal_error_line(md(component), message))
        lines.append("\n".join(body))
    return lines
