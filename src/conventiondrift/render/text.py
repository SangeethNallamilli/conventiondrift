"""C11 ``--format text`` report (D-TL-85, D-TL-86, SR T-01 b)."""

from __future__ import annotations

from collections.abc import Sequence

from conventiondrift.fallback import safe_error
from conventiondrift.model import Conflict, Result, Rule, RuleResult, SkippedFile
from conventiondrift.render.context import RenderContext
from conventiondrift.render.display import (
    display_rule,
    text_counts,
    text_field,
    text_ref,
    verdict_label,
)
from conventiondrift.render.findings import omitted_finding_count
from conventiondrift.render.strings import (
    FETCH_DEPTH,
    NO_INSTRUCTION_FILES,
    NO_PYTHON_FILES,
    TEXT_HEADER,
    conflict_incomplete_note,
    conflicts_unlisted_line,
    gating_line,
    not_annotated_line,
    pre_existing_line,
    read_only_line,
    scan_new_stale_line,
    window_unavailable,
)

__all__ = ["render_text"]


def render_text(result: Result, context: RenderContext) -> str:
    """The plain-text report: one keyword-prefixed record per line."""
    lines: list[str] = [TEXT_HEADER, f"mode {context.mode}"]
    if context.mode != "head-only":
        lines.append(f"analyzed {text_field(context.analyzed_sha)}")
    lines.extend(_mode_header(result, context))
    lines.append(f"analyzer-python {text_field(context.analyzer_python)}")
    lines.append(f"policy-source {context.policy_source}")
    if context.read_only_reason is not None:
        lines.append(f"read-only {read_only_line(context.read_only_reason)}")
    if context.mode == "scan":
        lines.append(f"scan {scan_new_stale_line()}")
    if not context.python_files_found:
        lines.append(f"no-python {NO_PYTHON_FILES}")
    if not result.instruction_files:
        lines.append(f"no-instruction {NO_INSTRUCTION_FILES}")
    kept, removed, ignored, not_verifiable = _classify(result.rule_results)
    for item in kept:
        lines.append(_rule_line(item, context))
    for item in not_verifiable:
        lines.append(f"not-verifiable {_brief(item)}")
    for skipped in result.skipped_files:
        lines.append(_skipped_line(skipped))
    preexisting = sum(1 for item in result.rule_results if item.case == "pre-existing-stale")
    if preexisting:
        lines.append(f"pre-existing {pre_existing_line(preexisting)}")
    for item in ignored:
        lines.append(f"ignored {_brief(item)}")
    for conflict_line in _conflict_lines(result):
        lines.append(conflict_line)
    for item in removed:
        lines.append(_removed_line(item))
    for note in result.notes:
        lines.append(f"note {text_field(note)}")
    for note in result.policy.notes:
        lines.append(f"note {text_field(note)}")
    for path, marker_line in result.unattached_markers:
        lines.append(f"unattached {text_ref(path, marker_line)}")
    for checker_id, policy in sorted(result.policy.checkers.items()):
        if not policy.enabled:
            lines.append(f"disabled {checker_id}")
    for note in result.policy.after_merge_notes:
        lines.append(f"after-merge {text_field(note)}")
    if result.counts.conflicts_unlisted:
        lines.append(
            f"conflicts-unlisted {conflicts_unlisted_line(result.counts.conflicts_unlisted)}"
        )
    if result.counts.conflicts_incomplete:
        lines.append(
            f"conflict-incomplete {conflict_incomplete_note(result.counts.conflicts_incomplete)}"
        )
    if context.mode == "compare":
        omitted = omitted_finding_count(result.rule_results)
        if omitted:
            lines.append(f"not-annotated {not_annotated_line(omitted)}")
    for error in result.internal_errors:
        component, message = safe_error(error)
        lines.append(f"internal-error {text_field(component)} {text_field(message)}")
    return "\n".join(lines) + "\n"


def _mode_header(result: Result, context: RenderContext) -> list[str]:
    if context.mode == "head-only":
        kind = context.head_kind or "checkout"
        kind_label = "PR head" if kind == "pr_head" else "checked-out commit"
        lines: list[str] = []
        if result.head_only_reason is not None:
            lines.append(f"head-only {result.head_only_reason}")
        lines.extend(
            (
                FETCH_DEPTH,
                f"analyzed {text_field(context.analyzed_sha)} ({kind_label})",
                gating_line(markdown=False),
            )
        )
        return lines
    if context.window_anchor is not None:
        anchor = context.window_anchor
        # Text form: "window {sentence}" but the sentence uses "ending at" in
        # summary and "ending" in the text template: "{days} days ending {iso}".
        label = "HEAD" if context.mode == "scan" else "PR head"
        iso = text_field(anchor.iso)
        sha = text_field(anchor.sha)
        return [f"window {anchor.days} days ending {iso} ({label} {sha})"]
    if result.window.unavailable_reason is not None:
        return [f"window {window_unavailable(result.window.unavailable_reason)}"]
    return []


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
        side = item.head or item.base
        if side is not None and str(side.verdict.value) == "Not verifiable":
            not_verifiable.append(item)
    return tuple(kept), tuple(removed), tuple(ignored), tuple(not_verifiable)


def _brief(item: RuleResult) -> str:
    rule = display_rule(item)
    return f"{text_ref(rule.file, rule.line)} {text_field(rule.text, quoted=True)}"


def _rule_line(item: RuleResult, context: RenderContext) -> str:
    lead = _brief(item)
    if context.mode in {"head-only", "scan"}:
        side = item.head or item.base
        if side is None:
            raise RuntimeError("rule has no side to render")
        return f"rule {lead} {side.verdict.value} {text_counts(side)}"
    parts: list[str] = []
    if item.head is not None:
        parts.append(f"head {item.head.verdict.value} {text_counts(item.head)}")
    if item.base is not None:
        parts.append(f"base {item.base.verdict.value} {text_counts(item.base)}")
    return f"rule {lead} {' '.join(parts)}"


def _skipped_line(item: SkippedFile) -> str:
    return f"skipped {text_field(item.path)} {item.reason}"


def _removed_line(item: RuleResult) -> str:
    lead = _brief(item)
    if item.base is None:
        return f"removed {lead}"
    return f"removed {lead} base {item.base.verdict.value} {text_counts(item.base)}"


def _conflict_lines(result: Result) -> list[str]:
    by_id = {item.rule_id: item for item in result.rule_results}
    listed: set[str] = set()
    lines: list[str] = []
    for pair in result.conflicts:
        lines.append(_pair_line(pair, by_id))
        listed.update(pair.rules)
    for item in result.rule_results:
        if item.conflict_with_total > 0 and item.rule_id not in listed:
            rule = display_rule(item)
            head = verdict_label(item.head)
            base = verdict_label(item.base)
            lines.append(f"conflict {text_ref(rule.file, rule.line)} head {head} base {base}")
    return lines


def _pair_line(pair: Conflict, by_id: dict[str, RuleResult]) -> str:
    left = by_id.get(pair.rules[0])
    right = by_id.get(pair.rules[1])
    left_rule = display_rule(left) if left is not None else _missing_rule(pair.rules[0])
    right_rule = display_rule(right) if right is not None else _missing_rule(pair.rules[1])
    head = (
        f"{verdict_label(left.head if left else None)}/"
        f"{verdict_label(right.head if right else None)}"
    )
    base = (
        f"{verdict_label(left.base if left else None)}/"
        f"{verdict_label(right.base if right else None)}"
    )
    return (
        f"conflict {text_ref(left_rule.file, left_rule.line)} "
        f"{text_ref(right_rule.file, right_rule.line)} {pair.checker} head {head} base {base}"
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
