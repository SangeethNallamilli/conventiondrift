"""C11 workflow-command annotations (D-TL-85, D-TL-86, SR T-01 a)."""

from __future__ import annotations

from conventiondrift.model import Result, Rule
from conventiondrift.render.context import RenderContext
from conventiondrift.render.escape import workflow_cmd, workflow_prop
from conventiondrift.render.findings import findings_in_order
from conventiondrift.render.strings import (
    MAX_FINDING_ANNOTATIONS,
    RUN_LEVEL_TITLE,
    conflict_incomplete_note,
    finding_annotation_title,
)

__all__ = [
    "MAX_FINDING_ANNOTATIONS",
    "format_run_level_annotation",
    "render_annotations",
]


def format_run_level_annotation(message: str) -> str:
    """One run-level warning; ``title`` and the message use the same escapers as findings."""
    return f"::warning title={workflow_prop(RUN_LEVEL_TITLE)}::{workflow_cmd(message)}"


def _finding_annotation(rule: Rule) -> str:
    title = finding_annotation_title(rule.id)
    return (
        f"::warning file={workflow_prop(rule.file)},line={rule.line},"
        f"title={workflow_prop(title)}::{workflow_cmd(rule.text)}"
    )


def render_annotations(result: Result, context: RenderContext) -> tuple[str, ...]:
    """Return the workflow commands to emit, or an empty tuple when none apply.

    Head-only and scan emit nothing (DESIGN §4, B4). Finding lines are capped at
    ``MAX_FINDING_ANNOTATIONS`` in ``rule_results`` order. An incomplete conflict
    check adds one run-level warning first; it does not use a finding slot
    (D-TL-86 #6).
    """
    if result.mode != "compare" or context.mode != "compare":
        return ()
    lines: list[str] = []
    if result.counts.conflicts_incomplete > 0:
        lines.append(
            format_run_level_annotation(
                conflict_incomplete_note(result.counts.conflicts_incomplete)
            )
        )
    for item in findings_in_order(result.rule_results)[:MAX_FINDING_ANNOTATIONS]:
        rule = item.head_rule
        if rule is None:
            continue
        lines.append(_finding_annotation(rule))
    return tuple(lines)
