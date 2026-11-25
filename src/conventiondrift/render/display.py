"""Shared formatting of rules, sides and text-format fields (not user-facing wording)."""

from __future__ import annotations

from conventiondrift.model import Rule, RuleResult, SideResult
from conventiondrift.render.escape import text_field
from conventiondrift.render.strings import recent_unavailable

# Re-export so existing callers can keep importing the text-field helper here.
__all__ = [
    "display_rule",
    "summary_counts",
    "summary_side",
    "text_counts",
    "text_field",
    "text_ref",
    "verdict_label",
]


def display_rule(rule_result: RuleResult) -> Rule:
    """The rule on the head side, or the base side when the rule was removed."""
    rule = rule_result.head_rule or rule_result.base_rule
    if rule is None:  # pragma: no cover — RuleResult requires at least one side
        raise RuntimeError("RuleResult must have a rule")
    return rule


def verdict_label(side: SideResult | None) -> str:
    if side is None:
        return "none"
    return str(side.verdict.value)


def summary_counts(side: SideResult) -> str:
    """``overall X of Y, recent …`` for a summary rule line."""
    overall = f"overall {side.overall.following} of {side.overall.relevant}"
    if side.recent is None:
        reason = side.recent_unavailable_reason or "no history"
        return f"{overall}, recent {recent_unavailable(reason)}"
    return f"{overall}, recent {side.recent.following} of {side.recent.relevant}"


def summary_side(side: SideResult) -> str:
    return f"{side.verdict.value} ({summary_counts(side)})"


def text_counts(side: SideResult) -> str:
    """``overall X of Y recent …`` for a text-format rule line (no commas around recent)."""
    overall = f"overall {side.overall.following} of {side.overall.relevant}"
    if side.recent is None:
        reason = side.recent_unavailable_reason or "no history"
        return f"{overall} recent {recent_unavailable(reason)}"
    return f"{overall} recent {side.recent.following} of {side.recent.relevant}"


def text_ref(file: str, line: int) -> str:
    """``{file}:{line}``, with ``file`` escaped as a text field."""
    return f"{text_field(file)}:{line}"
