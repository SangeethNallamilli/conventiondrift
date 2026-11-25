"""The comment/annotation finding predicate and the finding-annotation cap (D-TL-86)."""

from __future__ import annotations

from collections.abc import Sequence

from conventiondrift.model import Rule, RuleResult
from conventiondrift.render.strings import MAX_FINDING_ANNOTATIONS

__all__ = [
    "FINDING_CASES",
    "MAX_FINDING_ANNOTATIONS",
    "finding_rule",
    "findings_in_order",
    "is_finding",
]

FINDING_CASES = frozenset({"made-stale-by-code", "stale-rule-added"})
"""The same cases as ``render_comment`` (SPEC glossary "Warning")."""


def finding_rule(rule_result: RuleResult) -> Rule | None:
    """The head rule when ``rule_result`` is a finding, else ``None``."""
    rule = rule_result.head_rule
    head = rule_result.head
    if (
        rule_result.case in FINDING_CASES
        and rule is not None
        and head is not None
        and not rule.ignored
        and not rule.disabled
        and rule_result.conflict_with_total == 0
    ):
        return rule
    return None


def is_finding(rule_result: RuleResult) -> bool:
    return finding_rule(rule_result) is not None


def findings_in_order(rule_results: Sequence[RuleResult]) -> tuple[RuleResult, ...]:
    """Findings in ``rule_results`` order, which is already ``(file, line)``."""
    return tuple(item for item in rule_results if is_finding(item))


def omitted_finding_count(rule_results: Sequence[RuleResult]) -> int:
    """How many findings are past the annotation cap (D-TL-86 #6)."""
    total = len(findings_in_order(rule_results))
    return max(0, total - MAX_FINDING_ANNOTATIONS)
