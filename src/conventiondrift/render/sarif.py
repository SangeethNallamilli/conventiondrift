"""C11 SARIF 2.1.0 log for ``--format sarif`` and the code-scanning upload (T-026).

One run, one tool (``conventiondrift``), and one result per PR-caused Stale finding, located
at the instruction file and the rule's line (AC-F6.10). A finding is exactly what the comment
shows (cases 1 and 2, not ignored, not disabled, not conflicting), in report order, with no
cap: SARIF carries every finding (DECISIONS, annotation cap). Head-only and scan runs have no
finding, so their log has an empty ``results`` list.

``message.text`` is plain text, never Markdown (SECURITY-RULES R3.1). It reuses the comment's
finding lines (approved wording, D-PM-40) and passes each whole line through
``escape.sarif_text``; the lines are joined by LF. A ``replace`` suggestion with no
``new_text`` shows the finding and the most-used option without suggested text (D-PM-38).
No other SARIF field is built from repository text except the location: the artifact URI is
the repo-relative POSIX path through ``escape.sarif_uri`` (D-TL-97) and the region is the
rule's line number. The serializer is the
I-9 one, so the bytes are deterministic and ASCII-only.
"""

from __future__ import annotations

from typing import Final

from conventiondrift import __version__
from conventiondrift.model import Result, Rule, RuleResult
from conventiondrift.render.comment import finding_lines
from conventiondrift.render.escape import sarif_text, sarif_uri
from conventiondrift.render.findings import finding_rule
from conventiondrift.render.jsonreport import JsonValue, dump_json
from conventiondrift.render.strings import SARIF_RULES

__all__ = [
    "SARIF_LEVEL",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "TOOL_NAME",
    "render_sarif",
    "sarif_message",
    "sarif_object",
]

SARIF_SCHEMA: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
"""The official OASIS SARIF 2.1.0 (errata 01) JSON schema."""
SARIF_VERSION: Final = "2.1.0"
TOOL_NAME: Final = "conventiondrift"
SARIF_LEVEL: Final = "warning"
"""Same severity as the finding annotations."""

_RULE_INDEX: Final = {rule_id: index for index, (rule_id, _, _) in enumerate(SARIF_RULES)}


def _descriptors() -> list[JsonValue]:
    return [
        {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": short},
            "defaultConfiguration": {"level": SARIF_LEVEL},
        }
        for rule_id, name, short in SARIF_RULES
    ]


def sarif_message(rule_result: RuleResult) -> str:
    """The plain-text ``message.text`` for one finding; every line escaped by ``sarif_text``.

    Raises ``ValueError`` when ``rule_result`` is not a finding (a caller bug).
    """
    rule = finding_rule(rule_result)
    head = rule_result.head
    if rule is None or head is None:
        raise ValueError("not a finding")
    return "\n".join(sarif_text(line) for line in finding_lines(rule_result, rule, head) if line)


def _result(rule_result: RuleResult, rule: Rule) -> dict[str, JsonValue]:
    case = str(rule_result.case)  # a finding case; SARIF_RULES has one descriptor for each
    return {
        "ruleId": case,
        "ruleIndex": _RULE_INDEX[case],
        "level": SARIF_LEVEL,
        "message": {"text": sarif_message(rule_result)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": sarif_uri(rule.file)},
                    "region": {"startLine": rule.line},
                }
            }
        ],
    }


def sarif_object(result: Result) -> dict[str, JsonValue]:
    """The SARIF 2.1.0 log for ``result``, before serialization."""
    results: list[JsonValue] = []
    for item in result.rule_results:
        rule = finding_rule(item)
        if rule is not None:
            results.append(_result(item, rule))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "rules": _descriptors(),
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(result: Result) -> str:
    """The SARIF text for ``--format sarif`` and ``results.sarif``."""
    return dump_json(sarif_object(result))
