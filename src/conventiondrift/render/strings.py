"""Every user-visible C11 string (D-TL-85, D-TL-86). Wording changes stay in this module."""

from __future__ import annotations

from typing import Final, Literal

__all__ = [
    "ANNOTATION_TITLE_PREFIX",
    "FETCH_DEPTH",
    "HEADING",
    "INTERNAL_ERROR_HEADING",
    "MAX_FINDING_ANNOTATIONS",
    "NO_INSTRUCTION_FILES",
    "NO_PR_BODY",
    "NO_PYTHON_FILES",
    "PRT_BODY",
    "PRT_HEADING",
    "RUN_LEVEL_TITLE",
    "TEXT_HEADER",
    "analyzed_line",
    "analyzer_python_line",
    "conflict_incomplete_note",
    "conflicts_unlisted_line",
    "disabled_checker_line",
    "error_policy_source_line",
    "finding_annotation_title",
    "gating_line",
    "head_only_why",
    "internal_error_line",
    "mode_line",
    "no_comparison_sentence",
    "not_annotated_line",
    "policy_source_line",
    "pre_existing_line",
    "read_only_line",
    "recent_unavailable",
    "scan_new_stale_line",
    "unattached_marker_line",
    "window_unavailable",
]

MAX_FINDING_ANNOTATIONS: Final = 10
"""Finding annotations only; the run-level conflict warning is extra (D-TL-86 #6)."""

HEADING: Final = "# conventiondrift"
INTERNAL_ERROR_HEADING: Final = "## Internal error"
NO_PYTHON_FILES: Final = "No Python files found."
NO_INSTRUCTION_FILES: Final = "No instruction files found."
NO_PR_BODY: Final = "No PR to compare."
PRT_HEADING: Final = "# conventiondrift: unsupported trigger"
PRT_BODY: Final = "`pull_request_target` is not supported. Nothing was read from the pull request."
FETCH_DEPTH: Final = "fetch-depth: 0"
TEXT_HEADER: Final = "conventiondrift text 1"
RUN_LEVEL_TITLE: Final = "conventiondrift"
ANNOTATION_TITLE_PREFIX: Final = "conventiondrift: "
_NO_COMPARISON: Final = "No before/after comparison was made."
_FETCH_HINT: Final = f"To compare against the pull request base, check out with {FETCH_DEPTH}."
_GATING: Final = "Gating was not applied."
_SCAN_NEW_STALE: Final = (
    "new-stale cannot be met in scan mode because there are no before/after cases."
)

_MODE_LINE: Final = {
    "compare": "Compare report.",
    "head-only": "Head-only report.",
    "scan": "Scan report.",
}
_HEAD_ONLY_WHY: Final = {
    "shallow clone": "This is a shallow clone.",
    "missing object": "A required git object is missing.",
    "no merge base": "No merge-base exists.",
}
_READ_ONLY: Final = {
    "fork": "The comment was skipped because the token is read-only (fork pull request).",
    "dependabot": "The comment was skipped because the token is read-only (Dependabot).",
}


def _count_noun(count: int, singular: str, plural: str) -> str:
    """D-PM-39: ``1`` takes the singular form, every other count the plural."""
    return f"{count} {singular}" if count == 1 else f"{count} {plural}"


def mode_line(mode: Literal["compare", "head-only", "scan"]) -> str:
    return _MODE_LINE[mode]


def no_comparison_sentence() -> str:
    return _NO_COMPARISON


def head_only_why(
    reason: Literal["shallow clone", "missing object", "no merge base"] | None,
) -> str | None:
    if reason is None:
        return None
    return _HEAD_ONLY_WHY[reason]


def fetch_hint(*, markdown: bool) -> str:
    if markdown:
        return f"To compare against the pull request base, check out with `{FETCH_DEPTH}`."
    return _FETCH_HINT


def analyzed_line(sha: str, head_kind: Literal["pr_head", "checkout"], *, markdown: bool) -> str:
    kind = "PR head" if head_kind == "pr_head" else "checked-out commit"
    del markdown  # SHA is pre-wrapped by the caller when Markdown is required
    return f"Analyzed {sha} ({kind})."


def gating_line(*, markdown: bool) -> str:
    return _GATING if markdown else "gating was not applied"


def window_anchor_line(
    days: int,
    iso: str,
    sha: str,
    *,
    mode: Literal["compare", "head-only", "scan"],
) -> str:
    label = "HEAD" if mode == "scan" else "PR head"
    return f"{days} days ending at {iso} ({label} {sha})."


def window_unavailable(reason: str) -> str:
    return f"not available ({reason})"


def recent_unavailable(reason: str) -> str:
    return f"not available ({reason})"


def analyzer_python_line(version: str) -> str:
    return f"Analyzer Python: {version}"


def policy_source_line(source: Literal["base", "head"]) -> str:
    return f"Policy source: {source}"


def error_policy_source_line(
    explicit: str | None,
    *,
    config_known_present: bool,
) -> str:
    """The I-14 error-only policy-source line. Never presents the error-path fail-on."""
    if explicit is not None and explicit != "":
        return f"Policy source: {explicit}"
    if config_known_present:
        return "Policy source: base config could not be read"
    return "Policy source: default (none)"


def read_only_line(reason: Literal["fork", "dependabot"]) -> str:
    return _READ_ONLY[reason]


def scan_new_stale_line() -> str:
    return _SCAN_NEW_STALE


def pre_existing_line(count: int) -> str:
    return _count_noun(count, "pre-existing stale rule", "pre-existing stale rules")


def not_annotated_line(count: int) -> str:
    return _count_noun(count, "finding not annotated", "findings not annotated")


def conflict_incomplete_note(count: int) -> str:
    noun = "rule" if count == 1 else "rules"
    return f"conflict check stopped at the limit; {count} {noun} not fully checked"


def conflicts_unlisted_line(count: int) -> str:
    return _count_noun(count, "conflict not listed", "conflicts not listed")


def partners_phrase(count: int, *, incomplete: bool) -> str:
    noun = "partner" if count == 1 else "partners"
    if incomplete:
        return f"at least {count} {noun}"
    return f"{count} {noun}"


def disabled_checker_line(checker_id: str) -> str:
    return f"Checker {checker_id} is experimental, off by default."


def unattached_marker_line(file_shown: str, line: int) -> str:
    """``file_shown`` is already escaped (``md()`` or a text field)."""
    return f"Unattached ignore marker at {file_shown} line {line}."


def internal_error_line(component_shown: str, message: str) -> str:
    """``component_shown`` is already passed through ``md()``."""
    return f"Internal error in {component_shown}: {message}"


def finding_annotation_title(rule_id: str) -> str:
    return f"{ANNOTATION_TITLE_PREFIX}{rule_id}"
