"""C11 PR comment body: one renderer over one ``Result`` (INTERFACES I-1, I-3, DESIGN §10 B5).

``render_comment`` returns the exact raw Markdown the Action posts and
``--format comment`` prints, or ``None`` when there is no comment (AC-F5.5).
The layout is the approved AC-F6.7 snapshot (D-PM-40, SC-2.58), paragraphs joined by one
blank line: the I-3 marker (always line 1) and the header line; one fenced block per finding
(built by ``md_codeblock``); the conflict note and the truncation notice, when needed; and the
count line, always the last non-empty line.

Only cases 1 and 2 give a finding (SPEC glossary "Warning"). A rule that is
ignored or conflicting never does (AC-F9.10, AC-E.3, DESIGN S2). All repository-derived
text (rule text, paths, options, ``new_text``) appears only inside a finding block, and each
block is built by ``escape.md_codeblock`` from whole lines (INTERFACES I-14, item 4): this file
writes no fence and escapes nothing itself (SECURITY-RULES R3.2). Blocks sit at column 0 and
are joined with blank lines at top level, never inside a list, quote, table or HTML (item 9).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from conventiondrift.model import (
    Alternative,
    CausingFile,
    Result,
    Rule,
    RuleResult,
    SideResult,
)
from conventiondrift.render.escape import md_codeblock

__all__ = ["MAX_COMMENT_CHARS", "STICKY_MARKER", "render_comment"]

STICKY_MARKER: Final = "<!-- conventiondrift:sticky v1 -->"
"""I-3: line 1 of every comment body."""

MAX_COMMENT_CHARS: Final = 65_536
"""AC-E.13: GitHub's limit on a comment body, counted in characters."""

MAX_CAUSING_FILES: Final = 3
"""D-PM-40: causing files listed per finding before "+N more"."""

_RESOLVED: Final = "🧭 conventiondrift: resolved, this PR no longer changes any agent rule's status"
_WARNING: Final = "⚠️"
_INDENT: Final = "   "
_FINDING_CASES: Final = frozenset({"made-stale-by-code", "stale-rule-added"})
_WHY_LEAD: Final = "Agents treat this file as an instruction and will likely"


def _rules(count: int) -> str:
    """D-PM-39: "1 rule" / "N rules"."""
    return f"{count} rule" if count == 1 else f"{count} rules"


def _join_names(names: Sequence[str]) -> str:
    """``A``, ``A and B``, ``A, B and C``."""
    if len(names) == 1:
        return names[0]
    return f"{', '.join(names[:-1])} and {names[-1]}"


def _finding_parts(rule_result: RuleResult) -> tuple[Rule, SideResult] | None:
    """The head rule and its head side when ``rule_result`` is a finding, else ``None``."""
    rule = rule_result.head_rule
    head = rule_result.head
    if (
        rule_result.case in _FINDING_CASES
        and rule is not None
        and head is not None
        and not rule.ignored
        and not rule.disabled
        and rule_result.conflict_with_total == 0
    ):
        return rule, head
    return None


def _causing(files: Sequence[CausingFile]) -> str:
    """``removed in a.py, b.py, +N more``: up to three files, in C10's order."""
    shown = [f.file for f in files[:MAX_CAUSING_FILES]]
    if len(files) > MAX_CAUSING_FILES:
        shown.append(f"+{len(files) - MAX_CAUSING_FILES} more")
    verb = "removed" if all(f.following_delta < 0 for f in files) else "changed"
    return f"{verb} in {', '.join(shown)}"


def _suggestion_lines(rule_result: RuleResult, rule_text: str, relevant: int) -> list[str]:
    """The lines after the why paragraph. A blank line separates them; none means no block.

    Only ``replace`` with a ``new_text`` gets a Suggested fix block (D-PM-38, D-PM-40).
    """
    suggestion = rule_result.suggestion
    alternatives: Sequence[Alternative] = suggestion.alternatives
    top = alternatives[0] if alternatives else None
    if suggestion.kind == "replace" and suggestion.new_text is not None:
        return [
            "Suggested fix:",
            f"- {rule_text}",
            f"+ {suggestion.new_text}",
        ]
    if suggestion.kind == "replace" and top is not None:
        return [f"Most-used option now: {top.option} ({top.sites} of {relevant} sites)"]
    if suggestion.kind == "tie" and top is not None:
        tied = [a.option for a in alternatives if a.sites == top.sites]
        return [f"No single replacement: {_join_names(tied)} are tied at {top.sites} sites each."]
    if suggestion.kind == "remove-or-rewrite":
        lines = []
        if alternatives:
            seen = ", ".join(f"{a.option}: {a.sites} of {relevant} sites" for a in alternatives)
            lines.append(f"Observed now: {seen}")
        return [*lines, "Consider removing or rewriting this rule."]
    return []


def _finding(rule_result: RuleResult, rule: Rule, head: SideResult) -> str:
    """One finding as a fenced block (the seven AC-F6.3 fields, plus the tie wording)."""
    options = rule.match.preferred if rule.match is not None else frozenset[str]()
    prohibition_only = not options
    if prohibition_only and rule.match is not None:
        options = rule.match.prohibited
    label = " or ".join(sorted(options))
    verb = "avoided" if prohibition_only else "used"
    noun = "call sites" if rule.checker == "http-client" else "sites"
    relevant = head.overall.relevant
    after = f"{head.overall.following} of {relevant}"
    lines = [f'{_WARNING} {rule.file} line {rule.line}: "{rule.text}"']
    if rule_result.base is None:
        lines.append(f"After this PR:  {after} {noun} {verb} {label}")
    else:
        base = rule_result.base.overall
        lines.append(f"Before this PR: {base.following} of {base.relevant} {noun} {verb} {label}")
        if rule_result.causing_files:
            after += f" ({_causing(rule_result.causing_files)})"
        lines.append(f"After this PR:  {after}")
    lines.append(_WHY_LEAD)
    if prohibition_only:
        lines.append(f"keep avoiding {label}, which most code in this repo now uses.")
    else:
        lines.append(f"reintroduce {label} in future changes.")
    extra = _suggestion_lines(rule_result, rule.text, relevant)
    if extra:
        lines.extend(["", *extra])
    body = [lines[0], *(f"{_INDENT}{line}" if line else "" for line in lines[1:])]
    return md_codeblock(body)


def _count_line(result: Result) -> str:
    counts = result.counts
    return (
        f"{_rules(counts.rules_changed)} changed status · "
        f"{counts.rules_unchanged} unchanged · details in the job summary"
    )


def _conflict_note(result: Result) -> str | None:
    """I-13 C6 item 6 note, verbatim, with D-PM-39's singular form."""
    incomplete = result.counts.conflicts_incomplete
    if incomplete == 0:
        return None
    return f"conflict check stopped at the limit; {_rules(incomplete)} not fully checked"


def _more_findings(omitted: int) -> str:
    if omitted == 1:
        return "1 more finding is in the job summary."
    return f"{omitted} more findings are in the job summary."


def _assemble(
    header: str, entries: Sequence[str], note: str | None, tail: str, omitted: int
) -> str:
    parts = [f"{STICKY_MARKER}\n{header}", *entries]
    if note is not None:
        parts.append(note)
    if omitted:
        parts.append(_more_findings(omitted))
    parts.append(tail)
    return "\n\n".join(parts) + "\n"


def render_comment(result: Result, *, previous_comment: bool) -> str | None:
    """Return the comment body, or ``None`` when there is no comment.

    ``None`` for any mode but compare (head-only and scan post nothing, DESIGN §4), and for a
    compare run with no finding unless ``previous_comment`` is true: then the earlier comment is
    updated to the resolved text (AC-F5.7). A body over ``MAX_COMMENT_CHARS`` characters keeps
    whole findings only, in report order, and says how many more are in the job summary
    (AC-E.13); the count line stays last.
    """
    if result.mode != "compare":
        return None
    findings = [(r, *parts) for r in result.rule_results if (parts := _finding_parts(r))]
    note = _conflict_note(result)
    if not findings:
        if not previous_comment:
            return None
        return "\n\n".join(filter(None, [f"{STICKY_MARKER}\n{_RESOLVED}", note])) + "\n"
    noun = "rule" if len(findings) == 1 else "rules"
    header = f"🧭 conventiondrift: this PR makes {len(findings)} agent {noun} stale"
    tail = _count_line(result)
    entries = [_finding(*parts) for parts in findings]
    kept = 0
    entry_chars = 0  # each kept entry adds its text and one blank-line separator
    for entry in entries:
        entry_chars += len(entry) + 2
        fixed = _assemble(header, [], note, tail, len(entries) - kept - 1)
        if len(fixed) + entry_chars > MAX_COMMENT_CHARS:
            break
        kept += 1
    return _assemble(header, entries[:kept], note, tail, len(entries) - kept)
