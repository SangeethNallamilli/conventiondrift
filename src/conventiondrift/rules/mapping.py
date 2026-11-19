"""C6 checker mapping, rule identity and duplicates (DESIGN §7 steps 4-5, T-015, critical module).

``extract_rules`` turns instruction files into the I-13 ``Rule`` list and the
``Conflict`` list (``RuleExtractor`` is the I-11 ``Extractor`` over it):

1. Each file goes through ``extract_file`` (T-013), the only way a rule is
   made (SR C-2 on #32). I-7 markers come from ``Policy.markers`` alone, which
   holds the policy side's markers, so a head-side marker can never silence a
   rule in a gated run (SR C-1); a file with no entry there has no markers.
2. Rules with the same identity, (file, normalized text), are one rule at
   their first line, with the later lines in ``also_at`` (AC-E.20). Across
   files nothing merges: the file is part of the identity. A rule's id is
   ``file:line``, or ``file:line:column`` when two rules start on one line.
3. **Mapping** (``map_rule``): every checker's ``match_rule`` runs on the
   normalized text. The highest ``specificity`` wins. A tie, or no match at
   all, gives ``checker=None`` and ``match=None``, which C9 turns into Not
   verifiable with no warning (AC-F2.6, AC-F2.7, AC-F4.8). A checker that
   raises, or returns a match that is not valid for it (I-10 "RuleMatch
   validity"), is a checker bug and a ``ComponentError("checker:<id>")``.
4. ``ignored`` is set by an I-7 marker or a config ``ignore`` entry on any of
   the rule's lines; ``disabled`` when the winning checker is off in the
   policy (AC-F3.14); ``scope_dir`` is the file's folder, set by C4.
5. Conflicts come from ``conflicts.find_conflicts``.

Mapping is deterministic: checkers are tried in sorted id order and output is
in (file, line) order.
"""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from conventiondrift.checkers.base import Checker
from conventiondrift.errors import ComponentError
from conventiondrift.model import (
    CheckerId,
    Conflict,
    IgnoreEntry,
    InstructionFile,
    Policy,
    Rule,
    RuleMatch,
)
from conventiondrift.rules.conflicts import ConflictIndex, find_conflicts
from conventiondrift.rules.extract import ExtractedRule, FileRules, extract_file, normalize

__all__ = [
    "Extraction",
    "Mapped",
    "RuleExtractor",
    "extract_rules",
    "map_rule",
    "rule_id",
    "rule_identity",
]


class Mapped(NamedTuple):
    """The checker a rule maps to and its match; both None when it maps to none."""

    checker: CheckerId | None
    match: RuleMatch | None


UNMAPPED = Mapped(checker=None, match=None)


@dataclass(frozen=True, slots=True)
class Extraction:
    """What ``extract_rules`` found.

    ``files`` holds each file's ``extract_file`` result in path order, so the
    caller can list unattached markers and the R2.6 caps (DESIGN §10 S4).
    ``conflicts`` lists at most ``MAX_CONFLICTS`` conflicts and
    ``conflicts_dropped`` counts the rest (I-9 ``counts.conflicts_dropped``).
    ``conflict_lookup`` answers whether a rule is in a conflict and with which
    rules, whatever the cap cut (``conflict_with``).
    """

    rules: tuple[Rule, ...]
    conflicts: tuple[Conflict, ...]
    files: tuple[FileRules, ...]
    conflicts_dropped: int
    unattached_markers: tuple[tuple[str, int], ...]
    conflict_lookup: ConflictIndex


def rule_identity(file: str, normalized_text: str) -> tuple[str, str]:
    """A rule's identity within one run: its file and normalized text (DESIGN §7 step 5).

    Comparing base and head across file renames is C10's job (T-022).
    """
    return (file, normalized_text)


def rule_id(file: str, line: int, column: int, *, shares_line: bool) -> str:
    """A rule's id (INTERFACES I-13 "C6 conflict cap and rule ids").

    ``file:line``, or ``file:line:column`` for every rule when two or more rules
    start on that line. Ids are opaque, unique within a side, and never parsed.
    """
    return f"{file}:{line}:{column}" if shares_line else f"{file}:{line}"


def _is_valid(match: object, options: frozenset[str]) -> bool:
    """I-10 "RuleMatch validity", checked again here because C6 owns the subset check."""
    return (
        isinstance(match, RuleMatch)
        and type(match.specificity) is int
        and isinstance(match.preferred, frozenset)
        and isinstance(match.prohibited, frozenset)
        and bool(match.preferred | match.prohibited)
        and not match.preferred & match.prohibited
        and (match.preferred | match.prohibited) <= options
    )


def _match_of(checker: Checker, normalized_text: str) -> RuleMatch | None:
    try:
        match = checker.match_rule(normalized_text)
    except KeyboardInterrupt:
        raise
    except BaseException:  # noqa: BLE001 -- a broken checker fails closed, as in the C7 pool
        raise ComponentError(f"checker:{checker.id}", "match_rule failed") from None
    if match is not None and not _is_valid(match, checker.options):
        raise ComponentError(f"checker:{checker.id}", "match_rule returned an invalid match")
    return match


def map_rule(normalized_text: str, checkers: Mapping[str, Checker]) -> Mapped:
    """Run every checker's ``match_rule``; the highest specificity wins (DESIGN §7 step 4).

    A tie for the highest, or no match, gives ``UNMAPPED``. Raises
    ``ComponentError("checker:<id>")`` for the first checker, in id order, that
    raises or returns an invalid match.
    """
    found: list[tuple[Checker, RuleMatch]] = []
    for key in sorted(checkers):
        checker = checkers[key]
        match = _match_of(checker, normalized_text)
        if match is not None:
            found.append((checker, match))
    if not found:
        return UNMAPPED
    top = max(match.specificity for _, match in found)
    best = [(checker, match) for checker, match in found if match.specificity == top]
    if len(best) != 1:
        return UNMAPPED
    checker, match = best[0]
    return Mapped(checker=checker.id, match=match)


def _entry_matches(
    entry: IgnoreEntry, file: str, lines: frozenset[int], normalized_text: str
) -> bool:
    """A config ``ignore`` entry names a rule when every field it sets matches (I-6)."""
    if entry.file is None and entry.line is None and entry.text is None:
        return False
    return (
        (entry.file is None or entry.file == file)
        and (entry.line is None or entry.line in lines)
        and (entry.text is None or normalize(entry.text) == normalized_text)
    )


def _build(
    file: InstructionFile,
    group: Sequence[ExtractedRule],
    policy: Policy,
    checkers: Mapping[str, Checker],
    *,
    shares_line: bool,
) -> Rule:
    first = group[0]
    lines = frozenset(rule.line for rule in group)
    mapped = map_rule(first.normalized_text, checkers)
    disabled = False
    if mapped.checker is not None:
        checker_policy = policy.checkers.get(mapped.checker)
        if checker_policy is None:
            raise ComponentError("rules", "a checker is missing from the policy")
        disabled = not checker_policy.enabled
    ignored = any(rule.ignored for rule in group) or any(
        _entry_matches(entry, file.path, lines, first.normalized_text) for entry in policy.ignores
    )
    return Rule(
        id=rule_id(file.path, first.line, first.column, shares_line=shares_line),
        file=file.path,
        line=first.line,
        also_at=tuple(sorted(lines - {first.line})),
        text=first.text,
        normalized_text=first.normalized_text,
        checker=mapped.checker,
        match=mapped.match,
        scope_dir=file.scope_dir,
        ignored=ignored,
        disabled=disabled,
    )


def extract_rules(
    files: Sequence[InstructionFile], policy: Policy, checkers: Mapping[str, Checker]
) -> Extraction:
    """Instruction files to rules and conflicts (I-11 C6); see the module docstring.

    Raises ``ComponentError("rules")`` for a repeated file path or a checker
    missing from the policy, and ``ComponentError("checker:<id>")`` for a
    broken checker; none of these is ever treated as config.
    """
    ordered = sorted(files, key=lambda f: f.path)
    if len({f.path for f in ordered}) != len(ordered):
        raise ComponentError("rules", "an instruction file was given twice")
    results: list[FileRules] = []
    # Rule identity groups the rules, so only same-file duplicates merge. Files are in path
    # order and a group keeps the order its rules were found in, so output is in (file, line) order.
    groups: dict[tuple[str, str], tuple[InstructionFile, list[ExtractedRule]]] = {}
    for file in ordered:
        # Markers are the policy side's alone: never fall back to the file's own (SR C-1).
        result = extract_file(file.path, file.data, markers=policy.markers.get(file.path, ()))
        results.append(result)
        for rule in result.rules:
            identity = rule_identity(file.path, rule.normalized_text)
            groups.setdefault(identity, (file, []))[1].append(rule)
    starts = Counter((file.path, group[0].line) for file, group in groups.values())
    rules = [
        _build(file, group, policy, checkers, shares_line=starts[(file.path, group[0].line)] > 1)
        for file, group in groups.values()
    ]
    conflicts = find_conflicts(rules)
    return Extraction(
        rules=tuple(rules),
        conflicts=conflicts.found,
        files=tuple(results),
        conflicts_dropped=conflicts.unlisted,
        unattached_markers=tuple(
            (result.path, line) for result in results for line in result.unattached_markers
        ),
        conflict_lookup=conflicts.lookup,
    )


class RuleExtractor:
    """The I-11 ``Extractor``: ``extract_rules`` and its full ``Extraction`` (I-13 C6 item 3)."""

    def extract(
        self,
        files: Sequence[InstructionFile],
        policy: Policy,
        checkers: Mapping[str, Checker],
    ) -> Extraction:
        return extract_rules(files, policy, checkers)
