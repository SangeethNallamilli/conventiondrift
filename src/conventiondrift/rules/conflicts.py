"""C6 conflict detection, DESIGN §7 step 5 and §10 S9 (T-015, held to the critical thresholds).

Two rules conflict when they map to the same checker, their scopes overlap,
and either one's ``preferred`` options meet the other's ``prohibited`` options,
or both ``preferred`` sets are non-empty and disjoint (D-PM-05 #5, S9). So
"Use logging, not print" and "Never use print()" do not conflict, while
"Use requests" and "Never use requests" do (AC-E.21), as do "Use requests" in
the root file and "Use httpx" in a subfolder file (AC-E.4).

A rule with no checker, no match, or a disabled checker never conflicts: it is
not evaluated (AC-F3.14), so a conflict naming it would point at nothing.

Bounded work (SECURITY-RULES R2.6; INTERFACES I-13 C6 items 1, 4, 6). Only
rules that share a checker are paired, and rules with the same match and scope
form one *group*, so what is compared is a pair of groups, not of rules; a
non-conflicting rule costs nothing per pair. An evaluation (one pair of groups)
costs O(options per checker + ``MAX_SCOPE_DIR_BYTES``): the ``preferred`` and
``prohibited`` frozensets hold the checker's own option ids (registry
constants, never rule text; ``map_rule`` rejects anything else), and the scope
test is a prefix test on two ``scope_dir`` paths that C4 has validated and that
this module refuses above ``MAX_SCOPE_DIR_BYTES``. Rule text is never touched.
At most ``MAX_CONFLICT_PAIRS`` evaluations run per side, so that is a real time
bound. They run in a deterministic order, I-13 C6 item 8: groups sorted by
their key ``(checker, sorted preferred, sorted prohibited, scope_dir)``, then
pairs in that order, so the same rules always stop at the same pair, whatever
order the files came in. When the budget runs out, every rule with a pair not yet
evaluated is *incomplete* (``ConflictIndex.is_incomplete``): the partners found
so far stay, ``total`` becomes a lower bound, and nothing is dropped silently.

The listed ``found`` holds only the first ``MAX_CONFLICTS`` in sorted
``(a.id, b.id)`` order with ``a.id < b.id``; ``unlisted`` counts the rest.
``Conflicts.lookup`` (a ``ConflictIndex``) covers every conflict whatever the
cap cut, and gives at most ``MAX_CONFLICT_WITH`` sorted partners per rule.
Rule ids must be unique (``extract_rules`` makes them so); ``find_conflicts``
raises ``ValueError`` on a repeated id.
"""

from bisect import bisect_right
from collections.abc import Sequence
from heapq import merge
from itertools import islice
from typing import Final, NamedTuple

from conventiondrift.model import (
    CheckerId,
    Conflict,
    ConflictIndex,
    GroupKey,
    Rule,
    RuleMatch,
    group_key_order,
)

__all__ = [
    "MAX_CONFLICTS",
    "MAX_CONFLICT_PAIRS",
    "MAX_SCOPE_DIR_BYTES",
    "Conflicts",
    "find_conflicts",
    "incomplete_note",
    "matches_conflict",
    "scopes_overlap",
]

MAX_CONFLICTS: Final = 1_000
"""R2.6: conflicts listed per run; the rest are counted in ``Conflicts.unlisted``."""

MAX_CONFLICT_PAIRS: Final = 5_000_000
"""R2.6: pair evaluations per side; beyond it the remaining rules are incomplete."""

MAX_SCOPE_DIR_BYTES: Final = 4_096
"""R2.6: the longest ``Rule.scope_dir`` (UTF-8 bytes) compared; longer ones are incomplete."""


class Conflicts(NamedTuple):
    """``found``: the first ``MAX_CONFLICTS`` conflicts in sorted order; ``unlisted``: the rest."""

    found: tuple[Conflict, ...]
    unlisted: int
    lookup: ConflictIndex


def incomplete_note(count: int) -> str:
    """The note for ``count`` rules that were not fully checked (I-13 C6 item 4)."""
    noun = "rule" if count == 1 else "rules"
    return f"conflict check stopped at the limit; {count} {noun} not fully checked"


def _overlap(a: str, a_prefix: str, b: str, b_prefix: str) -> bool:
    """``scopes_overlap`` on scopes whose ``scope + "/"`` is already built (SR L-55-2)."""
    return not a or not b or a == b or a.startswith(b_prefix) or b.startswith(a_prefix)


def scopes_overlap(a: str, b: str) -> bool:
    """Whether two ``Rule.scope_dir`` folders share code: equal, or one holds the other.

    "" is the whole repository, so it overlaps every scope.
    """
    return _overlap(a, a + "/", b, b + "/")


def matches_conflict(a: RuleMatch, b: RuleMatch) -> bool:
    """Whether two matches of one checker name different options (S9)."""
    if a.preferred & b.prohibited or b.preferred & a.prohibited:
        return True
    return bool(a.preferred) and bool(b.preferred) and not a.preferred & b.preferred


def find_conflicts(rules: Sequence[Rule], *, max_pairs: int = MAX_CONFLICT_PAIRS) -> Conflicts:
    """Every conflicting pair among ``rules``, the first ``MAX_CONFLICTS`` of them listed.

    ``max_pairs`` is the evaluation budget; production uses the default and
    tests pass a small one. Raises ``ValueError`` if two rules share an id.
    """
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("rule ids must be unique")
    # One group per key. Specificity is not part of it: it doesn't matter here.
    members: dict[GroupKey, list[str]] = {}
    matches: dict[GroupKey, RuleMatch] = {}
    unchecked: set[str] = set()
    for rule in rules:
        if rule.checker is None or rule.match is None or rule.disabled:
            continue
        if len(rule.scope_dir.encode()) > MAX_SCOPE_DIR_BYTES:
            unchecked.add(rule.id)  # R2.6: never compared, never silent
            continue
        key = (rule.checker, rule.match.preferred, rule.match.prohibited, rule.scope_dir)
        members.setdefault(key, []).append(rule.id)
        matches[key] = rule.match
    # Deterministic order: sorted group keys (I-13 C6 item 8).
    keys = sorted(members, key=group_key_order)
    ids = tuple(tuple(sorted(members[key])) for key in keys)
    # Each group's scope and its "/"-terminated form are built once, not once per evaluation.
    scopes = [key[3] for key in keys]
    prefixes = [scope + "/" for scope in scopes]
    adjacent: list[list[int]] = [[] for _ in keys]
    by_checker: dict[CheckerId, list[int]] = {}
    for number, key in enumerate(keys):
        by_checker.setdefault(key[0], []).append(number)
    total = 0
    evaluated = 0
    unchecked_groups: set[int] = set()
    for numbers in by_checker.values():
        if unchecked_groups:  # the budget ran out in an earlier checker
            if len(numbers) > 1:
                unchecked_groups.update(numbers)
            continue
        for position, a in enumerate(numbers):
            for other in range(position + 1, len(numbers)):
                if evaluated == max_pairs:
                    # Group a has pairs left, and so does every group after it in this checker.
                    unchecked_groups.update(numbers[position:])
                    break
                evaluated += 1
                b = numbers[other]
                if _overlap(scopes[a], prefixes[a], scopes[b], prefixes[b]) and matches_conflict(
                    matches[keys[a]], matches[keys[b]]
                ):
                    adjacent[a].append(b)
                    adjacent[b].append(a)
                    total += len(ids[a]) * len(ids[b])
            if unchecked_groups:
                break
    for group in unchecked_groups:
        unchecked.update(ids[group])
    lookup = ConflictIndex(
        ids=ids,
        keys=tuple(keys),
        adjacent=tuple(tuple(group) for group in adjacent),  # ascending by construction
        incomplete_ids=frozenset(unchecked),
    )
    found: list[Conflict] = []
    group_of = {rule_id: g for g, group_ids in enumerate(ids) for rule_id in group_ids}
    for rule_id in sorted(group_of):
        room = MAX_CONFLICTS - len(found)
        if not room:
            break
        group = group_of[rule_id]
        # Partners after this rule, in order: each group's ids are sorted, so merge them.
        later = (ids[other][bisect_right(ids[other], rule_id) :] for other in adjacent[group])
        for partner in islice(merge(*later), room):
            found.append(Conflict(rules=(rule_id, partner), checker=keys[group][0]))
    return Conflicts(found=tuple(found), unlisted=total - len(found), lookup=lookup)
