"""C6 conflict detection, DESIGN §7 step 5 and §10 S9 (T-015, held to the critical thresholds).

Two rules conflict when they map to the same checker, their scopes overlap,
and either one's ``preferred`` options meet the other's ``prohibited`` options,
or both ``preferred`` sets are non-empty and disjoint (D-PM-05 #5, S9). So
"Use logging, not print" and "Never use print()" do not conflict, while
"Use requests" and "Never use requests" do (AC-E.21), as do "Use requests" in
the root file and "Use httpx" in a subfolder file (AC-E.4).

A rule with no checker, no match, or a disabled checker never conflicts: it is
not evaluated (AC-F3.14), so a conflict naming it would point at nothing.

Bounded work and the cap (SECURITY-RULES R2.6; INTERFACES I-13 "C6 conflict cap
and rule ids"): only rules that share a checker are paired, grouped by match
and scope so that non-conflicting rules cost nothing per pair. Every pair is
evaluated, but the listed ``found`` holds only the first ``MAX_CONFLICTS`` in
sorted ``(a.id, b.id)`` order with ``a.id < b.id``; ``unlisted`` counts the
rest, so nothing is dropped silently. ``Conflicts.lookup`` (a ``ConflictIndex``)
answers "is this rule in a conflict" and "which rules does it conflict with" for
any rule, whatever the cap cut. Rule ids must be unique (``extract_rules`` makes them so).
"""

from bisect import bisect_right
from collections.abc import Sequence
from heapq import merge
from itertools import combinations, islice
from typing import Final, NamedTuple

from conventiondrift.model import CheckerId, Conflict, Rule, RuleMatch

__all__ = [
    "MAX_CONFLICTS",
    "ConflictIndex",
    "Conflicts",
    "find_conflicts",
    "matches_conflict",
    "scopes_overlap",
]

MAX_CONFLICTS: Final = 1_000
"""R2.6: conflicts listed per run; the rest are counted in ``Conflicts.unlisted``."""


class ConflictIndex:
    """Which rules conflict, for every rule and independent of ``MAX_CONFLICTS``."""

    __slots__ = ("_adjacent", "_group_of", "_ids")

    def __init__(
        self,
        ids: Sequence[Sequence[str]],
        adjacent: Sequence[Sequence[int]],
    ) -> None:
        # ids[g]: the sorted rule ids of group g; adjacent[g]: the groups g conflicts with.
        self._ids = ids
        self._adjacent = adjacent
        self._group_of = {rule_id: g for g, members in enumerate(ids) for rule_id in members}

    def is_conflicting(self, rule_id: str) -> bool:
        """Whether ``rule_id`` is in at least one conflict; False for an unknown id."""
        group = self._group_of.get(rule_id)
        return group is not None and bool(self._adjacent[group])

    def partners(self, rule_id: str) -> tuple[str, ...]:
        """The ids ``rule_id`` conflicts with, sorted; empty for an unknown id."""
        group = self._group_of.get(rule_id)
        if group is None:
            return ()
        return tuple(sorted(i for other in self._adjacent[group] for i in self._ids[other]))


class Conflicts(NamedTuple):
    """``found``: the first ``MAX_CONFLICTS`` conflicts in sorted order; ``unlisted``: the rest."""

    found: tuple[Conflict, ...]
    unlisted: int
    lookup: ConflictIndex


def scopes_overlap(a: str, b: str) -> bool:
    """Whether two ``Rule.scope_dir`` folders share code: equal, or one holds the other.

    "" is the whole repository, so it overlaps every scope.
    """
    return not a or not b or a == b or a.startswith(b + "/") or b.startswith(a + "/")


def matches_conflict(a: RuleMatch, b: RuleMatch) -> bool:
    """Whether two matches of one checker name different options (S9)."""
    if a.preferred & b.prohibited or b.preferred & a.prohibited:
        return True
    return bool(a.preferred) and bool(b.preferred) and not a.preferred & b.preferred


def find_conflicts(rules: Sequence[Rule]) -> Conflicts:
    """Every conflicting pair among ``rules``, the first ``MAX_CONFLICTS`` of them listed."""
    # One group per (checker, preferred, prohibited, scope). Specificity is not part of the
    # key: it doesn't matter here.
    groups: dict[tuple[CheckerId, frozenset[str], frozenset[str], str], tuple[RuleMatch, list[str]]]
    groups = {}
    for rule in rules:
        if rule.checker is None or rule.match is None or rule.disabled:
            continue
        key = (rule.checker, rule.match.preferred, rule.match.prohibited, rule.scope_dir)
        groups.setdefault(key, (rule.match, []))[1].append(rule.id)
    keys = list(groups)
    ids = [sorted(groups[key][1]) for key in keys]
    adjacent: list[list[int]] = [[] for _ in keys]
    by_checker: dict[CheckerId, list[int]] = {}
    for number, key in enumerate(keys):
        by_checker.setdefault(key[0], []).append(number)
    total = 0
    for numbers in by_checker.values():
        for a, b in combinations(numbers, 2):
            if scopes_overlap(keys[a][3], keys[b][3]) and matches_conflict(
                groups[keys[a]][0], groups[keys[b]][0]
            ):
                adjacent[a].append(b)
                adjacent[b].append(a)
                total += len(ids[a]) * len(ids[b])
    lookup = ConflictIndex(ids, adjacent)
    found: list[Conflict] = []
    group_of = {rule_id: g for g, members in enumerate(ids) for rule_id in members}
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
