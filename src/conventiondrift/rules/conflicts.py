"""C6 conflict detection, DESIGN §7 step 5 and §10 S9 (T-015, held to the critical thresholds).

Two rules conflict when they map to the same checker, their scopes overlap,
and either one's ``preferred`` options meet the other's ``prohibited`` options,
or both ``preferred`` sets are non-empty and disjoint (D-PM-05 #5, S9). So
"Use logging, not print" and "Never use print()" do not conflict, while
"Use requests" and "Never use requests" do (AC-E.21), as do "Use requests" in
the root file and "Use httpx" in a subfolder file (AC-E.4).

A rule with no checker, no match, or a disabled checker never conflicts: it is
not evaluated (AC-F3.14), so a conflict naming it would point at nothing.

Work is bounded (SECURITY-RULES R2.6): rules are grouped by checker, match and
scope, so non-conflicting rules cost nothing per pair, and at most
``MAX_CONFLICTS`` conflicts are returned. ``find_conflicts`` counts the rest,
so the caller can list them.
"""

from collections.abc import Sequence
from itertools import combinations, islice, product
from typing import Final, NamedTuple

from conventiondrift.model import CheckerId, Conflict, Rule, RuleMatch

__all__ = ["MAX_CONFLICTS", "Conflicts", "find_conflicts", "matches_conflict", "scopes_overlap"]

MAX_CONFLICTS: Final = 1_000
"""R2.6: conflicts returned per run; the rest are counted in ``Conflicts.dropped``."""


_Key = tuple[frozenset[str], frozenset[str], str]
"""A rule's ``preferred``, ``prohibited`` and ``scope_dir``."""


class Conflicts(NamedTuple):
    """``found`` sorted by (rule ids, checker); ``dropped`` is how many the cap cut."""

    found: tuple[Conflict, ...]
    dropped: int


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
    """Every conflicting pair among ``rules`` (at most ``MAX_CONFLICTS``), sorted."""
    # checker -> (preferred, prohibited, scope) -> (a match with those sets, rule ids in order).
    # Specificity is not part of the key: it doesn't matter here.
    groups: dict[CheckerId, dict[_Key, tuple[RuleMatch, list[str]]]] = {}
    for rule in rules:
        if rule.checker is None or rule.match is None or rule.disabled:
            continue
        key = (rule.match.preferred, rule.match.prohibited, rule.scope_dir)
        group = groups.setdefault(rule.checker, {})
        group.setdefault(key, (rule.match, []))[1].append(rule.id)
    found: list[Conflict] = []
    total = 0
    for checker in sorted(groups):
        for (key_a, (match_a, ids_a)), (key_b, (match_b, ids_b)) in combinations(
            groups[checker].items(), 2
        ):
            if not (scopes_overlap(key_a[2], key_b[2]) and matches_conflict(match_a, match_b)):
                continue
            total += len(ids_a) * len(ids_b)
            for id_a, id_b in islice(product(ids_a, ids_b), MAX_CONFLICTS - len(found)):
                low, high = sorted((id_a, id_b))
                found.append(Conflict(rules=(low, high), checker=checker))
    found.sort(key=lambda c: (c.rules, c.checker))
    return Conflicts(found=tuple(found), dropped=total - len(found))
