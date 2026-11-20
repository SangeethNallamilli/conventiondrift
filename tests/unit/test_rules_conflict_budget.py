"""Unit tests for the bounded conflict check (T-015 follow-up, I-13 C6 items 4 to 6, R2.6).

A pair evaluation compares two groups of rules that share a checker, a match and a scope. The
budget is passed in as ``max_pairs`` so that the boundary needs a handful of rules, not 5M pairs.
"""

import dataclasses
import inspect
from collections.abc import Sequence
from itertools import combinations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conventiondrift.model import MAX_CONFLICT_WITH, CheckerId, ConflictIndex, Rule, RuleMatch
from conventiondrift.rules.conflicts import (
    MAX_CONFLICT_PAIRS,
    MAX_CONFLICTS,
    MAX_SCOPE_DIR_BYTES,
    find_conflicts,
    incomplete_note,
    matches_conflict,
    scopes_overlap,
)

HTTP: CheckerId = "http-client"
LOGGING: CheckerId = "logging"
MONEY: CheckerId = "money"


def _rule(n: int, checker: CheckerId = HTTP, scope: str = "", option: str | None = None) -> Rule:
    # Every rule has its own preferred option, so every two rules of a checker conflict, and
    # every rule is its own group: pairs of groups are pairs of rules.
    name = f"f{n:03}.md"
    return Rule(
        id=f"{name}:1",
        file=name,
        line=1,
        also_at=(),
        text="t",
        normalized_text="t",
        checker=checker,
        match=RuleMatch(frozenset({option or f"opt{n:03}"}), frozenset(), 1),
        scope_dir=scope,
        ignored=False,
        disabled=False,
    )


def _orders(rules: Sequence[Rule]) -> list[list[Rule]]:
    """Fixed reorderings: reversed, rotated, and interleaved odd/even."""
    items = list(rules)
    rotated = [items[n:] + items[:n] for n in (1, 3, 5)]
    return [items[::-1], *rotated, items[1::2] + items[0::2]]


def _ids(rules: Sequence[Rule]) -> list[str]:
    return sorted(r.id for r in rules)


def _pairs(count: int) -> int:
    return count * (count - 1) // 2


def test_the_budget_is_five_million_and_is_the_default() -> None:
    assert MAX_CONFLICT_PAIRS == 5_000_000
    assert inspect.signature(find_conflicts).parameters["max_pairs"].default == MAX_CONFLICT_PAIRS


def test_exactly_the_budget_checks_every_rule() -> None:
    rules = [_rule(n) for n in range(7)]
    budget = _pairs(len(rules))
    lookup = find_conflicts(rules, max_pairs=budget).lookup
    assert lookup.incomplete == 0
    assert not any(lookup.is_incomplete(r.id) for r in rules)
    assert all(lookup.total(r.id) == len(rules) - 1 for r in rules)
    assert lookup == find_conflicts(rules).lookup


def test_one_more_pair_than_the_budget_leaves_the_last_two_rules_incomplete() -> None:
    rules = [_rule(n) for n in range(7)]
    budget = _pairs(len(rules)) - 1
    result = find_conflicts(rules, max_pairs=budget)
    lookup = result.lookup
    # Pairs run in sorted order, so the one left out is the last: the two highest ids.
    last_two = _ids(rules)[-2:]
    assert [r.id for r in rules if lookup.is_incomplete(r.id)] == last_two
    assert lookup.incomplete == 2
    for rule in rules:
        total = lookup.total(rule.id)
        partners = lookup.partners(rule.id)
        assert total >= len(partners)
        assert list(partners) == sorted(partners)
        # Complete rules are exact; incomplete ones lack exactly the pair that was not run.
        assert total == (len(rules) - 2 if rule.id in last_two else len(rules) - 1)
    assert last_two[1] not in lookup.partners(last_two[0])
    assert last_two[0] not in lookup.partners(last_two[1])


def test_the_listing_and_the_unlisted_count_cover_only_the_evaluated_pairs() -> None:
    rules = [_rule(n) for n in range(7)]
    budget = _pairs(len(rules)) - 1
    result = find_conflicts(rules, max_pairs=budget)
    assert len(result.found) + result.unlisted == budget
    assert find_conflicts(rules).unlisted == 0
    assert len(find_conflicts(rules).found) == budget + 1


def test_partners_are_the_first_twenty_sorted_and_total_counts_all() -> None:
    rules = [_rule(n) for n in range(MAX_CONFLICT_WITH + 5)]
    shuffled = _orders(rules)[3]
    for max_pairs in (MAX_CONFLICT_PAIRS, _pairs(len(rules)) - 1):
        lookup = find_conflicts(shuffled, max_pairs=max_pairs).lookup
        first = rules[0].id
        others = _ids([r for r in rules if r.id != first])
        assert lookup.partners(first) == tuple(others[:MAX_CONFLICT_WITH])
        assert len(lookup.partners(first)) == MAX_CONFLICT_WITH
        assert lookup.total(first) == len(others) > MAX_CONFLICT_WITH
        for rule in rules:
            assert lookup.total(rule.id) >= len(lookup.partners(rule.id))
            assert len(lookup.partners(rule.id)) <= MAX_CONFLICT_WITH


def test_a_budget_of_zero_leaves_every_rule_that_has_a_pair_incomplete() -> None:
    rules = [_rule(0), _rule(1), _rule(2, LOGGING), _rule(3, LOGGING), _rule(4, MONEY)]
    lookup = find_conflicts(rules, max_pairs=0).lookup
    assert [r.id for r in rules if lookup.is_incomplete(r.id)] == _ids(rules[:4])
    assert lookup.incomplete == 4
    assert [lookup.total(r.id) for r in rules] == [0, 0, 0, 0, 0]
    # A checker with one rule has no pair, so it is checked whatever the budget.
    assert not lookup.is_incomplete(rules[4].id)


def test_the_budget_runs_out_in_checker_order_and_later_checkers_are_incomplete() -> None:
    http = [_rule(n) for n in range(3)]
    logging = [_rule(n, LOGGING) for n in (3, 4)]
    money = [_rule(5, MONEY)]
    rules = [*money, *logging, *http]
    assert _pairs(len(http)) == 3
    # The http-client rules use the whole budget; "logging" sorts after "http-client".
    lookup = find_conflicts(rules, max_pairs=3).lookup
    assert [r.id for r in rules if lookup.is_incomplete(r.id)] == _ids(logging)
    assert [lookup.total(r.id) for r in http] == [2, 2, 2]
    # One more evaluation finishes "logging" (one pair) and nothing is incomplete.
    assert find_conflicts(rules, max_pairs=4).lookup.incomplete == 0


def test_a_stop_inside_a_checker_leaves_the_rules_with_pairs_left_incomplete() -> None:
    rules = [_rule(n) for n in range(4)]
    ids = _ids(rules)
    # Pairs in order: (0,1) (0,2) (0,3) (1,2) (1,3) (2,3).
    lookup = find_conflicts(rules, max_pairs=3).lookup
    # Rule 0 has all its pairs, but 1, 2 and 3 still have some.
    assert [i for i in ids if lookup.is_incomplete(i)] == ids[1:]
    assert lookup.total(ids[0]) == 3
    lookup = find_conflicts(rules, max_pairs=4).lookup
    assert [i for i in ids if lookup.is_incomplete(i)] == ids[1:]
    lookup = find_conflicts(rules, max_pairs=5).lookup
    assert [i for i in ids if lookup.is_incomplete(i)] == ids[2:]
    assert [lookup.total(i) for i in ids] == [3, 3, 2, 2]


def test_stopping_at_a_pair_that_would_have_been_the_first_of_a_row() -> None:
    rules = [_rule(n) for n in range(3)]
    ids = _ids(rules)
    # Pairs: (0,1) (0,2) (1,2). After two, only (1,2) is left: rule 0 is complete.
    lookup = find_conflicts(rules, max_pairs=2).lookup
    assert [i for i in ids if lookup.is_incomplete(i)] == ids[1:]
    assert [lookup.total(i) for i in ids] == [2, 1, 1]


@pytest.mark.parametrize("max_pairs", [0, 1, 5, 9, 14, 20])
def test_reordering_the_rules_does_not_change_the_cutoff(max_pairs: int) -> None:
    rules = [_rule(n, LOGGING if n % 3 == 0 else HTTP) for n in range(14)]
    expected = find_conflicts(rules, max_pairs=max_pairs)
    for order in _orders(rules):
        got = find_conflicts(order, max_pairs=max_pairs)
        assert got == expected
        assert got.lookup == expected.lookup


def test_rules_that_share_a_group_cost_one_evaluation() -> None:
    # Ten rules with one match and scope are one group; against one other group that is one pair.
    same = [_rule(n, option="a") for n in range(10)]
    other = _rule(10, option="b")
    lookup = find_conflicts([*same, other], max_pairs=1).lookup
    assert lookup.incomplete == 0
    assert lookup.total(other.id) == len(same)
    assert all(lookup.total(r.id) == 1 for r in same)
    assert find_conflicts([*same, other], max_pairs=0).lookup.incomplete == len(same) + 1


def test_a_scope_of_exactly_the_longest_size_is_compared_and_one_byte_more_is_not() -> None:
    longest = "d" * MAX_SCOPE_DIR_BYTES
    here = find_conflicts([_rule(0, scope=longest), _rule(1)]).lookup
    assert here.incomplete == 0
    assert here.total("f000.md:1") == 1

    too_long = _rule(0, scope=longest + "d")
    there = find_conflicts([too_long, _rule(1)]).lookup
    assert there.is_incomplete(too_long.id)
    assert not there.is_incomplete("f001.md:1")
    assert there.incomplete == 1
    assert there.partners(too_long.id) == ()
    assert there.total(too_long.id) == 0
    assert there.total("f001.md:1") == 0


def test_the_scope_size_is_counted_in_bytes_not_characters() -> None:
    each = len("é".encode())
    fits = "é" * (MAX_SCOPE_DIR_BYTES // each)
    over = fits + "é"
    assert len(over) < MAX_SCOPE_DIR_BYTES < len(over.encode())
    assert find_conflicts([_rule(0, scope=fits), _rule(1)]).lookup.incomplete == 0
    assert find_conflicts([_rule(0, scope=over), _rule(1)]).lookup.incomplete == 1


def test_a_rule_with_no_checker_is_never_incomplete() -> None:
    plain = Rule(
        id="x.md:1",
        file="x.md",
        line=1,
        also_at=(),
        text="t",
        normalized_text="t",
        checker=None,
        match=None,
        scope_dir="d" * (MAX_SCOPE_DIR_BYTES + 1),
        ignored=False,
        disabled=False,
    )
    assert find_conflicts([plain], max_pairs=0).lookup.incomplete == 0


def test_a_repeated_rule_id_is_an_error_not_an_empty_result() -> None:
    rule = _rule(0)
    with pytest.raises(ValueError, match=r"^rule ids must be unique$"):
        find_conflicts([rule, rule])
    clash = dataclasses.replace(_rule(1), id=rule.id)
    with pytest.raises(ValueError, match=r"^rule ids must be unique$"):
        find_conflicts([rule, clash])


@pytest.mark.parametrize("count", [1, 2, 5, MAX_CONFLICT_WITH + 1])
def test_the_note_names_the_count_and_says_rule_for_exactly_one(count: int) -> None:
    noun = "rule" if count == 1 else "rules"
    assert incomplete_note(count) == (
        f"conflict check stopped at the limit; {count} {noun} not fully checked"
    )
    # The literal wording, for the two forms the contract pins.
    assert incomplete_note(1) == "conflict check stopped at the limit; 1 rule not fully checked"
    assert incomplete_note(5) == "conflict check stopped at the limit; 5 rules not fully checked"


def test_the_note_uses_the_count_of_incomplete_rules_one_and_many() -> None:
    one = [_rule(0), _rule(1, scope="d" * (MAX_SCOPE_DIR_BYTES + 1))]
    assert find_conflicts(one).lookup.incomplete == 1
    many = [_rule(n, scope="d" * (MAX_SCOPE_DIR_BYTES + 1)) for n in range(3)]
    lookups = [find_conflicts(one).lookup, find_conflicts(many).lookup]
    assert [incomplete_note(x.incomplete) for x in lookups] == [
        "conflict check stopped at the limit; 1 rule not fully checked",
        "conflict check stopped at the limit; 3 rules not fully checked",
    ]


def test_a_complete_check_is_a_value_independent_of_how_it_was_built() -> None:
    rules = [_rule(n) for n in range(5)]
    first = find_conflicts(rules).lookup
    again = find_conflicts(list(reversed(rules))).lookup
    assert first == again
    assert hash(first) == hash(again)
    assert isinstance(first, ConflictIndex)
    assert first != find_conflicts(rules[:4]).lookup
    assert all(first.total(a.id) == len(rules) - 1 for a, _ in combinations(rules, 2))


def test_a_rule_that_is_skipped_does_not_end_the_scan() -> None:
    # Rules the check leaves out come first, so a scan that stopped at them would see no conflict.
    unmapped = dataclasses.replace(_rule(0), checker=None, match=None)
    off = dataclasses.replace(_rule(1), disabled=True)
    too_long = _rule(2, scope="d" * (MAX_SCOPE_DIR_BYTES + 1))
    lookup = find_conflicts([unmapped, off, too_long, _rule(3), _rule(4)]).lookup
    assert lookup.partners("f003.md:1") == ("f004.md:1",)
    assert lookup.total("f004.md:1") == 1
    assert lookup.incomplete == 1


def test_after_the_budget_runs_out_every_later_checker_with_pairs_is_incomplete() -> None:
    first = [_rule(n) for n in range(3)]
    later = [_rule(n, LOGGING) for n in (3, 4)] + [_rule(n, MONEY) for n in (5, 6)]
    lookup = find_conflicts([*later, *first], max_pairs=2).lookup
    assert [r.id for r in [*first, *later] if lookup.is_incomplete(r.id)] == _ids(
        [*first[1:], *later]
    )


# --- group order and group-pair boundaries (I-13 C6 item 8) -------------------------------


def test_groups_run_in_sorted_key_order_not_in_id_order() -> None:
    # Ids f000 < f001 < f002, but the keys sort a (f001), m (f002), z (f000).
    rules = [_rule(0, option="z"), _rule(1, option="a"), _rule(2, option="m")]
    # Pairs in key order: (a, m), (a, z), (m, z). Two run; (m, z) is left.
    lookup = find_conflicts(rules, max_pairs=2).lookup
    assert [r.id for r in rules if lookup.is_incomplete(r.id)] == ["f000.md:1", "f002.md:1"]


def test_groups_with_one_match_run_in_scope_order() -> None:
    near = _rule(0, scope="b", option="x")
    far = _rule(1, scope="a", option="x")
    other = _rule(2, scope="a", option="y")
    # Keys: (x, scope a) = far, (x, scope b) = near, (y, scope a) = other, in that order:
    # the pairs are (far, near), (far, other), (near, other).
    lookup = find_conflicts([near, far, other], max_pairs=2).lookup
    assert [r.id for r in (near, far, other) if lookup.is_incomplete(r.id)] == [near.id, other.id]


def test_prohibited_options_are_part_of_the_group_key() -> None:
    plain = _rule(0, option="x")
    banned = dataclasses.replace(
        _rule(1, option="x"), match=RuleMatch(frozenset({"x"}), frozenset({"y"}), 1)
    )
    # Same checker, preferred and scope, but not the same group: two groups, one pair.
    assert find_conflicts([plain, banned], max_pairs=1).lookup.incomplete == 0
    assert find_conflicts([plain, banned], max_pairs=0).lookup.incomplete == 2


def _sized_groups() -> tuple[list[Rule], list[list[Rule]]]:
    sizes = (3, 2, MAX_CONFLICT_WITH + 5, 1)
    groups: list[list[Rule]] = []
    number = 0
    for size, option in zip(sizes, "abcd", strict=True):
        groups.append([_rule(number + n, option=option) for n in range(size)])
        number += size
    return [r for group in groups for r in group], groups


def test_the_budget_counts_group_pairs_exactly_at_the_limit() -> None:
    rules, groups = _sized_groups()
    group_pairs = _pairs(len(groups))
    assert group_pairs < len(rules)  # rule pairs would be far more
    lookup = find_conflicts(rules, max_pairs=group_pairs).lookup
    assert lookup.incomplete == 0
    for group in groups:
        for rule in group:
            assert lookup.total(rule.id) == len(rules) - len(group)  # exact
            assert lookup.total(rule.id) >= len(lookup.partners(rule.id))
            assert len(lookup.partners(rule.id)) <= MAX_CONFLICT_WITH
            assert list(lookup.partners(rule.id)) == sorted(lookup.partners(rule.id))


def test_the_budget_counts_group_pairs_one_more_than_the_limit() -> None:
    rules, groups = _sized_groups()
    lookup = find_conflicts(rules, max_pairs=_pairs(len(groups)) - 1).lookup
    # The last group pair, (c, d), was not evaluated: every member of both is incomplete.
    left_out = {r.id for r in groups[2] + groups[3]}
    assert {r.id for r in rules if lookup.is_incomplete(r.id)} == left_out
    assert lookup.incomplete == len(left_out) == MAX_CONFLICT_WITH + 6
    for group in groups:
        for rule in group:
            partners = lookup.partners(rule.id)
            assert lookup.total(rule.id) >= len(partners)
            assert len(partners) <= MAX_CONFLICT_WITH
            assert list(partners) == sorted(partners)
    exact = [rule.id for rule in groups[0] + groups[1]]
    assert [lookup.total(i) for i in exact] == [len(rules) - 3] * 3 + [len(rules) - 2] * 2
    # A "c" member lacks the "d" rule (a lower bound); the "d" rule lacks the 25 "c" rules.
    assert lookup.total(groups[2][0].id) == len(rules) - len(groups[2]) - 1
    assert lookup.total(groups[3][0].id) == len(groups[0]) + len(groups[1])


# --- the grouped index against a literal rule-pair reference -------------------------------

_BRUTE_CHECKERS: tuple[CheckerId, ...] = (HTTP, LOGGING)
_BRUTE_SCOPES = ("", "a", "a/b", "c", "d" * (MAX_SCOPE_DIR_BYTES + 1))
_OPTIONS = ("x", "y", "z")


@st.composite
def _brute_rules(draw: st.DrawFn) -> list[Rule]:
    count = draw(st.integers(0, 14))
    rules: list[Rule] = []
    for n in range(count):
        preferred = frozenset(draw(st.sets(st.sampled_from(_OPTIONS))))
        prohibited = frozenset(draw(st.sets(st.sampled_from(_OPTIONS)))) - preferred
        match = RuleMatch(preferred, prohibited, 1) if preferred | prohibited else None
        rules.append(
            dataclasses.replace(
                _rule(n),
                checker=draw(st.sampled_from([*_BRUTE_CHECKERS, None])),
                match=match,
                scope_dir=draw(st.sampled_from(_BRUTE_SCOPES)),
                disabled=draw(st.booleans()) and draw(st.booleans()),
            )
        )
    return rules


def _evaluated(rule: Rule) -> bool:
    """Whether the check looks at the rule at all (the over-long scope is the backstop)."""
    return (
        rule.checker is not None
        and rule.match is not None
        and not rule.disabled
        and len(rule.scope_dir.encode()) <= MAX_SCOPE_DIR_BYTES
    )


def _too_long(rule: Rule) -> bool:
    return (
        rule.checker is not None
        and rule.match is not None
        and not rule.disabled
        and not _evaluated(rule)
    )


class _Reference:
    """A literal rule-pair reference for ``find_conflicts`` under a group-pair budget.

    Groups are keyed by hand, run in the order I-13 C6 item 8 gives (sorted key, then pairs
    in that order), and each evaluated group pair is decided by testing every pair of rules
    in it, so nothing here relies on groups conflicting identically.
    """

    def __init__(self, rules: Sequence[Rule], budget: int) -> None:
        keyed: dict[tuple[str, tuple[str, ...], tuple[str, ...], str], list[Rule]] = {}
        for rule in rules:
            if _evaluated(rule):
                assert rule.match is not None and rule.checker is not None
                key = (
                    rule.checker,
                    tuple(sorted(rule.match.preferred)),
                    tuple(sorted(rule.match.prohibited)),
                    rule.scope_dir,
                )
                keyed.setdefault(key, []).append(rule)
        groups = [keyed[key] for key in sorted(keyed)]
        pairs = [
            (i, j)
            for i in range(len(groups))
            for j in range(i + 1, len(groups))
            if groups[i][0].checker == groups[j][0].checker
        ]
        self.partners: dict[str, list[str]] = {r.id: [] for g in groups for r in g}
        self.incomplete = {r.id for r in rules if _too_long(r)}
        for i, j in pairs[:budget]:
            for a in groups[i]:
                for b in groups[j]:
                    assert a.match is not None and b.match is not None
                    if scopes_overlap(a.scope_dir, b.scope_dir) and matches_conflict(
                        a.match, b.match
                    ):
                        self.partners[a.id].append(b.id)
                        self.partners[b.id].append(a.id)
        for i, j in pairs[budget:]:
            self.incomplete.update(r.id for r in groups[i] + groups[j])
        self.pairs = sorted((a, b) for a, others in self.partners.items() for b in others if a < b)
        self.checker = {r.id: r.checker for r in rules}


BUDGETS = (0, 1, 2, 5, 13, 40, MAX_CONFLICT_PAIRS)


def _assert_matches(rules: Sequence[Rule], budget: int) -> tuple[list[int], dict[str, int]]:
    expected = _Reference(rules, budget)
    result = find_conflicts(rules, max_pairs=budget)
    lookup = result.lookup
    for rule in rules:
        partners = sorted(expected.partners.get(rule.id, []))
        assert lookup.partners(rule.id) == tuple(partners[:MAX_CONFLICT_WITH])
        assert lookup.total(rule.id) == len(partners)
        assert lookup.total(rule.id) >= len(lookup.partners(rule.id))
        assert lookup.is_incomplete(rule.id) == (rule.id in expected.incomplete)
    assert lookup.incomplete == len(expected.incomplete)
    assert [c.rules for c in result.found] == expected.pairs[:MAX_CONFLICTS]
    assert all(c.checker == expected.checker[c.rules[0]] for c in result.found)
    assert result.unlisted == len(expected.pairs) - len(result.found)
    return [lookup.incomplete], {r.id: lookup.total(r.id) for r in rules}


@given(_brute_rules(), st.data())
def test_the_grouped_index_equals_a_rule_pair_reference(
    rules: list[Rule], data: st.DataObject
) -> None:
    previous_incomplete = len(rules) + 1
    previous_totals: dict[str, int] = {r.id: 0 for r in rules}
    shuffled = data.draw(st.permutations(rules))
    for budget in BUDGETS:
        (incomplete,), totals = _assert_matches(rules, budget)
        # The input order never changes the result under a budget.
        assert find_conflicts(shuffled, max_pairs=budget) == find_conflicts(rules, max_pairs=budget)
        # A bigger budget never leaves more rules incomplete, and a total only grows.
        assert incomplete <= previous_incomplete
        assert all(totals[i] >= previous_totals[i] for i in totals)
        previous_incomplete, previous_totals = incomplete, totals
