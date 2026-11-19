"""Unit tests for the bounded conflict check (T-015 follow-up, I-13 C6 items 4 to 6, R2.6).

A pair evaluation compares two groups of rules that share a checker, a match and a scope. The
budget is passed in as ``max_pairs`` so that the boundary needs a handful of rules, not 5M pairs.
"""

import dataclasses
import inspect
from collections.abc import Sequence
from itertools import combinations

import pytest

from conventiondrift.model import MAX_CONFLICT_WITH, CheckerId, ConflictIndex, Rule, RuleMatch
from conventiondrift.rules.conflicts import (
    MAX_CONFLICT_PAIRS,
    MAX_SCOPE_DIR_BYTES,
    find_conflicts,
    incomplete_note,
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


def test_the_note_names_the_count() -> None:
    assert incomplete_note(5) == "conflict check stopped at the limit; 5 rules not fully checked"


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
