"""Unit tests for C6 conflict detection in conventiondrift.rules.conflicts (T-015)."""

import itertools
from collections.abc import Sequence
from typing import get_args

import pytest

from conventiondrift.model import CheckerId, Conflict, Rule, RuleMatch
from conventiondrift.rules import conflicts as cf
from conventiondrift.rules.conflicts import (
    MAX_CONFLICTS,
    find_conflicts,
    matches_conflict,
    scopes_overlap,
)

CHECKER_IDS: tuple[CheckerId, ...] = get_args(CheckerId)
HTTP: CheckerId = "http-client"


def _match(
    preferred: Sequence[str] = (), prohibited: Sequence[str] = (), spec: int = 1
) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), spec)


def _rule(
    file: str,
    line: int,
    match: RuleMatch | None,
    *,
    checker: CheckerId | None = HTTP,
    scope: str = "",
    ignored: bool = False,
    disabled: bool = False,
) -> Rule:
    return Rule(
        id=f"{file}:{line}",
        file=file,
        line=line,
        also_at=(),
        text="t",
        normalized_text="t",
        checker=checker,
        match=match,
        scope_dir=scope,
        ignored=ignored,
        disabled=disabled,
    )


def _pairs(rules: Sequence[Rule]) -> list[tuple[str, str]]:
    return [c.rules for c in find_conflicts(rules).found]


# --- the conflict rule (DESIGN §7 step 5, S9) ------------------------------------------

REQUESTS = _match(["requests"])
HTTPX = _match(["httpx"])
NEVER_REQUESTS = _match([], ["requests"])


def test_ac_shape_use_requests_vs_never_use_requests_conflict() -> None:
    # AC-E.21's shape: "Use requests" (line 3) and "Never use requests" (line 8) in one file.
    rules = [_rule("AGENTS.md", 3, REQUESTS), _rule("AGENTS.md", 8, NEVER_REQUESTS)]
    assert find_conflicts(rules).found == (
        Conflict(rules=("AGENTS.md:3", "AGENTS.md:8"), checker=HTTP),
    )


def test_use_requests_vs_use_httpx_conflict_across_files() -> None:
    # AC-E.3's shape: root AGENTS.md and root CLAUDE.md name different preferred options.
    rules = [_rule("AGENTS.md", 1, REQUESTS), _rule("CLAUDE.md", 1, HTTPX)]
    assert _pairs(rules) == [("AGENTS.md:1", "CLAUDE.md:1")]


def test_root_vs_subfolder_rules_conflict() -> None:
    # AC-E.4's shape: root "Use requests" and services/billing "Use httpx".
    rules = [
        _rule("AGENTS.md", 1, REQUESTS, scope=""),
        _rule("services/billing/AGENTS.md", 1, HTTPX, scope="services/billing"),
    ]
    assert _pairs(rules) == [("AGENTS.md:1", "services/billing/AGENTS.md:1")]


def test_prefer_with_prohibited_vs_plain_prohibited_do_not_conflict() -> None:
    # "Use logging, not print" and "Never use print()" agree.
    both = _match(["logging"], ["print"])
    never_print = _match([], ["print"])
    assert _pairs([_rule("A.md", 1, both), _rule("A.md", 2, never_print)]) == []


def test_matching_preferred_options_do_not_conflict() -> None:
    assert (
        _pairs([_rule("A.md", 1, REQUESTS), _rule("A.md", 2, _match(["requests", "httpx"]))]) == []
    )


def test_identical_matches_do_not_conflict() -> None:
    assert _pairs([_rule("A.md", 1, REQUESTS), _rule("B.md", 1, REQUESTS)]) == []


def test_a_preferred_meeting_b_prohibited_conflicts_in_both_directions() -> None:
    first = _rule("A.md", 1, REQUESTS)
    second = _rule("A.md", 2, NEVER_REQUESTS)
    assert _pairs([first, second]) == [("A.md:1", "A.md:2")]
    assert _pairs([second, first]) == [("A.md:1", "A.md:2")]


def test_disjoint_preferred_conflicts_only_when_both_are_non_empty() -> None:
    # {requests} vs {httpx} conflicts. A prohibition that names another option does not.
    assert matches_conflict(REQUESTS, HTTPX)
    assert not matches_conflict(REQUESTS, _match([], ["httpx"]))
    assert not matches_conflict(_match([], ["httpx"]), _match([], ["requests"]))


def test_conflict_needs_a_non_empty_preferred_on_each_side() -> None:
    # Two pure prohibitions never conflict, and neither does one empty preferred set.
    assert not matches_conflict(_match([], ["a"]), _match([], ["b"]))
    assert not matches_conflict(_match(["a"], ["c"]), _match([], ["b"]))
    assert not matches_conflict(_match([], ["b"]), _match(["a"], ["c"]))


SAMPLE_MATCHES = (
    REQUESTS,
    HTTPX,
    NEVER_REQUESTS,
    _match(["logging"], ["print"]),
    _match(["requests", "x"]),
)


@pytest.mark.parametrize(("a", "b"), list(itertools.permutations(SAMPLE_MATCHES, 2)))
def test_matches_conflict_is_symmetric(a: RuleMatch, b: RuleMatch) -> None:
    assert matches_conflict(a, b) == matches_conflict(b, a)


@pytest.mark.parametrize(("a", "b"), list(itertools.combinations(CHECKER_IDS, 2)))
def test_rules_of_different_checkers_never_conflict(a: CheckerId, b: CheckerId) -> None:
    rules = [_rule("A.md", 1, REQUESTS, checker=a), _rule("A.md", 2, HTTPX, checker=b)]
    assert _pairs(rules) == []


@pytest.mark.parametrize("checker", CHECKER_IDS)
def test_conflict_names_the_checker(checker: CheckerId) -> None:
    rules = [_rule("A.md", 1, REQUESTS, checker=checker), _rule("A.md", 2, HTTPX, checker=checker)]
    assert find_conflicts(rules).found == (Conflict(("A.md:1", "A.md:2"), checker),)


# --- rules that never conflict ---------------------------------------------------------


def test_rules_without_checker_or_match_never_conflict() -> None:
    rules = [
        _rule("A.md", 1, REQUESTS),
        _rule("A.md", 2, HTTPX, checker=None),
        _rule("A.md", 3, None),
        _rule("A.md", 4, None, checker=None),
    ]
    assert _pairs(rules) == []


@pytest.mark.parametrize(
    "skipped",
    [
        _rule("A.md", 1, REQUESTS, checker=None),
        _rule("A.md", 1, None),
        _rule("A.md", 1, REQUESTS, disabled=True),
    ],
    ids=["no checker", "no match", "disabled"],
)
def test_a_skipped_rule_does_not_hide_the_rules_after_it(skipped: Rule) -> None:
    rules = [skipped, _rule("B.md", 1, REQUESTS), _rule("C.md", 1, HTTPX)]
    assert _pairs(rules) == [("B.md:1", "C.md:1")]


def test_disabled_rules_never_conflict() -> None:
    # A disabled rule is not evaluated (AC-F3.14), so it gets no conflict entry.
    rules = [_rule("A.md", 1, REQUESTS), _rule("A.md", 2, HTTPX, disabled=True)]
    assert find_conflicts(rules).found == ()


def test_ignored_rules_still_conflict() -> None:
    # An ignored rule gets a normal verdict and only stops counting for fail-on (S2).
    rules = [_rule("A.md", 1, REQUESTS, ignored=True), _rule("A.md", 2, HTTPX)]
    assert _pairs(rules) == [("A.md:1", "A.md:2")]


def test_no_rules_no_conflicts() -> None:
    assert find_conflicts([]) == cf.Conflicts(found=(), dropped=0)


# --- scope overlap ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "overlap"),
    [
        ("", "", True),
        ("", "services", True),
        ("services", "", True),
        ("services", "services", True),
        ("services", "services/billing", True),
        ("services/billing", "services", True),
        ("services/billing", "services/billing/api", True),
        ("services/billing", "services/orders", False),
        ("services", "services-extra", False),
        ("services-extra", "services", False),
        ("services", "web", False),
        ("a/b", "a/bc", False),
    ],
)
def test_scopes_overlap(a: str, b: str, overlap: bool) -> None:
    assert scopes_overlap(a, b) is overlap
    assert scopes_overlap(b, a) is overlap


def test_sibling_scopes_do_not_conflict() -> None:
    rules = [
        _rule("a/AGENTS.md", 1, REQUESTS, scope="a"),
        _rule("b/AGENTS.md", 1, HTTPX, scope="b"),
    ]
    assert _pairs(rules) == []


def test_nested_scope_conflicts_with_parent_but_not_with_sibling() -> None:
    rules = [
        _rule("services/AGENTS.md", 1, REQUESTS, scope="services"),
        _rule("services/billing/AGENTS.md", 1, HTTPX, scope="services/billing"),
        _rule("services/orders/AGENTS.md", 1, HTTPX, scope="services/orders"),
    ]
    assert _pairs(rules) == [
        ("services/AGENTS.md:1", "services/billing/AGENTS.md:1"),
        ("services/AGENTS.md:1", "services/orders/AGENTS.md:1"),
    ]


# --- output shape ----------------------------------------------------------------------


def test_each_pair_is_listed_once_with_sorted_ids_and_the_list_is_sorted() -> None:
    rules = [
        _rule("Z.md", 1, REQUESTS),
        _rule("B.md", 2, HTTPX),
        _rule("A.md", 9, HTTPX),
        _rule("A.md", 10, NEVER_REQUESTS),
    ]
    found = find_conflicts(rules).found
    assert [c.rules for c in found] == sorted(c.rules for c in found)
    assert len({c.rules for c in found}) == len(found)
    for conflict in found:
        assert conflict.rules == tuple(sorted(conflict.rules))
    assert ("A.md:9", "Z.md:1") in {c.rules for c in found}
    assert ("A.md:10", "Z.md:1") in {c.rules for c in found}
    # "Never use requests" and "Use httpx" name different options, so they agree.
    assert ("A.md:10", "B.md:2") not in {c.rules for c in found}
    assert ("A.md:10", "A.md:9") not in {c.rules for c in found}


def test_result_does_not_depend_on_rule_order() -> None:
    rules = [
        _rule("A.md", 1, REQUESTS),
        _rule("B.md", 1, HTTPX),
        _rule("C.md", 1, NEVER_REQUESTS),
        _rule("D.md", 1, _match(["urllib3"])),
    ]
    expected = find_conflicts(rules)
    for permutation in itertools.permutations(rules):
        assert find_conflicts(permutation) == expected


def test_the_same_id_on_both_sides_is_kept() -> None:
    # Two rules that start on one line share an id; the pair is still listed.
    rules = [_rule("A.md", 3, REQUESTS), _rule("A.md", 3, HTTPX)]
    assert _pairs(rules) == [("A.md:3", "A.md:3")]


# --- bounded work (SECURITY-RULES R2.6) --------------------------------------------------


def test_conflicts_are_capped_and_the_rest_counted() -> None:
    side = 40
    rules = [_rule(f"a{n}.md", 1, REQUESTS) for n in range(side)]
    rules += [_rule(f"b{n}.md", 1, HTTPX) for n in range(side)]
    result = find_conflicts(rules)
    assert side * side > MAX_CONFLICTS
    assert len(result.found) == MAX_CONFLICTS
    assert result.dropped == side * side - MAX_CONFLICTS
    assert [c.rules for c in result.found] == sorted(c.rules for c in result.found)


def test_exactly_the_cap_drops_nothing() -> None:
    first = [_rule(f"a{n}.md", 1, REQUESTS) for n in range(MAX_CONFLICTS)]
    result = find_conflicts([*first, _rule("b.md", 1, HTTPX)])
    assert len(result.found) == MAX_CONFLICTS
    assert result.dropped == 0
    over = find_conflicts([*first, _rule("a_extra.md", 1, REQUESTS), _rule("b.md", 1, HTTPX)])
    assert (len(over.found), over.dropped) == (MAX_CONFLICTS, 1)


def test_the_cap_holds_across_many_group_pairs() -> None:
    # Several conflicting group pairs, each below the cap but over it together.
    third = MAX_CONFLICTS // 3 + 1
    rules: list[Rule] = []
    for option in ("a", "b", "c"):
        rules += [_rule(f"{option}{n}.md", 1, _match([option])) for n in range(third)]
    result = find_conflicts(rules)
    assert len(result.found) == MAX_CONFLICTS
    assert result.dropped == 3 * third * third - MAX_CONFLICTS


def test_many_rules_with_one_match_cost_nothing_per_pair() -> None:
    # 20,000 rules in one group never compare pairwise; only distinct groups do.
    rules = [_rule(f"f{n}.md", 1, REQUESTS) for n in range(20_000)]
    assert find_conflicts(rules) == cf.Conflicts(found=(), dropped=0)
