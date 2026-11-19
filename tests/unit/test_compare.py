"""Unit tests for C10 before/after comparison (T-022; I-9, I-11 C10, DESIGN §10 B5).

Names deliberately avoid the ``test_ac_`` prefix: AC-named tests belong to the
Test Engineer. The AC or spec text each test exercises is given in a comment.
Expected values come from the spec text (D-TL-25), never from the code.
"""

import ast
import inspect
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import get_args, get_type_hints

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conventiondrift import compare as compare_module
from conventiondrift.compare import CASES, RENAME_STATUS, SUGGESTION_KINDS, compare, suggest
from conventiondrift.components import ChangedFile
from conventiondrift.model import (
    Alternative,
    CausingFile,
    Conflict,
    Counts,
    Rule,
    RuleMatch,
    RuleResult,
    SideResult,
    Site,
    SiteResult,
    Suggestion,
    Verdict,
)

# --- spec lists, typed from the documents -------------------------------------------

# I-9 `case`: "made-stale-by-code | stale-rule-added | fixed | pre-existing-stale | removed | null"
SPEC_CASES = ("made-stale-by-code", "stale-rule-added", "fixed", "pre-existing-stale", "removed")
# I-9 `suggestion.kind`: "replace | tie | remove-or-rewrite | none"
SPEC_KINDS = ("replace", "tie", "remove-or-rewrite", "none")
# I-9: "made-stale-by-code is case 1, stale-rule-added is case 2, fixed is case 3"
WARNING_CASES = {"made-stale-by-code", "stale-rule-added"}  # SPEC glossary: only cases 1 and 2 warn

S = Verdict.STALE
H = Verdict.HOLDS
C = Verdict.CONTESTED


def test_case_constant_matches_spec_list() -> None:
    assert set(CASES) == set(SPEC_CASES)
    assert len(CASES) == len(SPEC_CASES)


def test_suggestion_kinds_match_spec_list_and_model() -> None:
    assert set(SUGGESTION_KINDS) == set(SPEC_KINDS)
    assert len(SUGGESTION_KINDS) == len(SPEC_KINDS)
    assert set(get_args(get_type_hints(Suggestion)["kind"])) == set(SPEC_KINDS)


def test_public_names() -> None:
    assert set(compare_module.__all__) == {"CASES", "SUGGESTION_KINDS", "compare", "suggest"}
    for name in compare_module.__all__:
        assert hasattr(compare_module, name)


def test_rename_status_is_the_i14_letter() -> None:
    # I-14 ChangedFile: "(status letter, old path or None, new path);
    # old is non-None only for R and C"
    assert RENAME_STATUS == "R"


# --- builders -----------------------------------------------------------------------

USE_REQUESTS = RuleMatch(frozenset({"requests"}), frozenset(), 1)
USE_HTTPX = RuleMatch(frozenset({"httpx"}), frozenset(), 1)
LOGGING_NOT_PRINT = RuleMatch(frozenset({"logging"}), frozenset({"print"}), 1)
NO_PRINT = RuleMatch(frozenset(), frozenset({"print"}), 1)


def rule(
    text: str,
    *,
    file: str = "AGENTS.md",
    line: int = 1,
    match: RuleMatch | None = USE_REQUESTS,
    checker: str | None = "http-client",
    normalized: str | None = None,
) -> Rule:
    return Rule(
        id=f"{file}:{line}",
        file=file,
        line=line,
        also_at=(),
        text=text,
        normalized_text=normalized if normalized is not None else " ".join(text.lower().split()),
        checker=checker,  # type: ignore[arg-type]
        match=match,
        scope_dir="",
        ignored=False,
        disabled=False,
    )


def side(verdict: Verdict, sites: Sequence[tuple[str, int, str, bool]] = ()) -> SideResult:
    results = sorted(
        (
            SiteResult(site=Site(file=f, line=ln, col=0, option=opt), follows=fol, recent=False)
            for f, ln, opt, fol in sites
        ),
        key=lambda r: (r.site.file, r.site.line, r.site.col, r.site.option),
    )
    following = sum(r.follows for r in results)
    counts = Counts(following, len(results) - following, len(results))
    return SideResult(
        verdict=verdict,
        sites=tuple(results),
        overall=counts,
        recent=None,
        recent_unavailable_reason="no history",
    )


def sites(
    file: str, option: str, follows: bool, n: int, start: int = 1
) -> list[tuple[str, int, str, bool]]:
    return [(file, start + i, option, follows) for i in range(n)]


R1 = rule("Use requests for HTTP calls", line=9)


# I-13 C10 ruling 7: case 1 needs code, i.e. a changed file whose sites moved. A head
# side that is Stale with sites in an unchanged file (or none) has no causing files.
CODE_CHANGE: list[ChangedFile] = [("M", "src/a.py", "src/a.py")]


def head_side(verdict: Verdict) -> SideResult:
    """A head side whose sites sit in the changed file ``src/a.py`` (base has no sites)."""
    return side(verdict, sites("src/a.py", "httpx", False, 3))


def only(results: tuple[RuleResult, ...]) -> RuleResult:
    assert len(results) == 1
    return results[0]


# --- cases: same rule on both sides (brief §7.5, F5, D-PM-05 #3) --------------------


def _expected_same_rule(base: Verdict, head: Verdict) -> str | None:
    # Brief §7.5 / SPEC F5 text: case 1 "verdict changes to Stale"; case 3 "Stale at base
    # is no longer Stale at head"; "already Stale before the PR and unchanged" is
    # pre-existing; anything else is not a case.
    if base is S and head is S:
        return "pre-existing-stale"
    if base is S:
        return "fixed"
    if head is S:
        return "made-stale-by-code"
    return None


@pytest.mark.parametrize("base_v", list(Verdict))
@pytest.mark.parametrize("head_v", list(Verdict))
def test_same_rule_case_for_every_verdict_pair(base_v: Verdict, head_v: Verdict) -> None:
    got = only(compare([(R1, side(base_v))], [(R1, head_side(head_v))], CODE_CHANGE))
    assert got.case == _expected_same_rule(base_v, head_v)
    assert got.base_rule == R1 and got.head_rule == R1


@pytest.mark.parametrize("head_v", list(Verdict))
def test_head_only_rule_is_case_2_only_when_stale(head_v: Verdict) -> None:
    # Case 2: "The PR adds or edits a rule that the code contradicts" (Stale at head).
    got = only(compare([], [(R1, side(head_v))], [("M", "AGENTS.md", "AGENTS.md")]))
    assert got.case == ("stale-rule-added" if head_v is S else None)
    assert got.base_rule is None and got.base is None


@pytest.mark.parametrize("base_v", list(Verdict))
def test_base_only_rule_is_fixed_when_stale_else_removed(base_v: Verdict) -> None:
    # D-PM-05 #3/#4: a deleted base-Stale rule is fixed; other rules are "removed".
    got = only(compare([(R1, side(base_v))], [], [("D", None, "AGENTS.md")]))
    assert got.case == ("fixed" if base_v is S else "removed")
    assert got.head_rule is None and got.head is None
    assert got.base == side(base_v)  # I-9: a removed rule still reports its base side
    assert got.rule_id == R1.id


@pytest.mark.parametrize("v", list(Verdict))
def test_no_base_means_no_cases(v: Verdict) -> None:
    # Head-only and scan modes: no comparison, so no case (I-9 `base` is null).
    got = only(compare(None, [(R1, side(v, sites("a.py", "httpx", False, 5)))], []))
    assert got.case is None
    assert got.causing_files == ()
    assert got.base is None


def test_every_case_value_is_reachable() -> None:
    seen: set[str | None] = set()
    for b in Verdict:
        for h in Verdict:
            seen.add(only(compare([(R1, side(b))], [(R1, head_side(h))], CODE_CHANGE)).case)
        seen.add(only(compare([], [(R1, side(b))], [])).case)
        seen.add(only(compare([(R1, side(b))], [], [])).case)
    assert seen == set(CASES) | {None}


# --- AC scenarios -------------------------------------------------------------------


def _f5_1_sides() -> tuple[SideResult, SideResult]:
    # AC-F5.1: 40 HTTP sites, 3 requests at base (Contested via recent 40%); the PR
    # replaces the 3 requests sites in src/api/client.py with httpx: 0 of 40 at head.
    base = side(
        C, sites("src/api/client.py", "requests", True, 3) + sites("src/x.py", "httpx", False, 37)
    )
    head = side(
        S, sites("src/api/client.py", "httpx", False, 3) + sites("src/x.py", "httpx", False, 37)
    )
    return base, head


def test_f5_1_case_1_causing_file_and_replacement() -> None:
    base, head = _f5_1_sides()
    got = only(
        compare([(R1, base)], [(R1, head)], [("M", "src/api/client.py", "src/api/client.py")])
    )
    assert got.case == "made-stale-by-code"
    # AC-F6.3 #5: causing file src/api/client.py; "removed in src/api/client.py".
    assert got.causing_files == (CausingFile("src/api/client.py", -3, 3),)
    # AC-F6.3 #7: "- Use requests for HTTP calls" / "+ Use httpx for HTTP calls".
    assert got.suggestion.kind == "replace"
    assert got.suggestion.named_option == "requests"
    assert got.suggestion.new_text == "Use httpx for HTTP calls"
    assert got.suggestion.alternatives == (Alternative("httpx", 40),)


def test_f5_4_only_the_pr_caused_rule_has_a_case() -> None:
    # AC-F5.4: R Contested at base (and head), S Holds -> Stale because of code.
    r = rule("Use requests for HTTP calls", line=3)
    s_rule = rule("Use logging, not print.", line=5, match=LOGGING_NOT_PRINT, checker="logging")
    out = compare(
        [(r, side(C)), (s_rule, side(H))],
        [(r, side(C)), (s_rule, side(S, sites("src/app.py", "print", False, 2)))],
        [("M", "docs/guide.md", "docs/guide.md"), ("M", "src/app.py", "src/app.py")],
    )
    by_id = {x.rule_id: x for x in out}
    assert by_id[r.id].case is None
    assert by_id[s_rule.id].case == "made-stale-by-code"


def test_f5_6_three_pre_existing_plus_one_pr_caused() -> None:
    # AC-F5.6: 3 rules Stale at base and still Stale with unchanged text, plus 1 PR-caused.
    pre = [rule(f"Use requests for thing {i}", line=i) for i in range(1, 4)]
    new = rule("Use requests for HTTP calls", line=9)
    out = compare(
        [(p, side(S)) for p in pre] + [(new, side(C))],
        [(p, side(S)) for p in pre] + [(new, side(S))],
        [("M", "src/a.py", "src/a.py")],
    )
    assert sum(x.case == "pre-existing-stale" for x in out) == 3
    assert [x.rule_id for x in out if x.case in WARNING_CASES] == [new.id]


def test_f5_3a_text_replaced_with_suggestion_that_holds_is_fixed() -> None:
    # AC-F5.3 (a): the PR replaces the Stale rule's text with the suggested wording, which Holds.
    old = rule("Use requests for HTTP calls", line=9)
    new = rule("Use httpx for HTTP calls", line=9, match=USE_HTTPX)
    out = compare([(old, side(S))], [(new, side(H))], [("M", "AGENTS.md", "AGENTS.md")])
    cases = {(x.base_rule is not None, x.head_rule is not None): x.case for x in out}
    assert cases == {(True, False): "fixed", (False, True): None}
    assert not [x for x in out if x.case in WARNING_CASES]


def test_f5_3b_code_change_makes_rule_hold_is_fixed() -> None:
    # AC-F5.3 (b): code changes so the rule Holds at head.
    got = only(compare([(R1, side(S))], [(R1, side(H))], [("M", "src/a.py", "src/a.py")]))
    assert got.case == "fixed"


def test_deleted_stale_rule_replaced_by_a_stale_rule_is_not_fixed() -> None:
    # D-PM-05 #3: "deleted or replaced in the PR, with no Stale rule replacing it, counts as fixed".
    old = rule("Use requests for HTTP calls", line=9)
    new = rule("Use requests for all HTTP calls", line=9)
    out = compare([(old, side(S))], [(new, side(S))], [("M", "AGENTS.md", "AGENTS.md")])
    cases = {(x.base_rule is not None, x.head_rule is not None): x.case for x in out}
    assert cases == {(True, False): "removed", (False, True): "stale-rule-added"}


@pytest.mark.parametrize(
    "new",
    [
        rule(
            "Use logging",
            line=9,
            match=RuleMatch(frozenset({"logging"}), frozenset(), 1),
            checker="logging",
        ),
        rule("Use requests for HTTP calls everywhere", file="CLAUDE.md", line=9),
    ],
    ids=["other-checker", "other-file"],
)
def test_stale_new_rule_elsewhere_does_not_block_fixed(new: Rule) -> None:
    out = compare([(R1, side(S))], [(new, side(S))], [])
    assert {x.rule_id: x.case for x in out if x.head_rule is None} == {R1.id: "fixed"}


def test_head_rule_not_stale_does_not_block_fixed() -> None:
    new = rule("Use requests for all HTTP calls", line=9)
    out = compare([(R1, side(S))], [(new, side(C))], [])
    assert {x.case for x in out} == {"fixed", None}


def test_e8_rename_only_pr_changes_nothing() -> None:
    # AC-E.8: renames/moves of Python files, identical content, same scope:
    # no comment and every rule's counts unchanged.
    base = side(C, sites("src/old.py", "requests", True, 3) + sites("src/x.py", "httpx", False, 5))
    head = side(C, sites("src/new.py", "requests", True, 3) + sites("src/x.py", "httpx", False, 5))
    got = only(compare([(R1, base)], [(R1, head)], [("R", "src/old.py", "src/new.py")]))
    assert got.case is None
    assert got.causing_files == ()
    assert got.base is not None and got.head is not None
    assert got.base.overall == got.head.overall


def test_e8_instruction_file_rename_keeps_rule_identity() -> None:
    # SPEC glossary "Same rule": same instruction file (renames followed) and same text.
    moved = replace(R1, id="CLAUDE.md:9", file="CLAUDE.md")
    got = only(compare([(R1, side(S))], [(moved, side(S))], [("R", "AGENTS.md", "CLAUDE.md")]))
    assert got.case == "pre-existing-stale"
    assert got.base_rule == R1 and got.head_rule == moved
    assert got.rule_id == "CLAUDE.md:9"


def test_without_the_rename_a_moved_file_is_a_new_rule() -> None:
    # No R entry: AGENTS.md was deleted (D-PM-05 #4: its Stale rule is fixed) and
    # CLAUDE.md is a new file whose Stale rule is case 2.
    moved = replace(R1, id="CLAUDE.md:9", file="CLAUDE.md")
    out = compare(
        [(R1, side(S))],
        [(moved, side(S))],
        [("D", None, "AGENTS.md"), ("A", None, "CLAUDE.md")],
    )
    assert {x.rule_id: x.case for x in out} == {
        "AGENTS.md:9": "fixed",
        "CLAUDE.md:9": "stale-rule-added",
    }


def test_copy_is_not_a_rename() -> None:
    copied = replace(R1, id="CLAUDE.md:9", file="CLAUDE.md")
    out = compare(
        [(R1, side(S))], [(R1, side(S)), (copied, side(S))], [("C", "AGENTS.md", "CLAUDE.md")]
    )
    by_id = {x.rule_id: x.case for x in out}
    assert by_id == {"AGENTS.md:9": "pre-existing-stale", "CLAUDE.md:9": "stale-rule-added"}


def test_a_new_file_at_a_renamed_away_path_is_new() -> None:
    # AGENTS.md -> CLAUDE.md, and a new AGENTS.md with the same text: the base rule
    # follows the rename, the new AGENTS.md rule is new.
    moved = replace(R1, id="CLAUDE.md:9", file="CLAUDE.md")
    out = compare(
        [(R1, side(C))],
        [(R1, side(S)), (moved, side(C))],
        [("R", "AGENTS.md", "CLAUDE.md"), ("A", None, "AGENTS.md")],
    )
    by_id = {x.rule_id: (x.base_rule is not None, x.case) for x in out}
    assert by_id == {"AGENTS.md:9": (False, "stale-rule-added"), "CLAUDE.md:9": (True, None)}


def test_e9_move_out_of_scope_contested_to_holds_is_no_case() -> None:
    # AC-E.9: services/billing/client.py (3 requests) moves to shared/client.py, out of
    # the rule's scope. Contested (7/10) -> Holds (7/7): neither case 1, 2 nor 3.
    r = rule("Use httpx for HTTP calls", file="services/billing/CLAUDE.md", line=2, match=USE_HTTPX)
    base = side(
        C,
        sites("services/billing/client.py", "requests", False, 3)
        + sites("services/billing/a.py", "httpx", True, 7),
    )
    head = side(H, sites("services/billing/a.py", "httpx", True, 7))
    got = only(
        compare([(r, base)], [(r, head)], [("R", "services/billing/client.py", "shared/client.py")])
    )
    assert got.case is None
    assert got.head is not None and got.head.overall == Counts(7, 0, 7)
    # The moved file's 3 sites left the rule's scope: it is the file that caused the change.
    assert got.causing_files == (CausingFile("shared/client.py", 0, -3),)


def test_e10_deleted_instruction_file() -> None:
    # AC-E.10: AGENTS.md (1 Stale + 4 other rules) is deleted: no warnings, the Stale
    # rule is fixed and the 4 others are "removed".
    rules = [rule(f"Use requests for thing {i}", line=i) for i in range(1, 6)]
    verdicts = [S, H, C, Verdict.INSUFFICIENT, Verdict.NOT_VERIFIABLE]
    out = compare(
        list(zip(rules, map(side, verdicts), strict=True)), [], [("D", None, "AGENTS.md")]
    )
    assert [x.case for x in out] == ["fixed", "removed", "removed", "removed", "removed"]
    assert not [x for x in out if x.case in WARNING_CASES]


def test_e10_deleted_file_in_t008_status_shape() -> None:
    # Robust to a deletion reported with the old path filled in.
    out = compare([(R1, side(S))], [], [("D", "AGENTS.md", "AGENTS.md")])
    assert only(out).case == "fixed"


def test_e11_instruction_only_pr_lists_only_the_added_rule() -> None:
    # AC-E.11: only AGENTS.md changes: a contradicted rule is added (as in AC-F5.2) and
    # an unrelated sentence is edited. No case 1 is possible: the code is unchanged.
    keep = rule("Use requests for HTTP calls", line=3)
    edited_old = rule("Use requests for retries", line=4)
    edited_new = rule("Use requests for retries and timeouts", line=4)
    added = rule(
        "Use print() for debug output",
        line=12,
        match=RuleMatch(frozenset({"print"}), frozenset(), 1),
        checker="logging",
    )
    logging_sites = sites("src/a.py", "logging", False, 18) + sites("src/b.py", "print", True, 2)
    out = compare(
        [(keep, side(H)), (edited_old, side(H))],
        [(keep, side(H)), (edited_new, side(H)), (added, side(S, logging_sites))],
        [("M", "AGENTS.md", "AGENTS.md")],
    )
    assert [x.rule_id for x in out if x.case in WARNING_CASES] == [added.id]
    assert only(tuple(x for x in out if x.rule_id == added.id)).case == "stale-rule-added"
    assert "made-stale-by-code" not in {x.case for x in out}


# --- rule identity --------------------------------------------------------------------


def test_identity_uses_normalized_text_and_ignores_line() -> None:
    # D-PM-05 #3: same text after whitespace and case normalization; a moved line is the same rule.
    head_rule = rule("use   REQUESTS for http calls", line=20)
    got = only(compare([(R1, side(S))], [(head_rule, side(S))], []))
    assert got.case == "pre-existing-stale"
    assert got.rule_id == "AGENTS.md:20"


def test_edited_text_is_a_new_rule() -> None:
    edited = rule("Use requests for HTTP calls only", line=9)
    out = compare([(R1, side(C))], [(edited, side(S))], [])
    assert len(out) == 2
    assert {x.case for x in out} == {"removed", "stale-rule-added"}


@pytest.mark.parametrize("which", ["base", "head"])
def test_duplicate_identity_on_one_side_is_rejected(which: str) -> None:
    dup = [(R1, side(S)), (replace(R1, line=10, id="AGENTS.md:10"), side(S))]
    with pytest.raises(ValueError, match=f"^two {which} rules share one identity$"):
        if which == "base":
            compare(dup, [], [])
        else:
            compare([], dup, [])


def test_results_are_sorted_like_result_rule_results() -> None:
    # I-13 Result.rule_results: sorted by (file, line) of head_rule, else base_rule.
    a = rule("Use requests a", file="b/AGENTS.md", line=1)
    b = rule("Use requests b", file="AGENTS.md", line=7)
    gone = rule("Use requests aaa", file="AGENTS.md", line=7)  # sorts before b's text
    c_ = rule("Use requests c", file="AGENTS.md", line=2)
    out = compare([(gone, side(H))], [(a, side(H)), (b, side(H)), (c_, side(H))], [])
    keys = [
        ((x.head_rule or x.base_rule).file, (x.head_rule or x.base_rule).line, x.head_rule is None)
        for x in out
    ]  # type: ignore[union-attr]
    assert keys == [
        ("AGENTS.md", 2, False),
        ("AGENTS.md", 7, False),
        ("AGENTS.md", 7, True),
        ("b/AGENTS.md", 1, False),
    ]


def test_same_position_ties_break_on_text() -> None:
    x = rule("Use requests x", line=1)
    y = rule("Use requests y", line=1)
    out = compare([(y, side(H)), (x, side(H))], [], [])
    assert [r.base_rule.normalized_text for r in out] == ["use requests x", "use requests y"]  # type: ignore[union-attr]


def test_conflict_with_comes_from_the_rule_id_side() -> None:
    other = rule("Use httpx for HTTP calls", file="CLAUDE.md", line=3, match=USE_HTTPX)
    third = rule(
        "Use urllib3", file="z.md", line=1, match=RuleMatch(frozenset({"urllib3"}), frozenset(), 1)
    )
    gone = rule("Use requests everywhere", line=4)
    out = compare(
        [(gone, side(H))],
        [(R1, side(C)), (other, side(C)), (third, side(C))],
        [],
        head_conflicts=[
            Conflict(("AGENTS.md:9", "z.md:1"), "http-client"),
            Conflict(("AGENTS.md:9", "CLAUDE.md:3"), "http-client"),
        ],
        base_conflicts=[Conflict(("AGENTS.md:4", "CLAUDE.md:3"), "http-client")],
    )
    by_id = {x.rule_id: x.conflict_with for x in out}
    assert by_id == {
        "AGENTS.md:4": ("CLAUDE.md:3",),
        "AGENTS.md:9": ("CLAUDE.md:3", "z.md:1"),
        "CLAUDE.md:3": ("AGENTS.md:9",),
        "z.md:1": ("AGENTS.md:9",),
    }


def test_stale_without_causing_files_is_case_2_not_case_1() -> None:
    # I-13 C10 ruling 7: "made-stale-by-code requires a non-empty causing_files". A rule
    # that turns Stale with no causing files was caused by the PR's instruction change.
    got = only(compare([(R1, side(H))], [(R1, side(S, sites("src/a.py", "httpx", False, 3)))], []))
    assert got.causing_files == ()
    assert got.case == "stale-rule-added"


def test_moved_instruction_file_with_a_new_scope_is_case_2() -> None:
    # Ruling 7's own example: an instruction file moved and its scope changed, so the same
    # rule sees other sites. No code changed, so no causing files, and the PR caused it.
    moved = replace(R1, id="sub/AGENTS.md:9", file="sub/AGENTS.md", scope_dir="sub")
    head = side(S, sites("sub/x.py", "httpx", False, 4))
    got = only(compare([(R1, side(H))], [(moved, head)], [("R", "AGENTS.md", "sub/AGENTS.md")]))
    assert (got.case, got.causing_files) == ("stale-rule-added", ())


def test_stale_with_causing_files_stays_case_1() -> None:
    # Ruling 7, the other side: causing files present, so code caused it.
    got = only(compare([(R1, side(H))], [(R1, head_side(S))], CODE_CHANGE))
    assert got.causing_files == (CausingFile("src/a.py", 0, 3),)
    assert got.case == "made-stale-by-code"


def test_line_col_ids_do_not_change_rule_identity() -> None:
    # I-13 C6 ruling 2 (#53): two rules on one line get ``file:line:col`` ids, and
    # "identity for comparison is unchanged: (file after renames, normalized text)".
    # Base: both rules share line 9. Head: the file was renamed and the line edited so
    # one rule is alone on its line (``file:line``) and the other moved to a new column.
    one = rule("Use requests for HTTP calls", line=9)
    two = rule("Use logging, not print.", line=9, match=LOGGING_NOT_PRINT, checker="logging")
    b1 = replace(one, id="AGENTS.md:9:1")
    b2 = replace(two, id="AGENTS.md:9:30")
    h1 = replace(one, id="CLAUDE.md:9:5", file="CLAUDE.md")
    h2 = replace(two, id="CLAUDE.md:9:40", file="CLAUDE.md")
    out = compare(
        [(b1, side(S)), (b2, side(H))],
        [(h1, side(S)), (h2, side(H))],
        [("R", "AGENTS.md", "CLAUDE.md")],
    )
    # Ties on (file, line) are free (I-13 Result): compare as a mapping.
    assert {x.rule_id: (x.case, x.base_rule, x.head_rule) for x in out} == {
        "CLAUDE.md:9:5": ("pre-existing-stale", b1, h1),
        "CLAUDE.md:9:40": (None, b2, h2),
    }
    # An id that loses its column (the other rule left the line) is still the same rule.
    alone = replace(one, id="AGENTS.md:9")
    out = compare([(b1, side(S)), (b2, side(H))], [(alone, side(S))], [])
    assert {x.rule_id: x.case for x in out} == {
        "AGENTS.md:9": "pre-existing-stale",
        "AGENTS.md:9:30": "removed",
    }


def test_line_col_ids_flow_into_conflict_with_and_results() -> None:
    # Two rules on one line conflict with a third; ids (with columns) are used verbatim,
    # and a removed base rule keeps its base id.
    a = replace(rule("Use requests for HTTP calls", line=9), id="AGENTS.md:9:1")
    b = replace(rule("Use httpx for HTTP calls", line=9, match=USE_HTTPX), id="AGENTS.md:9:31")
    gone = replace(rule("Use requests everywhere", line=9), id="AGENTS.md:9:61")
    out = compare(
        [(gone, side(H))],
        [(a, side(C)), (b, side(C))],
        [],
        head_conflicts=[Conflict(("AGENTS.md:9:1", "AGENTS.md:9:31"), "http-client")],
    )
    by_id = {x.rule_id: (x.case, x.conflict_with) for x in out}
    assert by_id == {
        "AGENTS.md:9:1": (None, ("AGENTS.md:9:31",)),
        "AGENTS.md:9:31": (None, ("AGENTS.md:9:1",)),
        "AGENTS.md:9:61": ("removed", ()),
    }


# --- causing_files (I-9, B5) ---------------------------------------------------------


def test_causing_files_sorted_by_abs_delta_then_path() -> None:
    # I-9: "sorted by |delta| descending and then by path".
    base = side(
        C,
        sites("b.py", "requests", True, 2)
        + sites("a.py", "requests", True, 2)
        + sites("c.py", "requests", True, 1),
    )
    head = side(
        S,
        sites("b.py", "httpx", False, 2)
        + sites("a.py", "httpx", False, 2)
        + sites("c.py", "httpx", False, 1),
    )
    changed: list[ChangedFile] = [("M", p, p) for p in ("c.py", "b.py", "a.py")]
    got = only(compare([(R1, base)], [(R1, head)], changed))
    assert [f.file for f in got.causing_files] == ["a.py", "b.py", "c.py"]
    assert got.causing_files[0] == CausingFile("a.py", -2, 2)
    assert got.causing_files[2] == CausingFile("c.py", -1, 1)


def test_causing_files_larger_delta_first() -> None:
    base = side(C, sites("a.py", "requests", True, 1) + sites("z.py", "requests", True, 4))
    head = side(S, sites("a.py", "httpx", False, 1) + sites("z.py", "httpx", False, 4))
    got = only(compare([(R1, base)], [(R1, head)], [("M", "a.py", "a.py"), ("M", "z.py", "z.py")]))
    assert [f.file for f in got.causing_files] == ["z.py", "a.py"]


def test_causing_files_only_changed_files() -> None:
    # I-9: "files changed in the PR whose sites for this rule changed".
    base = side(
        C, sites("touched.py", "requests", True, 1) + sites("untouched.py", "requests", True, 2)
    )
    head = side(S, sites("touched.py", "httpx", False, 1))
    got = only(compare([(R1, base)], [(R1, head)], [("M", "touched.py", "touched.py")]))
    assert got.causing_files == (CausingFile("touched.py", -1, 1),)


def test_causing_files_changed_file_with_unchanged_sites_is_left_out() -> None:
    same = sites("a.py", "requests", True, 2)
    got = only(compare([(R1, side(C, same))], [(R1, side(C, same))], [("M", "a.py", "a.py")]))
    assert got.causing_files == ()


def test_causing_files_added_and_deleted_files() -> None:
    base = side(C, sites("gone.py", "requests", True, 2))
    head = side(S, sites("new.py", "httpx", False, 3))
    got = only(compare([(R1, base)], [(R1, head)], [("D", None, "gone.py"), ("A", None, "new.py")]))
    assert got.causing_files == (CausingFile("new.py", 0, 3), CausingFile("gone.py", -2, 0))


def test_causing_files_renamed_and_edited_file_uses_new_path() -> None:
    base = side(C, sites("old.py", "requests", True, 3))
    head = side(
        S, sites("new.py", "requests", True, 1) + sites("new.py", "httpx", False, 2, start=10)
    )
    got = only(compare([(R1, base)], [(R1, head)], [("R", "old.py", "new.py")]))
    assert got.causing_files == (CausingFile("new.py", -2, 2),)


def test_causing_files_empty_for_one_sided_results() -> None:
    out = compare([(R1, side(S, sites("a.py", "httpx", False, 5)))], [], [("D", None, "a.py")])
    assert only(out).causing_files == ()
    out = compare([], [(R1, side(S, sites("a.py", "httpx", False, 5)))], [("A", None, "a.py")])
    assert only(out).causing_files == ()


# --- suggestion (I-9, B5, N3, D-PM-05 #20, SC-2.44) -----------------------------------


def head_with(counts: dict[str, int], preferred: frozenset[str]) -> SideResult:
    rows: list[tuple[str, int, str, bool]] = []
    for i, (opt, n) in enumerate(sorted(counts.items())):
        rows += sites(f"f{i}.py", opt, opt in preferred, n)
    return side(C, rows)


def test_suggestion_tie_names_both_and_no_replacement() -> None:
    # AC-F6.4: httpx 10 and aiohttp 10 tie: name both, no single replacement.
    s = suggest(R1, head_with({"httpx": 10, "aiohttp": 10, "requests": 1}, USE_REQUESTS.preferred))
    assert s.kind == "tie"
    assert {a.option for a in s.alternatives} == {"httpx", "aiohttp"}
    assert all(a.sites == 10 for a in s.alternatives)
    assert s.new_text is None
    assert s.named_option == "requests"


def test_suggestion_tie_lists_every_candidate_ranked() -> None:
    s = suggest(R1, head_with({"httpx": 10, "aiohttp": 10, "urllib3": 2}, USE_REQUESTS.preferred))
    assert s.kind == "tie"
    assert s.alternatives == (
        Alternative("aiohttp", 10),
        Alternative("httpx", 10),
        Alternative("urllib3", 2),
    )


def test_suggestion_two_option_rule_swaps_both() -> None:
    # AC-F6.4: "Use logging, not print." with print most used -> "Use print, not logging."
    r = rule("Use logging, not print.", match=LOGGING_NOT_PRINT, checker="logging")
    s = suggest(r, head_with({"print": 18, "logging": 2}, LOGGING_NOT_PRINT.preferred))
    assert s.kind == "replace"
    assert s.new_text == "Use print, not logging."
    assert s.named_option == "logging"
    assert s.alternatives == (Alternative("print", 18),)


def test_suggestion_two_option_rule_with_a_third_top_option() -> None:
    # The candidate isn't the "not Y" option: only the preferred token changes.
    r = rule("Use logging, not print.", match=LOGGING_NOT_PRINT, checker="logging")
    s = suggest(r, head_with({"structlog": 9, "print": 3}, LOGGING_NOT_PRINT.preferred))
    assert s.kind == "replace"
    assert s.new_text == "Use structlog, not print."


def test_suggestion_single_option_rule_changes_only_preferred_tokens() -> None:
    # I-9: the "not Y" swap is for two-option rules; a one-option rule only replaces
    # its preferred token, even when the candidate is named elsewhere in the text.
    r = rule("Use requests; httpx is not needed")
    s = suggest(r, head_with({"httpx": 4}, USE_REQUESTS.preferred))
    assert s.new_text == "Use httpx; httpx is not needed"


def test_suggestion_ties_on_count_break_by_option_name() -> None:
    # Ranked by head site count; equal counts in a fixed (option name) order. The
    # files are laid out so the later name is seen first.
    rows = (
        sites("a.py", "zeta", False, 2)
        + sites("b.py", "alpha", False, 2)
        + sites("c.py", "mid", False, 5)
    )
    s = suggest(R1, side(C, rows))
    assert s.alternatives == (
        Alternative("mid", 5),
        Alternative("alpha", 2),
        Alternative("zeta", 2),
    )


def test_suggestion_prohibition_only_is_never_inverted() -> None:
    # AC-F6.4 / SC-2.44: "Never use print()." -> observed practice with counts
    # ("print: 18 of 20 sites") and remove-or-rewrite, no generated sentence.
    r = rule("Never use print().", match=NO_PRINT, checker="logging")
    s = suggest(r, head_with({"print": 18, "logging": 2}, NO_PRINT.preferred))
    assert s.kind == "remove-or-rewrite"
    assert s.new_text is None
    assert s.named_option is None
    assert s.alternatives == (Alternative("print", 18), Alternative("logging", 2))
    assert sum(a.sites for a in s.alternatives) == 20


def test_suggestion_none_without_candidate_sites() -> None:
    # I-9: "none: there are no candidate sites".
    s = suggest(R1, head_with({"requests": 7}, USE_REQUESTS.preferred))
    assert s == Suggestion(kind="none", named_option="requests", alternatives=(), new_text=None)
    assert suggest(R1, None) == Suggestion(
        kind="none", named_option="requests", alternatives=(), new_text=None
    )


def test_suggestion_none_for_prohibition_only_without_sites() -> None:
    r = rule("Never use print().", match=NO_PRINT, checker="logging")
    assert suggest(r, side(Verdict.INSUFFICIENT)).kind == "none"


@pytest.mark.parametrize(
    "r",
    [
        rule("Use requests", match=None, checker=None),
        rule("Use requests", match=USE_REQUESTS, checker=None),
    ],
    ids=["no-match", "no-checker"],
)
def test_suggestion_none_without_a_rule_match(r: Rule) -> None:
    # I-13 Q8: named_option is None when there is no rule match.
    s = suggest(r, head_with({"httpx": 5}, frozenset()))
    assert s == Suggestion(kind="none", named_option=None, alternatives=(), new_text=None)


def test_suggestion_replace_ranks_by_head_count() -> None:
    s = suggest(R1, head_with({"httpx": 3, "aiohttp": 9, "requests": 1}, USE_REQUESTS.preferred))
    assert s.kind == "replace"
    assert s.alternatives == (Alternative("aiohttp", 9), Alternative("httpx", 3))
    assert s.new_text == "Use aiohttp for HTTP calls"


def test_suggestion_replace_ignores_case_and_matches_whole_words() -> None:
    r = rule("Use Requests (not requests_mock) for HTTP; requests rocks")
    s = suggest(r, head_with({"httpx": 3}, USE_REQUESTS.preferred))
    assert s.new_text == "Use httpx (not requests_mock) for HTTP; httpx rocks"


def test_suggestion_replace_without_the_token_in_text_has_no_new_text() -> None:
    r = rule("Prefer the standard HTTP client", match=USE_REQUESTS)
    s = suggest(r, head_with({"httpx": 3}, USE_REQUESTS.preferred))
    assert s.kind == "replace"
    assert s.new_text is None


def test_suggestion_replace_swap_only_token_is_not_enough() -> None:
    # Only the "not Y" token appears: no preferred token, so no new text.
    r = rule("Not print.", match=LOGGING_NOT_PRINT, checker="logging")
    s = suggest(r, head_with({"print": 3}, LOGGING_NOT_PRINT.preferred))
    assert s.new_text is None


def test_suggestion_multiple_preferred_options() -> None:
    m = RuleMatch(frozenset({"httpx", "aiohttp"}), frozenset({"requests"}), 1)
    r = rule("Use httpx or aiohttp, not requests.", match=m)
    s = suggest(r, head_with({"requests": 8, "httpx": 1}, m.preferred))
    assert s.named_option == "aiohttp"  # the rule's preferred option, picked deterministically
    assert s.alternatives == (Alternative("requests", 8),)
    assert s.new_text == "Use requests or requests, not aiohttp."


def test_suggestion_longer_option_token_wins_over_prefix() -> None:
    m = RuleMatch(frozenset({"f-string"}), frozenset({"f"}), 1)
    r = rule("Use f-string, not f.", match=m, checker="string-format")
    s = suggest(r, head_with({"f": 4}, m.preferred))
    assert s.new_text == "Use f, not f-string."


def test_suggestion_on_rule_results_uses_head_side() -> None:
    base, head = _f5_1_sides()
    got = only(compare([(R1, base)], [(R1, head)], []))
    assert got.suggestion == suggest(R1, head)
    gone = only(compare([(R1, base)], [], []))
    assert gone.suggestion.kind == "none"


# --- properties -----------------------------------------------------------------------

_VERDICTS = st.sampled_from(list(Verdict))
_TEXTS = st.sampled_from([f"use requests {i}" for i in range(6)])


@given(
    base=st.dictionaries(_TEXTS, _VERDICTS, max_size=6),
    head=st.dictionaries(_TEXTS, _VERDICTS, max_size=6),
)
def test_one_result_per_identity(base: dict[str, Verdict], head: dict[str, Verdict]) -> None:
    def mk(
        texts: dict[str, Verdict], build: Callable[[Verdict], SideResult] = side
    ) -> list[tuple[Rule, SideResult]]:
        return [(rule(t, line=i + 1), build(v)) for i, (t, v) in enumerate(sorted(texts.items()))]

    out = compare(mk(base), mk(head, head_side), CODE_CHANGE)
    assert len(out) == len(set(base) | set(head))
    for x in out:
        assert x.case in set(CASES) | {None}
        rule_ = x.head_rule or x.base_rule
        assert rule_ is not None
        t = rule_.normalized_text
        if t in base and t in head:
            assert x.case == _expected_same_rule(base[t], head[t])
    assert sum(x.case in WARNING_CASES for x in out) == sum(
        1 for t, v in head.items() if v is S and (t not in base or base[t] is not S)
    )


@given(
    base_rows=st.lists(st.tuples(st.sampled_from("abc"), st.booleans()), max_size=12),
    head_rows=st.lists(st.tuples(st.sampled_from("abc"), st.booleans()), max_size=12),
)
def test_causing_deltas_sum_to_the_count_change(
    base_rows: list[tuple[str, bool]], head_rows: list[tuple[str, bool]]
) -> None:
    def mk(rows: list[tuple[str, bool]]) -> SideResult:
        return side(
            C,
            [
                (f"{f}.py", i, "requests" if fol else "httpx", fol)
                for i, (f, fol) in enumerate(rows)
            ],
        )

    b, h = mk(base_rows), mk(head_rows)
    got = only(compare([(R1, b)], [(R1, h)], [("M", f"{p}.py", f"{p}.py") for p in "abc"]))
    assert (
        sum(f.following_delta for f in got.causing_files)
        == h.overall.following - b.overall.following
    )
    assert sum(f.contradicting_delta for f in got.causing_files) == (
        h.overall.contradicting - b.overall.contradicting
    )
    keys = [
        (-(abs(f.following_delta) + abs(f.contradicting_delta)), f.file) for f in got.causing_files
    ]
    assert keys == sorted(keys)
    assert all(f.following_delta or f.contradicting_delta for f in got.causing_files)


# --- purity (DESIGN §1, I-11 C10: "none (pure)") ----------------------------------------

_ALLOWED_IMPORT_ROOTS = {"re", "collections", "typing", "conventiondrift"}
_BANNED_NAMES = {"open", "exec", "eval", "compile", "__import__", "print", "input"}


def test_compare_module_is_pure() -> None:
    path = Path(inspect.getsourcefile(compare_module) or compare_module.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    # mutmut 3 runs the suite from a ``mutants/`` copy whose trampolines import ``mutmut``.
    under_mutmut = "mutants" in path.parts
    assert roots <= _ALLOWED_IMPORT_ROOTS | ({"mutmut"} if under_mutmut else set())
    assert not {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} & _BANNED_NAMES
    conv = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("conventiondrift")
    }
    assert conv <= {"conventiondrift.model", "conventiondrift.components"}
