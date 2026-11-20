"""Unit tests for the C11 PR comment body (T-024; INTERFACES I-1, I-3, I-14; D-PM-38 to D-PM-40).

Names avoid the ``test_ac_`` prefix, and ``tests/snapshot/test_comment_snapshots.py`` and
``tests/unit/test_render_comment.py`` are left to the Test Engineer. The AC or ruling each
test exercises is named in a comment. Expected text is typed from the spec, not from the code.
"""

import ast
import re
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from typing import get_args

import pytest

from conventiondrift.model import (
    Alternative,
    Case,
    CausingFile,
    CheckerId,
    CheckerPolicy,
    Counts,
    Policy,
    ReportCounts,
    Result,
    Rule,
    RuleMatch,
    RuleResult,
    SideResult,
    Suggestion,
    Thresholds,
    Verdict,
    Window,
)
from conventiondrift.render import comment as comment_module
from conventiondrift.render.comment import MAX_COMMENT_CHARS, STICKY_MARKER, render_comment

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "tests" / "snapshot" / "approved" / "ac_f6_7.md"

COUNT_LINE = re.compile(r"^\d+ rules? changed status · \d+ unchanged · details in the job summary$")
# AC-F6.6, case-insensitive substrings.
BANNED = (
    "wrong",
    "incorrect",
    "violat",
    "bad",
    "mistake",
    "fault",
    "blame",
    "you must",
    "your code is",
)
FENCE_OPEN = re.compile(r"^(`{3,})[a-z0-9-]*$")


# --- builders ---------------------------------------------------------------------------


def _policy() -> Policy:
    return Policy(
        effective_fail_on="none",
        gated=False,
        source="base",
        history_days=90,
        thresholds=Thresholds(80, 20, 20, 50, 70, 5),
        excludes=(),
        max_file_bytes=1048576,
        checkers=MappingProxyType({cid: CheckerPolicy(True, ()) for cid in get_args(CheckerId)}),
        ignores=(),
        markers=MappingProxyType({}),
        paths=None,
        comment=True,
        sarif=False,
        after_merge_notes=(),
        notes=(),
    )


def _result(
    rule_results: Sequence[RuleResult] = (),
    *,
    mode: str = "compare",
    changed: int | None = None,
    unchanged: int = 8,
    incomplete: int = 0,
) -> Result:
    return Result(
        mode=mode,  # type: ignore[arg-type]
        base_sha="a" * 40,
        head_sha="b" * 40,
        head_only_reason=None,
        window=Window(end=None, days=90, available=False, unavailable_reason="no history"),
        policy=_policy(),
        instruction_files=(),
        skipped_files=(),
        rule_results=tuple(rule_results),
        conflicts=(),
        unattached_markers=(),
        internal_errors=(),
        counts=ReportCounts(
            stale=len(rule_results),
            new_stale=len(rule_results),
            rules_changed=len(rule_results) if changed is None else changed,
            rules_unchanged=unchanged,
            conflicts_incomplete=incomplete,
        ),
        notes=(),
        analyzer_python="3.13.5",
    )


def _side(following: int, relevant: int) -> SideResult:
    return SideResult(
        verdict=Verdict.STALE,
        sites=(),
        overall=Counts(following, relevant - following, relevant),
        recent=None,
        recent_unavailable_reason="no history",
    )


def _rule(
    text: str = "Use requests for HTTP calls",
    *,
    file: str = "AGENTS.md",
    line: int = 9,
    checker: CheckerId = "http-client",
    preferred: Sequence[str] = ("requests",),
    prohibited: Sequence[str] = (),
    ignored: bool = False,
    disabled: bool = False,
) -> Rule:
    return Rule(
        id=f"{file}:{line}",
        file=file,
        line=line,
        also_at=(),
        text=text,
        normalized_text=text.lower(),
        checker=checker,
        match=RuleMatch(frozenset(preferred), frozenset(prohibited), 1),
        scope_dir="",
        ignored=ignored,
        disabled=disabled,
    )


REPLACE_HTTPX = Suggestion(
    "replace", "requests", (Alternative("httpx", 37),), "Use httpx for HTTP calls"
)
CLIENT = (CausingFile("src/api/client.py", -3, 3),)


def _finding(
    rule: Rule | None = None,
    *,
    case: Case | None = "made-stale-by-code",
    base: SideResult | None = None,
    head: SideResult | None = None,
    causing: tuple[CausingFile, ...] = CLIENT,
    suggestion: Suggestion = REPLACE_HTTPX,
    conflict_with: tuple[str, ...] = (),
    conflict_total: int = 0,
    conflict_incomplete: bool = False,
) -> RuleResult:
    rule = rule or _rule()
    return RuleResult(
        rule_id=rule.id,
        base_rule=rule,
        head_rule=rule,
        base=_side(3, 40) if base is None else base,
        head=_side(0, 40) if head is None else head,
        conflict_with=conflict_with,
        conflict_with_total=conflict_total,
        conflict_incomplete=conflict_incomplete,
        case=case,
        causing_files=causing,
        suggestion=suggestion,
    )


def _fixture() -> Result:
    """The AC-F5.1 fixture: one finding and 8 other recognized rules."""
    return _result([_finding()], unchanged=8)


def _body(result: Result, *, previous: bool = False) -> str:
    body = render_comment(result, previous_comment=previous)
    assert body is not None
    return body


def _blocks(body: str) -> list[list[str]]:
    """Parse fences the way CommonMark does for column-0 fences; fail if one is left open."""
    lines = body.split("\n")
    blocks: list[list[str]] = []
    i = 0
    while i < len(lines):
        match = FENCE_OPEN.match(lines[i])
        if match is None:
            i += 1
            continue
        fence = match.group(1)
        j = i + 1
        while not (re.fullmatch(rf"`{{{len(fence)},}}\s*", lines[j]) if j < len(lines) else True):
            j += 1
        assert j < len(lines), "a fence was never closed"
        blocks.append(lines[i + 1 : j])
        i = j + 1
    return blocks


def _outside(body: str) -> str:
    """The body with every fenced block removed."""
    kept: list[str] = []
    inside: str | None = None
    for line in body.split("\n"):
        if inside is None:
            match = FENCE_OPEN.match(line)
            if match:
                inside = match.group(1)
            else:
                kept.append(line)
        elif re.fullmatch(rf"`{{{len(inside)},}}\s*", line):
            inside = None
    return "\n".join(kept)


# --- AC-F6.7 snapshot, I-3 -------------------------------------------------------------


def test_snapshot_file_is_the_approved_bytes() -> None:
    data = SNAPSHOT.read_bytes()
    assert len(data) == 482
    import hashlib

    assert hashlib.sha256(data).hexdigest() == (
        "ed2030ce913db645294724cfe839028130263101dd642b4c3e612f0979a47dda"
    )


def test_fixture_body_is_byte_identical_to_the_approved_snapshot() -> None:
    # AC-F6.7 / SC-2.58: the body minus the identification line (I-3 line 1).
    body = _body(_fixture())
    first, rest = body.split("\n", 1)
    assert first == "<!-- conventiondrift:sticky v1 -->"
    assert rest.encode("utf-8") == SNAPSHOT.read_bytes()


def test_marker_is_line_one_of_every_body() -> None:
    # I-3: also for the resolved body.
    assert STICKY_MARKER == "<!-- conventiondrift:sticky v1 -->"
    assert _body(_fixture()).split("\n")[0] == STICKY_MARKER
    assert _body(_result(), previous=True).split("\n")[0] == STICKY_MARKER


def test_body_uses_lf_has_one_final_newline_and_no_trailing_spaces() -> None:
    for body in (_body(_fixture()), _body(_result(), previous=True)):
        assert "\r" not in body
        assert body.endswith("\n") and not body.endswith("\n\n")
        assert all(line == line.rstrip(" ") for line in body.split("\n"))


# --- AC-F6.3 fields, AC-F5.1 -------------------------------------------------------------


def test_finding_has_the_seven_fields() -> None:
    body = _body(_fixture())
    assert 'AGENTS.md line 9: "Use requests for HTTP calls"' in body  # 1, 2
    assert "Before this PR: 3 of 40 call sites used requests" in body  # 3
    assert "After this PR:  0 of 40 (removed in src/api/client.py)" in body  # 4, 5
    assert "- Use requests for HTTP calls" in body  # 7
    assert "+ Use httpx for HTTP calls" in body


def test_why_paragraph_has_exactly_one_period() -> None:
    # AC-F6.3 item 6, for each kind of suggestion.
    suggestions = [
        REPLACE_HTTPX,
        Suggestion("tie", "requests", (Alternative("httpx", 10), Alternative("aiohttp", 10)), None),
        Suggestion("remove-or-rewrite", None, (Alternative("print", 18),), None),
        Suggestion("replace", "requests", (), None),
        Suggestion("none", "requests", (), None),
    ]
    for suggestion in suggestions:
        rule = _rule("Never use print()", preferred=(), prohibited=("print",), checker="logging")
        rule = rule if suggestion.kind == "remove-or-rewrite" else _rule()
        block = _blocks(_body(_result([_finding(rule, suggestion=suggestion)])))[0]
        start = next(i for i, line in enumerate(block) if line.startswith("   Agents treat"))
        paragraph = " ".join(line.strip() for line in block[start : start + 2])
        assert paragraph.count(".") == 1 and paragraph.endswith(".")


def test_count_noun_is_call_sites_for_http_client_and_sites_otherwise() -> None:
    # D-PM-40.
    logging_rule = _rule("Use logging", checker="logging", preferred=("logging",))
    body = _body(_result([_finding(logging_rule, suggestion=Suggestion("none", None, (), None))]))
    assert "Before this PR: 3 of 40 sites used logging" in body
    assert "call sites" in _body(_fixture())


def test_rule_added_shows_only_the_after_line() -> None:
    # AC-F5.2 (part), D-PM-40: no base counts, only After.
    rule = _rule("Use print() for debug output", line=12, checker="logging", preferred=("print",))
    finding = RuleResult(
        rule_id=rule.id,
        base_rule=None,
        head_rule=rule,
        base=None,
        head=_side(2, 20),
        conflict_with=(),
        conflict_with_total=0,
        conflict_incomplete=False,
        case="stale-rule-added",
        causing_files=(),
        suggestion=Suggestion("none", "print", (), None),
    )
    body = _body(_result([finding]))
    assert 'AGENTS.md line 12: "Use print() for debug output"' in body
    assert "After this PR:  2 of 20 sites used print" in body
    assert "Before this PR" not in body
    assert "Suggested fix" not in body


def test_rule_added_with_a_base_side_still_shows_the_before_line() -> None:
    # I-13 ruling 7: a newly Stale rule with no causing files is case 2 but may have a base.
    body = _body(_result([_finding(case="stale-rule-added", causing=())]))
    assert "Before this PR: 3 of 40 call sites used requests" in body
    assert "After this PR:  0 of 40\n" in body


# --- AC-F6.4 suggestions -----------------------------------------------------------------


def test_two_option_swap_is_shown_as_a_diff() -> None:
    rule = _rule("Use logging, not print.", checker="logging", preferred=("logging",))
    suggestion = Suggestion(
        "replace", "logging", (Alternative("print", 18),), "Use print, not logging."
    )
    block = _blocks(_body(_result([_finding(rule, suggestion=suggestion)])))[0]
    assert "   Suggested fix:" in block
    assert "   - Use logging, not print." in block
    assert "   + Use print, not logging." in block


def test_tie_names_both_and_proposes_no_single_replacement() -> None:
    suggestion = Suggestion(
        "tie", "requests", (Alternative("httpx", 10), Alternative("aiohttp", 10)), None
    )
    body = _body(_result([_finding(suggestion=suggestion)]))
    assert "No single replacement: httpx and aiohttp are tied at 10 sites each." in body
    assert "Suggested fix" not in body
    assert "\n   + " not in body


def test_tie_lists_only_the_tied_options_and_joins_three_with_and() -> None:
    alternatives = (
        Alternative("a", 7),
        Alternative("b", 7),
        Alternative("c", 7),
        Alternative("d", 1),
    )
    body = _body(_result([_finding(suggestion=Suggestion("tie", "requests", alternatives, None))]))
    assert "No single replacement: a, b and c are tied at 7 sites each." in body


def test_a_tie_with_one_named_option_still_names_it() -> None:
    # C10 never emits this (a tie has two or more candidates); the renderer must not drop the name.
    suggestion = Suggestion("tie", "requests", (Alternative("httpx", 4),), None)
    assert "No single replacement: httpx are tied at 4 sites each." in _body(
        _result([_finding(suggestion=suggestion)])
    )


def test_prohibition_only_shows_observed_counts_and_no_replacement() -> None:
    rule = _rule("Never use print().", checker="logging", preferred=(), prohibited=("print",))
    suggestion = Suggestion(
        "remove-or-rewrite", None, (Alternative("print", 18), Alternative("logging", 2)), None
    )
    finding = _finding(rule, base=_side(19, 20), head=_side(2, 20), suggestion=suggestion)
    body = _body(_result([finding]))
    assert "Before this PR: 19 of 20 sites avoided print" in body
    assert "Observed now: print: 18 of 20 sites, logging: 2 of 20 sites" in body
    assert "\n   Consider removing or rewriting this rule.\n```" in body
    assert "keep avoiding print, which most code in this repo now uses." in body
    assert "Suggested fix" not in body
    assert "\n   + " not in body


def test_prohibition_only_without_candidates_still_proposes_removal() -> None:
    rule = _rule("Never use print().", checker="logging", preferred=(), prohibited=("print",))
    suggestion = Suggestion("remove-or-rewrite", None, (), None)
    body = _body(_result([_finding(rule, suggestion=suggestion)]))
    assert "Observed now" not in body
    block = _blocks(body)[0]
    assert block[-1] == "   Consider removing or rewriting this rule."
    assert block[-2] == ""


def test_replace_without_new_text_shows_the_finding_and_the_most_used_option() -> None:
    # D-PM-38: never garbled text, and no Suggested fix block.
    suggestion = Suggestion(
        "replace", "requests", (Alternative("httpx", 30), Alternative("x", 2)), None
    )
    body = _body(_result([_finding(suggestion=suggestion)]))
    assert 'AGENTS.md line 9: "Use requests for HTTP calls"' in body
    assert "Most-used option now: httpx (30 of 40 sites)" in body
    assert "Suggested fix" not in body
    assert "\n   - " not in body and "\n   + " not in body


def test_replace_without_new_text_and_without_candidates_shows_only_the_finding() -> None:
    suggestion = Suggestion("replace", "requests", (), None)
    block = _blocks(_body(_result([_finding(suggestion=suggestion)])))[0]
    assert block[-1].startswith("   reintroduce requests")


def test_multi_preferred_rule_names_each_option() -> None:
    rule = _rule("Use httpx or aiohttp", preferred=("httpx", "aiohttp"))
    suggestion = Suggestion("replace", "aiohttp", (Alternative("requests", 9),), None)
    body = _body(_result([_finding(rule, suggestion=suggestion)]))
    assert "40 call sites used aiohttp or httpx" in body
    assert "reintroduce aiohttp or httpx in future changes." in body


def test_suggestion_none_has_no_extra_block() -> None:
    block = _blocks(
        _body(_result([_finding(suggestion=Suggestion("none", "requests", (), None))]))
    )[0]
    assert block[-1].startswith("   reintroduce requests")


# --- causing files -----------------------------------------------------------------------


def _causing(count: int, delta: int = -1) -> tuple[CausingFile, ...]:
    return tuple(CausingFile(f"src/f{i}.py", delta, -delta) for i in range(count))


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (1, "(removed in src/f0.py)"),
        (3, "(removed in src/f0.py, src/f1.py, src/f2.py)"),
        (4, "(removed in src/f0.py, src/f1.py, src/f2.py, +1 more)"),
        (10, "(removed in src/f0.py, src/f1.py, src/f2.py, +7 more)"),
    ],
)
def test_causing_files_list_up_to_three_then_plus_n_more(count: int, expected: str) -> None:
    # D-PM-40.
    assert expected in _body(_result([_finding(causing=_causing(count))]))


def test_causing_files_that_add_sites_read_changed_not_removed() -> None:
    body = _body(
        _result([_finding(causing=(CausingFile("a.py", 2, -2), CausingFile("b.py", -1, 1)))])
    )
    assert "(changed in a.py, b.py)" in body


def test_a_causing_file_with_no_following_change_reads_changed() -> None:
    body = _body(_result([_finding(causing=(CausingFile("a.py", 0, 0),))]))
    assert "(changed in a.py)" in body


def test_no_causing_files_means_no_parenthesis() -> None:
    assert "After this PR:  0 of 40\n" in _body(_result([_finding(causing=())]))


# --- which rules are findings ------------------------------------------------------------


@pytest.mark.parametrize("case", ["fixed", "pre-existing-stale", "removed", None])
def test_only_cases_one_and_two_are_findings(case: Case | None) -> None:
    assert render_comment(_result([_finding(case=case)]), previous_comment=False) is None


def test_ignored_disabled_and_conflicting_rules_have_no_entry() -> None:
    # AC-F9.10, AC-E.3, DESIGN S2.
    rules = [
        _finding(_rule(line=1, ignored=True)),
        _finding(_rule(line=2, disabled=True)),
        _finding(_rule(line=3), conflict_with=("CLAUDE.md:3",), conflict_total=1),
        _finding(
            _rule(line=4),
            conflict_with=("CLAUDE.md:3",),
            conflict_total=5,
            conflict_incomplete=True,
        ),
        _finding(_rule(line=5)),
    ]
    body = _body(_result(rules))
    assert "this PR makes 1 agent rule stale" in body
    assert body.count('"Use requests for HTTP calls"') == 1
    assert "AGENTS.md line 5" in body


def test_incomplete_rule_with_known_partners_is_conflicting_and_has_no_entry() -> None:
    # I-13 C6 item 6, "one status rule": conflicting iff conflict_with_total > 0, incomplete or not.
    finding = _finding(conflict_with=("CLAUDE.md:3",), conflict_total=1, conflict_incomplete=True)
    assert render_comment(_result([finding], incomplete=1), previous_comment=False) is None


def test_incomplete_rule_with_no_known_partner_is_not_conflicting_and_has_its_entry() -> None:
    # Same ruling: an incomplete rule with total == 0 may warn on its own verdict, and the
    # run-level note still flags it.
    finding = _finding(conflict_incomplete=True)
    body = _body(_result([finding], incomplete=1))
    assert 'AGENTS.md line 9: "Use requests for HTTP calls"' in body
    assert "this PR makes 1 agent rule stale" in body
    assert "conflict check stopped at the limit; 1 rule not fully checked" in body


def test_an_incomplete_conflicting_rule_does_not_hide_another_incomplete_rule() -> None:
    hidden = _finding(
        _rule(line=1), conflict_with=("CLAUDE.md:3",), conflict_total=4, conflict_incomplete=True
    )
    shown = _finding(_rule(line=2), conflict_incomplete=True)
    body = _body(_result([hidden, shown], incomplete=2))
    assert "AGENTS.md line 2" in body and "AGENTS.md line 1:" not in body
    assert "this PR makes 1 agent rule stale" in body


def test_a_rule_without_a_checker_match_still_renders() -> None:
    # Cannot happen for a Stale rule; the renderer must not raise on it.
    rule = replace(_rule(), match=None)
    block = _blocks(_body(_result([_finding(rule)])))[0]
    assert block[0] == '⚠️ AGENTS.md line 9: "Use requests for HTTP calls"'


def test_a_rule_without_a_head_side_is_not_a_finding() -> None:
    finding = replace(_finding(), head=None)
    assert render_comment(_result([finding]), previous_comment=False) is None


def test_only_ignored_findings_means_no_comment() -> None:
    assert render_comment(_result([_finding(_rule(ignored=True))]), previous_comment=False) is None


# --- AC-F5.5, AC-F5.7: no body, resolved state -------------------------------------------


def test_nothing_changed_and_no_earlier_comment_gives_no_body() -> None:
    assert render_comment(_result(changed=0), previous_comment=False) is None


def test_fixed_rules_alone_give_no_body_without_an_earlier_comment() -> None:
    assert render_comment(_result(changed=2), previous_comment=False) is None


def test_resolved_body_when_an_earlier_comment_exists() -> None:
    body = _body(_result(), previous=True)
    assert body == (
        "<!-- conventiondrift:sticky v1 -->\n"
        "🧭 conventiondrift: resolved, this PR no longer changes any agent rule's status\n"
    )
    assert body.split("\n")[1] == (
        "🧭 conventiondrift: resolved, this PR no longer changes any agent rule's status"
    )


@pytest.mark.parametrize("mode", ["head-only", "scan"])
@pytest.mark.parametrize("previous", [False, True])
def test_head_only_and_scan_post_nothing(mode: str, previous: bool) -> None:
    result = _result([_finding()], mode=mode)
    assert render_comment(result, previous_comment=previous) is None


def test_previous_comment_flag_does_not_change_a_body_with_findings() -> None:
    assert _body(_fixture(), previous=True) == _body(_fixture(), previous=False)


# --- AC-F6.5, D-PM-39 grammar --------------------------------------------------------------


def test_header_and_count_line_grammar() -> None:
    one = _body(_result([_finding(_rule(line=1))], changed=1, unchanged=0))
    assert "this PR makes 1 agent rule stale" in one
    assert one.rstrip("\n").split("\n")[-1] == (
        "1 rule changed status · 0 unchanged · details in the job summary"
    )
    findings = [_finding(_rule(line=n)) for n in range(1, 12)]
    many = _body(_result(findings, changed=11, unchanged=1))
    assert "this PR makes 11 agent rules stale" in many
    assert many.rstrip("\n").split("\n")[-1] == (
        "11 rules changed status · 1 unchanged · details in the job summary"
    )


def test_count_line_uses_the_report_counts_not_the_finding_count() -> None:
    body = _body(_result([_finding()], changed=3, unchanged=5))
    assert body.rstrip("\n").split("\n")[-1] == (
        "3 rules changed status · 5 unchanged · details in the job summary"
    )


def test_count_line_is_the_last_non_empty_line_and_matches_the_regex() -> None:
    result = _result([_finding(_rule(line=n)) for n in range(1, 4)], incomplete=2)
    last = [line for line in _body(result).split("\n") if line][-1]
    assert COUNT_LINE.fullmatch(last)


# --- incomplete conflict note (I-13 C6 item 6, D-PM-39) -----------------------------------


def test_incomplete_conflict_note_is_plural_and_before_the_count_line() -> None:
    lines = _body(_result([_finding()], incomplete=3)).rstrip("\n").split("\n")
    assert lines[-3:] == [
        "conflict check stopped at the limit; 3 rules not fully checked",
        "",
        "1 rule changed status · 8 unchanged · details in the job summary",
    ]


def test_incomplete_conflict_note_is_singular_for_one_rule() -> None:
    body = _body(_result([_finding()], incomplete=1))
    assert "conflict check stopped at the limit; 1 rule not fully checked\n" in body


def test_no_note_when_every_conflict_check_completed() -> None:
    assert "conflict check" not in _body(_fixture())


def test_note_also_appears_in_the_resolved_body() -> None:
    body = _body(_result(incomplete=2), previous=True)
    assert body == (
        "<!-- conventiondrift:sticky v1 -->\n"
        "🧭 conventiondrift: resolved, this PR no longer changes any agent rule's status\n\n"
        "conflict check stopped at the limit; 2 rules not fully checked\n"
    )


def test_note_is_not_inside_a_block() -> None:
    body = _body(_result([_finding()], incomplete=2))
    assert "conflict check" in _outside(body)


# --- AC-F6.6 tone ------------------------------------------------------------------------


def test_no_banned_word_in_any_fixed_sentence() -> None:
    results = [
        _fixture(),
        _result(
            [
                _finding(
                    suggestion=Suggestion(
                        "tie", "requests", (Alternative("httpx", 3), Alternative("h", 3)), None
                    )
                )
            ]
        ),
        _result(
            [
                _finding(
                    _rule(
                        "Never use print().", checker="logging", preferred=(), prohibited=("print",)
                    ),
                    suggestion=Suggestion(
                        "remove-or-rewrite", None, (Alternative("print", 1),), None
                    ),
                )
            ],
            incomplete=2,
        ),
        _result(
            [
                _finding(
                    suggestion=Suggestion("replace", "requests", (Alternative("httpx", 3),), None)
                )
            ]
        ),
        _result([_finding(causing=_causing(5))]),
        _result(),
    ]
    for result in results:
        for previous in (False, True):
            body = render_comment(result, previous_comment=previous)
            if body is None:
                continue
            lowered = body.lower()
            for word in BANNED:
                assert word not in lowered, word


def test_truncated_body_is_free_of_banned_words() -> None:
    body = _body(
        _result(
            [_finding(_rule(f"Rule number {n:04d}" + "x" * 500, line=n)) for n in range(1, 400)]
        )
    )
    assert not any(word in body.lower() for word in BANNED)


# --- AC-E.13 truncation ------------------------------------------------------------------


def _many(count: int, text_len: int = 40) -> Result:
    findings = [
        _finding(_rule(f"Rule {n:05d} " + "r" * text_len, line=n)) for n in range(1, count + 1)
    ]
    return _result(findings, changed=count, unchanged=0)


def test_500_findings_fit_end_with_the_count_line_and_point_to_the_summary() -> None:
    body = _body(_many(500, text_len=200))
    assert len(body) <= MAX_COMMENT_CHARS
    last = [line for line in body.split("\n") if line][-1]
    assert last == "500 rules changed status · 0 unchanged · details in the job summary"
    shown = len(_blocks(body))
    assert 0 < shown < 500
    assert f"{500 - shown} more findings are in the job summary.\n\n500 rules changed" in body
    assert "this PR makes 500 agent rules stale" in body


def test_truncation_keeps_whole_entries_in_report_order() -> None:
    body = _body(_many(500, text_len=200))
    blocks = _blocks(body)
    for index, block in enumerate(blocks, start=1):
        assert block[0] == f'⚠️ AGENTS.md line {index}: "Rule {index:05d} ' + "r" * 200 + '"'
        assert block[-1].startswith("   reintroduce") or block[-1].startswith("   + ")


def test_truncation_keeps_the_longest_body_that_fits() -> None:
    # One more entry (plus its blank-line separator) would go over the limit.
    result = _many(500, text_len=200)
    body = _body(result)
    shown = len(_blocks(body))
    single = _body(replace(result, rule_results=(result.rule_results[shown],)))
    next_entry = single.split("\n\n")[1]
    assert len(body) <= MAX_COMMENT_CHARS
    assert len(body) + len(next_entry) + 2 > MAX_COMMENT_CHARS


def _padded(count: int, pad: int) -> Result:
    """``count`` findings of one size, the last rule text ``pad`` characters longer.

    No suggestion, so the rule text appears once per entry and ``pad`` adds exactly ``pad``.
    """
    plain = Suggestion("none", "requests", (), None)

    def entry(n: int, extra: int) -> RuleResult:
        return _finding(_rule(f"Rule {n:05d} " + "r" * (400 + extra), line=n), suggestion=plain)

    findings = [entry(n, 0) for n in range(1, count)]
    return _result([*findings, entry(count, pad)], changed=count, unchanged=0)


def _largest_untruncated() -> int:
    count = 1
    while "more finding" not in _body(_padded(count + 1, 0)):
        count += 1
    return count


def test_a_body_of_exactly_the_limit_is_kept_whole_and_one_more_character_cuts_an_entry() -> None:
    count = _largest_untruncated()
    slack = MAX_COMMENT_CHARS - len(_body(_padded(count, 0)))
    assert 0 <= slack < 500  # an entry is about 700 characters; the padded line stays under its cap
    exact = _body(_padded(count, slack))
    assert len(exact) == MAX_COMMENT_CHARS
    assert "more finding" not in exact
    assert len(_blocks(exact)) == count
    over = _body(_padded(count, slack + 1))
    assert len(over) <= MAX_COMMENT_CHARS
    assert "\n\n1 more finding is in the job summary.\n\n" in over
    assert len(_blocks(over)) == count - 1


def test_a_singular_notice_when_one_finding_is_left_out() -> None:
    for count in range(2, 400):
        body = _body(_many(count, text_len=700))
        if "more finding" in body:
            assert "\n\n1 more finding is in the job summary.\n\n" in body
            assert len(_blocks(body)) == count - 1
            assert len(body) <= MAX_COMMENT_CHARS
            return
    pytest.fail("no count left exactly one finding out")


def test_nothing_is_cut_when_the_body_fits() -> None:
    body = _body(_many(5))
    assert "more finding" not in body
    assert len(_blocks(body)) == 5


def test_notice_comes_after_the_note_and_before_the_count_line() -> None:
    result = replace(
        _many(500, text_len=200),
        counts=ReportCounts(
            stale=500, new_stale=500, rules_changed=500, rules_unchanged=0, conflicts_incomplete=1
        ),
    )
    tail = _body(result).rstrip("\n").split("\n\n")[-3:]
    assert tail[0] == "conflict check stopped at the limit; 1 rule not fully checked"
    assert re.fullmatch(r"\d+ more findings are in the job summary\.", tail[1])
    assert COUNT_LINE.fullmatch(tail[2])


def test_the_worst_case_block_is_far_below_the_limit() -> None:
    # SR condition 5: one block is bounded (every line is cut at 1000 characters), so the
    # "drop lines from one oversize block" case cannot arise.
    long = "x" * 100_000
    suggestion = Suggestion("replace", "requests", (Alternative("h" * 100_000, 1),), long)
    finding = _finding(_rule(long, file="f" * 5000), causing=_causing(50), suggestion=suggestion)
    body = _body(_result([finding]))
    assert len(body) < 15_000
    assert "more finding" not in body


# --- hostile text and block placement (I-14 items 4, 9) ------------------------------------


HOSTILE = (
    "Use `requests`, ping @someone <img src=x> [l](https://e.example) **b** #123\n```\n~~~\n```` "
)


def test_hostile_rule_text_stays_inside_one_closed_block() -> None:
    suggestion = Suggestion("replace", "requests", (Alternative("httpx", 1),), HOSTILE + "new")
    result = _result(
        [_finding(_rule(HOSTILE, file="src/@someone/<b>x</b>.py"), suggestion=suggestion)]
    )
    body = _body(result)
    blocks = _blocks(body)
    assert len(blocks) == 1
    outside = _outside(body)
    for needle in ("@someone", "<img", "evil", "<b>", "#123", "requests"):
        assert needle not in outside
    assert body.split("\n")[0] == STICKY_MARKER


def test_every_fence_opens_at_column_zero_with_blank_lines_around_it() -> None:
    body = _body(_many(6))
    lines = body.split("\n")
    opens = 0
    inside = False
    for i, line in enumerate(lines):
        if not inside and FENCE_OPEN.match(line):
            opens += 1
            assert lines[i - 1] == ""
            inside = True
        elif inside and re.fullmatch(r"`{3,}", line):
            assert lines[i + 1] == ""
            inside = False
    assert opens == 6 and not inside


def test_body_has_no_other_fence_text_outside_the_blocks() -> None:
    body = _body(_many(3))
    assert "`" not in _outside(body)


def test_fence_grows_with_backticks_in_rule_text() -> None:
    body = _body(_result([_finding(_rule("Use ````` for quoting"))]))
    assert body.split("\n")[3] == "``````"
    assert body.split("\n\n")[-2].endswith("\n``````")


def test_a_very_long_rule_text_is_cut_with_a_marker() -> None:
    body = _body(_result([_finding(_rule("r" * 5000))]))
    assert "more chars]" in body


def test_blocks_are_joined_with_blank_lines_at_top_level() -> None:
    plain = Suggestion("none", None, (), None)
    findings = [_finding(_rule(line=n), suggestion=plain) for n in (1, 2)]
    body = _body(_result(findings))
    parts = body.rstrip("\n").split("\n\n")
    assert parts[0].startswith(STICKY_MARKER)
    assert [p.split("\n")[0] for p in parts[1:3]] == ["```", "```"]
    assert COUNT_LINE.fullmatch(parts[3])


SRC = ROOT / "src" / "conventiondrift"
ESCAPE_MODULE = SRC / "render" / "escape.py"


def fence_writes(source: str) -> list[int]:
    """Line numbers where ``source`` could write a code fence (CR1 on #56, I-14 item 9).

    Flags a string constant (an f-string part included) holding three backticks or three
    tildes, and a backtick or tilde string repeated by ``*``. A constant that is only a
    member of a tuple, list or set compared with ``in`` or ``not in`` is a *read* (the rule
    extractor recognises fences in instruction files) and is allowed.
    """
    tree = ast.parse(source)
    reads: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(
            isinstance(op, ast.In | ast.NotIn) for op in node.ops
        ):
            for side in (node.left, *node.comparators):
                if isinstance(side, ast.Tuple | ast.List | ast.Set):
                    reads.update(id(item) for item in side.elts)
    found: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in reads and ("`" * 3 in node.value or "~" * 3 in node.value):
                found.append(node.lineno)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            for side in (node.left, node.right):
                if isinstance(side, ast.Constant) and side.value in ("`", "~"):
                    found.append(node.lineno)
    return sorted(set(found))


def test_fence_scanner_finds_planted_writes_and_allows_reads() -> None:
    fence = "`" * 3
    assert fence_writes(f'x = "{fence}\\n" + body') == [1]
    assert fence_writes(f'x = f"{fence}{{info}}"') == [1]
    assert fence_writes('x = "~~~"') == [1]
    assert fence_writes('n = 4\nx = "`" * n') == [2]
    assert fence_writes('x = n * "~"') == [1]
    assert fence_writes(f'if line[:3] not in ("{fence}", "~~~"):\n    pass') == []
    assert fence_writes('x = "`"') == []


def test_nothing_in_src_except_escape_writes_a_fence() -> None:
    # I-14 item 9: only md_codeblock writes a fence. The vendored YAML is third-party code.
    files = [
        path
        for path in SRC.rglob("*.py")
        if path != ESCAPE_MODULE and "_vendor" not in path.relative_to(SRC).parts
    ]
    assert SRC / "render" / "comment.py" in files
    offenders = {
        str(path.relative_to(SRC)): lines
        for path in files
        if (lines := fence_writes(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}


def test_escape_module_is_where_the_fence_is_written() -> None:
    # Keeps the scan honest: the one allowed writer really is found by the same scanner.
    assert fence_writes(ESCAPE_MODULE.read_text(encoding="utf-8"))


def test_renderer_module_escapes_nothing_itself() -> None:
    source = Path(comment_module.__file__).read_text(encoding="utf-8")
    assert fence_writes(source) == []
    assert "md(" not in source and "md_cell(" not in source and ".replace(" not in source
    assert "md_codeblock(" in source


def test_two_renders_of_one_result_are_identical() -> None:
    result = _many(30)
    assert _body(result) == _body(result)
