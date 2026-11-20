"""Unit tests for C6 checker mapping, duplicates, ignores and conflicts (T-015).

The checkers here are stand-ins written only against I-10: each matches
phrases it is given, so mapping is tested without the real checkers
(T-016 to T-019).
"""

import ast
import dataclasses
import inspect
import itertools
from collections.abc import Callable, Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import Any, Literal, get_args

import pytest

from conventiondrift.checkers.base import Checker
from conventiondrift.components import Extractor
from conventiondrift.errors import ComponentError
from conventiondrift.model import (
    MAX_CONFLICT_WITH,
    CheckerId,
    CheckerPolicy,
    Extraction,
    FileContext,
    IgnoreEntry,
    InstructionFile,
    Policy,
    Rule,
    RuleMatch,
    Site,
    Thresholds,
)
from conventiondrift.rules import mapping
from conventiondrift.rules.conflicts import (
    MAX_CONFLICT_PAIRS,
    MAX_CONFLICTS,
    MAX_SCOPE_DIR_BYTES,
)
from conventiondrift.rules.extract import MARKER, MAX_RULES_PER_FILE, normalize
from conventiondrift.rules.mapping import (
    UNMAPPED,
    Mapped,
    RuleExtractor,
    extract_rules,
    map_rule,
    rule_id,
    rule_identity,
)

CHECKER_IDS: tuple[CheckerId, ...] = get_args(CheckerId)
Phrase = tuple[str, Sequence[str], Sequence[str], int]
"""A needle, then the preferred and prohibited options and the specificity it gives."""


class PhraseChecker:
    """A checker whose ``match_rule`` answers the best phrase found in the text."""

    experimental = False
    inputs: frozenset[Literal["python-ast", "manifest"]] = frozenset({"python-ast"})

    def __init__(
        self,
        checker_id: CheckerId,
        options: Iterable[str],
        phrases: Sequence[Phrase],
        log: list[str] | None = None,
    ) -> None:
        self.id: CheckerId = checker_id
        self.options = frozenset(options)
        self.phrases = phrases
        self.log = log

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        if self.log is not None:
            self.log.append(self.id)
        hits = [
            RuleMatch(frozenset(preferred), frozenset(prohibited), spec)
            for needle, preferred, prohibited, spec in self.phrases
            if needle in normalized_text
        ]
        return max(hits, key=lambda m: m.specificity, default=None)

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]:
        return {}

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]:
        return ()


class ScriptedChecker(PhraseChecker):
    """Returns ``result`` for every text, or raises it when it is an exception."""

    def __init__(self, checker_id: CheckerId, options: Iterable[str], result: object) -> None:
        super().__init__(checker_id, options, ())
        self.result = result

    def match_rule(self, normalized_text: str) -> RuleMatch | None:
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result  # type: ignore[return-value]  # a broken checker, on purpose


# AC-F2.5's eight canonical sentences, each with the checker that must take it.
CANONICAL: tuple[tuple[CheckerId, str, Phrase], ...] = (
    ("logging", "Use logging, not print.", ("logging", ["logging"], ["print"], 2)),
    ("http-client", "Use httpx for HTTP calls.", ("httpx", ["httpx"], [], 2)),
    ("test-framework", "Use pytest, not unittest.", ("pytest", ["pytest"], ["unittest"], 2)),
    ("money", "Store money as integer cents.", ("integer cents", ["integer-cents"], [], 2)),
    ("string-format", "Use f-strings for string formatting.", ("f-strings", ["f-string"], [], 2)),
    ("exceptions", "Do not use bare except.", ("bare except", [], ["bare-except"], 2)),
    ("type-hints", "Always use type hints.", ("type hints", ["annotated"], [], 2)),
    ("package-manager", "Use uv for dependencies.", (" uv ", ["uv"], [], 2)),
)
OPTIONS: dict[CheckerId, frozenset[str]] = {
    "logging": frozenset({"logging", "print"}),
    "http-client": frozenset({"httpx", "requests", "urllib"}),
    "test-framework": frozenset({"pytest", "unittest"}),
    "money": frozenset({"integer-cents", "float"}),
    "string-format": frozenset({"f-string", "percent"}),
    "exceptions": frozenset({"bare-except", "specific"}),
    "type-hints": frozenset({"annotated", "bare"}),
    "package-manager": frozenset({"uv", "pip", "poetry"}),
}


def canonical_checkers(log: list[str] | None = None) -> dict[str, Checker]:
    return {cid: PhraseChecker(cid, OPTIONS[cid], [phrase], log) for cid, _, phrase in CANONICAL}


def make_policy(
    *,
    enabled: Mapping[CheckerId, bool] | None = None,
    ignores: tuple[IgnoreEntry, ...] = (),
    markers: Mapping[str, tuple[tuple[int, bool], ...]] | None = None,
) -> Policy:
    enabled = enabled or {}
    return Policy(
        effective_fail_on="none",
        gated=False,
        source="head",
        history_days=90,
        thresholds=Thresholds(80, 20, 20, 50, 70, 5),
        excludes=(),
        max_file_bytes=1048576,
        checkers=MappingProxyType(
            {cid: CheckerPolicy(enabled.get(cid, True), ()) for cid in CHECKER_IDS}
        ),
        ignores=ignores,
        markers=MappingProxyType(dict(markers or {})),
        paths=None,
        comment=True,
        sarif=False,
        after_merge_notes=(),
        notes=(),
    )


def instruction_file(path: str, text: str, scope_dir: str = "") -> InstructionFile:
    return InstructionFile(
        path=path, data=text.encode(), scope_dir=scope_dir, via_paths_input=False
    )


def rules_of(
    files: Sequence[InstructionFile],
    checkers: Mapping[str, Checker] | None = None,
    policy: Policy | None = None,
) -> tuple[Rule, ...]:
    return extract_rules(files, policy or make_policy(), checkers or {}).rules


def only_rule(text: str, checkers: Mapping[str, Checker] | None = None, **kw: Any) -> Rule:
    (rule,) = rules_of([instruction_file("AGENTS.md", text, **kw)], checkers)
    return rule


# --- AC-F2.5: the mapping algorithm over the eight canonical sentences ---------------------


def test_eight_canonical_sentences_map_to_one_checker_each() -> None:
    text = "".join(sentence + "\n" for _, sentence, _ in CANONICAL)
    rules = rules_of([instruction_file("AGENTS.md", text)], canonical_checkers())
    assert [(r.line, r.checker) for r in rules] == [
        (n, cid) for n, (cid, _, _) in enumerate(CANONICAL, start=1)
    ]
    assert all(r.match is not None and not r.disabled for r in rules)


@pytest.mark.parametrize(("expected", "sentence", "phrase"), CANONICAL, ids=lambda v: str(v)[:18])
def test_each_canonical_sentence_is_matched_by_its_checker_alone(
    expected: CheckerId, sentence: str, phrase: Phrase
) -> None:
    del phrase
    checkers = canonical_checkers()
    matching = [cid for cid, checker in checkers.items() if checker.match_rule(normalize(sentence))]
    assert matching == [expected]
    assert map_rule(normalize(sentence), checkers).checker == expected


def test_money_checker_off_still_maps_and_marks_the_rule_disabled() -> None:
    # AC-F3.14: the money rule is kept for the summary but is not evaluated.
    policy = make_policy(enabled={"money": False})
    (rule,) = rules_of(
        [instruction_file("AGENTS.md", "Store money as integer cents.\n")],
        canonical_checkers(),
        policy,
    )
    assert rule.checker == "money"
    assert rule.match is not None
    assert rule.disabled


@pytest.mark.parametrize("off", CHECKER_IDS)
def test_only_the_rules_of_a_disabled_checker_are_disabled(off: CheckerId) -> None:
    text = "".join(sentence + "\n" for _, sentence, _ in CANONICAL)
    policy = make_policy(enabled={off: False})
    rules = rules_of([instruction_file("AGENTS.md", text)], canonical_checkers(), policy)
    assert {r.checker for r in rules if r.disabled} == {off}
    assert len([r for r in rules if r.disabled]) == 1


def test_a_disabled_checker_still_takes_part_in_the_specificity_contest() -> None:
    # The winner decides: a disabled checker that wins makes the rule disabled, and a
    # disabled checker that ties still makes the rule ambiguous.
    http = PhraseChecker("http-client", OPTIONS["http-client"], [("requests", ["httpx"], [], 3)])
    logging = PhraseChecker("logging", OPTIONS["logging"], [("requests", [], ["print"], 2)])
    policy = make_policy(enabled={"http-client": False})
    (rule,) = rules_of(
        [instruction_file("AGENTS.md", "Never use requests.\n")],
        {"http-client": http, "logging": logging},
        policy,
    )
    assert (rule.checker, rule.disabled) == ("http-client", True)


# --- AC-F2.6, AC-F2.7, AC-F4.8: ties and no match ------------------------------------------


@pytest.mark.parametrize(("a", "b"), list(itertools.combinations(CHECKER_IDS, 2)))
def test_two_checkers_with_the_same_specificity_is_not_verifiable(
    a: CheckerId, b: CheckerId
) -> None:
    # AC-F2.6: "Never use print or requests" matches two checkers with no more specific one.
    checkers: dict[str, Checker] = {
        a: PhraseChecker(a, {"x"}, [("print or requests", [], ["x"], 5)]),
        b: PhraseChecker(b, {"y"}, [("print or requests", [], ["y"], 5)]),
    }
    assert map_rule("never use print or requests", checkers) == UNMAPPED
    rule = only_rule("Never use print or requests", checkers)
    assert (rule.checker, rule.match, rule.disabled) == (None, None, False)


def test_the_more_specific_checker_wins() -> None:
    checkers = {
        "logging": PhraseChecker("logging", {"print"}, [("print", [], ["print"], 1)]),
        "http-client": PhraseChecker("http-client", {"requests"}, [("print", [], ["requests"], 2)]),
    }
    mapped = map_rule("never use print", checkers)
    assert mapped.checker == "http-client"
    assert mapped.match == RuleMatch(frozenset(), frozenset({"requests"}), 2)


def test_the_winner_does_not_depend_on_checker_order() -> None:
    low = PhraseChecker("logging", {"print"}, [("print", [], ["print"], 1)])
    high = PhraseChecker("http-client", {"requests"}, [("print", [], ["requests"], 2)])
    for order in itertools.permutations([low, high]):
        assert map_rule("print", {c.id: c for c in order}).checker == "http-client"


def test_a_tie_below_the_top_does_not_matter() -> None:
    checkers = {
        "logging": PhraseChecker("logging", {"a"}, [("z", [], ["a"], 1)]),
        "exceptions": PhraseChecker("exceptions", {"b"}, [("z", [], ["b"], 1)]),
        "http-client": PhraseChecker("http-client", {"c"}, [("z", [], ["c"], 2)]),
    }
    assert map_rule("z", checkers).checker == "http-client"


def test_a_tie_at_the_top_is_not_verifiable_even_with_a_lower_third() -> None:
    checkers = {
        "logging": PhraseChecker("logging", {"a"}, [("z", [], ["a"], 3)]),
        "exceptions": PhraseChecker("exceptions", {"b"}, [("z", [], ["b"], 3)]),
        "http-client": PhraseChecker("http-client", {"c"}, [("z", [], ["c"], 2)]),
    }
    assert map_rule("z", checkers) == UNMAPPED


def test_specificity_zero_and_negative_are_ordinary_numbers() -> None:
    checkers = {
        "logging": PhraseChecker("logging", {"a"}, [("z", [], ["a"], -1)]),
        "http-client": PhraseChecker("http-client", {"c"}, [("z", [], ["c"], -2)]),
    }
    assert map_rule("z", checkers).checker == "logging"
    assert map_rule("z", {"logging": checkers["logging"]}).checker == "logging"


def test_a_single_match_is_enough() -> None:
    only = PhraseChecker("logging", {"print"}, [("print", [], ["print"], 1)])
    other = PhraseChecker("http-client", {"requests"}, [("requests", [], ["requests"], 9)])
    assert map_rule("print", {"logging": only, "http-client": other}).checker == "logging"


def test_a_rule_no_checker_matches_is_not_verifiable_and_still_listed() -> None:
    # AC-F2.7 and AC-F4.8: "Always keep functions small" is a rule with no checker.
    rule = only_rule("Always keep functions small\n", canonical_checkers())
    assert (rule.line, rule.text) == (1, "Always keep functions small")
    assert (rule.checker, rule.match) == (None, None)
    assert not rule.disabled
    assert not rule.ignored


def test_no_checkers_at_all_maps_nothing() -> None:
    assert map_rule("use httpx", {}) == UNMAPPED
    assert only_rule("Use httpx for HTTP calls.\n").checker is None


def test_mapped_is_a_named_pair() -> None:
    assert Mapped(None, None) == UNMAPPED
    assert UNMAPPED.checker is None
    assert UNMAPPED.match is None


def test_checkers_are_tried_in_sorted_id_order() -> None:
    log: list[str] = []
    map_rule("use httpx", canonical_checkers(log))
    assert log == sorted(cid for cid, _, _ in CANONICAL)


def test_every_checker_is_run_even_after_a_match() -> None:
    log: list[str] = []
    map_rule("use logging, not print.", canonical_checkers(log))
    assert sorted(log) == sorted(cid for cid, _, _ in CANONICAL)


# --- I-10 RuleMatch validity: a broken checker fails closed --------------------------------

OPTS = frozenset({"a", "b"})


def _bypass(match: RuleMatch, **fields: object) -> RuleMatch:
    for name, value in fields.items():
        object.__setattr__(match, name, value)
    return match


def _bad_matches() -> dict[str, object]:
    ok = RuleMatch(frozenset({"a"}), frozenset(), 1)
    return {
        "option outside options": RuleMatch(frozenset({"c"}), frozenset(), 1),
        "prohibited outside options": RuleMatch(frozenset({"a"}), frozenset({"c"}), 1),
        "empty": _bypass(RuleMatch(frozenset({"a"}), frozenset(), 1), preferred=frozenset()),
        "overlap": _bypass(RuleMatch(frozenset({"a"}), frozenset({"b"}), 1), prohibited=OPTS),
        "preferred not a frozenset": _bypass(ok, preferred={"a"}),
        "prohibited not a frozenset": _bypass(ok, prohibited={"b"}),
        "bool specificity": _bypass(ok, specificity=True),
        "float specificity": _bypass(ok, specificity=1.0),
        "not a RuleMatch": ("a", "b", 1),
        "a dict": {"preferred": {"a"}},
        "a truthy string": "match",
    }


@pytest.mark.parametrize("kind", _bad_matches())
@pytest.mark.parametrize("checker_id", CHECKER_IDS)
def test_an_invalid_match_is_that_checkers_component_error(
    kind: str, checker_id: CheckerId
) -> None:
    broken = ScriptedChecker(checker_id, OPTS, _bad_matches()[kind])
    with pytest.raises(ComponentError) as caught:
        map_rule("anything", {checker_id: broken})
    assert caught.value.component == f"checker:{checker_id}"
    assert caught.value.message == "match_rule returned an invalid match"
    with pytest.raises(ComponentError):
        only_rule("Use anything.\n", {checker_id: broken})


def test_a_valid_match_inside_the_options_is_accepted() -> None:
    both = RuleMatch(frozenset({"a"}), frozenset({"b"}), 1)
    assert map_rule("x", {"logging": ScriptedChecker("logging", OPTS, both)}).match == both


@pytest.mark.parametrize(
    "error",
    [ValueError("secret rule text"), KeyError("k"), SystemExit(0), MemoryError(), RuntimeError()],
    ids=lambda e: type(e).__name__,
)
def test_a_checker_that_raises_is_that_checkers_component_error(error: BaseException) -> None:
    broken = ScriptedChecker("exceptions", OPTS, error)
    with pytest.raises(ComponentError) as caught:
        map_rule("secret rule text", {"exceptions": broken})
    assert caught.value.component == "checker:exceptions"
    assert caught.value.message == "match_rule failed"
    assert "secret" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_a_keyboard_interrupt_from_a_checker_propagates() -> None:
    broken = ScriptedChecker("exceptions", OPTS, KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        map_rule("x", {"exceptions": broken})


def test_the_first_broken_checker_in_id_order_is_reported() -> None:
    checkers = {
        "type-hints": ScriptedChecker("type-hints", OPTS, RuntimeError()),
        "exceptions": ScriptedChecker("exceptions", OPTS, RuntimeError()),
    }
    with pytest.raises(ComponentError) as caught:
        map_rule("x", checkers)
    assert caught.value.component == "checker:exceptions"


def test_a_broken_checker_is_not_hidden_by_a_tie_or_a_winner() -> None:
    good = PhraseChecker("logging", {"a"}, [("x", [], ["a"], 9)])
    broken = ScriptedChecker("money", OPTS, RuntimeError())
    with pytest.raises(ComponentError):
        map_rule("x", {"logging": good, "money": broken})


# --- AC-E.20: duplicates merge ---------------------------------------------------------------


def _dup_lines() -> str:
    lines = ["# Rules", "", "- Use httpx for HTTP calls.", ""]
    lines += [f"Prose line {n}." if n % 2 else "" for n in range(5, 20)]
    lines += ["- Use httpx for HTTP calls.", ""]
    return "\n".join(lines)


def test_a_duplicate_rule_is_one_rule_at_its_first_line_with_also_at() -> None:
    text = _dup_lines()
    assert text.split("\n")[2] == "- Use httpx for HTTP calls."
    assert text.split("\n")[19] == "- Use httpx for HTTP calls."
    (rule,) = rules_of([instruction_file("AGENTS.md", text)], canonical_checkers())
    assert (rule.id, rule.file, rule.line, rule.also_at) == ("AGENTS.md:3", "AGENTS.md", 3, (20,))
    assert rule.checker == "http-client"


def test_three_occurrences_list_the_later_lines_in_order() -> None:
    text = "Use httpx for HTTP calls.\n\nUse httpx for HTTP calls.\n\nUse httpx for HTTP calls.\n"
    (rule,) = rules_of([instruction_file("AGENTS.md", text)])
    assert (rule.line, rule.also_at) == (1, (3, 5))


def test_duplicates_ignore_case_whitespace_emphasis_and_backticks() -> None:
    text = (
        "Use httpx for HTTP calls.\n\n"
        "USE  `httpx`  for **HTTP** calls.\n\n"
        "use httpx\tfor http calls.\n"
    )
    (rule,) = rules_of([instruction_file("AGENTS.md", text)])
    assert (rule.line, rule.also_at) == (1, (3, 5))
    assert rule.text == "Use httpx for HTTP calls."  # the first occurrence's own text


def test_different_text_is_a_different_rule() -> None:
    text = "Use httpx for HTTP calls.\n\nUse httpx for all HTTP calls.\n"
    rules = rules_of([instruction_file("AGENTS.md", text)])
    assert [(r.line, r.also_at) for r in rules] == [(1, ()), (3, ())]


def test_the_same_text_in_two_files_is_two_rules() -> None:
    files = [instruction_file(p, "Use httpx for HTTP calls.\n") for p in ("AGENTS.md", "CLAUDE.md")]
    rules = rules_of(files)
    assert [(r.id, r.also_at) for r in rules] == [("AGENTS.md:1", ()), ("CLAUDE.md:1", ())]


def test_two_equal_sentences_on_one_line_are_one_rule_with_a_plain_id() -> None:
    (rule,) = rules_of([instruction_file("AGENTS.md", "Use httpx. Use httpx.\n")])
    assert (rule.id, rule.line, rule.also_at) == ("AGENTS.md:1", 1, ())


def test_a_rule_alone_on_its_line_has_a_file_line_id_even_beside_a_shared_line() -> None:
    text = "- Use a. Use b.\n- Use c.\n"
    assert [r.id for r in rules_of([instruction_file("AGENTS.md", text)])] == [
        "AGENTS.md:1:3",
        "AGENTS.md:1:10",
        "AGENTS.md:2",
    ]


def test_every_rule_on_a_shared_line_gets_file_line_column_ids() -> None:
    text = "Use requests. Never use requests. Use httpx.\n"
    rules = rules_of([instruction_file("AGENTS.md", text)])
    assert [(r.id, r.line) for r in rules] == [
        ("AGENTS.md:1:1", 1),
        ("AGENTS.md:1:15", 1),
        ("AGENTS.md:1:35", 1),
    ]
    assert len({r.id for r in rules}) == 3


def test_ids_stay_unique_per_side_and_the_same_line_in_two_files_is_not_shared() -> None:
    files = [instruction_file(p, "Use a. Use b.\n") for p in ("A.md", "B.md")]
    ids = [r.id for r in rules_of(files)]
    assert ids == ["A.md:1:1", "A.md:1:8", "B.md:1:1", "B.md:1:8"]
    only = rules_of([instruction_file("A.md", "Use a.\n"), instruction_file("B.md", "Use b.\n")])
    assert [r.id for r in only] == ["A.md:1", "B.md:1"]


def test_identity_is_unchanged_by_the_column_in_an_id() -> None:
    # Comparison identity stays (file, normalized text); the id is only a label.
    (first, second) = rules_of([instruction_file("AGENTS.md", "Use a. Use b.\n")])
    assert rule_identity(first.file, first.normalized_text) == ("AGENTS.md", "use a.")
    assert rule_identity(second.file, second.normalized_text) == ("AGENTS.md", "use b.")


def test_two_sentences_on_one_line_conflict_by_their_distinct_ids() -> None:
    # I-13 "C6 conflict cap and rule ids": distinct ids, and a conflict reference resolves.
    text = "Use requests. Use httpx.\n"
    result = extract_rules([instruction_file("AGENTS.md", text)], make_policy(), http_only())
    first, second = result.rules
    assert (first.id, second.id) == ("AGENTS.md:1:1", "AGENTS.md:1:15")
    assert first.id != second.id
    assert [(c.rules, c.checker) for c in result.conflicts] == [
        (("AGENTS.md:1:1", "AGENTS.md:1:15"), "http-client")
    ]
    by_id = {r.id: r for r in result.rules}
    assert all(by_id[i].checker == "http-client" for i in result.conflicts[0].rules)
    assert result.conflict_lookup.partners(first.id) == (second.id,)
    assert result.conflict_lookup.partners(second.id) == (first.id,)


def test_a_conflict_between_two_rules_on_one_line_names_both_distinct_ids() -> None:
    # The TE's repro: one line, "Use requests. Never use requests."
    text = "Use requests. Never use requests.\n"
    result = extract_rules([instruction_file("AGENTS.md", text)], make_policy(), http_only())
    assert [r.id for r in result.rules] == ["AGENTS.md:1:1", "AGENTS.md:1:15"]
    assert [(c.rules, c.checker) for c in result.conflicts] == [
        (("AGENTS.md:1:1", "AGENTS.md:1:15"), "http-client")
    ]
    assert set(result.conflicts[0].rules) == {r.id for r in result.rules}
    assert result.conflicts_dropped == 0


@pytest.mark.parametrize("shares_line", [False, True])
def test_rule_id_format(shares_line: bool) -> None:
    got = rule_id("a/B.md", 12, 7, shares_line=shares_line)
    assert got == ("a/B.md:12:7" if shares_line else "a/B.md:12")


def test_duplicates_in_a_file_do_not_conflict_with_themselves() -> None:
    text = "Use requests.\n\nUse requests.\n"
    assert (
        extract_rules([instruction_file("AGENTS.md", text)], make_policy(), http_only()).conflicts
        == ()
    )


def test_rule_identity_is_the_file_and_the_normalized_text() -> None:
    assert rule_identity("AGENTS.md", "use x.") == ("AGENTS.md", "use x.")
    assert rule_identity("AGENTS.md", "use x.") != rule_identity("CLAUDE.md", "use x.")
    assert rule_identity("AGENTS.md", "use x.") != rule_identity("AGENTS.md", "use y.")


# --- ignored: I-7 markers and config ignore entries --------------------------------------------


def test_a_marker_on_the_rules_line_ignores_it() -> None:
    policy = make_policy(markers={"AGENTS.md": ((1, False),)})
    text = f"- Use httpx for HTTP calls. {MARKER}\n"
    (rule,) = rules_of([instruction_file("AGENTS.md", text)], None, policy)
    assert rule.ignored
    assert rule.normalized_text == "use httpx for http calls."  # the marker is not rule text


def test_a_marker_alone_on_the_line_above_ignores_the_next_rule() -> None:
    policy = make_policy(markers={"AGENTS.md": ((1, True),)})
    text = f"{MARKER}\n- Use httpx for HTTP calls.\n\n- Use pytest.\n"
    first, second = rules_of([instruction_file("AGENTS.md", text)], None, policy)
    assert (first.ignored, second.ignored) == (True, False)


def test_a_same_line_marker_does_not_reach_the_next_line() -> None:
    policy = make_policy(markers={"AGENTS.md": ((1, False),)})
    text = f"- Use pytest. {MARKER}\n- Use httpx.\n"
    first, second = rules_of([instruction_file("AGENTS.md", text)], None, policy)
    assert (first.ignored, second.ignored) == (True, False)


def test_markers_come_from_the_policy_side_only() -> None:
    # SR C-1: the file carries a marker but the policy side has none for it, so a gated
    # run must not honour it, even for a file the policy never mentions.
    text = f"- Use httpx for HTTP calls. {MARKER}\n"
    (rule,) = rules_of([instruction_file("AGENTS.md", text)], None, make_policy(markers={}))
    assert not rule.ignored
    other = make_policy(markers={"CLAUDE.md": ((1, False),)})
    (rule,) = rules_of([instruction_file("AGENTS.md", text)], None, other)
    assert not rule.ignored


def test_a_policy_marker_applies_even_if_this_sides_file_lacks_it() -> None:
    policy = make_policy(markers={"AGENTS.md": ((1, False),)})
    (rule,) = rules_of(
        [instruction_file("AGENTS.md", "- Use httpx for HTTP calls.\n")], None, policy
    )
    assert rule.ignored


def test_an_unattached_marker_is_reported_in_the_file_results() -> None:
    policy = make_policy(markers={"AGENTS.md": ((3, False),)})
    result = extract_rules([instruction_file("AGENTS.md", "- Use httpx.\n\nProse.\n")], policy, {})
    assert [(f.path, f.unattached_markers) for f in result.files] == [("AGENTS.md", (3,))]
    assert [r.ignored for r in result.rules] == [False]


def test_a_config_entry_by_file_and_line_ignores_the_rule() -> None:
    policy = make_policy(ignores=(IgnoreEntry(file="AGENTS.md", line=3, text=None),))
    text = "# T\n\n- Use httpx for HTTP calls.\n\n- Use pytest.\n"
    first, second = rules_of([instruction_file("AGENTS.md", text)], None, policy)
    assert (first.ignored, second.ignored) == (True, False)


def test_a_config_entry_can_name_a_duplicates_later_line() -> None:
    policy = make_policy(ignores=(IgnoreEntry(file="AGENTS.md", line=3, text=None),))
    text = "Use httpx for HTTP calls.\n\nUse httpx for HTTP calls.\n"
    (rule,) = rules_of([instruction_file("AGENTS.md", text)], None, policy)
    assert (rule.line, rule.also_at, rule.ignored) == (1, (3,), True)


def test_a_marker_on_a_later_duplicate_ignores_the_merged_rule() -> None:
    policy = make_policy(markers={"AGENTS.md": ((3, False),)})
    text = f"Use httpx for HTTP calls.\n\nUse httpx for HTTP calls. {MARKER}\n"
    (rule,) = rules_of([instruction_file("AGENTS.md", text)], None, policy)
    assert rule.ignored


@pytest.mark.parametrize(
    "entry",
    [
        IgnoreEntry(file="CLAUDE.md", line=1, text=None),
        IgnoreEntry(file="AGENTS.md", line=2, text=None),
        IgnoreEntry(file=None, line=None, text="Use pytest."),
        IgnoreEntry(file=None, line=None, text="Use httpx for HTTP calls"),
        IgnoreEntry(file=None, line=None, text=None),
        IgnoreEntry(file="AGENTS.md", line=None, text="Use pytest."),
        IgnoreEntry(file="CLAUDE.md", line=None, text="Use httpx for HTTP calls."),
        IgnoreEntry(file=None, line=1, text="Use pytest."),
    ],
)
def test_a_config_entry_that_names_another_rule_ignores_nothing(entry: IgnoreEntry) -> None:
    policy = make_policy(ignores=(entry,))
    (rule,) = rules_of([instruction_file("AGENTS.md", "Use httpx for HTTP calls.\n")], None, policy)
    assert not rule.ignored


@pytest.mark.parametrize(
    "entry",
    [
        IgnoreEntry(file=None, line=None, text="Use httpx for HTTP calls."),
        IgnoreEntry(file=None, line=None, text="  USE  httpx  FOR http calls. "),
        IgnoreEntry(file=None, line=None, text="`Use` **httpx** for HTTP calls."),
        IgnoreEntry(file="AGENTS.md", line=None, text="Use httpx for HTTP calls."),
        IgnoreEntry(file=None, line=1, text=None),
        IgnoreEntry(file="AGENTS.md", line=1, text="Use httpx for HTTP calls."),
        IgnoreEntry(file="AGENTS.md", line=None, text=None),
    ],
)
def test_a_config_entry_matches_when_every_field_it_sets_matches(entry: IgnoreEntry) -> None:
    policy = make_policy(ignores=(entry,))
    (rule,) = rules_of([instruction_file("AGENTS.md", "Use httpx for HTTP calls.\n")], None, policy)
    assert rule.ignored


def test_a_text_entry_ignores_the_rule_in_every_file() -> None:
    policy = make_policy(
        ignores=(IgnoreEntry(file=None, line=None, text="Use httpx for HTTP calls."),)
    )
    files = [
        instruction_file(p, "Use httpx for HTTP calls.\n") for p in ("AGENTS.md", "b/CLAUDE.md")
    ]
    assert [r.ignored for r in rules_of(files, None, policy)] == [True, True]


def test_the_second_config_entry_can_match() -> None:
    policy = make_policy(
        ignores=(
            IgnoreEntry(file="X.md", line=1, text=None),
            IgnoreEntry(file="AGENTS.md", line=1, text=None),
        )
    )
    (rule,) = rules_of([instruction_file("AGENTS.md", "Use httpx.\n")], None, policy)
    assert rule.ignored


def test_an_ignored_rule_is_still_mapped() -> None:
    policy = make_policy(ignores=(IgnoreEntry(file="AGENTS.md", line=1, text=None),))
    (rule,) = rules_of(
        [instruction_file("AGENTS.md", "Use httpx for HTTP calls.\n")], canonical_checkers(), policy
    )
    assert (rule.ignored, rule.checker) == (True, "http-client")


# --- scope, ids, order --------------------------------------------------------------------------


@pytest.mark.parametrize("scope", ["", "services", "services/billing"])
def test_scope_dir_comes_from_the_instruction_file(scope: str) -> None:
    assert only_rule("Use httpx.\n", scope_dir=scope).scope_dir == scope


def test_rules_are_sorted_by_file_then_line_whatever_the_input_order() -> None:
    files = [
        instruction_file("services/AGENTS.md", "Use b.\n\nUse c.\n", "services"),
        instruction_file("CLAUDE.md", "Use d.\n"),
        instruction_file("AGENTS.md", "Prose.\n\nUse a.\n"),
    ]
    expected = ["AGENTS.md:3", "CLAUDE.md:1", "services/AGENTS.md:1", "services/AGENTS.md:3"]
    for order in itertools.permutations(files):
        assert [r.id for r in rules_of(order)] == expected


def test_rule_fields_come_from_the_first_occurrence() -> None:
    (rule,) = rules_of([instruction_file("a/AGENTS.md", "x\n\n- Use  **HTTPX**  here.\n", "a")])
    assert rule == Rule(
        id="a/AGENTS.md:3",
        file="a/AGENTS.md",
        line=3,
        also_at=(),
        text="Use **HTTPX** here.",
        normalized_text="use httpx here.",
        checker=None,
        match=None,
        scope_dir="a",
        ignored=False,
        disabled=False,
    )


def test_a_file_with_no_rules_gives_none_but_is_still_reported() -> None:
    result = extract_rules([instruction_file("AGENTS.md", "Just prose.\n")], make_policy(), {})
    assert result.rules == ()
    assert result.conflicts == ()
    assert [f.path for f in result.files] == ["AGENTS.md"]


def test_no_files_no_rules() -> None:
    result = extract_rules([], make_policy(), canonical_checkers())
    assert (result.rules, result.conflicts, result.files, result.conflicts_dropped) == (
        (),
        (),
        (),
        0,
    )


def test_the_per_file_rule_cap_is_counted_in_the_file_results() -> None:
    text = "".join(f"- Use thing number {n}.\n" for n in range(MAX_RULES_PER_FILE + 3))
    result = extract_rules([instruction_file("AGENTS.md", text)], make_policy(), {})
    assert len(result.rules) == MAX_RULES_PER_FILE
    assert result.files[0].rules_dropped == 3


def test_mapping_never_calls_a_checker_for_an_empty_file() -> None:
    log: list[str] = []
    extract_rules(
        [instruction_file("AGENTS.md", "Prose only.\n")], make_policy(), canonical_checkers(log)
    )
    assert log == []


def test_each_distinct_rule_is_mapped_once() -> None:
    log: list[str] = []
    text = "Use httpx for HTTP calls.\n\nUse httpx for HTTP calls.\n"
    extract_rules([instruction_file("AGENTS.md", text)], make_policy(), canonical_checkers(log))
    assert len(log) == len(CANONICAL)


# --- errors -----------------------------------------------------------------------------------


def test_a_repeated_file_path_is_a_rules_error() -> None:
    files = [instruction_file("AGENTS.md", "Use a.\n"), instruction_file("AGENTS.md", "Use b.\n")]
    with pytest.raises(ComponentError) as caught:
        extract_rules(files, make_policy(), {})
    assert caught.value.component == "rules"
    assert caught.value.message == "an instruction file was given twice"


def test_a_checker_missing_from_the_policy_is_a_rules_error() -> None:
    policy = make_policy()
    object.__setattr__(
        policy,
        "checkers",
        MappingProxyType({k: v for k, v in policy.checkers.items() if k != "logging"}),
    )
    with pytest.raises(ComponentError) as caught:
        extract_rules(
            [instruction_file("AGENTS.md", "Use logging, not print.\n")],
            policy,
            canonical_checkers(),
        )
    assert caught.value.component == "rules"
    assert caught.value.message == "a checker is missing from the policy"
    # A rule that no checker takes needs nothing from the policy.
    assert rules_of(
        [instruction_file("AGENTS.md", "Always keep it small.\n")], canonical_checkers(), policy
    )


def test_a_broken_checker_fails_the_whole_extraction() -> None:
    checkers = {"exceptions": ScriptedChecker("exceptions", OPTS, RuntimeError())}
    with pytest.raises(ComponentError) as caught:
        rules_of([instruction_file("AGENTS.md", "Use a.\n")], checkers)
    assert caught.value.component == "checker:exceptions"


# --- conflicts through extraction -----------------------------------------------------------------


def http_only() -> dict[str, Checker]:
    return {
        "http-client": PhraseChecker(
            "http-client",
            OPTIONS["http-client"],
            [
                ("never use requests", [], ["requests"], 3),
                ("use requests", ["requests"], [], 2),
                ("use httpx", ["httpx"], [], 2),
            ],
        )
    }


def test_same_file_use_and_never_use_requests_is_a_conflict() -> None:
    # AC-E.21: "Use requests" (line 3) and "Never use requests" (line 8).
    lines = ["# Rules", "", "Use requests.", "", "", "", "", "Never use requests.", ""]
    result = extract_rules(
        [instruction_file("AGENTS.md", "\n".join(lines))], make_policy(), http_only()
    )
    assert [(r.line, r.checker) for r in result.rules] == [(3, "http-client"), (8, "http-client")]
    assert [(c.rules, c.checker) for c in result.conflicts] == [
        (("AGENTS.md:3", "AGENTS.md:8"), "http-client")
    ]


def test_root_and_subfolder_rules_conflict_and_the_rules_are_unchanged() -> None:
    # AC-E.4: root "Use requests" and services/billing "Use httpx".
    files = [
        instruction_file("AGENTS.md", "Use requests.\n"),
        instruction_file("services/billing/AGENTS.md", "Use httpx.\n", "services/billing"),
    ]
    result = extract_rules(files, make_policy(), http_only())
    assert [(c.rules, c.checker) for c in result.conflicts] == [
        (("AGENTS.md:1", "services/billing/AGENTS.md:1"), "http-client")
    ]
    assert [r.checker for r in result.rules] == ["http-client", "http-client"]


def test_root_files_with_different_preferred_options_conflict() -> None:
    # AC-E.3: root AGENTS.md "Use requests for HTTP calls",
    # root CLAUDE.md "Use httpx for HTTP calls".
    files = [
        instruction_file("AGENTS.md", "Use requests for HTTP calls.\n"),
        instruction_file("CLAUDE.md", "Use httpx for HTTP calls.\n"),
    ]
    result = extract_rules(files, make_policy(), http_only())
    assert [c.rules for c in result.conflicts] == [("AGENTS.md:1", "CLAUDE.md:1")]


def test_a_duplicate_does_not_conflict_but_a_conflict_names_the_merged_rule() -> None:
    # AC-E.20 with a conflicting rule elsewhere: the merged rule is listed once, at line 3.
    text = "\n".join(
        ["", "", "Use httpx.", "", "Never use requests.", "", "Use requests.", "", "Use httpx."]
    )
    result = extract_rules([instruction_file("AGENTS.md", text)], make_policy(), http_only())
    assert [(r.line, r.also_at) for r in result.rules] == [(3, (9,)), (5, ()), (7, ())]
    assert [c.rules for c in result.conflicts] == [
        ("AGENTS.md:3", "AGENTS.md:7"),  # httpx and requests are both preferred
        ("AGENTS.md:5", "AGENTS.md:7"),  # "Never use requests" against "Use requests"
    ]


def test_disabled_and_unmapped_rules_have_no_conflicts() -> None:
    policy = make_policy(enabled={"http-client": False})
    files = [
        instruction_file("AGENTS.md", "Use requests.\n"),
        instruction_file("CLAUDE.md", "Use httpx.\n"),
    ]
    assert extract_rules(files, policy, http_only()).conflicts == ()
    assert extract_rules(files, make_policy(), {}).conflicts == ()


def test_the_conflict_cap_is_reported_by_the_extraction() -> None:
    side = 33
    files = [instruction_file(f"a{n}/AGENTS.md", "Use requests.\n", f"a{n}") for n in range(side)]
    files += [instruction_file(f"b{n}/AGENTS.md", "Use httpx.\n", "") for n in range(side)]
    result = extract_rules(files, make_policy(), http_only())
    assert side * side > MAX_CONFLICTS
    assert len(result.conflicts) == MAX_CONFLICTS
    assert result.conflicts_dropped == side * side - MAX_CONFLICTS
    assert all(result.conflict_lookup.total(r.id) > 0 for r in result.rules)
    # Rules whose pairs the cap left unlisted still know their partners (conflict_with).
    assert side > MAX_CONFLICT_WITH
    lookup = result.conflict_lookup
    assert all(len(lookup.partners(r.id)) == MAX_CONFLICT_WITH for r in result.rules)
    assert all(lookup.total(r.id) == side for r in result.rules)
    listed = {i for c in result.conflicts for i in c.rules}
    assert len(listed) < len(result.rules)


def _budget_files(side: int = 4) -> list[InstructionFile]:
    """``side`` rules of one option in their own folders and ``side`` of another at the root.

    Groups run in sorted key order, so the "httpx" folders come first and the shared
    "requests" group is last: the last pair evaluated is (a3, that group), a conflict.

    The first are one group each, the second share one: ``side + 1`` groups, so
    ``(side + 1) * side / 2`` pair evaluations.
    """
    files = [instruction_file(f"a{n}/AGENTS.md", "Use httpx.\n", f"a{n}") for n in range(side)]
    files += [instruction_file(f"b{n}/AGENTS.md", "Use requests.\n", "") for n in range(side)]
    return files


def test_exactly_the_pair_budget_gives_no_note_and_one_more_gives_one() -> None:
    side = 4
    pairs = (side + 1) * side // 2
    files = _budget_files(side)
    exact = extract_rules(files, make_policy(), http_only(), max_conflict_pairs=pairs)
    assert exact.notes == ()
    assert exact.conflict_lookup.incomplete == 0
    assert exact == extract_rules(files, make_policy(), http_only())

    short = extract_rules(files, make_policy(), http_only(), max_conflict_pairs=pairs - 1)
    lookup = short.conflict_lookup
    # The last pair is (a3, the "b" group): both groups are incomplete, nothing else.
    expected = {"a3/AGENTS.md:1"} | {f"b{n}/AGENTS.md:1" for n in range(side)}
    assert {r.id for r in short.rules if lookup.is_incomplete(r.id)} == expected
    assert lookup.incomplete == len(expected) == 5
    assert short.notes == ("conflict check stopped at the limit; 5 rules not fully checked",)
    for rule in short.rules:
        assert lookup.total(rule.id) >= len(lookup.partners(rule.id))
    # a0 to a2 conflict with all four "b" rules; each "b" rule with a0 to a2 and, were it run,
    # a3 (a lower bound); a3 itself got no pair.
    totals = {r.id: lookup.total(r.id) for r in short.rules}
    assert [totals[f"a{n}/AGENTS.md:1"] for n in range(side)] == [side, side, side, 0]
    assert [totals[f"b{n}/AGENTS.md:1"] for n in range(side)] == [side - 1] * side


def test_a_stopped_conflict_check_lists_what_it_found_and_nothing_twice() -> None:
    side = 4
    pairs = (side + 1) * side // 2
    files = _budget_files(side)
    full = extract_rules(files, make_policy(), http_only())
    short = extract_rules(files, make_policy(), http_only(), max_conflict_pairs=pairs - 1)
    assert len(full.conflicts) == side * side
    # The one unevaluated pair is (a3, the b group): side conflicts fewer, none dropped as unlisted.
    assert len(short.conflicts) == side * side - side
    assert short.conflicts_dropped == 0
    assert set(short.conflicts) <= set(full.conflicts)


def test_reordering_the_files_does_not_change_the_extraction_or_its_cutoff() -> None:
    files = _budget_files(5)
    for budget in (0, 3, 7, 14, 15, 100):
        expected = extract_rules(files, make_policy(), http_only(), max_conflict_pairs=budget)
        for order in (files[::-1], files[3:] + files[:3], files[1::2] + files[0::2]):
            got = extract_rules(order, make_policy(), http_only(), max_conflict_pairs=budget)
            assert got == expected
            assert got.conflict_lookup == expected.conflict_lookup


def test_a_rule_in_a_too_deep_folder_is_incomplete_and_noted() -> None:
    # The C6 backstop for I-13 C6 item 6: C4 should have skipped this file, but if one arrives
    # its rules are not compared (so not conflicting) and are counted, with the note.
    deep = "d" * MAX_SCOPE_DIR_BYTES
    files = [
        instruction_file("AGENTS.md", "Use httpx.\n"),
        instruction_file("ok/AGENTS.md", "Use requests.\n", deep),
        instruction_file("big/AGENTS.md", "Use requests.\n", deep + "d"),
    ]
    got = extract_rules(files, make_policy(), http_only())
    lookup = got.conflict_lookup
    assert [r.id for r in got.rules if lookup.is_incomplete(r.id)] == ["big/AGENTS.md:1"]
    assert lookup.total("big/AGENTS.md:1") == 0
    assert [c.rules for c in got.conflicts] == [("AGENTS.md:1", "ok/AGENTS.md:1")]
    assert got.notes == ("conflict check stopped at the limit; 1 rule not fully checked",)


def test_the_extractor_uses_the_default_budget() -> None:
    assert inspect.signature(extract_rules).parameters["max_conflict_pairs"].default == (
        MAX_CONFLICT_PAIRS
    )


# --- the I-11 Extractor ---------------------------------------------------------------------------


def test_rule_extractor_returns_the_full_extraction_unchanged() -> None:
    # I-13 C6 item 3: the Extractor returns what extract_rules produces, nothing trimmed.
    extractor: Extractor = RuleExtractor()
    policy = make_policy(markers={"AGENTS.md": ((9, False),)})
    long_file = "".join(f"- Use thing number {n}.\n" for n in range(MAX_RULES_PER_FILE + 2))
    files = [
        instruction_file("AGENTS.md", "Use requests.\n"),
        instruction_file("CLAUDE.md", "Use httpx.\n"),
        instruction_file("LONG.md", long_file),
    ]
    got = extractor.extract(files, policy, http_only())
    assert isinstance(got, Extraction)
    assert got.rules == extract_rules(files, policy, http_only()).rules
    assert got.conflicts == extract_rules(files, policy, http_only()).conflicts
    assert len(got.conflicts) == 1
    assert got.conflicts_dropped == 0
    assert [(f.path, f.rules_dropped, f.candidates_dropped) for f in got.files] == [
        ("AGENTS.md", 0, 0),
        ("CLAUDE.md", 0, 0),
        ("LONG.md", 2, 0),
    ]
    assert got.unattached_markers == (("AGENTS.md", 9),)
    assert got.conflict_lookup.partners("AGENTS.md:1") == ("CLAUDE.md:1",)


def test_unattached_markers_are_listed_by_file_in_path_order() -> None:
    policy = make_policy(markers={"B.md": ((2, True), (4, False)), "A.md": ((7, False),)})
    files = [instruction_file("B.md", "- Use x.\n"), instruction_file("A.md", "- Use y.\n")]
    got = extract_rules(files, policy, {})
    assert got.unattached_markers == (("A.md", 7), ("B.md", 2), ("B.md", 4))
    assert extract_rules(files, make_policy(), {}).unattached_markers == ()


def test_extraction_is_a_frozen_value() -> None:
    result = extract_rules([], make_policy(), {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.rules = ()  # type: ignore[misc]


def test_the_module_exports_its_public_names() -> None:
    assert sorted(mapping.__all__) == sorted(
        [
            "Mapped",
            "RuleExtractor",
            "extract_rules",
            "map_rule",
            "rule_id",
            "rule_identity",
        ]
    )
