"""Unit tests for the shared rule-sentence reading, conventiondrift.checkers.phrases (T-016)."""

import ast
import re
import sys
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path

import pytest
from checker_support import MIB, assert_linear, best_time

from conventiondrift.checkers.phrases import (
    BREAK_MARKS,
    BREAK_WORDS,
    CALL_SUFFIX,
    MERGED,
    NEGATIONS,
    TOKEN,
    TRAILING_PAIRS,
    TRAILING_WORDS,
    VERB_CUES,
    Mention,
    _read,
    classify,
    clauses,
    first_cue,
    is_negated,
    last_trailing_cue,
)
from conventiondrift.model import RuleMatch

OPTIONS = frozenset({"a", "b", "c"})


def find(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    """A finder: the words ``a``, ``b`` and ``c`` are the options of the same name."""
    for index, word in enumerate(clause):
        if word in OPTIONS:
            yield index, word


def rule(*, preferred: str = "", prohibited: str = "", specificity: int) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), specificity)


# --- tokens and clauses ---------------------------------------------------------------------

# Each mark or word that ends a clause (INTERFACES I-10, "Negation in phrases.py").
BREAKS = [
    ". ",
    ";",
    ":",
    "(",
    ")",
    "\u2013",  # en dash
    "\u2014",  # em dash
    " - ",  # a hyphen with a space on both sides
    " -- ",
    " --- ",
    " but ",
    " then ",
    " instead ",
    " however ",
]
# What does not end a clause: negation carries through each of these.
NON_BREAKS = [" and ", " or ", " nor ", ", ", ",", " , ", " also ", " -x ", " x- "]


@pytest.mark.parametrize("mark", BREAKS)
def test_each_break_ends_the_negated_clause(mark: str) -> None:
    assert classify(f"never a{mark}b", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )
    assert clauses(f"never a{mark}b") == (("never", "a"), ("b",))


@pytest.mark.parametrize("mark", NON_BREAKS)
def test_each_non_break_keeps_the_negation_going(mark: str) -> None:
    got = clauses(f"never a{mark}b")
    assert len(got) == 1
    assert classify(f"never a{mark}b", find, OPTIONS) == rule(prohibited="ab", specificity=2)


def test_and_or_nor_and_commas_all_negate_the_whole_list() -> None:
    # "no print or requests" style: every item in the list is prohibited.
    assert classify("never a or b", find, OPTIONS) == rule(prohibited="ab", specificity=2)
    assert classify("never a, b", find, OPTIONS) == rule(prohibited="ab", specificity=2)
    assert classify("never a nor b", find, OPTIONS) == rule(prohibited="ab", specificity=2)
    assert classify("avoid a and b", find, OPTIONS) == rule(prohibited="ab", specificity=2)


def test_clauses_before_a_cue_are_not_negated_even_across_a_comma() -> None:
    assert classify("use a, not b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify("use a, use b, never c", find, OPTIONS) == rule(
        preferred="ab", prohibited="c", specificity=3
    )
    assert classify("use a, never b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )


def test_a_negation_runs_through_a_comma_to_the_end_of_the_clause() -> None:
    # The negation reaches "b" after the comma: "b" is no positive verb cue. Only a break
    # stops it.
    assert classify("never use a, b. use c", find, OPTIONS) == rule(
        preferred="c", prohibited="ab", specificity=3
    )
    assert classify("never use a, b; use c", find, OPTIONS) == rule(
        preferred="c", prohibited="ab", specificity=3
    )
    assert classify("no a, b or c", find, OPTIONS) is None  # all three prohibited: nothing allowed
    assert classify("no a, b or c", find, frozenset("abcd")) == rule(
        prohibited="abc", specificity=3
    )


def test_instead_of_and_rather_than_prohibit_what_follows() -> None:
    assert classify("use a instead of b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify("use a rather than b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert clauses("use a rather than b") == (("use", "a", "rather than", "b"),)
    assert clauses("use a instead of b") == (("use", "a"), ("instead of", "b"))


def test_a_bare_instead_only_ends_the_clause() -> None:
    assert clauses("don't a, instead use b") == (("don't", "a"), ("use", "b"))
    assert classify("don't a, instead use b", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )
    # "instead" at the very end, or followed by something other than "of", is no cue.
    assert clauses("use a instead") == (("use", "a"),)
    assert clauses("instead of") == (("instead of",),)
    assert clauses("instead ofa b") == (("ofa", "b"),)


def test_instead_of_starts_a_new_clause_that_a_cue_before_it_does_not_reach() -> None:
    # "never a instead of b": a is negated by "never"; b by "instead of".
    assert classify("never a instead of b", find, OPTIONS) == rule(prohibited="ab", specificity=2)


def test_a_break_word_inside_a_longer_word_does_not_cut() -> None:
    assert clauses("use android thenable butter however1") == (
        ("use", "android", "thenable", "butter", "however1"),
    )


def test_empty_clauses_are_dropped() -> None:
    assert clauses(";; but ; use a ,") == (("use", "a"),)
    assert clauses("") == ()
    assert clauses("...") == ()
    assert clauses("instead instead") == ()


def test_clauses_lowercase_their_input() -> None:
    assert clauses("USE A, NOT B BUT C") == (("use", "a", "not", "b"), ("c",))


def test_dotted_names_are_one_word_and_a_final_dot_is_a_break() -> None:
    assert clauses("use logging.info.") == (("use", "logging.info"),)
    assert clauses("use a.b.c, not d.") == (("use", "a.b.c", "not", "d"),)
    assert clauses("print()") == (("print",),)
    assert clauses("a.b. c") == (("a.b",), ("c",))


def test_hyphens_inside_words_are_not_dashes() -> None:
    # A hyphen between word characters joins them into one word (I-10 item 4b).
    assert clauses("bare-except f-strings x-") == (("bare-except", "f-strings", "x"),)
    assert clauses("-x") == (("x",),)
    assert clauses("a-b-c a.b-c a-b.c") == (("a-b-c", "a.b-c", "a-b.c"),)
    assert clauses("never a-b") == (("never", "a-b"),)
    # ... and they are not dashes, so they end no clause.
    assert len(clauses("never a-b c")) == 1


def test_apostrophes_stay_inside_words_and_other_marks_are_dropped() -> None:
    assert clauses("don't use `a`!") == (("don't", "use", "a"),)
    assert clauses("don\u2019t use a") == (("don\u2019t", "use", "a"),)
    assert clauses("a/b c") == (("a", "b", "c"),)


def test_digits_and_underscores_are_word_characters() -> None:
    assert clauses("use __name__ and log2") == (("use", "__name__", "and", "log2"),)


PREFIX_CUES = [
    "no",
    "never",
    "not",
    "don't",
    "don\u2019t",
    "dont",
    "do not",
    "avoid",
    "without",
    "shouldn't",
    "shouldn\u2019t",
    "should not",
    "mustn't",
    "mustn\u2019t",
    "must not",
    "stop using",
    "instead of",
    "rather than",
]
TRAILING_CUES = [
    "is banned",
    "are banned",
    "forbidden",
    "is forbidden",
    "prohibited",
    "is prohibited",
    "disallowed",
    "are disallowed",
    "deprecated",
    "is deprecated",
    "not allowed",
    "is not allowed",
    "are not allowed",
]


def test_the_tables_are_what_the_docs_say() -> None:
    assert BREAK_WORDS == {"but", "then", "instead", "however"}
    assert BREAK_MARKS == set(";:().-\u2013\u2014")
    assert VERB_CUES == {"use", "prefer", "choose", "pick", "switch", "always", "instead"}
    assert NEGATIONS == {
        "no",
        "never",
        "not",
        "dont",
        "don't",
        "don\u2019t",
        "avoid",
        "without",
        "shouldn't",
        "shouldn\u2019t",
        "mustn't",
        "mustn\u2019t",
        "stop using",
        "rather than",
        "instead of",
    }
    assert TRAILING_WORDS == {"forbidden", "prohibited", "disallowed", "deprecated"}
    assert TRAILING_PAIRS == {("is", "banned"), ("are", "banned"), ("not", "allowed")}
    assert MERGED == {
        ("stop", "using"): "stop using",
        ("rather", "than"): "rather than",
        ("no", "matter"): "no matter",
        ("no", "doubt"): "no doubt",
        ("not", "only"): "not only",
    }


# --- the wider cue list (INTERFACES I-10 item 3; CON-67) ------------------------------------


@pytest.mark.parametrize("cue", PREFIX_CUES)
def test_each_prefix_cue_prohibits_what_follows_it(cue: str) -> None:
    assert classify(f"{cue} b", find, OPTIONS) == rule(prohibited="b", specificity=1)
    assert classify(f"use a {cue} b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify(f"use a. {cue} b, c", find, OPTIONS) == rule(
        preferred="a", prohibited="bc", specificity=3
    )


@pytest.mark.parametrize("cue", PREFIX_CUES)
def test_each_prefix_cue_stops_at_a_break(cue: str) -> None:
    assert classify(f"{cue} b; use c", find, OPTIONS) == rule(
        preferred="c", prohibited="b", specificity=2
    )


@pytest.mark.parametrize("cue", TRAILING_CUES)
def test_each_trailing_cue_prohibits_what_comes_before_it(cue: str) -> None:
    assert classify(f"b {cue}", find, OPTIONS) == rule(prohibited="b", specificity=1)
    assert classify(f"use a. b {cue}", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify(f"a and b {cue}", find, OPTIONS) == rule(prohibited="ab", specificity=2)


@pytest.mark.parametrize("cue", TRAILING_CUES)
def test_a_trailing_cue_stops_at_a_break_in_both_directions(cue: str) -> None:
    # What is in a clause before or after the cue's own clause is not reached.
    assert classify(f"use a; b {cue}; use c", find, OPTIONS) == rule(
        preferred="ac", prohibited="b", specificity=3
    )
    assert classify(f"b {cue}. a", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )


def test_an_option_named_after_a_trailing_cue_makes_the_sentence_unreadable() -> None:
    # I-10 item 4a: the cue reaches back, so a mention after it can't be placed.
    assert classify("b is banned a", find, OPTIONS) is None
    assert classify("b forbidden a", find, OPTIONS) is None
    assert classify("use b. a is forbidden, b", find, OPTIONS) is None


def test_the_two_word_cues_need_both_words() -> None:
    for text in ("a banned", "a is allowed", "a allowed", "a was banned", "a has been banned"):
        assert classify(text, find, OPTIONS) == rule(preferred="a", specificity=1), text
    assert last_trailing_cue(("banned",)) is None
    assert last_trailing_cue(("allowed", "a", "not")) is None  # no wrap-around to the last word
    assert last_trailing_cue(("banned", "a", "is")) is None


def test_last_trailing_cue_is_the_index_of_the_last_cue_and_of_a_pair_its_second_word() -> None:
    assert last_trailing_cue(("a", "is", "banned")) == 2
    assert last_trailing_cue(("a", "forbidden", "b", "is", "not", "allowed")) == 5
    assert last_trailing_cue(("a", "deprecated", "b")) == 1
    assert last_trailing_cue(("a", "b")) is None
    assert last_trailing_cue(()) is None


def test_a_mention_on_the_trailing_cue_itself_is_not_negated() -> None:
    def cue_as_option(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
        return ((i, "a") for i, word in enumerate(clause) if word == "forbidden")

    # Nothing comes after the mention here, so the trailing cue doesn't reach it.
    assert classify("x forbidden", cue_as_option, OPTIONS) == rule(preferred="a", specificity=1)


def test_a_prefix_and_a_trailing_cue_together() -> None:
    # "never" reaches b and c after it, "c is banned" reaches the words before it: all three.
    assert classify("never a b c is banned", find, OPTIONS) is None
    assert classify("never a b c is banned", find, frozenset("abcd")) == rule(
        prohibited="abc", specificity=3
    )
    # With the cue between two mentions they are not one list (I-10 item 4a, contiguity guard).
    assert classify("a never b c is banned", find, frozenset("abcd")) is None


def test_stop_using_is_one_cue() -> None:
    assert clauses("stop using a") == (("stop using", "a"),)
    assert clauses("stop using") == (("stop using",),)
    assert clauses("please stop a using") == (("please", "stop", "a", "using"),)
    assert clauses("stop usingx a") == (("stop", "usingx", "a"),)
    assert classify("stop a", find, OPTIONS) == rule(preferred="a", specificity=1)


# --- commas (I-10 refinement b) -------------------------------------------------------------


@pytest.mark.parametrize("verb", sorted(VERB_CUES))
def test_a_comma_before_a_positive_verb_cue_ends_the_negated_clause(verb: str) -> None:
    assert classify(f"don't a, {verb} b", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )
    # "instead" is a break word and is dropped; the other verbs start the next clause.
    second = ("b",) if verb == "instead" else (verb, "b")
    assert clauses(f"never a, {verb} b") == (("never", "a"), second)
    # Also without a space after the comma and with a space before it.
    assert clauses(f"never a,{verb} b") == (("never", "a"), second)
    assert clauses(f"never a , {verb} b") == (("never", "a"), second)


@pytest.mark.parametrize("word", ["b", "or", "and", "also", "usex", "user", "1", "not", "no"])
def test_a_comma_before_anything_else_does_not_end_the_clause(word: str) -> None:
    assert len(clauses(f"never a, {word} b")) == 1
    assert classify(f"no a, {word} b", find, OPTIONS) == rule(prohibited="ab", specificity=2)


def test_a_comma_before_a_clause_mark_leaves_that_mark_to_end_the_clause() -> None:
    assert clauses("never a, (b") == (("never", "a"), ("b",))


def test_a_comma_at_the_end_or_before_a_mark_ends_nothing() -> None:
    assert clauses("never a,") == (("never", "a"),)
    assert clauses("never a,,b") == (("never", "a", "b"),)
    assert clauses("never a, , use b") == (("never", "a"), ("use", "b"))
    assert clauses(",") == ()


def test_the_comma_examples_of_i10() -> None:
    # "Don't print, use logging." prohibits print and prefers logging; "no print, requests or
    # urllib" prohibits all three.
    assert classify("don't a, use b", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )
    assert classify("no a, b or c", find, frozenset("abcd")) == rule(
        prohibited="abc", specificity=3
    )


# --- empty () after a name (I-10 refinement a) ----------------------------------------------


@pytest.mark.parametrize("name", ["a", "`a`", "`a()`", "A", "a_", "a1", "logging.warn", "a.b"])
def test_an_empty_call_suffix_is_removed_and_ends_nothing(name: str) -> None:
    assert clauses(f"never use {name}() or b()") == clauses(f"never use {name} or b")
    assert len(clauses(f"never use {name}() or b()")) == 1


def test_a_call_suffix_is_deleted_not_replaced_by_anything() -> None:
    # Whatever follows it is joined to the name (a replacement could split the word).
    assert clauses("use a()b") == (("use", "ab"),)


def test_the_i10_example_with_call_suffixes_prohibits_both() -> None:
    assert classify("Never use a() or b()", find, OPTIONS) == rule(prohibited="ab", specificity=2)
    assert classify("Never use `a()` or `b()`", find, OPTIONS) == rule(
        prohibited="ab", specificity=2
    )
    assert classify("Never use `a`() or `b`()", find, OPTIONS) == rule(
        prohibited="ab", specificity=2
    )


def test_parentheses_that_are_not_an_empty_call_suffix_still_end_the_clause() -> None:
    assert clauses("never a () b") == (("never", "a"), ("b",))  # a space before the "("
    assert clauses("never a(b)") == (("never", "a"), ("b",))
    assert clauses("never a( )b") == (("never", "a"), ("b",))
    assert clauses("() a") == (("a",),)  # nothing before it, so nothing is a name
    assert clauses("never a;() b") == (("never", "a"), ("b",))
    assert clauses("never a-() b") == (("never", "a"), ("b",))


def test_call_suffix_is_one_character_of_lookbehind_and_two_literal_characters() -> None:
    assert CALL_SUFFIX.sub("", "a() `a`() _() 1() x()") == "a `a` _ 1 x"
    assert CALL_SUFFIX.sub("", " () (()") == " () (()"  # not after a name character
    assert CALL_SUFFIX.pattern == r"(?<=[a-z0-9_`])\(\)"


# --- negation -------------------------------------------------------------------------------


@pytest.mark.parametrize("word", sorted(NEGATIONS))
def test_every_negation_cue_negates_what_follows_it(word: str) -> None:
    clause = ("use", word, "a")
    assert is_negated(clause, 2) is True


@pytest.mark.parametrize("cue", TRAILING_CUES)
def test_is_negated_sees_a_trailing_cue_after_the_word_and_not_before_it(cue: str) -> None:
    clause = ("a", *cue.split())
    assert is_negated(clause, 0) is True
    assert is_negated(("use", "a", *cue.split(), "b"), 1) is True
    if "not" not in cue.split():  # "not" is also a prefix cue: it reaches what follows it
        assert is_negated(("use", "a", *cue.split(), "b"), len(cue.split()) + 2) is False


def test_negation_needs_a_cue_before_the_target() -> None:
    assert is_negated(("not", "a"), 1) is True
    assert is_negated(("not", "a"), 0) is False  # the word itself is not "before"
    assert is_negated(("a", "not"), 0) is False
    assert is_negated(("use", "a"), 1) is False
    assert is_negated((), 0) is False


# --- classify -------------------------------------------------------------------------------


def test_classify_sorts_mentions_by_polarity() -> None:
    assert classify("use a, not b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify("never use b", find, OPTIONS) == rule(prohibited="b", specificity=1)
    assert classify("use c", find, OPTIONS) == rule(preferred="c", specificity=1)


def test_specificity_counts_distinct_options_not_mentions() -> None:
    assert classify("use a, use a, use a", find, OPTIONS) == rule(preferred="a", specificity=1)
    assert classify("never a or b", find, OPTIONS) == rule(prohibited="ab", specificity=2)
    assert classify("never a or a", find, OPTIONS) == rule(prohibited="a", specificity=1)


def test_no_mention_is_no_match() -> None:
    assert classify("use something else", find, OPTIONS) is None
    assert classify("", find, OPTIONS) is None


def test_an_option_named_in_a_negated_and_a_plain_clause_is_no_match() -> None:
    assert classify("use a, not a", find, OPTIONS) is None
    assert classify("use a. never a", find, OPTIONS) is None
    assert classify("never a; use a", find, OPTIONS) is None
    assert classify("never a but use a", find, OPTIONS) is None


def test_a_rule_that_forbids_every_option_is_no_match() -> None:
    assert classify("never a or b or c", find, OPTIONS) is None
    assert classify("never a or b", find, OPTIONS) is not None
    assert classify("never a", find, frozenset({"a"})) is None


def test_a_rule_that_prefers_every_option_is_no_match() -> None:
    assert classify("use a or b or c", find, OPTIONS) is None
    assert classify("use a, use b; use c", find, OPTIONS) is None
    assert classify("use a or b", find, OPTIONS) is not None
    assert classify("use a", find, frozenset({"a"})) is None


def test_forbidding_every_option_is_fine_when_something_is_preferred() -> None:
    assert classify("use a, not b", find, frozenset({"a", "b"})) == rule(
        preferred="a", prohibited="b", specificity=2
    )


# --- R2.5: the regex is linear time ---------------------------------------------------------


def test_token_is_a_single_compiled_regex() -> None:
    assert isinstance(TOKEN, re.Pattern)


@pytest.mark.parametrize(
    "hostile",
    [
        "a" * 200_000,
        "a." * 100_000,
        "a." * 100_000 + "!",
        "a.a" * 66_000 + ".",
        "'" * 200_000,
        "a" * 100_000 + "." * 100_000,
        ".a" * 100_000,
        ", " * 100_000,
        "-" * 200_000,
        " -" * 100_000,
        "- " * 100_000,
        " - " * 100_000,
        "a -" * 100_000,
        "--" * 100_000 + "x",
        "(" * 200_000,
        "instead " * 100_000,
        "instead of " * 60_000,
        "\u2014" * 200_000,
    ],
)
def test_clauses_run_in_linear_time_on_adversarial_text(hostile: str) -> None:
    # Best of three, and 5 s for a text this size that takes milliseconds: a loaded runner
    # can't fail it, a quadratic path (minutes) can.
    assert best_time(partial(clauses, hostile)) < 5.0


MERGED_PAIRS = "stop using a no matter a not only no doubt a rather than a "

HOSTILE_SENTENCES: dict[str, Callable[[int], str]] = {
    # About n bytes each. Every shape puts ~n/2 mentions or marks in one clause, or in many
    # clauses, and each one stands for a code path that no other shape here reaches.
    # ``classify`` reads the sentence with ``_read`` (what ``clauses`` is), so these also time
    # the tokenizer and the clause cutter; ``clauses`` has its own list of texts above.
    "cue then many mentions": lambda n: "never " + "a " * (n // 2),
    "mentions with commas": lambda n: "never " + "a, " * (n // 3),
    "a cue before every mention": lambda n: "never a " * (n // 8),
    "one mention per clause": lambda n: "never a. " * (n // 9),
    "instead of before every mention": lambda n: "use a instead of b " * (n // 19),
    "dashes": lambda n: "never a - " * (n // 10),
    # CON-67: trailing cues, commas before a verb cue, call suffixes, set phrases.
    "mentions then a trailing cue": lambda n: "a " * (n // 2) + "is banned",
    "a trailing cue after every mention": lambda n: "a is banned " * (n // 12),
    "commas before a verb cue": lambda n: "never a, use " * (n // 13),
    "call suffixes and open parentheses": lambda n: "never a() a( " * (n // 13),
    "merged pairs": lambda n: MERGED_PAIRS * (n // len(MERGED_PAIRS)),
    "hyphen and dot chain": lambda n: "a.b-" * (n // 4) + "c",
    "double hyphens": lambda n: "a--" * (n // 3),
    "a trailing cue with a verb cue": lambda n: "use " * (n // 4) + "a is forbidden",
    # CON-67 round 2 (comma guard): commas in a clause with a trailing cue.
    "mentions with commas then a trailing cue": lambda n: "a, " * (n // 3) + "is banned",
    # CON-67 round 3 (contiguity guard): the one shape where the guard reads every gap.
    "mentions joined by and, then a trailing cue": lambda n: "a and " * (n // 6) + "are banned",
    "commas only then a trailing cue": lambda n: ", " * (n // 2) + "a is banned",
    "one mention each side of many commas": lambda n: "a " + ", " * (n // 2) + "b is banned",
}
# Left out of the list above, each one the same path as one kept (the shapes of #58 and of the
# first two rounds of #61; CI took over 10 minutes with them):
# - "no cue, many mentions": "use " + 100,000 mentions is in ``test_one_clause_with_100_000_...``.
# - "mentions with or", "mixed options", "commas before other words": plain words, as in
#   "cue then many mentions" and "mentions with commas" (the last one was the same text).
# - "cues only", "trailing cues only", "many trailing cues and mentions after": a run of cues in
#   one clause, as in "a cue before every mention" and "a trailing cue after every mention".
# - "commas only", "x commas then a mention and a trailing cue": the commas of "commas only then
#   a trailing cue", with the same one mention after them.
# - "call suffixes", "unbalanced parentheses": one text, "call suffixes and open parentheses".
# - "stop using ...", "set phrases", "not only and no doubt", "rather than ...": one MERGED table
#   lookup in ``_read``, all five pairs in "merged pairs".
# - "runs of no-", "no-op before every mention", "hyphens and dots": one TOKEN word with
#   ``[.-]`` repeats, as in "hyphen and dot chain" (and "no-op" is a plain word to everything
#   after ``_read``).


@pytest.mark.parametrize("kind", HOSTILE_SENTENCES)
def test_classify_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    assert_linear(HOSTILE_SENTENCES[kind], lambda text: classify(text, find, OPTIONS), label=kind)


def test_one_clause_with_100_000_mentions_is_read_once() -> None:
    # The CR1 case: is_negated used to scan clause[:index] for every mention (quadratic).
    for text, expected in (
        ("never " + "a " * 100_000, rule(prohibited="a", specificity=1)),
        ("use " + "a " * 100_000, rule(preferred="a", specificity=1)),
    ):
        assert best_time(partial(classify, text, find, OPTIONS), repeat=1) < 5.0
        assert classify(text, find, OPTIONS) == expected


def test_a_cue_in_the_middle_of_a_1_mib_clause_splits_the_polarity() -> None:
    # INTERFACES I-10: a cue applies from the cue to the end of its clause, so the words
    # before it are preferred and the words after it are prohibited, however many there are.
    count = MIB // 4
    text = "use " + "a " * count + "not " + "b " * count
    assert len(text) >= MIB - 8
    options = frozenset({"a", "b"})
    result = classify(text, find, options)
    assert result == rule(preferred="a", prohibited="b", specificity=2)
    assert best_time(partial(classify, text, find, options)) < 5.0


# --- I-10 "Negation" item 4 (CR1 on #61) ---------------------------------------------------------

HTTP = frozenset({"requests", "httpx", "urllib", "aiohttp"})


def find_http(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    """A finder for a four-option checker (the http-client one comes with T-017)."""
    for index, word in enumerate(clause):
        if word in HTTP:
            yield index, word


def test_item_4a_print_is_forbidden_still_prohibits_it_and_the_comma_splits() -> None:
    assert classify("a is forbidden.", find, OPTIONS) == rule(prohibited="a", specificity=1)
    assert classify("a is forbidden, use b.", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )
    assert clauses("a is forbidden, use b") == (("a", "is", "forbidden"), ("use", "b"))


@pytest.mark.parametrize(
    "sentence",
    [
        "use a, everything else is forbidden.",
        "use a, anything else is banned.",
        "use a only, other approaches are not allowed.",
        "use a for all output, other methods are deprecated.",
        "use a, it is forbidden to b.",  # a verb cue, and an option after the trailing cue
        "use a, b is banned.",
        "use a, other things are prohibited.",
        "use a, others are disallowed.",
    ],
)
def test_item_4a_a_trailing_cue_in_a_clause_with_a_verb_cue_is_unreadable(sentence: str) -> None:
    assert classify(sentence, find, OPTIONS) is None


@pytest.mark.parametrize("verb", sorted(VERB_CUES - {"instead"}))
def test_item_4a_every_verb_cue_makes_a_trailing_cue_clause_unreadable(verb: str) -> None:
    # Anywhere in the clause: before the cue, after it, or before the option.
    assert classify(f"{verb} x, b is forbidden", find, OPTIONS) is None
    assert classify(f"b {verb} x is forbidden", find, OPTIONS) is None
    assert classify(f"b is forbidden to {verb} x", find, OPTIONS) is None
    assert classify(f"x {verb} is forbidden", find, OPTIONS) is None  # no option at all: None


def test_item_4a_a_bare_instead_is_a_break_so_the_trailing_clause_stays_readable() -> None:
    assert classify("use a instead, b is forbidden", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )


def test_item_4a_a_verb_cue_in_another_clause_does_not_matter() -> None:
    assert classify("use a; b is forbidden", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify("use a. b is banned. use c", find, OPTIONS) == rule(
        preferred="ac", prohibited="b", specificity=3
    )
    assert classify("b is forbidden; use a, c", find, OPTIONS) == rule(
        preferred="ac", prohibited="b", specificity=3
    )


def test_item_4a_only_an_option_after_the_cue_counts_not_one_on_the_cue() -> None:
    def on_the_cue(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
        return ((i, "a") for i, word in enumerate(clause) if word == "forbidden")

    assert classify("x forbidden", on_the_cue, OPTIONS) == rule(preferred="a", specificity=1)


@pytest.mark.parametrize(
    "sentence",
    [
        "use httpx, everything else is forbidden.",
        "use httpx, other clients are banned.",
        "use httpx only, anything else is not allowed.",
        "use httpx, requests is forbidden.",
        "use httpx, it is forbidden to use urllib or aiohttp.",
    ],
)
def test_item_4a_with_four_options_a_trailing_cue_with_a_verb_cue_is_unreadable(
    sentence: str,
) -> None:
    assert classify(sentence, find_http, HTTP) is None


@pytest.mark.parametrize(
    ("sentence", "expected"),
    [
        (
            "requests and urllib and aiohttp are banned; use httpx.",
            RuleMatch(frozenset({"httpx"}), frozenset({"requests", "urllib", "aiohttp"}), 4),
        ),
        (
            "requests is forbidden, use httpx.",
            RuleMatch(frozenset({"httpx"}), frozenset({"requests"}), 2),
        ),
        ("httpx is forbidden.", RuleMatch(frozenset(), frozenset({"httpx"}), 1)),
        (
            "requests and urllib and aiohttp are forbidden.",
            RuleMatch(frozenset(), frozenset({"requests", "urllib", "aiohttp"}), 3),
        ),
        (
            "use httpx; requests and urllib are deprecated.",
            RuleMatch(frozenset({"httpx"}), frozenset({"requests", "urllib"}), 3),
        ),
    ],
)
def test_item_4a_with_four_options_a_readable_trailing_cue_prohibits_what_it_reaches(
    sentence: str, expected: RuleMatch
) -> None:
    assert classify(sentence, find_http, HTTP) == expected


# --- I-10 item 4a, comma guard (CR1 F1 on #61) ---------------------------------------------------

BARE_BROAD_SPECIFIC = frozenset({"bare", "broad", "specific"})


def find_exceptions(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    """A finder for a three-option checker: the options of ``exceptions``, one word each."""
    for index, word in enumerate(clause):
        if word in BARE_BROAD_SPECIFIC:
            yield index, word


@pytest.mark.parametrize(
    "sentence",
    [
        "a, b is banned.",
        "a, b are banned.",
        "a, b and c are banned.",  # the list form (accepted coverage loss)
        "a, b is forbidden",
        "b is fine, a is not allowed.",
        "a is fine, b is forbidden.",
        "a is tolerated, b is deprecated.",
        "a and b, c are prohibited.",
        "a, a is banned.",  # the same option on both sides still counts
        "a is acceptable, so b is banned.",
        "a, x, b is banned.",
        "a x, y b is disallowed.",
    ],
)
def test_item_4a_a_comma_with_mentions_on_both_sides_in_a_trailing_cue_clause_is_unreadable(
    sentence: str,
) -> None:
    assert classify(sentence, find, OPTIONS) is None


@pytest.mark.parametrize(
    ("sentence", "expected"),
    [
        ("a and b are banned.", rule(prohibited="ab", specificity=2)),
        ("a or b is forbidden.", rule(prohibited="ab", specificity=2)),
        ("a is banned, use b.", rule(preferred="b", prohibited="a", specificity=2)),
        ("a is banned, always b.", rule(preferred="b", prohibited="a", specificity=2)),
        # A comma with mentions on one side only does not matter ...
        ("x, a is banned.", rule(prohibited="a", specificity=1)),
        (", a is banned.", rule(prohibited="a", specificity=1)),
        ("x y, a is banned.", rule(prohibited="a", specificity=1)),
        ("a is banned, x", rule(prohibited="a", specificity=1)),
        ("a x is banned, y z.", rule(prohibited="a", specificity=1)),
        ("a, x is banned.", rule(prohibited="a", specificity=1)),
        ("a and, x are banned.", rule(prohibited="a", specificity=1)),
        # ... and so does one in a clause with no trailing cue, or in another clause.
        ("use a, b.", rule(preferred="ab", specificity=2)),
        ("never a, b.", rule(prohibited="ab", specificity=2)),
        ("use a, b; c is banned.", rule(preferred="ab", prohibited="c", specificity=3)),
        ("a, b. c is banned.", rule(preferred="ab", prohibited="c", specificity=3)),
        ("a is fine; b is banned, x.", rule(preferred="a", prohibited="b", specificity=2)),
    ],
)
def test_item_4a_the_comma_guard_leaves_these_readable(sentence: str, expected: RuleMatch) -> None:
    assert classify(sentence, find, OPTIONS) == expected


def test_item_4a_a_trailing_cue_clause_with_no_mention_is_just_ignored() -> None:
    # Nothing to place, nothing to doubt: the other clauses decide.
    assert classify("use a; everything else is banned.", find, OPTIONS) == rule(
        preferred="a", specificity=1
    )
    assert classify("use a. x, y are forbidden.", find, OPTIONS) == rule(
        preferred="a", specificity=1
    )
    assert classify("x is banned.", find, OPTIONS) is None  # nothing mentioned at all


def test_item_4a_the_comma_guard_is_about_the_commas_that_survive_the_2b_split() -> None:
    # "a is banned, use b": the comma before "use" ends the clause, so no comma is left in it.
    assert clauses("a is banned, use b") == (("a", "is", "banned"), ("use", "b"))
    assert classify("a is banned, use b", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )
    # A comma that survives is the one before "b" here.
    assert classify("a, b is banned, use c", find, OPTIONS) is None


def test_item_4a_comma_guard_three_options_for_exceptions() -> None:
    options = BARE_BROAD_SPECIFIC
    for sentence in (
        "broad is acceptable, bare is forbidden.",
        "broad is fine, bare is not allowed.",
        "specific is tolerated, bare is banned.",
        "bare, broad and specific are banned.",
        "bare, broad are deprecated.",
    ):
        assert classify(sentence, find_exceptions, options) is None, sentence
    assert classify("bare and broad are banned.", find_exceptions, options) == RuleMatch(
        frozenset(), frozenset({"bare", "broad"}), 2
    )
    assert classify("bare is banned, use specific.", find_exceptions, options) == RuleMatch(
        frozenset({"specific"}), frozenset({"bare"}), 2
    )
    assert classify("bare is banned; broad is forbidden.", find_exceptions, options) == RuleMatch(
        frozenset(), frozenset({"bare", "broad"}), 2
    )


def test_item_4a_comma_guard_four_options_for_an_http_client() -> None:
    for sentence in (
        "requests, urllib and aiohttp are banned.",
        "requests, urllib are forbidden.",
        "requests, urllib and aiohttp are forbidden.",
        "httpx is fine, requests is banned.",
        "httpx is acceptable, requests is not allowed.",
        "requests, httpx and urllib and aiohttp are deprecated.",
        "requests, urllib and aiohttp are banned; use httpx.",  # the list form, lost on purpose
    ):
        assert classify(sentence, find_http, HTTP) is None, sentence
    assert classify("requests and urllib are banned.", find_http, HTTP) == RuleMatch(
        frozenset(), frozenset({"requests", "urllib"}), 2
    )
    assert classify("requests is banned, use httpx.", find_http, HTTP) == RuleMatch(
        frozenset({"httpx"}), frozenset({"requests"}), 2
    )
    assert classify("requests and urllib are banned; use httpx.", find_http, HTTP) == RuleMatch(
        frozenset({"httpx"}), frozenset({"requests", "urllib"}), 3
    )


def test_item_4a_print_requests_and_urllib_list_is_unreadable_when_all_three_are_options() -> None:
    options = frozenset({"print", "requests", "urllib"})

    def find_three(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
        return ((i, word) for i, word in enumerate(clause) if word in options)

    assert classify("print, requests and urllib are banned.", find_three, options) is None
    assert classify("print and requests are banned.", find_three, options) == RuleMatch(
        frozenset(), frozenset({"print", "requests"}), 2
    )
    assert classify("print is banned, use logging.", find_three, options) == RuleMatch(
        frozenset(), frozenset({"print"}), 1
    )


# --- I-10 item 4a, contiguity guard (CR1 round 3 on #61) -----------------------------------------


@pytest.mark.parametrize(
    "sentence",
    [
        "httpx is fine and requests is forbidden.",
        "httpx is fine or requests is banned.",
        "httpx is fine nor requests is not allowed.",
        "requests and the urllib library are banned.",  # a word between two mentions: accepted loss
        "requests and also urllib are banned.",
        "requests or maybe urllib or aiohttp are deprecated.",
        "requests and urllib and, in tests, aiohttp are banned.",  # the commas are no excuse
        "requests and `the` urllib are banned.",  # a backtick doesn't hide a word
        "requests and urllib are fine and aiohttp is banned.",
    ],
)
def test_item_4a_a_word_between_two_mentions_makes_the_list_unreadable(sentence: str) -> None:
    assert classify(sentence, find_http, HTTP) is None, sentence


@pytest.mark.parametrize(
    ("sentence", "prohibited"),
    [
        ("requests and urllib are banned.", {"requests", "urllib"}),
        ("requests or urllib are banned.", {"requests", "urllib"}),
        ("requests nor urllib are banned.", {"requests", "urllib"}),
        ("requests and urllib or aiohttp are banned.", {"requests", "urllib", "aiohttp"}),
        ("`requests` and `urllib` are forbidden.", {"requests", "urllib"}),
        ("requests urllib are banned.", {"requests", "urllib"}),  # nothing between them
        ("the requests library is banned.", {"requests"}),  # one mention: no gap to read
        ("requests and urllib libraries are not allowed.", {"requests", "urllib"}),  # after
        ("it is clear that requests and urllib are banned.", {"requests", "urllib"}),  # before
    ],
)
def test_item_4a_a_list_of_mentions_with_only_connectors_between_them_maps(
    sentence: str, prohibited: set[str]
) -> None:
    result = classify(sentence, find_http, HTTP)
    assert result == RuleMatch(frozenset(), frozenset(prohibited), len(prohibited)), sentence


def test_item_4a_contiguity_with_the_two_options_of_a_print_rule() -> None:
    options = frozenset({"print", "requests", "urllib"})

    def find_three(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
        return ((i, word) for i, word in enumerate(clause) if word in options)

    assert classify("print and requests are banned.", find_three, options) == RuleMatch(
        frozenset(), frozenset({"print", "requests"}), 2
    )
    assert classify("print and the requests library are banned.", find_three, options) is None


def test_item_4a_contiguity_with_three_options_for_exceptions() -> None:
    assert classify("bare and broad are banned.", find_exceptions, BARE_BROAD_SPECIFIC) == (
        RuleMatch(frozenset(), frozenset({"bare", "broad"}), 2)
    )
    for sentence in (
        "bare is acceptable and broad is forbidden.",
        "bare is fine or broad is not allowed.",
        "bare and the broad ones are banned.",
    ):
        assert classify(sentence, find_exceptions, BARE_BROAD_SPECIFIC) is None, sentence


def test_item_4a_contiguity_is_only_read_in_a_clause_with_a_trailing_cue() -> None:
    # A prefix cue reaches every mention in its clause, whatever lies between them.
    assert classify("never use requests and the urllib library.", find_http, HTTP) == RuleMatch(
        frozenset(), frozenset({"requests", "urllib"}), 2
    )
    # Another clause's words don't count: the guard looks inside one clause.
    assert classify("requests is banned. urllib is fine.", find_http, HTTP) == RuleMatch(
        frozenset({"urllib"}), frozenset({"requests"}), 2
    )
    assert classify("requests is banned; urllib is banned.", find_http, HTTP) == RuleMatch(
        frozenset(), frozenset({"requests", "urllib"}), 2
    )


def find_phrases(clause: tuple[str, ...]) -> Iterator[Mention]:
    """Two-word mentions that tell ``classify`` which words are theirs: "bare except" and
    "catching exception". Each one's index is its first word, as ``Mention`` requires."""
    for index, word in enumerate(clause):
        if word == "bare" and clause[index + 1 : index + 2] == ("except",):
            yield index, "bare", range(index, index + 2)
        elif word == "catching" and clause[index + 1 : index + 2] == ("exception",):
            yield index, "broad", range(index, index + 2)


def find_phrases_without_spans(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    return ((index, option) for index, option, *_ in find_phrases(clause))


def test_item_4a_the_words_of_a_mention_are_not_words_between_mentions() -> None:
    options = frozenset({"bare", "broad", "specific"})
    expected = RuleMatch(frozenset(), frozenset({"bare", "broad"}), 2)
    both = "bare except and catching exception are banned."
    assert classify(both, find_phrases, options) == expected
    assert classify("catching exception or bare except are banned.", find_phrases, options) == (
        expected
    )
    # Told only the index of each mention, ``classify`` sees "except" and "catching" in the gap.
    assert classify(both, find_phrases_without_spans, options) is None
    # A word that is not part of either mention still breaks the list.
    for sentence in (
        "bare except and the catching exception are banned.",
        "bare except or even catching exception are banned.",
        "bare except is fine and catching exception is banned.",
    ):
        assert classify(sentence, find_phrases, options) is None, sentence


def test_item_4a_a_mention_starts_at_its_index_whatever_its_range_says() -> None:
    # The contract is that a range starts at the index. ``classify`` doesn't read the range's
    # start: a finder that gives the *last* word as the index (and a range that starts before
    # it) is read as a one-word-and-after mention, so the first word counts as a word between.
    def last_word_as_index(clause: tuple[str, ...]) -> Iterator[Mention]:
        for index, word in enumerate(clause):
            if word == "bare" and clause[index + 1 : index + 2] == ("except",):
                yield index, "bare", range(index, index + 2)
            elif word == "exception" and clause[index - 1 : index] == ("catching",):
                yield index, "broad", range(index - 1, index + 1)

    options = frozenset({"bare", "broad", "specific"})
    assert classify("bare except and catching exception are banned.", find_phrases, options) == (
        RuleMatch(frozenset(), frozenset({"bare", "broad"}), 2)
    )
    assert (
        classify("bare except and catching exception are banned.", last_word_as_index, options)
        is None
    )


def test_item_4a_the_order_the_finder_gives_mentions_in_does_not_matter() -> None:
    options = frozenset({"a", "b", "c"})

    def backwards(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
        return iter(sorted(find(clause), reverse=True))

    assert classify("a and b are banned.", backwards, options) == rule(
        prohibited="ab", specificity=2
    )
    assert classify("a x b are banned.", backwards, options) is None
    assert classify("x a and b y are banned.", backwards, options) == rule(
        prohibited="ab", specificity=2
    )


def test_item_4a_the_comma_positions_are_word_counts_before_each_comma() -> None:
    assert _read("a, b, c is banned") == [(("a", "b", "c", "is", "banned"), (1, 2))]
    assert _read(", a,") == [(("a",), (0, 1))]
    assert _read("a, use b, c") == [(("a",), ()), (("use", "b", "c"), (2,))]
    assert _read("a, b; c, d") == [(("a", "b"), (1,)), (("c", "d"), (1,))]
    assert _read("a, b. c") == [(("a", "b"), (1,)), (("c",), ())]
    assert _read("") == []


def test_item_4b_a_hyphen_joins_tokens_so_no_op_and_non_blocking_hold_no_cue() -> None:
    assert clauses("use a no-op logger") == (("use", "a", "no-op", "logger"),)
    assert clauses("use non-blocking a") == (("use", "non-blocking", "a"),)
    assert classify("use a no-op b", find, OPTIONS) == rule(preferred="ab", specificity=2)
    assert classify("use non-blocking a", find, OPTIONS) == rule(preferred="a", specificity=1)
    assert classify("use no-op a", find, OPTIONS) == rule(preferred="a", specificity=1)
    assert classify("use a-no b", find, OPTIONS) == rule(preferred="b", specificity=1)
    assert classify("use a no-no-no-b c", find, OPTIONS) == rule(preferred="ac", specificity=2)
    # The words are not cues in any position, nor does a trailing hyphen join anything.
    assert first_cue(clauses("no-op")[0]) is None
    assert first_cue(clauses("non-blocking")[0]) is None
    assert clauses("no- a") == (("no", "a"),)
    assert classify("no- a", find, OPTIONS) == rule(prohibited="a", specificity=1)


def test_item_4b_a_double_hyphen_never_joins_words_even_when_unspaced() -> None:
    # CR1 S1: "--" ends a clause even with no space around it ("print--use").
    assert clauses("print--use logging") == (("print",), ("use", "logging"))
    assert clauses("a--b") == (("a",), ("b",))
    assert clauses("a---b") == (("a",), ("b",))
    assert clauses("never a--b") == (("never", "a"), ("b",))
    assert classify("never a--use b", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )
    assert classify("a--b is banned", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    # A single hyphen between word characters still joins them.
    assert clauses("a-b") == (("a-b",),)


def test_item_4b_a_real_cue_still_works_next_to_a_hyphenated_word() -> None:
    assert classify("never use no-op a", find, OPTIONS) == rule(prohibited="a", specificity=1)
    assert classify("use a, no non-blocking b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )


def test_item_4b_no_matter_is_never_a_cue() -> None:
    assert clauses("use a no matter b") == (("use", "a", "no matter", "b"),)
    assert classify("use a no matter b", find, OPTIONS) == rule(preferred="ab", specificity=2)
    assert classify("no matter a", find, OPTIONS) == rule(preferred="a", specificity=1)
    assert first_cue(clauses("no matter")[0]) is None


def test_item_4b_no_doubt_is_never_a_cue() -> None:
    assert clauses("use a no doubt b") == (("use", "a", "no doubt", "b"),)
    assert classify("use a no doubt b", find, OPTIONS) == rule(preferred="ab", specificity=2)
    assert classify("no doubt a", find, OPTIONS) == rule(preferred="a", specificity=1)
    assert first_cue(clauses("no doubt")[0]) is None


def test_item_4b_not_only_is_never_a_cue() -> None:
    assert clauses("use a not only b") == (("use", "a", "not only", "b"),)
    assert classify("use a not only b", find, OPTIONS) == rule(preferred="ab", specificity=2)
    assert classify("not only a", find, OPTIONS) == rule(preferred="a", specificity=1)
    assert first_cue(clauses("not only")[0]) is None


def test_item_4b_the_set_phrases_need_both_words_and_a_real_cue_after_them_still_works() -> None:
    # Whole words only: these are not the set phrases, so "no" and "not" are cues again.
    for text in ("no matterx a", "no matt a", "not onlyx a", "no doubtful a", "no a"):
        assert classify(text, find, OPTIONS) == rule(prohibited="a", specificity=1), text
    assert classify("no matter what, never a", find, OPTIONS) == rule(prohibited="a", specificity=1)
    assert classify("not only a but not b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    # A set phrase at the end of a text has no second word to look at.
    assert clauses("use a no") == (("use", "a", "no"),)


def test_item_4c_over_and_a_bare_rather_are_not_cues_but_rather_than_is() -> None:
    assert first_cue(("prefer", "a", "over", "b")) is None
    assert first_cue(("rather", "a")) is None
    assert classify("prefer a over b", find, OPTIONS) == rule(preferred="ab", specificity=2)
    assert classify("rather a", find, OPTIONS) == rule(preferred="a", specificity=1)
    assert classify("use a rather than b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert clauses("use a rather") == (("use", "a", "rather"),)
    assert clauses("use a rather thanx b") == (("use", "a", "rather", "thanx", "b"),)
    assert "over" not in NEGATIONS
    assert "rather" not in NEGATIONS
    assert "dont" in NEGATIONS


def test_first_cue_is_the_index_of_the_first_cue() -> None:
    assert first_cue(("use", "a", "not", "b", "never")) == 2
    assert first_cue(("never",)) == 0
    assert first_cue(("use", "a")) is None
    assert first_cue(()) is None


def test_a_mention_on_the_cue_itself_is_not_negated() -> None:
    def cues_as_options(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
        return ((i, "a") for i, word in enumerate(clause) if word == "not")

    # The mention is the cue word: nothing comes before it, so it is preferred.
    assert classify("not", cues_as_options, OPTIONS) == rule(preferred="a", specificity=1)


# --- the import rule (INTERFACES I-10, "Shared phrase helper") ------------------------------


def _real_src(test_file: str) -> Path:
    """The pristine ``src/conventiondrift``. mutmut runs the suite from a ``mutants/`` copy whose
    sources gain a ``mutmut`` import, so the last ``mutants`` segment is dropped, as in
    ``test_checkers_purity.real_checkers_dir``."""
    found = Path(test_file).resolve().parents[2] / "src" / "conventiondrift"
    parts = found.parts
    indexes = [i for i, part in enumerate(parts) if part == "mutants"]
    if not indexes:
        return found
    original = Path(*parts[: indexes[-1]], *parts[indexes[-1] + 1 :])
    return original if original.is_dir() else found


SRC = _real_src(__file__)


def _imported_modules(path: Path) -> set[str]:
    """Every module a file imports, absolute names only (a relative import is reported as ``.``)."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text("utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add("." * node.level + (node.module or ""))
    return found


def test_phrases_imports_only_the_standard_library_and_model() -> None:
    imports = _imported_modules(SRC / "checkers" / "phrases.py")
    assert imports  # the scanner found something to check
    for name in imports:
        assert name == "conventiondrift.model" or name.split(".")[0] in sys.stdlib_module_names, (
            name
        )


def test_components_imports_only_the_standard_library_and_model() -> None:
    imports = _imported_modules(SRC / "components.py")
    assert imports
    for name in imports:
        assert name == "conventiondrift.model" or name.split(".")[0] in sys.stdlib_module_names, (
            name
        )
