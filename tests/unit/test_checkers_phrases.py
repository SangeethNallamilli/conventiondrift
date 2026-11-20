"""Unit tests for the shared rule-sentence reading, conventiondrift.checkers.phrases (T-016)."""

import re
import time
from collections.abc import Iterator

import pytest

from conventiondrift.checkers.phrases import BREAKS, NEGATIONS, TOKEN, classify, clauses, is_negated
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


def test_clauses_cut_at_commas_semicolons_colons_and_the_break_words() -> None:
    assert clauses("use a, not b; avoid c: never a and use b but not c then stop") == (
        ("use", "a"),
        ("not", "b"),
        ("avoid", "c"),
        ("never", "a"),
        ("use", "b"),
        ("not", "c"),
        ("stop",),
    )


def test_a_break_word_inside_a_longer_word_does_not_cut() -> None:
    assert clauses("use android, thenable, butter") == (
        ("use", "android"),
        ("thenable",),
        ("butter",),
    )


def test_empty_clauses_are_dropped() -> None:
    assert clauses(",, and ; use a ,") == (("use", "a"),)
    assert clauses("") == ()
    assert clauses("...") == ()


def test_clauses_lowercase_their_input() -> None:
    assert clauses("USE A, NOT B") == (("use", "a"), ("not", "b"))


def test_dotted_names_are_one_word_and_a_final_dot_is_not_part_of_it() -> None:
    assert clauses("use logging.info.") == (("use", "logging.info"),)
    assert clauses("use a.b.c, not d.") == (("use", "a.b.c"), ("not", "d"))
    assert clauses("print()") == (("print",),)


def test_apostrophes_stay_inside_words_and_other_marks_are_dropped() -> None:
    assert clauses("don't use `a`!") == (("don't", "use", "a"),)
    assert clauses("don\u2019t use a") == (("don\u2019t", "use", "a"),)
    assert clauses("a/b (c)") == (("a", "b", "c"),)


def test_digits_and_underscores_are_word_characters() -> None:
    assert clauses("use __name__ and log2") == (("use", "__name__"), ("log2",))


def test_the_tables_are_what_the_docs_say() -> None:
    assert BREAKS == {",", ";", ":", "and", "but", "then"}
    assert NEGATIONS == {
        "never",
        "not",
        "dont",
        "don't",
        "don\u2019t",
        "avoid",
        "over",
        "instead",
        "rather",
        "without",
    }


# --- negation -------------------------------------------------------------------------------


@pytest.mark.parametrize("word", sorted(NEGATIONS))
def test_every_negation_word_negates_what_follows_it(word: str) -> None:
    clause = ("use", word, "a")
    assert is_negated(clause, 2) is True


def test_negation_needs_a_word_before_the_target() -> None:
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


def test_negation_does_not_cross_a_clause_break() -> None:
    assert classify("never use a, use b", find, OPTIONS) == rule(
        preferred="b", prohibited="a", specificity=2
    )


def test_no_mention_is_no_match() -> None:
    assert classify("use something else", find, OPTIONS) is None
    assert classify("", find, OPTIONS) is None


def test_the_same_option_preferred_and_prohibited_is_no_match() -> None:
    assert classify("use a, not a", find, OPTIONS) is None


def test_a_rule_that_forbids_every_option_is_no_match() -> None:
    assert classify("never a or b or c", find, OPTIONS) is None
    assert classify("never a or b", find, OPTIONS) is not None
    assert classify("never a", find, frozenset({"a"})) is None


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
    ],
)
def test_clauses_run_in_linear_time_on_adversarial_text(hostile: str) -> None:
    start = time.perf_counter()
    clauses(hostile)
    assert time.perf_counter() - start < 2.0
