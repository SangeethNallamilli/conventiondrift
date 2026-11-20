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
    NEGATIONS,
    TOKEN,
    classify,
    clauses,
    first_cue,
    is_negated,
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
NON_BREAKS = [" and ", " or ", " nor ", ", ", ",", " , ", " also ", "-", " -x ", " x- "]


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
    # The negation reaches "b" after the comma; only a break stops it.
    assert classify("never use a, use b. use c", find, OPTIONS) == rule(
        preferred="c", prohibited="ab", specificity=3
    )
    assert classify("never use a, use b; use c", find, OPTIONS) == rule(
        preferred="c", prohibited="ab", specificity=3
    )


def test_instead_of_and_rather_than_prohibit_what_follows() -> None:
    assert classify("use a instead of b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify("use a rather than b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
    assert classify("use a over b", find, OPTIONS) == rule(
        preferred="a", prohibited="b", specificity=2
    )
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
    assert clauses("bare-except f-strings x-") == (("bare", "except", "f", "strings", "x"),)
    assert clauses("-x") == (("x",),)


def test_apostrophes_stay_inside_words_and_other_marks_are_dropped() -> None:
    assert clauses("don't use `a`!") == (("don't", "use", "a"),)
    assert clauses("don\u2019t use a") == (("don\u2019t", "use", "a"),)
    assert clauses("a/b c") == (("a", "b", "c"),)


def test_digits_and_underscores_are_word_characters() -> None:
    assert clauses("use __name__ and log2") == (("use", "__name__", "and", "log2"),)


def test_the_tables_are_what_the_docs_say() -> None:
    assert BREAK_WORDS == {"but", "then", "instead", "however"}
    assert BREAK_MARKS == set(";:().-\u2013\u2014")
    assert NEGATIONS == {
        "never",
        "not",
        "dont",
        "don't",
        "don\u2019t",
        "avoid",
        "over",
        "rather",
        "without",
        "instead of",
    }


def test_the_wider_cue_list_is_not_read_yet() -> None:
    # A separate follow-up adds these; until then they are not cues, so a mention reads as
    # preferred (and the all-preferred guard keeps "use a; no b" from ever reading as Holds).
    for text in (
        "no a",
        "shouldn't a",
        "mustn't a",
        "stop using a",
        "a is banned",
        "a forbidden",
        "a is prohibited",
        "a is disallowed",
        "a deprecated",
        "a is not allowed",  # the trailing "not" only reaches what follows it
    ):
        assert classify(text, find, OPTIONS) == rule(preferred="a", specificity=1), text


# --- negation -------------------------------------------------------------------------------


@pytest.mark.parametrize("word", sorted(NEGATIONS))
def test_every_negation_cue_negates_what_follows_it(word: str) -> None:
    clause = ("use", word, "a")
    assert is_negated(clause, 2) is True


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


HOSTILE_SENTENCES: dict[str, Callable[[int], str]] = {
    # About n bytes each; every one puts ~n/2 mentions in one clause or in many clauses.
    "cue then many mentions": lambda n: "never " + "a " * (n // 2),
    "no cue, many mentions": lambda n: "use " + "a " * (n // 2),
    "mentions with commas": lambda n: "never " + "a, " * (n // 3),
    "mentions with or": lambda n: "never a" + " or a" * (n // 5),
    "a cue before every mention": lambda n: "never a " * (n // 8),
    "one mention per clause": lambda n: "never a. " * (n // 9),
    "instead of before every mention": lambda n: "use a instead of b " * (n // 19),
    "mixed options": lambda n: "never a b c " * (n // 12),
    "dashes": lambda n: "never a - " * (n // 10),
    "cues only": lambda n: "never " * (n // 6),
}


@pytest.mark.parametrize("kind", HOSTILE_SENTENCES)
def test_classify_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    make = HOSTILE_SENTENCES[kind]
    assert_linear(make, lambda text: classify(text, find, OPTIONS), label=kind)
    assert_linear(make, clauses, label=kind)


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
