"""Unit tests for the exceptions checker, conventiondrift.checkers.exceptions (T-016).

Covers AC-F3.7 and the exceptions half of AC-F2.5. Counts go through the real walk and pool.
"""

import ast
import itertools
import random
import textwrap

import pytest
from checker_support import (
    REGISTRY_UNDER_TEST,
    assert_linear,
    counts,
    extracted,
    rules_of,
    sites_of,
)

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.exceptions import ExceptionsChecker
from conventiondrift.checkers.exceptions.match import OPTIONS, _find, match_rule
from conventiondrift.checkers.exceptions.sites import BROAD_NAMES, exception_sites
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site
from conventiondrift.rules.mapping import map_rule

NO_BARE_OR_BROAD = match_rule("do not use bare except or catch exception")


def match(prohibited: tuple[str, ...]) -> RuleMatch:
    return RuleMatch(frozenset(), frozenset(prohibited), len(prohibited))


def src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = ExceptionsChecker()
    assert checker.id == "exceptions"
    assert checker.experimental is False
    assert checker.options == frozenset({"bare-except", "broad-except", "specific"}) == OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert set(checker.ast_handlers()) == {ast.ExceptHandler}


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, ExceptionsChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    sentence = "do not use bare except."
    assert ExceptionsChecker().match_rule(sentence) == match_rule(sentence)


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "prohibited"),
    [
        # AC-F2.5 line 6 and AC-F3.7's rule.
        ("do not use bare except.", ("bare-except",)),
        ("do not use bare except or catch exception", ("bare-except", "broad-except")),
        ("never use bare except", ("bare-except",)),
        ("never use bare excepts.", ("bare-except",)),
        ("don't use a bare except clause.", ("bare-except",)),
        ("don\u2019t use bare exceptions.", ("bare-except",)),
        ("avoid bare-except.", ("bare-except",)),
        ("never catch exception.", ("broad-except",)),
        ("avoid catching exception.", ("broad-except",)),
        ("do not catches exception.", ("broad-except",)),
        ("never write except exception.", ("broad-except",)),
        ("avoid broad except clauses.", ("broad-except",)),
        ("avoid generic exceptions.", ("broad-except",)),
        ("never use blanket exception handlers.", ("broad-except",)),
        ("never catch baseexception.", ("broad-except",)),
        ("never use a bare except and do not catch exception.", ("bare-except", "broad-except")),
        ("do not use bare except, do not catch exception.", ("bare-except", "broad-except")),
        ("NEVER USE BARE EXCEPT.", ("bare-except",)),
    ],
)
def test_match_rule_reads_prohibitions(sentence: str, prohibited: tuple[str, ...]) -> None:
    assert match_rule(sentence) == match(prohibited)


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use logging, not print.",
        "always use type hints.",
        "do not use f-strings.",
        "never catch exceptions.",  # the plural names no class
        "never raise exception.",  # not a catch
        "bare means empty.",
        "never use bare.",
        "use bare except.",  # a request, not a prohibition
        "always catch exception.",
        "always catch exception, never use bare except.",  # asks and forbids
        "never use bare except; always use bare except.",
        "use bare except and bare except.",
    ],
)
def test_match_rule_does_not_map_what_is_not_a_prohibition_about_except(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_specificity_is_the_number_of_options_named() -> None:
    one = match_rule("do not use bare except.")
    two = match_rule("do not use bare except or catch exception")
    assert one is not None
    assert two is not None
    assert (one.specificity, two.specificity) == (1, 2)


def test_a_first_word_is_not_judged_by_the_last_word_of_its_clause() -> None:
    # "exception" is first, so nothing is before it; it must not read the clause's last word.
    assert match_rule("exception catch, never use bare except.") == match(("bare-except",))


def test_it_leaves_the_other_canonical_sentences_alone_ac_f2_5() -> None:
    others = [
        "use logging, not print.",
        "use httpx for http calls.",
        "use pytest, not unittest.",
        "store money as integer cents.",
        "use f-strings for string formatting.",
        "always use type hints.",
        "use uv for dependencies.",
    ]
    assert [s for s in others if match_rule(s)] == []


def test_the_registry_maps_the_bare_except_rule_to_exceptions() -> None:
    assert rules_of("Do not use bare except.") == [(1, "exceptions")]
    assert rules_of("Do not use bare except or catch Exception") == [(1, "exceptions")]


# --- sites: AC-F3.7 -------------------------------------------------------------------------


def test_f3_7_one_bare_one_exception_and_five_specific_count_5_and_2() -> None:
    source = src(
        """
        def work() -> None:
            try:
                pass
            except:
                pass
            try:
                pass
            except Exception:
                pass
            try:
                pass
            except ValueError:
                pass
            try:
                pass
            except KeyError:
                pass
            try:
                pass
            except ValueError:
                pass
            try:
                pass
            except KeyError:
                pass
            try:
                pass
            except ValueError:
                pass
        """
    )
    sites = sites_of("exceptions", {"src/mod.py": source})
    assert NO_BARE_OR_BROAD is not None
    assert counts(NO_BARE_OR_BROAD, sites) == (5, 2)
    assert sorted(s.option for s in sites) == ["bare-except", "broad-except"] + ["specific"] * 5


def test_the_bare_except_only_rule_counts_exception_as_following() -> None:
    source = "try:\n    pass\nexcept:\n    pass\ntry:\n    pass\nexcept Exception:\n    pass\n"
    sites = sites_of("exceptions", {"a.py": source})
    only_bare = match_rule("do not use bare except.")
    assert only_bare is not None
    assert counts(only_bare, sites) == (1, 1)


def test_a_site_is_at_the_except_keyword() -> None:
    source = "try:\n    pass\nexcept ValueError:\n    pass\n"
    assert sites_of("exceptions", {"src/a.py": source}) == [Site("src/a.py", 3, 0, "specific")]


def test_a_nested_handler_has_its_own_column() -> None:
    source = "def f():\n    try:\n        pass\n    except:\n        pass\n"
    assert sites_of("exceptions", {"src/a.py": source}) == [Site("src/a.py", 4, 4, "bare-except")]


@pytest.mark.parametrize(
    ("clause", "option"),
    [
        ("except:", "bare-except"),
        ("except Exception:", "broad-except"),
        ("except Exception as exc:", "broad-except"),
        ("except BaseException:", "broad-except"),
        ("except builtins.Exception:", "broad-except"),
        ("except (ValueError, Exception):", "broad-except"),
        ("except (ValueError, (KeyError, Exception)):", "broad-except"),
        ("except* Exception:", "broad-except"),
        ("except ValueError:", "specific"),
        ("except (ValueError, KeyError):", "specific"),
        ("except KeyError as exc:", "specific"),
        ("except errors.ValueError:", "specific"),
        ("except mylib.Exception:", "specific"),
        ("except builtins.ValueError:", "specific"),
        ("except exceptions.Exception:", "specific"),
        ("except MyException:", "specific"),
        ("except ():", "specific"),
        ("except get_errors():", "specific"),
        ("except* ValueError:", "specific"),
    ],
)
def test_each_kind_of_clause(clause: str, option: str) -> None:
    source = f"try:\n    pass\n{clause}\n    pass\n"
    assert [s.option for s in sites_of("exceptions", {"src/a.py": source})] == [option]


def test_the_broad_names_are_exception_and_baseexception() -> None:
    assert BROAD_NAMES == {"Exception", "BaseException"}


def test_tests_and_scripts_are_not_exempt() -> None:
    source = "try:\n    pass\nexcept:\n    pass\n"
    sites = sites_of("exceptions", {"tests/test_x.py": source, "scripts/run.py": source})
    assert [(s.file, s.option) for s in sites] == [
        ("scripts/run.py", "bare-except"),
        ("tests/test_x.py", "bare-except"),
    ]


def test_a_deeply_nested_type_tuple_does_not_recurse() -> None:
    depth = 150
    expr = "(" * depth + "ValueError," + ")," * (depth - 1) + ")"
    source = f"try:\n    pass\nexcept {expr}:\n    pass\n"
    assert [s.option for s in sites_of("exceptions", {"src/a.py": source})] == ["specific"]


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": "try:\n    pass\nexcept:\n    pass\n" for i in range(3)}
    assert len(sites_of("exceptions", files, max_workers=2)) == 3


def test_the_handler_reads_the_node_directly() -> None:
    tree = parse(b"try:\n    pass\nexcept Exception:\n    pass\n")
    node = tree.body[0]
    assert isinstance(node, ast.Try)
    ctx = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())
    assert list(exception_sites(node.handlers[0], ctx)) == [Site("a.py", 3, 0, "broad-except")]


def test_the_handler_gives_nothing_for_a_node_that_is_not_a_handler() -> None:
    ctx = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())
    assert list(exception_sites(ast.Name("x"), ctx)) == []


def test_a_later_always_is_not_a_cue_so_the_whole_sentence_prohibits_bare_except() -> None:
    # Pinned in #58 and revisited in CON-67 (T-016a): the wider cue list and the comma rule
    # (I-10) leave this answer as it was. "always" ends a clause only after a comma ("never use
    # bare except, always use bare except" does read as prohibit then prefer), and "and" never
    # ends one, so here the negation of "never" runs on to the end and both halves read as
    # forbidden. A sentence that is self-contradictory anyway; its reading is a prohibition.
    assert match_rule("never use bare except and always use bare except.") == match(
        ("bare-except",)
    )
    assert match_rule("never use bare except, always use bare except.") is None  # prohibit + prefer


# CON-67 / AC-T016a.2: the five phrasings with "bare except" never map it as preferred.
CON_67_PHRASINGS = [
    "No bare except.",
    "bare except is banned.",
    "Never use bare except.",
    "bare except is not allowed.",
    "Don't use bare except.",
]


@pytest.mark.parametrize("sentence", CON_67_PHRASINGS)
def test_t016a_2_a_negated_bare_except_never_maps_as_preferred(sentence: str) -> None:
    found = match_rule(sentence.lower())
    assert found is None or "bare-except" not in found.preferred
    assert found == match(("bare-except",))


@pytest.mark.parametrize("sentence", CON_67_PHRASINGS)
def test_t016a_2_the_registry_maps_each_phrasing_to_exceptions(sentence: str) -> None:
    mapped = map_rule(sentence.lower(), REGISTRY_UNDER_TEST)
    assert mapped.checker == "exceptions"
    assert mapped.match == match(("bare-except",))


def test_t016a_2_in_an_agents_md_no_line_maps_bare_except_as_preferred() -> None:

    text = "\n".join(CON_67_PHRASINGS) + "\n"
    rules = extracted(text)
    assert [(r.line, r.checker) for r in rules] == [(3, "exceptions"), (5, "exceptions")]
    for rule in rules:
        assert rule.match == match(("bare-except",))


@pytest.mark.parametrize(
    ("sentence", "prohibited"),
    [
        ("never use bare except() or baseexception.", ("bare-except", "broad-except")),
        ("don't use bare except, use specific exceptions.", ("bare-except",)),
        ("stop using bare except.", ("bare-except",)),
        ("bare except and catch exception are forbidden.", ("bare-except", "broad-except")),
        ("catching exception is deprecated.", ("broad-except",)),
    ],
)
def test_the_wider_cues_read_for_exceptions_too(sentence: str, prohibited: tuple[str, ...]) -> None:
    assert match_rule(sentence) == match(prohibited)


HOSTILE_RULES = {
    "no cue": lambda n: "never " + "bare except " * (n // 12),
    "request": lambda n: "always catch exception " * (n // 24),
    "both": lambda n: "never bare except or catch exception " * (n // 38),
}


@pytest.mark.timing
@pytest.mark.parametrize("kind", HOSTILE_RULES)
def test_match_rule_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    assert_linear(HOSTILE_RULES[kind], match_rule, label=kind)


def test_hyphenated_spellings_are_read_as_the_options_they_name() -> None:
    # A hyphen joins words (I-10 item 4b), so "bare-except" is one word and is read as such.
    assert match_rule("avoid bare-except.") == match(("bare-except",))
    assert match_rule("never use bare-excepts.") == match(("bare-except",))
    assert match_rule("never use broad-except.") == match(("broad-except",))
    assert match_rule("never use generic-exceptions or bare-exception.") == match(
        ("bare-except", "broad-except")
    )
    assert match_rule("no blanket-exception.") == match(("broad-except",))
    assert match_rule("never use bare-nonsense.") is None


def test_trailing_cue_reach_applies_to_exceptions_too() -> None:
    assert match_rule("bare except is forbidden.") == match(("bare-except",))
    assert match_rule("bare except is forbidden, use specific exceptions.") == match(
        ("bare-except",)
    )
    assert match_rule("use specific exceptions, bare except is forbidden.") is None
    assert match_rule("use specific exceptions; bare except is banned.") == match(("bare-except",))
    assert match_rule("no-op handlers are fine, but never use bare except.") == match(
        ("bare-except",)
    )


# --- CON-67 round 2: the comma guard (CR1 F1 on #61, I-10 item 4a) --------------------------


@pytest.mark.parametrize(
    "sentence",
    [
        "Catching Exception is acceptable, bare except is forbidden.",
        "Catching Exception is fine, bare except is not allowed.",
        "Broad except is tolerated, bare except is banned.",
        "Catching Exception is acceptable, bare except is deprecated.",
        "Bare except, catching Exception and BaseException are banned.",  # list form
    ],
)
def test_f1_a_comma_between_two_mentions_in_a_trailing_cue_clause_is_not_verifiable(
    sentence: str,
) -> None:
    # Reading it as "prohibit both" would be wrong: the first half allows one of them.
    assert match_rule(sentence.lower()) is None


@pytest.mark.parametrize(
    ("sentence", "prohibited"),
    [
        ("Bare except and catching Exception are banned.", ("bare-except", "broad-except")),
        ("Bare except is banned, use specific exceptions.", ("bare-except",)),
        ("Bare except is forbidden.", ("bare-except",)),
    ],
)
def test_f1_the_forms_without_a_surviving_comma_still_map(
    sentence: str, prohibited: tuple[str, ...]
) -> None:
    assert match_rule(sentence.lower()) == match(prohibited)


# --- CON-67 round 3: the contiguity guard (CR1 on #61, I-10 item 4a) -------------------------


@pytest.mark.parametrize(
    "sentence",
    [
        "Catching Exception is acceptable and bare except is forbidden.",
        "Catching Exception is fine or bare except is not allowed.",
        "Catching Exception is fine nor bare except is banned.",
        "Bare except is fine and broad except is deprecated.",
        "Bare except and the catching Exception clause are banned.",
        "Bare except and also catching Exception are banned.",
        # A word after or before a phrase isn't part of it, wherever the phrase stands:
        "Bare except clauses and catching Exception are banned.",
        "Catching Exception clauses and bare except are banned.",
        "Broad except clauses and bare except are banned.",
        "Bare except and the broad except are banned.",
        "Bare except and the catching Exception are banned.",
    ],
)
def test_round_3_a_word_between_two_mentions_in_a_trailing_cue_clause_is_not_verifiable(
    sentence: str,
) -> None:
    assert match_rule(sentence.lower()) is None


@pytest.mark.parametrize(
    ("sentence", "prohibited"),
    [
        ("Bare except and catching Exception are banned.", ("bare-except", "broad-except")),
        ("Catching Exception or bare except is forbidden.", ("bare-except", "broad-except")),
        ("Bare excepts or generic exceptions are deprecated.", ("bare-except", "broad-except")),
        (
            "`bare except` and `catching Exception` are not allowed.",
            ("bare-except", "broad-except"),
        ),
        ("Bare-except nor blanket-exceptions are disallowed.", ("bare-except", "broad-except")),
        ("Bare except and BaseException are prohibited.", ("bare-except", "broad-except")),
        ("Generic exceptions and bare except are banned.", ("bare-except", "broad-except")),
        ("Bare except or blanket exceptions are banned.", ("bare-except", "broad-except")),
        ("Catching Exception nor bare excepts are banned.", ("bare-except", "broad-except")),
        ("The broad except is banned.", ("broad-except",)),
        (
            "Bare except and catching Exception clauses are forbidden.",
            ("bare-except", "broad-except"),
        ),
    ],
)
def test_round_3_a_phrase_with_its_own_words_and_connectors_between_them_still_maps(
    sentence: str, prohibited: tuple[str, ...]
) -> None:
    # "bare except" and "catching Exception" are two words each; those are the mention's own.
    assert match_rule(sentence.lower()) == match(prohibited)


def test_round_3_with_a_prefix_cue_the_words_between_mentions_do_not_matter() -> None:
    assert match_rule("never use a bare except or, worse, catching exception.") == match(
        ("bare-except", "broad-except")
    )


def test_round_3_a_second_phrase_that_would_share_a_word_is_not_a_second_mention() -> None:
    # "except exception" would start inside "bare except": the first phrase is the mention.
    assert match_rule("never use bare except exception.") == match(("bare-except",))
    assert match_rule("broad except exception is banned.") == match(("broad-except",))
    # Phrases that follow each other without sharing a word are both mentions.
    assert match_rule("bare except catching exception are banned.") == match(
        ("bare-except", "broad-except")
    )
    assert match_rule("catching exception bare except are banned.") == match(
        ("bare-except", "broad-except")
    )


def test_round_3_cue_reach_is_the_same_for_a_phrase_that_starts_at_its_index() -> None:
    # A prefix cue reaches a phrase that follows it, and a trailing cue one that precedes it, for
    # each shape of phrase (the mention's index is its first word).
    both = ("bare-except", "broad-except")
    assert match_rule("never catching exception.") == match(("broad-except",))
    assert match_rule("never use bare except or catching exception.") == match(both)
    assert match_rule("never use catching exception, bare except.") == match(both)
    assert match_rule("do not use broad except.") == match(("broad-except",))
    assert match_rule("avoid generic exceptions and bare excepts.") == match(both)
    assert match_rule("catching exception is banned.") == match(("broad-except",))
    assert match_rule("broad excepts and bare except are not allowed.") == match(both)
    assert match_rule("blanket exception is forbidden, use specific exceptions.") == match(
        ("broad-except",)
    )
    # A phrase after the trailing cue, or one before a prefix cue, is not reached.
    assert match_rule("bare except is banned catching exception") is None
    assert match_rule("catching exception, never bare except.") is None  # preferred mention


_WORDS = (
    "bare except excepts exception exceptions catch catching catches broad generic blanket "
    "baseexception bare-except broad-exceptions generic-except and or the x"
).split()


def _spans(clause: tuple[str, ...]) -> list[tuple[int, int, int]]:
    """``(index, start, stop)`` of each mention ``_find`` gives, after checking its shape."""
    found = []
    for mention in _find(clause):
        assert len(mention) == 3, (clause, mention)
        index, _option, words = mention
        assert words.step == 1 and len(words) >= 1, (clause, mention)
        assert words.start == index, (clause, mention)  # a span starts at its index
        assert 0 <= words.start and words.stop <= len(clause), (clause, mention)
        found.append((index, words.start, words.stop))
    for (_, _, stop), (_, start, _) in itertools.pairwise(found):
        assert stop <= start, (clause, found)  # no two spans share a word, in order
    return found


def test_round_3_find_gives_spans_that_start_at_their_index_and_never_overlap() -> None:
    # Every clause of up to four words, from the words the finder looks at and a few it doesn't.
    count = 0
    for size in range(1, 5):
        for clause in itertools.product(_WORDS, repeat=size):
            _spans(clause)
            count += 1
    assert count > 100_000
    # Longer clauses: a seeded random sample, and the phrases that run into each other.
    rng = random.Random(61)  # noqa: S311 - a fixed-seed test generator
    for _ in range(20_000):
        _spans(tuple(rng.choices(_WORDS, k=rng.randint(5, 14))))
    for text in (
        "bare except exception",
        "broad except exception exception",
        "catching exception except exception",
        "bare except bare except bare except",
        "catch catching exception exception",
        "bare " * 50 + "except exception " * 50,
    ):
        _spans(tuple(text.split()))


def test_round_3_find_spans_match_the_phrases() -> None:
    assert _spans(("bare", "except")) == [(0, 0, 2)]
    assert _spans(("x", "catching", "exception")) == [(1, 1, 3)]
    assert _spans(("a", "broad", "excepts", "b")) == [(1, 1, 3)]
    assert _spans(("bare-except",)) == [(0, 0, 1)]
    assert _spans(("baseexception", "bare", "except")) == [(0, 0, 1), (1, 1, 3)]


@pytest.mark.parametrize(
    "sentence",
    [
        "Catching Exception is acceptable; bare except is forbidden.",
        "Catching Exception is fine. Bare except is not allowed.",
    ],
)
def test_f1_with_a_semicolon_or_full_stop_the_acceptance_is_a_preferred_mention(
    sentence: str,
) -> None:
    # No comma is involved here. "acceptable" and "fine" are no cues, so catching Exception reads
    # as preferred, and `exceptions` maps prohibitions only: Not verifiable.
    assert match_rule(sentence.lower()) is None
