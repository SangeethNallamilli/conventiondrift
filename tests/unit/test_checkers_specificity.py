"""One shared test over every registered checker: the specificity convention (INTERFACES I-10).

Every checker sets ``specificity = len(preferred | prohibited)`` and nothing else, so C6's
comparison is the same for all of them and the AC-F2.6 tie on "Never use print or requests"
holds by construction. The test reads ``REGISTRY``, so a checker added by T-017 to T-019 is
covered without changing this file. A checker that needs another measure needs an ADR first.
"""

import pytest

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.base import Checker
from conventiondrift.model import CheckerId
from conventiondrift.rules.extract import normalize

CANONICAL: dict[CheckerId, str] = {
    # AC-F2.5's eight canonical sentences, by the checker that must take each.
    "logging": "Use logging, not print.",
    "http-client": "Use httpx for HTTP calls.",
    "test-framework": "Use pytest, not unittest.",
    "money": "Store money as integer cents.",
    "string-format": "Use f-strings for string formatting.",
    "exceptions": "Do not use bare except.",
    "type-hints": "Always use type hints.",
    "package-manager": "Use uv for dependencies.",
}

# Sentences in each DESIGN §7 shape and from the other ACs, with the options of many checkers
# (one, two and several per sentence), plus ones no checker should take.
SENTENCES: tuple[str, ...] = (
    *CANONICAL.values(),
    "Never use print or requests.",  # AC-F2.6
    "Never use print().",
    "Use print() for debug output.",
    "Use httpx, not requests.",
    "Use httpx, not requests or aiohttp.",
    "Prefer pytest over unittest.",
    "Prefer logging over print.",
    "Always use f-strings.",
    "Do not use bare except.",
    "Do not use bare except or catch Exception",  # AC-F3.7's rule
    "Don't use the % operator or .format().",
    "Avoid catching Exception.",
    "Avoid unittest.",
    "Never use pip, use uv.",
    "Use Poetry for dependencies.",
    "Use logging, not print, and never use bare except.",
    "Keep money as integer cents.",
    "Represent prices as Decimal.",
    "Annotate every function.",
    "Always keep functions small.",  # AC-F2.7: no checker takes it
    "We use Django.",
    "",
)


def _checkers() -> list[Checker]:
    return list(REGISTRY)


@pytest.mark.parametrize("checker", _checkers(), ids=lambda c: c.id)
def test_every_match_has_specificity_len_preferred_union_prohibited(checker: Checker) -> None:
    for sentence in SENTENCES:
        match = checker.match_rule(normalize(sentence))
        if match is not None:
            assert match.specificity == len(match.preferred | match.prohibited), sentence


@pytest.mark.parametrize("checker", _checkers(), ids=lambda c: c.id)
def test_the_canonical_sentence_is_taken_by_its_checker(checker: Checker) -> None:
    # Keeps the test above from passing vacuously: each checker produces matches on this set.
    match = checker.match_rule(normalize(CANONICAL[checker.id]))
    assert match is not None
    assert match.specificity == len(match.preferred | match.prohibited) >= 1


@pytest.mark.parametrize("checker", _checkers(), ids=lambda c: c.id)
def test_every_match_is_valid_for_its_checker(checker: Checker) -> None:
    for sentence in SENTENCES:
        match = checker.match_rule(normalize(sentence))
        if match is not None:
            assert (match.preferred | match.prohibited) <= checker.options, sentence
            assert not match.preferred & match.prohibited, sentence


def test_the_registry_is_not_empty() -> None:
    assert REGISTRY
