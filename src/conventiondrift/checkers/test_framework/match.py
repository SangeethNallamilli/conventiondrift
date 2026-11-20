"""``match_rule`` for the test-framework checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about the test framework when its sentence names ``pytest`` (or ``py.test``) or
``unittest`` (or ``unittest.TestCase``); the polarity of each mention comes from
``phrases.classify``. So "Use pytest, not unittest." prefers pytest and forbids unittest, and
"Avoid unittest." only forbids unittest. "Prefer pytest over unittest." names both as preferred,
which ``classify`` turns into Not verifiable (I-10 "Negation in phrases.py" 4(c)).
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import classify
from conventiondrift.model import RuleMatch

__all__ = ["OPTIONS", "PYTEST_WORDS", "UNITTEST_WORDS", "match_rule"]

OPTIONS: Final = frozenset({"pytest", "unittest"})
"""Pytest-style test functions and ``unittest.TestCase`` subclasses."""

PYTEST_WORDS: Final = frozenset({"pytest", "py.test"})
UNITTEST_WORDS: Final = frozenset({"unittest", "unittest.testcase"})


def _find(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    for index, word in enumerate(clause):
        if word in PYTEST_WORDS:
            yield index, "pytest"
        elif word in UNITTEST_WORDS:
            yield index, "unittest"


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The options a rule sentence prefers and forbids, or None if it isn't about a framework."""
    return classify(normalized_text, _find, OPTIONS)
