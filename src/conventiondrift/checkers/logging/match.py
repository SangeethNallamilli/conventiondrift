"""``match_rule`` for the logging checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about logging when its sentence mentions ``logging``, a ``logger`` or
``print``; the polarity of each mention comes from ``phrases.classify``. So
"Use logging, not print." prefers logging and forbids print, "Never use print()."
only forbids print, and "Use print() for debug output." prefers print.
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import classify
from conventiondrift.model import RuleMatch

__all__ = ["LOGGING_WORDS", "OPTIONS", "PRINT_WORDS", "match_rule"]

OPTIONS: Final = frozenset({"logging", "print"})
"""The logging checker's options: calls to the logging module (or a logger) and ``print()``."""

LOGGING_WORDS: Final = frozenset({"logging", "logger", "loggers"})
PRINT_WORDS: Final = frozenset({"print", "prints"})


def _find(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    for index, word in enumerate(clause):
        if word in LOGGING_WORDS:
            yield index, "logging"
        elif word in PRINT_WORDS:
            yield index, "print"


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The options a rule sentence prefers and forbids, or None if it isn't about logging."""
    return classify(normalized_text, _find, OPTIONS)
