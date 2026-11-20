"""Shared word-level reading of rule sentences for the ``match_rule`` of each checker (I-10).

``match_rule`` gets the normalized text of one rule sentence (lowercase, single
spaces; DESIGN §7 step 2). A checker reads it in three steps:

1. ``clauses`` cuts the sentence into word lists at ``,`` ``;`` ``:`` and the
   words "and", "but" and "then", so "use logging, not print" is two clauses.
2. The checker's own ``find`` says which of its options a clause mentions, and
   at which word.
3. ``classify`` sorts each mention by polarity: a mention after a negation word
   in its clause (``NEGATIONS``) is prohibited, any other mention is preferred.
   So "never use print or requests" prohibits print and "use logging instead
   of print" prefers logging and prohibits print.

A sentence that doesn't give a usable ``RuleMatch`` (nothing mentioned, the same
option both preferred and prohibited, or every option prohibited) is not
mapped, which makes the rule Not verifiable, never a wrong verdict.

Specificity is the number of distinct options the sentence mentions. Two
checkers that each find one option in a sentence tie, and a tie is Not
verifiable (AC-F2.6).

The one regex, ``TOKEN``, is applied to repo text (SECURITY-RULES R2.5): it is a
single character class repeated, and an optional ``.name`` suffix that starts
with a literal dot, so it can't backtrack and runs in linear time.
"""

import re
from collections.abc import Callable, Iterable
from typing import Final

from conventiondrift.model import RuleMatch

__all__ = ["BREAKS", "NEGATIONS", "TOKEN", "Finder", "classify", "clauses", "is_negated"]

TOKEN: Final = re.compile(r"[,;:]|[a-z0-9_'\u2019]+(?:\.[a-z0-9_]+)*")
"""A clause delimiter, or a word. A dotted name such as ``logging.warn`` is one word."""

BREAKS: Final = frozenset({",", ";", ":", "and", "but", "then"})
"""Tokens that end a clause; negation doesn't carry across them."""

NEGATIONS: Final = frozenset(
    {"never", "not", "dont", "don't", "don\u2019t", "avoid", "over", "instead", "rather", "without"}
)
"""Words that make what follows, in the same clause, something the rule forbids."""

Finder = Callable[[tuple[str, ...]], Iterable[tuple[int, str]]]
"""Gives the ``(word index, option)`` pairs one checker finds in a clause."""


def clauses(text: str) -> tuple[tuple[str, ...], ...]:
    """The sentence as non-empty word lists, cut at ``BREAKS``."""
    found: list[tuple[str, ...]] = []
    current: list[str] = []
    for token in TOKEN.findall(text.lower()):
        if token in BREAKS:
            if current:
                found.append(tuple(current))
                current = []
        else:
            current.append(token)
    if current:
        found.append(tuple(current))
    return tuple(found)


def is_negated(clause: tuple[str, ...], index: int) -> bool:
    """Whether a negation word comes before ``clause[index]`` in its clause."""
    return any(word in NEGATIONS for word in clause[:index])


def classify(text: str, find: Finder, options: frozenset[str]) -> RuleMatch | None:
    """The ``RuleMatch`` for ``text``, or None when it can't be read as a rule for ``options``."""
    preferred: set[str] = set()
    prohibited: set[str] = set()
    for clause in clauses(text):
        for index, option in find(clause):
            (prohibited if is_negated(clause, index) else preferred).add(option)
    mentioned = preferred | prohibited
    if not mentioned or preferred & prohibited:
        return None
    if not preferred and prohibited >= options:
        return None
    return RuleMatch(
        preferred=frozenset(preferred), prohibited=frozenset(prohibited), specificity=len(mentioned)
    )
