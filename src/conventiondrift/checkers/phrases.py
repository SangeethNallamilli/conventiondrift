"""Shared word-level reading of rule sentences for the ``match_rule`` of each checker (I-10).

``match_rule`` gets the normalized text of one rule sentence (lowercase, single
spaces; DESIGN §7 step 2). A checker reads it in three steps:

1. ``clauses`` cuts the sentence into word lists (the clause rules below).
2. The checker's own ``find`` says which of its options a clause mentions, and
   at which word.
3. ``classify`` sorts each mention by polarity: a mention after a negation cue
   (``NEGATIONS``) in its clause is prohibited, any other mention is preferred.

Clause rules (INTERFACES I-10, "Negation in phrases.py"):

* A negation cue applies from the cue to the end of its clause. Words before
  the cue are not negated, so "use logging, not print" prefers logging and
  prohibits print.
* A clause ends at ``.``, ``;``, ``:``, ``(``, ``)``, a dash (an en or em dash,
  ``--``, or a hyphen with a space on both sides; a hyphen inside a word such
  as "bare-except" is not a dash), and at the words ``but``, ``then``,
  ``instead`` and ``however``.
* ``and``, ``or``, ``nor`` and ``,`` do **not** end a clause, so "never use
  print or requests" and "do not use print, requests" prohibit both.
* "X instead of Y" and "X rather than Y" prohibit Y. ``instead of`` is read as
  one cue that starts a new clause; a bare ``instead`` (as in "don't print,
  instead use logging") only ends the clause.
* Only the cues in ``NEGATIONS`` are read. Any other phrasing ("no print",
  "print is banned") is not a cue, so what it mentions reads as preferred.

A sentence that doesn't give a usable ``RuleMatch`` is not mapped, which makes
the rule Not verifiable, never a wrong verdict. That is the case when:

* nothing is mentioned;
* an option is named in both a negated and a non-negated clause;
* every option is prohibited (the rule would allow nothing); or
* every option is preferred (every site would follow, so the rule would always
  hold; this is also what an unread cue such as "no" looks like).

Specificity is the number of distinct options the sentence mentions
(``len(preferred | prohibited)``, binding for every checker, I-10). Two checkers
that each find one option in a sentence tie, and a tie is Not verifiable
(AC-F2.6).

Everything here is linear in the length of the sentence: ``clauses`` reads each
token once, ``first_cue`` runs once per clause, and a mention is negated exactly
when it comes after that cue.

The one regex, ``TOKEN``, is applied to repo text (SECURITY-RULES R2.5). It is a
single character class repeated, an optional ``.name`` suffix that starts with a
literal dot, single characters, and ``--`` followed by more hyphens, so it can't
backtrack and runs in linear time.
"""

import re
from collections.abc import Callable, Iterable
from typing import Final

from conventiondrift.model import RuleMatch

__all__ = [
    "BREAK_MARKS",
    "BREAK_WORDS",
    "NEGATIONS",
    "TOKEN",
    "Finder",
    "classify",
    "clauses",
    "first_cue",
    "is_negated",
]

TOKEN: Final = re.compile(
    r"[a-z0-9_'\u2019]+(?:\.[a-z0-9_]+)*|[;:().\u2013\u2014]|(?<=\s)-(?=\s)|--+"
)
"""A word, or a clause mark. A dotted name such as ``logging.warn`` is one word."""

BREAK_MARKS: Final = frozenset(";:().-\u2013\u2014")
"""First characters of the mark tokens, each of which ends a clause."""

BREAK_WORDS: Final = frozenset({"but", "then", "instead", "however"})
"""Words that end a clause; negation doesn't carry across them."""

INSTEAD_OF: Final = "instead of"
"""The cue ``clauses`` makes of the words "instead of" (a clause break, then a cue)."""

NEGATIONS: Final = frozenset(
    {
        "never",
        "not",
        "dont",
        "don't",
        "don\u2019t",
        "avoid",
        "over",
        "rather",
        "without",
        INSTEAD_OF,
    }
)
"""Cues that make what follows, to the end of the same clause, something the rule forbids."""

Finder = Callable[[tuple[str, ...]], Iterable[tuple[int, str]]]
"""Gives the ``(word index, option)`` pairs one checker finds in a clause."""


def clauses(text: str) -> tuple[tuple[str, ...], ...]:
    """The sentence as non-empty word lists, cut at the clause breaks above."""
    tokens = TOKEN.findall(text.lower())
    found: list[tuple[str, ...]] = []
    current: list[str] = []
    index = 0
    while index < len(tokens):
        word = tokens[index]
        index += 1
        is_instead_of = word == "instead" and tokens[index : index + 1] == ["of"]
        if word in BREAK_WORDS or word[0] in BREAK_MARKS:
            if current:
                found.append(tuple(current))
                current = []
            if is_instead_of:
                current.append(INSTEAD_OF)
                index += 1
        else:
            current.append(word)
    if current:
        found.append(tuple(current))
    return tuple(found)


def first_cue(clause: tuple[str, ...]) -> int | None:
    """The index of the first negation cue in ``clause``, or None when it has none."""
    for index, word in enumerate(clause):
        if word in NEGATIONS:
            return index
    return None


def _after(cue: int | None, index: int) -> bool:
    """Whether the word at ``index`` comes after the clause's first cue (so it is negated)."""
    return cue is not None and cue < index


def is_negated(clause: tuple[str, ...], index: int) -> bool:
    """Whether a negation cue comes before ``clause[index]`` in its clause."""
    return _after(first_cue(clause), index)


def classify(text: str, find: Finder, options: frozenset[str]) -> RuleMatch | None:
    """The ``RuleMatch`` for ``text``, or None when it can't be read as a rule for ``options``."""
    preferred: set[str] = set()
    prohibited: set[str] = set()
    for clause in clauses(text):
        # The cue is found once per clause, not once per mention: a hostile sentence with
        # 100,000 mentions in one clause must not cost 100,000 scans (linear time, R2.5).
        cue = first_cue(clause)
        for index, option in find(clause):
            (prohibited if _after(cue, index) else preferred).add(option)
    mentioned = preferred | prohibited
    if not mentioned or preferred & prohibited:
        return None
    if not preferred and prohibited >= options:
        return None
    if preferred >= options:
        return None
    return RuleMatch(
        preferred=frozenset(preferred), prohibited=frozenset(prohibited), specificity=len(mentioned)
    )
