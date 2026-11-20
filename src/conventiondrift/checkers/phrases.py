"""Shared word-level reading of rule sentences for the ``match_rule`` of each checker (I-10).

``match_rule`` gets the normalized text of one rule sentence (lowercase, single
spaces; DESIGN §7 step 2). A checker reads it in three steps:

1. ``clauses`` cuts the sentence into word lists (the clause rules below).
2. The checker's own ``find`` says which of its options a clause mentions, and
   at which word.
3. ``classify`` sorts each mention by polarity: a mention that a negation cue
   reaches (``NEGATIONS`` after it, or ``TRAILING_WORDS`` / ``TRAILING_PAIRS``
   before it, in the same clause) is prohibited, any other mention is preferred.

Clause rules (INTERFACES I-10, "Negation in phrases.py"):

* A negation cue (``NEGATIONS``: "no", "never", "not", "don't", "avoid",
  "without", "shouldn't", "mustn't", "stop using", "instead of", "rather than",
  and so "do not", "should not" and "must not" through "not") applies from the
  cue to the end of its clause. Words before the cue are not negated, so "use
  logging, not print" prefers logging and prohibits print. A bare "rather" or
  "over" is not a cue ("prefer X over Y" prefers both, which the all-preferred
  guard below turns into Not verifiable).
* A trailing cue applies from the start of its clause to the cue: "print is
  banned", "print is forbidden", "prohibited", "disallowed", "deprecated", "is
  not allowed" and "are banned" prohibit what is mentioned before them in the
  same clause. ("banned" alone, as in "print was banned", is not a cue.) If the
  clause also holds a positive verb cue (``VERB_CUES``) anywhere, or mentions
  an option after the trailing cue, the whole sentence is not mapped: "use
  logging, everything else is forbidden" and "use logging, it is forbidden to
  print" are Not verifiable, while "print is forbidden" prohibits print and
  "print is forbidden, use logging" splits at the comma (below).
* Words are joined by a hyphen into one word: "no-op" and "non-blocking" hold no
  cue. The phrases "no matter", "no doubt" and "not only" are never cues.
* A clause ends at ``.``, ``;``, ``:``, ``(``, ``)``, a dash (an en or em dash,
  ``--``, or a hyphen with a space on both sides; a hyphen inside a word such
  as "bare-except" is not a dash), and at the words ``but``, ``then``,
  ``instead`` and ``however``.
* A comma ends a clause only when the next word is a positive verb cue
  (``VERB_CUES``: "use", "prefer", "choose", "pick", "switch", "always",
  "instead"). So "don't print, use logging" prohibits print and prefers
  logging, while "no print, requests or urllib" prohibits all three.
* ``and``, ``or`` and ``nor`` do **not** end a clause, so "never use print or
  requests" prohibits both.
* An empty ``()`` right after a name, with or without backticks (``print()``,
  `` `print`() ``), is a call suffix. It is removed before the sentence is cut
  into clauses, so "never use print() or requests()" prohibits both.
* "X instead of Y" and "X rather than Y" prohibit Y. ``instead of`` is read as
  one cue that starts a new clause; a bare ``instead`` (as in "don't print,
  instead use logging") only ends the clause.
* Only the cues above are read. Any other phrasing ("print has been banned")
  is not a cue, so what it mentions reads as preferred.

A sentence that doesn't give a usable ``RuleMatch`` is not mapped, which makes
the rule Not verifiable, never a wrong verdict. That is the case when:

* nothing is mentioned;
* an option is named in both a negated and a non-negated clause;
* every option is prohibited (the rule would allow nothing); or
* every option is preferred (every site would follow, so the rule would always
  hold; this is also what a cue that isn't read looks like); or
* a clause with a trailing cue also holds a positive verb cue or an option
  mentioned after the cue.

Specificity is the number of distinct options the sentence mentions
(``len(preferred | prohibited)``, binding for every checker, I-10). Two checkers
that each find one option in a sentence tie, and a tie is Not verifiable
(AC-F2.6).

Everything here is linear in the length of the sentence: ``clauses`` reads each
token once, ``first_cue`` and ``last_trailing_cue`` run once per clause, and a
mention is negated exactly when it comes after the first cue or before the last
trailing cue.

The two regexes, ``TOKEN`` and ``CALL_SUFFIX``, are applied to repo text
(SECURITY-RULES R2.5). ``TOKEN`` is a single character class repeated, an
optional ``.name`` suffix that starts with a literal dot, single characters, and
``--`` followed by more hyphens; ``CALL_SUFFIX`` is one character of lookbehind
and the literal ``()``. Neither can backtrack, so both run in linear time.
"""

import re
from collections.abc import Callable, Iterable
from typing import Final

from conventiondrift.model import RuleMatch

__all__ = [
    "BREAK_MARKS",
    "BREAK_WORDS",
    "CALL_SUFFIX",
    "NEGATIONS",
    "TOKEN",
    "TRAILING_PAIRS",
    "TRAILING_WORDS",
    "VERB_CUES",
    "Finder",
    "classify",
    "clauses",
    "first_cue",
    "is_negated",
    "last_trailing_cue",
]

TOKEN: Final = re.compile(
    r"[a-z0-9_'\u2019]+(?:[.-][a-z0-9_]+)*|[;:().,\u2013\u2014]|(?<=\s)-(?=\s)|--+"
)
"""A word, or a clause mark. A dotted or hyphenated name such as ``logging.warn`` or
``no-op`` is one word."""

CALL_SUFFIX: Final = re.compile(r"(?<=[a-z0-9_`])\(\)")
"""An empty ``()`` right after a name or its closing backtick: ``print()``, `` `print`() ``."""

BREAK_MARKS: Final = frozenset(";:().-\u2013\u2014")
"""First characters of the mark tokens, each of which ends a clause."""

BREAK_WORDS: Final = frozenset({"but", "then", "instead", "however"})
"""Words that end a clause; negation doesn't carry across them."""

VERB_CUES: Final = frozenset({"use", "prefer", "choose", "pick", "switch", "always", "instead"})
"""Positive verb cues: a comma before one ends a clause, and one in a clause with a trailing cue
makes the sentence unreadable."""

INSTEAD_OF: Final = "instead of"
"""The cue ``clauses`` makes of the words "instead of" (a clause break, then a cue)."""

STOP_USING: Final = "stop using"
"""The cue ``clauses`` makes of the words "stop using"."""

RATHER_THAN: Final = "rather than"
"""The cue ``clauses`` makes of the words "rather than"."""

MERGED: Final = {
    ("stop", "using"): STOP_USING,
    ("rather", "than"): RATHER_THAN,
    ("no", "matter"): "no matter",
    ("no", "doubt"): "no doubt",
    ("not", "only"): "not only",
}
"""Word pairs that ``clauses`` reads as one word. The first two are cues; the other three are
set phrases that are never cues (their first word would be one)."""

NEGATIONS: Final = frozenset(
    {
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
        STOP_USING,
        RATHER_THAN,
        INSTEAD_OF,
    }
)
"""Cues that make what follows, to the end of the same clause, something the rule forbids.

"do not", "should not" and "must not" are read through "not". A bare "rather" or "over" is not
a cue."""

TRAILING_WORDS: Final = frozenset({"forbidden", "prohibited", "disallowed", "deprecated"})
"""Cues that make what comes before them, from the start of the same clause, forbidden."""

TRAILING_PAIRS: Final = frozenset({("is", "banned"), ("are", "banned"), ("not", "allowed")})
"""Two-word trailing cues; the cue is at the second word."""

Finder = Callable[[tuple[str, ...]], Iterable[tuple[int, str]]]
"""Gives the ``(word index, option)`` pairs one checker finds in a clause."""


def clauses(text: str) -> tuple[tuple[str, ...], ...]:
    """The sentence as non-empty word lists, cut at the clause breaks above."""
    tokens = TOKEN.findall(CALL_SUFFIX.sub("", text.lower()))
    found: list[tuple[str, ...]] = []
    current: list[str] = []
    index = 0
    while index < len(tokens):
        word = tokens[index]
        following = tokens[index + 1 : index + 2]
        pair = (word, following[0] if following else "")
        index += 1
        is_break = word in BREAK_WORDS or word[0] in BREAK_MARKS
        if word == ",":
            is_break = bool(following) and following[0] in VERB_CUES
        elif pair in MERGED:
            current.append(MERGED[pair])
            index += 1
        elif not is_break:
            current.append(word)
        if is_break:
            if current:
                found.append(tuple(current))
                current = []
            if word == "instead" and following == ["of"]:
                current.append(INSTEAD_OF)
                index += 1
    if current:
        found.append(tuple(current))
    return tuple(found)


def first_cue(clause: tuple[str, ...]) -> int | None:
    """The index of the first negation cue in ``clause``, or None when it has none."""
    for index, word in enumerate(clause):
        if word in NEGATIONS:
            return index
    return None


def last_trailing_cue(clause: tuple[str, ...]) -> int | None:
    """The index of the last trailing cue in ``clause`` (the second word of a pair), or None."""
    last = None
    for index, word in enumerate(clause):
        if word in TRAILING_WORDS or (index and (clause[index - 1], word) in TRAILING_PAIRS):
            last = index
    return last


def _reached(cue: int | None, end: int | None, index: int) -> bool:
    """Whether a cue reaches the word at ``index``: after the first cue, or before the last
    trailing cue."""
    return (cue is not None and cue < index) or (end is not None and index < end)


def _unreadable(clause: tuple[str, ...], mentions: list[tuple[int, str]], end: int) -> bool:
    """Whether a clause with a trailing cue at ``end`` can't be read: it holds a positive verb
    cue anywhere, or mentions an option after the cue (I-10, "Negation" item 4)."""
    return any(word in VERB_CUES for word in clause) or any(index > end for index, _ in mentions)


def is_negated(clause: tuple[str, ...], index: int) -> bool:
    """Whether a negation cue in ``clause`` reaches ``clause[index]``."""
    return _reached(first_cue(clause), last_trailing_cue(clause), index)


def classify(text: str, find: Finder, options: frozenset[str]) -> RuleMatch | None:
    """The ``RuleMatch`` for ``text``, or None when it can't be read as a rule for ``options``."""
    preferred: set[str] = set()
    prohibited: set[str] = set()
    for clause in clauses(text):
        # The cues are found once per clause, not once per mention: a hostile sentence with
        # 100,000 mentions in one clause must not cost 100,000 scans (linear time, R2.5).
        cue = first_cue(clause)
        end = last_trailing_cue(clause)
        mentions = list(find(clause))
        if end is not None and _unreadable(clause, mentions, end):
            return None
        for index, option in mentions:
            (prohibited if _reached(cue, end, index) else preferred).add(option)
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
