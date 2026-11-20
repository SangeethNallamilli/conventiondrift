"""Shared word-level reading of rule sentences for the ``match_rule`` of each checker (I-10).

``match_rule`` gets the normalized text of one rule sentence (lowercase, single
spaces; DESIGN §7 step 2). A checker reads it in three steps:

1. ``clauses`` cuts the sentence into word lists (the clause rules below).
2. The checker's own ``find`` says which of its options a clause mentions, and
   at which word.
3. ``classify`` sorts each mention by polarity: a mention that a negation cue
   reaches (``NEGATIONS`` after it, or ``TRAILING_WORDS`` / ``TRAILING_PAIRS`` /
   ``TRAILING_PHRASES`` before it, in the same clause) is prohibited, any other
   mention is preferred.

Clause rules (INTERFACES I-10, "Negation in phrases.py"):

* A negation cue (``NEGATIONS``: "no", "never", "neither", "not", "don't", "avoid",
  "without", "shouldn't", "mustn't", "stop using", "instead of", "rather than",
  and so "do not", "should not" and "must not" through "not") applies from the
  cue to the end of its clause. Words before the cue are not negated, so "use
  logging, not print" prefers logging and prohibits print, and "neither
  requests nor urllib is allowed" prohibits both (``neither`` added by the
  item 5 rulings). A bare "rather" is not a cue.
* ``over`` is a cue like "rather than" only when a positive verb cue
  (``COMPARATIVE_VERBS``: "use", "prefer", "choose", "pick", "switch",
  "always") comes before it in its clause (I-10 item 5d): "prefer pytest over
  unittest" prefers pytest and prohibits unittest. With no such verb before it,
  ``over`` is no cue, and an option named anywhere after it in the clause
  makes the sentence unreadable (below), as does one named after ``than``,
  ``vs`` or ``versus`` (``COMPARATIVES``): "httpx over requests", "httpx is
  better than requests", "httpx is better than the requests library", "httpx
  vs requests" (item 5 ruling 2: not only the next word). ``over`` with no
  option after it in its clause ("over http") changes nothing. "vs." and "v."
  are read as "vs", never as a word and a clause break.
* A trailing cue applies from the start of its clause to the cue: "print is
  banned", "print is forbidden", "prohibited", "disallowed", "deprecated", "is
  not allowed" and "are banned" prohibit what is mentioned before them in the
  same clause. ("banned" alone, as in "print was banned", is not a cue.) If the
  clause also holds a positive verb cue (``VERB_CUES``) anywhere, or mentions
  an option after the trailing cue, the whole sentence is not mapped: "use
  logging, everything else is forbidden" and "use logging, it is forbidden to
  print" are Not verifiable, while "print is forbidden" prohibits print and
  "print is forbidden, use logging" splits at the comma (below). So is a clause
  whose comma (one that did not end the clause) has option mentions on both
  sides: "catching exception is fine, bare except is forbidden", and the list
  form "print, requests and urllib are banned" (coverage lost on purpose).
  "print and requests are banned" has no comma and prohibits both. So is a clause
  whose mentions are not one unbroken list: only ``and``, ``or`` and ``nor``
  (and commas, and backticks, which are not words) may sit between two mentions,
  so "catching exception is fine and bare except is forbidden" and "print and the
  requests library are banned" are not mapped either.
* Curly apostrophes (U+2019 and U+2018) are made straight before anything
  else, so "don\u2019t" is "don't" and every cue with an apostrophe matches
  both forms (item 5 ruling 5).
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
* Longer trailing cues (I-10 item 5a, ``TRAILING_PHRASES``) are read as whole
  phrases: "is", "are", "was", "were", "has been" or "have been" before
  "banned", "forbidden", "prohibited", "disallowed" or "deprecated"; "is" or
  "are" before "not allowed", "not permitted", "no longer allowed" or "no
  longer permitted"; and "should not", "shouldn't", "must not", "mustn't",
  "cannot", "can't" or "may not" before "be used". So "print has been banned"
  and "print should not be used" prohibit print. A prefix cue word inside one
  of these phrases (the "not" of "is not allowed") is part of the trailing cue.
* Only the cues above are read. Any other phrasing ("print not permitted") is
  not a cue; the unreached-cue guard below keeps it from reading as preferred.

A sentence that doesn't give a usable ``RuleMatch`` is not mapped, which makes
the rule Not verifiable, never a wrong verdict. That is the case when:

* nothing is mentioned;
* an option is named in both a negated and a non-negated clause;
* every option is prohibited (the rule would allow nothing, I-10 item 5c); or
* every option is preferred (every site would follow, so the rule would always
  hold; this is also what a cue that isn't read looks like); or
* a clause with a trailing cue also holds a positive verb cue, an option
  mentioned after the cue, a comma with option mentions on both sides, or
  a word other than ``and``, ``or`` and ``nor`` between two mentions; or
* a clause names an option but its last prefix cue (one that is not part of a
  trailing cue) reaches none of its mentions (the unreached-cue guard, I-10
  item 5b): "print never in library code" or "print should not be called"
  are not mapped, rather than preferring print; or
* a clause names an option anywhere after ``than``, ``vs``, ``versus``, or an
  ``over`` that no positive verb cue comes before (I-10 item 5d and ruling 2).

Specificity is the number of distinct options the sentence mentions
(``len(preferred | prohibited)``, binding for every checker, I-10). Two checkers
that each find one option in a sentence tie, and a tie is Not verifiable
(AC-F2.6).

Everything here is linear in the length of the sentence: ``clauses`` reads each
token once, the cues are found once per clause (a trailing phrase is at most
``MAX_TRAILING`` words, so each word is compared with a fixed number of them), and a
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
    "APOSTROPHES",
    "BREAK_MARKS",
    "BREAK_WORDS",
    "CALL_SUFFIX",
    "COMPARATIVES",
    "COMPARATIVE_VERBS",
    "NEGATIONS",
    "TOKEN",
    "TRAILING_PAIRS",
    "TRAILING_PHRASES",
    "TRAILING_WORDS",
    "VERB_CUES",
    "Finder",
    "Mention",
    "classify",
    "clauses",
    "first_cue",
    "is_negated",
    "last_trailing_cue",
]

TOKEN: Final = re.compile(r"[a-z0-9_']+(?:[.-][a-z0-9_]+)*|[;:().,\u2013\u2014]|(?<=\s)-(?=\s)|--+")
"""A word, or a clause mark. A dotted or hyphenated name such as ``logging.warn`` or
``no-op`` is one word."""

APOSTROPHES: Final = str.maketrans({"\u2019": "'", "\u2018": "'"})
"""Curly apostrophes (U+2019, and U+2018 typed for one) made straight before the sentence is cut
into words, so every cue with an apostrophe matches both forms: "don\u2019t", "shouldn\u2019t",
"can\u2019t" (I-10 item 5 ruling 5)."""

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
    ("vs", "."): "vs",
    ("v", "."): "vs",
}
"""Word pairs that ``clauses`` reads as one word. The first two are cues; the next three are
set phrases that are never cues (their first word would be one); and "vs." and "v." are
"vs", so their dot ends no clause (I-10 item 5d)."""

OVER: Final = "over"
"""A cue like "rather than" after a ``COMPARATIVE_VERBS`` word in its clause (I-10 item 5d)."""

COMPARATIVE_VERBS: Final = frozenset({"use", "prefer", "choose", "pick", "switch", "always"})
"""The positive verb cues that make a later ``over`` in the same clause a cue."""

COMPARATIVES: Final = frozenset({"than", "vs", "versus"})
"""Words after which a named option makes the sentence unreadable, as after an ``over`` that no
``COMPARATIVE_VERBS`` word comes before ("rather than" is one word, a cue, and not ``than``)."""

_COMPARED: Final = COMPARATIVES | {OVER}
"""Every word ``_comparative`` looks at; ``classify`` skips it for a clause with none of them."""

NEGATIONS: Final = frozenset(
    {
        "no",
        "never",
        "neither",
        "not",
        "dont",
        "don't",
        "avoid",
        "without",
        "shouldn't",
        "mustn't",
        STOP_USING,
        RATHER_THAN,
        INSTEAD_OF,
    }
)
"""Cues that make what follows, to the end of the same clause, something the rule forbids.

"do not", "should not" and "must not" are read through "not". A bare "rather" is not a cue, and
``over`` is one only after a ``COMPARATIVE_VERBS`` word (``first_cue``)."""

TRAILING_WORDS: Final = frozenset({"forbidden", "prohibited", "disallowed", "deprecated"})
"""Cues that make what comes before them, from the start of the same clause, forbidden."""

TRAILING_PAIRS: Final = frozenset({("is", "banned"), ("are", "banned"), ("not", "allowed")})
"""Two-word trailing cues; the cue is at the second word."""

_COPULAS: Final = (("is",), ("are",), ("was",), ("were",), ("has", "been"), ("have", "been"))
_BANS: Final = ("banned", "forbidden", "prohibited", "disallowed", "deprecated")
_NOT_ALLOWED: Final = (
    ("not", "allowed"),
    ("not", "permitted"),
    ("no", "longer", "allowed"),
    ("no", "longer", "permitted"),
)
_MODALS: Final = (
    ("should", "not"),
    ("shouldn't",),
    ("must", "not"),
    ("mustn't",),
    ("cannot",),
    ("can't",),
    ("may", "not"),
)

TRAILING_PHRASES: Final = frozenset(
    {(*copula, ban) for copula in _COPULAS for ban in _BANS}
    | {(be, *rest) for be in ("is", "are") for rest in _NOT_ALLOWED}
    | {(*modal, "be", "used") for modal in _MODALS}
)
"""The whole-phrase trailing cues of I-10 item 5a, as word tuples; the cue is at the last word.
(Curly apostrophes are straightened before any cue is matched: ``APOSTROPHES``.)"""

_TRAILING: Final = frozenset((word,) for word in TRAILING_WORDS) | TRAILING_PAIRS | TRAILING_PHRASES
"""Every trailing cue as a word tuple."""

MAX_TRAILING: Final = max(len(phrase) for phrase in _TRAILING)
"""The most words a trailing cue has (4: "is no longer allowed", "should not be used")."""

_TRAILING_LAST: Final = frozenset(phrase[-1] for phrase in _TRAILING)
"""The words a trailing cue can end with; only at one of them is a cue looked for."""

CONNECTORS: Final = frozenset({"and", "or", "nor"})
"""The only words that may sit between two mentions in a clause with a trailing cue."""

Mention = tuple[int, str] | tuple[int, str, range]
"""``(word index, option)``, or with the words the mention is made of as a half-open ``range`` of
word indexes (for "bare except" at index 0, ``range(0, 2)``). Without one, a mention covers its
one word. A range **must start at the index** (``classify`` reads the cues' reach from the
index and the gaps between mentions from the ranges), and the ranges of one clause must not
overlap: a finder that breaks either has a bug. Private to ``checkers/``: the ``Checker``
protocol in ``components.py`` doesn't know about it."""

Finder = Callable[[tuple[str, ...]], Iterable[Mention]]
"""Gives the mentions one checker finds in a clause."""


def _read(text: str) -> list[tuple[tuple[str, ...], tuple[int, ...]]]:
    """The clauses of ``text`` with, for each, the commas that did not end it. A comma is its
    number of words before it, so a word at an index below that is before the comma."""
    tokens = TOKEN.findall(CALL_SUFFIX.sub("", text.lower().translate(APOSTROPHES)))
    found: list[tuple[tuple[str, ...], tuple[int, ...]]] = []
    current: list[str] = []
    commas: list[int] = []
    index = 0
    while index < len(tokens):
        word = tokens[index]
        following = tokens[index + 1 : index + 2]
        pair = (word, following[0] if following else "")
        index += 1
        is_break = word in BREAK_WORDS or word[0] in BREAK_MARKS
        if word == ",":
            is_break = bool(following) and following[0] in VERB_CUES
            if not is_break:
                commas.append(len(current))
        elif pair in MERGED:
            current.append(MERGED[pair])
            index += 1
        elif not is_break:
            current.append(word)
        if is_break:
            if current:
                found.append((tuple(current), tuple(commas)))
            current = []
            commas = []
            if word == "instead" and following == ["of"]:
                current.append(INSTEAD_OF)
                index += 1
    if current:
        found.append((tuple(current), tuple(commas)))
    return found


def clauses(text: str) -> tuple[tuple[str, ...], ...]:
    """The sentence as non-empty word lists, cut at the clause breaks above."""
    return tuple(words for words, _ in _read(text))


def first_cue(clause: tuple[str, ...]) -> int | None:
    """The index of the first negation cue in ``clause``, or None when it has none. ``over`` is a
    cue when a ``COMPARATIVE_VERBS`` word comes before it in the clause (I-10 item 5d)."""
    if NEGATIONS.isdisjoint(clause) and OVER not in clause:
        return None
    verb = False
    for index, word in enumerate(clause):
        if word in NEGATIONS or (verb and word == OVER):
            return index
        verb = verb or word in COMPARATIVE_VERBS
    return None


def _comparative(clause: tuple[str, ...], mentions: list[Mention]) -> bool:
    """Whether ``clause`` names an option anywhere after ``than``, ``vs``, ``versus``, or an
    ``over`` that no ``COMPARATIVE_VERBS`` word comes before (I-10 item 5d, ruling 2): that is,
    whether one of those words comes before the last mention. Only the words before it are
    read."""
    last = max(mention[0] for mention in mentions)
    verb = False
    for index in range(last):
        word = clause[index]
        if word in COMPARATIVES or (word == OVER and not verb):
            return True
        verb = verb or word in COMPARATIVE_VERBS
    return False


def _trailing_spans(clause: tuple[str, ...]) -> list[tuple[int, int]]:
    """The ``(first, last)`` word indexes of each trailing cue in ``clause``, in order: for each
    word that ends one, the longest cue that ends there. Each word is compared with at most
    ``MAX_TRAILING`` slices of at most ``MAX_TRAILING`` words, so this is linear. A clause
    without any word a cue ends with (most of them) is ruled out by one set test."""
    if _TRAILING_LAST.isdisjoint(clause):
        return []
    spans: list[tuple[int, int]] = []
    for index, word in enumerate(clause):
        if word not in _TRAILING_LAST:
            continue
        for length in range(min(MAX_TRAILING, index + 1), 0, -1):
            if clause[index - length + 1 : index + 1] in _TRAILING:
                spans.append((index - length + 1, index))
                break
    return spans


def last_trailing_cue(clause: tuple[str, ...]) -> int | None:
    """The index of the last trailing cue in ``clause`` (the last word of a phrase), or None."""
    spans = _trailing_spans(clause)
    return spans[-1][1] if spans else None


def _unreached(
    clause: tuple[str, ...], spans: list[tuple[int, int]], mentions: list[Mention]
) -> bool:
    """Whether the last prefix cue of ``clause`` that is not part of a trailing cue (``spans``)
    reaches none of ``mentions`` (I-10 item 5b, the unreached-cue guard). A cue reaches what
    comes after it, so the last one reaches the fewest mentions: when it reaches one, every
    earlier cue does too."""
    start = max(mention[0] for mention in mentions)
    if NEGATIONS.isdisjoint(clause[start:]):
        return False
    inside = {position for first, last in spans for position in range(first, last + 1)}
    return any(
        clause[index] in NEGATIONS and index not in inside for index in range(start, len(clause))
    )


def _reached(cue: int | None, end: int | None, index: int) -> bool:
    """Whether a cue reaches the word at ``index``: after the first cue, or before the last
    trailing cue."""
    return (cue is not None and cue < index) or (end is not None and index < end)


def _span(mention: Mention) -> tuple[int, int]:
    """The first word of a mention (its index) and the one after its last. The range's own start
    is not read: a mention starts at its index, as ``Mention`` says."""
    if len(mention) == 3:
        return mention[0], mention[2].stop
    return mention[0], mention[0] + 1


def _unbroken(clause: tuple[str, ...], mentions: list[Mention]) -> bool:
    """Whether the mentions of ``clause`` form one list: every word from the first mention to the
    last that is not part of a mention is one of ``CONNECTORS``. Each word is read once."""
    spans = [_span(mention) for mention in mentions]
    owned = {position for start, stop in spans for position in range(start, stop)}
    low = min(start for start, _ in spans)
    high = max(stop for _, stop in spans)
    return all(
        clause[position] in CONNECTORS for position in range(low, high) if position not in owned
    )


def _unreadable(
    clause: tuple[str, ...], commas: tuple[int, ...], mentions: list[Mention], end: int
) -> bool:
    """Whether a clause with a trailing cue at ``end`` can't be read (I-10, "Negation" item 4a):
    it holds a positive verb cue anywhere, it mentions an option after the cue, a comma that
    did not end the clause has option mentions on both sides of it ("catching exception is
    fine, bare except is forbidden"; also the list form "print, requests and urllib are
    banned"), or the mentions are not one unbroken list ("catching exception is fine and bare
    except is forbidden", "print and the requests library are banned")."""
    if any(word in VERB_CUES for word in clause):
        return True
    if not mentions:
        return False
    indexes = [mention[0] for mention in mentions]
    first = min(indexes)
    last = max(indexes)
    return (
        last > end
        or any(first < comma <= last for comma in commas)
        or not _unbroken(clause, mentions)
    )


def is_negated(clause: tuple[str, ...], index: int) -> bool:
    """Whether a negation cue in ``clause`` reaches ``clause[index]``."""
    return _reached(first_cue(clause), last_trailing_cue(clause), index)


def classify(text: str, find: Finder, options: frozenset[str]) -> RuleMatch | None:
    """The ``RuleMatch`` for ``text``, or None when it can't be read as a rule for ``options``."""
    preferred: set[str] = set()
    prohibited: set[str] = set()
    for clause, commas in _read(text):
        # The cues are found once per clause, not once per mention: a hostile sentence with
        # 100,000 mentions in one clause must not cost 100,000 scans (linear time, R2.5).
        cue = first_cue(clause)
        spans = _trailing_spans(clause)
        end = spans[-1][1] if spans else None
        mentions = list(find(clause))
        if end is not None and _unreadable(clause, commas, mentions, end):
            return None
        # Each guard is skipped by one set test when the clause holds none of its words, which
        # keeps the many-short-clauses texts cheap (R2.5 tests, CI time).
        if mentions and (
            (not NEGATIONS.isdisjoint(clause) and _unreached(clause, spans, mentions))
            or (not _COMPARED.isdisjoint(clause) and _comparative(clause, mentions))
        ):
            return None
        for mention in mentions:
            index, option = mention[0], mention[1]
            (prohibited if _reached(cue, end, index) else preferred).add(option)
    mentioned = preferred | prohibited
    if not mentioned or preferred & prohibited:
        return None
    if prohibited >= options:
        return None
    if preferred >= options:
        return None
    return RuleMatch(
        preferred=frozenset(preferred), prohibited=frozenset(prohibited), specificity=len(mentioned)
    )
