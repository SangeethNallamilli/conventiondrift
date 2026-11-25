"""``match_rule`` for the http-client checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about HTTP clients when its sentence names one of the libraries in
``OPTIONS``; the polarity of each mention comes from ``phrases.classify``. So
"Use httpx for HTTP calls." prefers httpx, "Use httpx, not requests." prefers
httpx and forbids requests, and "Never use requests." only forbids requests.
``urllib`` is also read from ``urllib.request``. A sentence that names no library
(for example "Use an async HTTP client.") is not mapped.

"requests" is also an ordinary noun, so a bare ``requests`` names the library only when it
looks like it (INTERFACES I-10 item 6(a)):

* it is backticked (`` `requests` ``), or the next word is "library", "package", "module"
  or "lib";
* it is at an *anchor*, the word right after a positive verb cue ("use", "prefer", "choose",
  "pick", "always", "switch to", "over to"), a prefix negation cue (``phrases.NEGATIONS``)
  or a reverse-form or comparative cue ("rather than", "instead of", "over", "than", "vs",
  "vs.", "v.", "versus"; the comparatives keep 5(d)'s Not verifiable for "httpx is better
  than requests.");
* it is in a list that starts at an anchor: single words joined only by "and", "or",
  "nor", commas and backticks;
* it is in a list with a trailing cue right after it, anywhere in the clause, when the list
  has two or more items or the cue's verb is singular ("is", "was", "has been"). So "httpx
  is fine and requests is forbidden." stays Not verifiable under the 4(a) contiguity guard
  instead of prohibiting httpx.

Any other ``requests`` is read as a noun and names nothing: "Always set a timeout on
requests.", "Never log requests." and "Use httpx to make requests." (which maps httpx alone).
"Requests are forbidden." on its own is Not verifiable (accepted coverage loss).
"""

import re
from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import (
    APOSTROPHES,
    BREAK_WORDS,
    CALL_SUFFIX,
    COMPARATIVE_VERBS,
    COMPARATIVES,
    NEGATIONS,
    TOKEN,
    TRAILING_PAIRS,
    TRAILING_PHRASES,
    TRAILING_WORDS,
    classify,
)
from conventiondrift.model import RuleMatch

__all__ = [
    "ANCHOR_PAIRS",
    "ANCHOR_WORDS",
    "LIBRARY_NOUNS",
    "NOUN",
    "OPTIONS",
    "WORDS",
    "match_rule",
]

OPTIONS: Final = frozenset({"requests", "httpx", "aiohttp", "urllib"})
"""The http-client checker's options: the library that a call goes through."""

WORDS: Final = {
    "requests": "requests",
    "httpx": "httpx",
    "aiohttp": "aiohttp",
    "urllib": "urllib",
    "urllib.request": "urllib",
}
"""Each word that names a library, and the option it stands for."""


def _find(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    for index, word in enumerate(clause):
        option = WORDS.get(word)
        if option is not None:
            yield index, option


_TOKENS: Final = re.compile(TOKEN.pattern + "|`")
"""``phrases.TOKEN`` plus the backtick, which the shared clause rules drop. One more
single-character alternative, so it still runs in linear time (R2.5)."""

NOUN: Final = "requests_noun"
"""What a ``requests`` that doesn't look like the library is rewritten to: no option's word."""

LIBRARY_NOUNS: Final = frozenset({"library", "package", "module", "lib"})
ANCHOR_WORDS: Final = NEGATIONS | COMPARATIVE_VERBS | COMPARATIVES | {"over"}
"""A word right after one of these is at an anchor."""
ANCHOR_PAIRS: Final = frozenset(
    {("switch", "to"), ("over", "to"), ("instead", "of"), ("rather", "than"), ("stop", "using")}
)
"""Two-word cues (read before ``phrases`` merges them): the word right after is at an anchor."""
_CONNECTORS: Final = frozenset({"and", "or", "nor"})
_TRAILING: Final = frozenset((word,) for word in TRAILING_WORDS) | TRAILING_PAIRS | TRAILING_PHRASES
_TRAILING_MAX: Final = max(len(phrase) for phrase in _TRAILING)
_SINGULAR: Final = (("is",), ("was",), ("has", "been"))


def _trailing_cue(words: tuple[str, ...]) -> tuple[str, ...] | None:
    """The trailing cue that ``words`` (the next few words of a clause) start with, if any."""
    for size in range(_TRAILING_MAX, 0, -1):
        if words[:size] in _TRAILING and len(words) >= size:
            return words[:size]
    return None


def _library(pieces: list[str]) -> set[int]:
    """The indexes of the ``requests`` pieces that look like the library (I-10 6(a)).

    One pass over the pieces, with a look-ahead of at most ``_TRAILING_MAX`` words each time
    a list ends, so the time is linear in the sentence (R2.5).
    """
    found: set[int] = set()
    prev: tuple[str | None, str | None] = (None, None)
    in_list = False  # the last word was a list item
    after_sep = False  # a separator came after it
    items: list[int] = []
    head = False  # the list didn't start at an anchor: a trailing cue after it decides

    def close(next_word: int | None) -> None:
        if head and items and next_word is not None:
            ahead: list[str] = []
            for piece in pieces[next_word : next_word + _TRAILING_MAX]:
                if not (piece[0].isalnum() or piece[0] in "_'"):
                    break
                ahead.append(piece)
            cue = _trailing_cue(tuple(ahead))
            if cue is not None and (
                len(items) > 1 or any(cue[: len(verb)] == verb for verb in _SINGULAR)
            ):
                found.update(items)

    for index, piece in enumerate(pieces):
        if piece == "`":
            after_sep = after_sep or in_list
            continue
        if piece == ",":
            after_sep = after_sep or in_list
            prev = (None, None)
            continue
        if piece == "." and prev[1] in ("vs", "v"):  # "vs." and "v." are the vs cue (5(d))
            prev = (prev[0], "vs")
            continue
        if not (piece[0].isalnum() or piece[0] in "_'"):  # a mark: BREAK_MARKS or ","
            close(None)
            in_list, after_sep, items, head = False, False, [], False
            prev = (None, None)
            continue
        if in_list and piece in _CONNECTORS:
            after_sep = True
            prev = (prev[1], piece)
            continue
        member = in_list and after_sep
        if in_list and not member:
            close(index)
        anchored = prev[1] in ANCHOR_WORDS or prev in ANCHOR_PAIRS
        if member:
            items.append(index)
        elif anchored:
            items, head = [index], False
        else:  # a list that a trailing cue may follow (it starts the clause in I-10 6(a))
            items, head = [index], True
        in_list, after_sep = bool(items), False
        if piece == "requests":
            nxt = pieces[index + 1] if index + 1 < len(pieces) else ""
            ticked = index > 0 and pieces[index - 1] == "`" and nxt == "`"
            if ticked or nxt in LIBRARY_NOUNS or (items and not head):
                found.add(index)
        if piece in BREAK_WORDS:
            close(None)
            in_list, after_sep, items, head = False, False, [], False
        prev = (prev[1], piece)
    close(None)
    return found


def _nouns(text: str) -> str:
    """``text`` with each ``requests`` that doesn't look like the library made ``NOUN``."""
    text = CALL_SUFFIX.sub("  ", text.lower().translate(APOSTROPHES))
    spans = [(m.start(), m.end(), m.group()) for m in _TOKENS.finditer(text)]
    library = _library([piece for _, _, piece in spans])
    parts: list[str] = []
    last = 0
    for index, (start, end, piece) in enumerate(spans):
        if piece == "requests" and index not in library:
            parts.append(text[last:start])
            parts.append(NOUN)
            last = end
    parts.append(text[last:])
    return "".join(parts)


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The libraries a rule sentence prefers and forbids, or None if it names none."""
    return classify(_nouns(normalized_text), _find, OPTIONS)
