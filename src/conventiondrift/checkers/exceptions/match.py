"""``match_rule`` for the exceptions checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

Only prohibitions are mapped: "Do not use bare except.", "Never catch Exception."
and "Do not use bare except or catch Exception." A sentence that asks for
something (for example "Always catch Exception") or mixes asking and forbidding
is not mapped, so its rule is Not verifiable, never a wrong verdict.

What is read as each option:

* ``bare-except``: "bare except", "bare excepts", "bare exception(s)".
* ``broad-except``: "catch Exception", "catching Exception", "except Exception",
  "broad / generic / blanket except or exception(s)", and "BaseException".

A mention is made of all the words of its phrase ("bare except", "catching Exception"), which is
what ``classify`` needs to tell a list of mentions from words between them. It starts at its first
word, and two mentions never share a word.

A hyphen joins words (``phrases.TOKEN``), so the hyphenated spellings "bare-except",
"broad-except" and so on are one word each; they are read as the same options, as they were
when a hyphen still split words (they are also the option ids and linter rule names).
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import Mention, classify
from conventiondrift.model import RuleMatch

__all__ = ["OPTIONS", "match_rule"]

OPTIONS: Final = frozenset({"bare-except", "broad-except", "specific"})
"""``except:``, ``except Exception:`` (or ``BaseException``), and any other ``except`` clause."""

_EXCEPT_WORDS: Final = frozenset({"except", "excepts", "exception", "exceptions"})
_CATCH_WORDS: Final = frozenset({"catch", "catching", "catches", "except"})
_BROAD_WORDS: Final = frozenset({"broad", "generic", "blanket"})
_HYPHENATED: Final = {
    **{f"bare-{word}": "bare-except" for word in _EXCEPT_WORDS},
    **{f"{kind}-{word}": "broad-except" for kind in _BROAD_WORDS for word in _EXCEPT_WORDS},
}


def _find(clause: tuple[str, ...]) -> Iterator[Mention]:
    """The mentions in ``clause``, each as ``(start, option, range(start, stop))``: the index is
    the first word of the phrase, as ``classify`` needs, and no two mentions share a word. When
    two phrases would overlap ("bare except exception"), the first one is the mention."""
    taken = 0  # the first word that no mention yielded so far has used
    for index, word in enumerate(clause):
        before = clause[index - 1] if index else ""
        after = clause[index + 1] if index + 1 < len(clause) else ""
        if word == "bare" and after in _EXCEPT_WORDS:
            start, stop, option = index, index + 2, "bare-except"
        elif word in _HYPHENATED:
            start, stop, option = index, index + 1, _HYPHENATED[word]
        elif word == "baseexception":
            start, stop, option = index, index + 1, "broad-except"
        elif word == "exception" and before in _CATCH_WORDS:
            start, stop, option = index - 1, index + 1, "broad-except"
        elif word in _EXCEPT_WORDS and before in _BROAD_WORDS:
            start, stop, option = index - 1, index + 1, "broad-except"
        else:
            continue
        if start >= taken:
            yield start, option, range(start, stop)
            taken = stop


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The options a rule sentence forbids, or None if it isn't a prohibition about ``except``."""
    match = classify(normalized_text, _find, OPTIONS)
    if match is None or match.preferred:
        return None
    return match
