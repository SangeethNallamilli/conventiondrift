"""``match_rule`` for the money checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about money when its sentence says "integer cent(s)", as two words or joined by a
hyphen or underscore. That mention is the option ``integer-cents``, with its polarity from
``phrases.classify``: "Store money as integer cents." (AC-F2.5 line 4) prefers
``integer-cents``. A site then follows or contradicts under the I-10 rule: ``integer-cents``
follows that sentence and ``float`` contradicts it.

The option ids are ``integer-cents`` and ``float``, matching the C6 stand-ins in
``tests/unit/test_rules_mapping.py`` and the I-8 follows/contradicts wording.
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import Mention, classify
from conventiondrift.model import RuleMatch

__all__ = ["HINT_WORDS", "HYPHENATED", "OPTIONS", "match_rule"]

OPTIONS: Final = frozenset({"integer-cents", "float"})
"""Values that follow "integer cents", and float-literal values that contradict it (I-8)."""

HINT_WORDS: Final = frozenset({"cent", "cents"})
"""Words that, after "integer" or "integer-" / "integer_", name the integer-cents option."""

HYPHENATED: Final = frozenset(
    {f"integer-{word}" for word in HINT_WORDS} | {f"integer_{word}" for word in HINT_WORDS}
)
"""The joined spellings, one word each ("integer-cents", "integer_cents")."""


def _find(clause: tuple[str, ...]) -> Iterator[Mention]:
    for index, word in enumerate(clause):
        after = clause[index + 1] if index + 1 < len(clause) else ""
        if word in HYPHENATED:
            yield index, "integer-cents"
        elif word == "integer" and after in HINT_WORDS:
            yield index, "integer-cents", range(index, index + 2)


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The options a rule sentence prefers and forbids, or None if it isn't about money."""
    return classify(normalized_text, _find, OPTIONS)
