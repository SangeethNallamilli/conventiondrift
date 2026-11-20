"""``match_rule`` for the exceptions checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

Only prohibitions are mapped: "Do not use bare except.", "Never catch Exception."
and "Do not use bare except or catch Exception." A sentence that asks for
something (for example "Always catch Exception") or mixes asking and forbidding
is not mapped, so its rule is Not verifiable, never a wrong verdict.

What is read as each option:

* ``bare-except``: "bare except", "bare excepts", "bare exception(s)".
* ``broad-except``: "catch Exception", "catching Exception", "except Exception",
  "broad / generic / blanket except or exception(s)", and "BaseException".
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import classify
from conventiondrift.model import RuleMatch

__all__ = ["OPTIONS", "match_rule"]

OPTIONS: Final = frozenset({"bare-except", "broad-except", "specific"})
"""``except:``, ``except Exception:`` (or ``BaseException``), and any other ``except`` clause."""

_EXCEPT_WORDS: Final = frozenset({"except", "excepts", "exception", "exceptions"})
_CATCH_WORDS: Final = frozenset({"catch", "catching", "catches", "except"})
_BROAD_WORDS: Final = frozenset({"broad", "generic", "blanket"})


def _find(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    for index, word in enumerate(clause):
        before = clause[index - 1] if index else ""
        after = clause[index + 1] if index + 1 < len(clause) else ""
        if word == "bare" and after in _EXCEPT_WORDS:
            yield index, "bare-except"
        elif word == "baseexception":
            yield index, "broad-except"
        elif word == "exception" and before in _CATCH_WORDS:
            yield index, "broad-except"
        elif word in _EXCEPT_WORDS and before in _BROAD_WORDS:
            yield index, "broad-except"


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The options a rule sentence forbids, or None if it isn't a prohibition about ``except``."""
    match = classify(normalized_text, _find, OPTIONS)
    if match is None or match.preferred:
        return None
    return match
