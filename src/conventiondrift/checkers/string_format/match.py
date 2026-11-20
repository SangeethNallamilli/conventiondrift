"""``match_rule`` for the string-format checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about string formatting when its sentence names one of these:

* ``f-string``: "f-string(s)", "fstring(s)", "f string(s)".
* ``format``: ``.format()`` and ``str.format`` (a leading dot or a call suffix is read as
  part of the name, so neither ends the clause).
* ``percent``: ``%s``, ``%d`` and ``%r``, "% operator", "% formatting", "%-formatting",
  "percent formatting" and "printf-style".

The polarity of each mention comes from ``phrases.classify``. So "Use f-strings for string
formatting." prefers f-strings, "Use f-strings, not .format()." also forbids ``format``, and
"Don't use the % operator or .format()." forbids ``percent`` and ``format``. The words
"string formatting" alone name nothing, and a bare "%" (as in "90% coverage") is not read.

A rule that limits the choice to some strings is not mapped (D-PM-44 b, D-PM-26 #2, AC-N1.5):
"Log messages are f-strings.", "Use f-strings in log messages." and "Error messages use
%-formatting." are Not verifiable, because the whole-tree counts would judge them wrongly.
A sentence is read as limited when it has one of the words in ``SCOPE_WORDS``.
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import classify, clauses
from conventiondrift.model import RuleMatch

__all__ = ["OPTIONS", "SCOPE_WORDS", "match_rule"]

OPTIONS: Final = frozenset({"f-string", "format", "percent"})
"""The string-format checker's options (INTERFACES leaves their ids open; T-017)."""

SCOPE_WORDS: Final = frozenset(
    {
        "log",
        "logs",
        "logging",
        "logger",
        "loggers",
        "message",
        "messages",
        "error",
        "errors",
        "exception",
        "exceptions",
        "sql",
        "query",
        "queries",
        "url",
        "urls",
        "path",
        "paths",
        "template",
        "templates",
        "docstring",
        "docstrings",
        "comment",
        "comments",
        "output",
    }
)
"""Words that name a kind of string: a rule that has one is about those strings only."""

_PERCENT_FORMS: Final = (
    "%s",
    "%d",
    "%r",
    "% operator",
    "% formatting",
    "%-formatting",
    "%-style",
    "% style",
)
"""Spellings of ``%`` formatting that are made one word before the sentence is read."""

_PERCENT_WORD: Final = "cd_percent"
_FORMAT_WORD: Final = "str.format"


def _prepare(text: str) -> str:
    """Make the spellings above single words, which the shared clause rules would split."""
    text = text.replace("()", "").replace(".format", f" {_FORMAT_WORD} ")
    for form in _PERCENT_FORMS:
        text = text.replace(form, f" {_PERCENT_WORD} ")
    return text


def _find(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    for index, word in enumerate(clause):
        after = clause[index + 1] if index + 1 < len(clause) else ""
        if word in ("fstring", "fstrings") or (word == "f" and after in ("string", "strings")):
            yield index, "f-string"
        elif word == _FORMAT_WORD:
            yield index, "format"
        elif word == _PERCENT_WORD or (word == "percent" and after == "formatting"):
            yield index, "percent"
        elif word == "printf" and after == "style":
            yield index, "percent"


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The formats a rule sentence prefers and forbids, or None if it names none."""
    text = _prepare(normalized_text)
    if any(word in SCOPE_WORDS for clause in clauses(text) for word in clause):
        return None
    return classify(text, _find, OPTIONS)
