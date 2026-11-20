"""``match_rule`` for the string-format checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about string formatting when its sentence names one of these:

* ``f-string``: "f-string(s)", "fstring(s)", "f string(s)".
* ``format``: ``.format()`` and ``str.format`` (a leading dot or a call suffix is read as
  part of the name, so neither ends the clause).
* ``percent``: ``%s``, ``%d`` and ``%r``, "% operator", "% formatting", "%-formatting",
  "percent formatting", "printf-style" and "printf style".

The polarity of each mention comes from ``phrases.classify``. So "Use f-strings for string
formatting." prefers f-strings, "Use f-strings, not .format()." also forbids ``format``, and
"Don't use the % operator or .format()." forbids ``percent`` and ``format``. The words
"string formatting" alone name nothing, and a bare "%" (as in "90% coverage") is not read.
The spellings are whole words only (``SPELLINGS``): ``.format_map``, ``config.formatter``
and "100% style" name nothing.

A rule that limits the choice to some strings is not mapped (D-PM-44 b, D-PM-26 #2, AC-N1.5):
"Log messages are f-strings.", "Use f-strings in log messages." and "Error messages use
%-formatting." are Not verifiable, because the whole-tree counts would judge them wrongly.
A sentence is read as limited when it has one of the words in ``SCOPE_WORDS``.
"""

import re
from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import Mention, classify, clauses
from conventiondrift.model import RuleMatch

__all__ = ["OPTIONS", "SCOPE_WORDS", "SPELLINGS", "match_rule"]

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

SPELLINGS: Final = re.compile(
    r"(?<![a-z0-9_.])(?:str)?\.format(?![a-z0-9_])"
    r"|(?<![a-z0-9_])%(?:[sdr](?![a-z0-9_])| operator| formatting|-formatting|-style| style)"
)
"""``.format``/``str.format`` and the ``%`` spellings, matched only as whole words.

``.format`` must not run on into an identifier (``.format_map``, ``.formatted``,
``config.formatter``) or follow one (``config.format``); ``str.format`` is the one dotted
form read. A ``%`` must not follow a letter, digit or underscore, so "keep 100% style" and
"90% formatting" name nothing, and ``%s``, ``%d`` and ``%r`` must not run on into a word.
The regex is applied to repo text (SECURITY-RULES R2.5). It is an alternation of literals
with optional fixed parts and one-character lookarounds, so it can't backtrack and runs in
linear time."""

_PERCENT_WORD: Final = "cd_percent"
_F_STRING_WORDS: Final = frozenset({"f-string", "f-strings", "fstring", "fstrings"})
"""One-word spellings of f-string (the clause rules keep a hyphenated word whole, I-10 4b)."""
_FORMAT_WORD: Final = "str.format"


def _word(found: re.Match[str]) -> str:
    return f" {_PERCENT_WORD if found.group().startswith('%') else _FORMAT_WORD} "


def _prepare(text: str) -> str:
    """Make the spellings above single words, which the shared clause rules would split."""
    return SPELLINGS.sub(_word, text.replace("()", ""))


def _find(clause: tuple[str, ...]) -> Iterator[Mention]:
    for index, word in enumerate(clause):
        after = clause[index + 1] if index + 1 < len(clause) else ""
        if word in _F_STRING_WORDS:
            yield index, "f-string"
        elif word == "f" and after in ("string", "strings"):
            yield index, "f-string", range(index, index + 2)
        elif word == _FORMAT_WORD:
            yield index, "format"
        elif word in (_PERCENT_WORD, "printf-style"):
            yield index, "percent"
        elif (word, after) in (("percent", "formatting"), ("printf", "style")):
            yield index, "percent", range(index, index + 2)


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The formats a rule sentence prefers and forbids, or None if it names none."""
    text = _prepare(normalized_text)
    if any(word in SCOPE_WORDS for clause in clauses(text) for word in clause):
        return None
    return classify(text, _find, OPTIONS)
