"""``match_rule`` for the type-hints checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about type hints when its sentence says "type hint(s)" or "type annotation(s)", as two
words or joined by a hyphen. Each such mention is the option ``annotated``, with its polarity
from ``phrases.classify``: "Always use type hints." prefers annotated functions and "Don't use
type hints." forbids them. Other words ("annotate", "typed", "mypy") are not read, so their
rules are Not verifiable.

A two-word mention covers both words (``phrases.Mention``) and starts at "type".

A rule that limits type hints to some functions or files is not mapped (D-TL-63): "Use type
hints in public APIs." and "Add type hints to new code." are Not verifiable, because the
whole-tree counts would judge them wrongly. A sentence is read as limited when it has one of
the words in ``SCOPE_WORDS``, in any clause. The check is the same as
``string_format.match.SCOPE_WORDS``: membership in the tokens from ``phrases.clauses``, so only
whole words count ("newline" and "testing" are not "new" or "test"). Words that do not narrow
the rule below the whole tree ("function(s)", "method(s)", "class(es)", "code", "module(s)",
"package(s)", "all", "every") are left out, so "Always use type hints." and "Use type hints in
every module." still map. The test-framework checker has no scope words.
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import Mention, classify, clauses
from conventiondrift.model import RuleMatch

__all__ = ["HINT_WORDS", "HYPHENATED", "OPTIONS", "SCOPE_WORDS", "match_rule"]

OPTIONS: Final = frozenset({"annotated", "unannotated"})
"""Functions with at least one parameter or return annotation, and functions with none."""

HINT_WORDS: Final = frozenset({"hint", "hints", "annotation", "annotations"})
"""Words that, after "type" or "type-", name type hints."""

HYPHENATED: Final = frozenset(f"type-{word}" for word in HINT_WORDS)
"""The hyphenated spellings, one word each ("type-hints")."""

SCOPE_WORDS: Final = frozenset(
    {
        "public",
        "private",
        "internal",
        "exported",
        "api",
        "apis",
        "interface",
        "interfaces",
        "endpoint",
        "endpoints",
        "new",
        "test",
        "tests",
        "script",
        "scripts",
        "library",
        "libraries",
    }
)
"""Words that name a subset of functions or files: a rule that has one is about those only."""


def _find(clause: tuple[str, ...]) -> Iterator[Mention]:
    for index, word in enumerate(clause):
        after = clause[index + 1] if index + 1 < len(clause) else ""
        if word in HYPHENATED:
            yield index, "annotated"
        elif word == "type" and after in HINT_WORDS:
            yield index, "annotated", range(index, index + 2)


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The options a rule sentence prefers and forbids, or None if it isn't about type hints."""
    if any(word in SCOPE_WORDS for clause in clauses(normalized_text) for word in clause):
        return None
    return classify(normalized_text, _find, OPTIONS)
