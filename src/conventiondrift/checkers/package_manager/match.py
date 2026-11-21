"""``match_rule`` for the package-manager checker (INTERFACES I-10; critical module, A-2).

A rule is about the package manager when its sentence names one of the managers in
``OPTIONS`` as a whole word; the polarity of each mention comes from ``phrases.classify``.
So "Use uv for dependencies." (AC-F2.5 line 8) prefers uv, "Use Poetry for dependencies."
(AC-F3.9) prefers poetry, and "Never use pip, use uv." forbids pip and prefers uv. A
file name such as ``uv.lock`` or a tool such as ``pip-tools`` is one token and names
nothing.
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import classify
from conventiondrift.model import RuleMatch

__all__ = ["OPTIONS", "match_rule"]

OPTIONS: Final = frozenset({"pip", "poetry", "uv", "pdm"})
"""The managers the project brief lists for checker 8; each option id is also its word."""


def _find(clause: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    for index, word in enumerate(clause):
        if word in OPTIONS:
            yield index, word


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The managers a rule sentence prefers and forbids, or None if it names none."""
    return classify(normalized_text, _find, OPTIONS)
