"""``match_rule`` for the http-client checker (INTERFACES I-10; critical module, DESIGN §12 A-2).

A rule is about HTTP clients when its sentence names one of the libraries in
``OPTIONS``; the polarity of each mention comes from ``phrases.classify``. So
"Use httpx for HTTP calls." prefers httpx, "Use httpx, not requests." prefers
httpx and forbids requests, and "Never use requests." only forbids requests.
``urllib`` is also read from ``urllib.request``. A sentence that names no library
(for example "Use an async HTTP client.") is not mapped.
"""

from collections.abc import Iterator
from typing import Final

from conventiondrift.checkers.phrases import classify
from conventiondrift.model import RuleMatch

__all__ = ["OPTIONS", "WORDS", "match_rule"]

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


def match_rule(normalized_text: str) -> RuleMatch | None:
    """The libraries a rule sentence prefers and forbids, or None if it names none."""
    return classify(normalized_text, _find, OPTIONS)
