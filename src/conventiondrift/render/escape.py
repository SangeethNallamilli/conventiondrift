"""The only escaping code in conventiondrift (DESIGN §3a, SECURITY-RULES R3).

One function per sink (R3.2). Everything shown to a user that comes from the
repo, the event payload or another user goes through exactly one of these:

* :func:`md` - comment and job summary (GitHub Flavored Markdown), outside tables.
* :func:`md_cell` - same as :func:`md`, plus ``|`` escaped as ``\\|`` for GFM tables.
* :func:`workflow_cmd` - the message part of a workflow command (annotations).
* :func:`workflow_prop` - a property value of a workflow command (``file=``, ``title=``).
* :func:`output_heredoc` - one ``GITHUB_OUTPUT`` entry with a random delimiter.
* :func:`sarif_text` - a SARIF ``message.text`` (plain text, never Markdown).

Nothing in this package ever writes ``GITHUB_ENV`` or ``GITHUB_PATH``.
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from collections.abc import Callable
from typing import Final

__all__ = [
    "md",
    "md_cell",
    "output_heredoc",
    "sarif_text",
    "workflow_cmd",
    "workflow_prop",
]

# C1, Cf, Zl, Zp and Cs become U+XXXX (I-14). Matched by unicodedata category,
# never a hand-written code-point list, so new code points are covered too.
_LABEL_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})
_C0_LIMIT: Final = 0x20
_DEL: Final = 0x7F
_CONTROL_PICTURE_BASE: Final = 0x2400
_DELETE_PICTURE: Final = "\u2421"

_BACKTICK_RUN: Final = re.compile(r"`+")  # single quantifier, linear time


def _codepoint_label(char: str) -> str:
    """Visible ``U+XXXX`` form pinned by I-14: uppercase hex, at least 4 digits."""
    return f"U+{ord(char):04X}"


def _visible_text(text: str) -> str:
    """I-14 invisible-character mapping, applied first by every escape function.

    U+0000-U+001F become Control Pictures (U+2400 + code point). DEL becomes
    ``␡``. Every other Cc, Cf, Zl, Zp or Cs character becomes
    :func:`_codepoint_label`. All other characters are left unchanged.
    """
    parts: list[str] = []
    for char in text:
        code = ord(char)
        if code < _C0_LIMIT:
            parts.append(chr(_CONTROL_PICTURE_BASE + code))
        elif code == _DEL:
            parts.append(_DELETE_PICTURE)
        elif unicodedata.category(char) in _LABEL_CATEGORIES:
            parts.append(_codepoint_label(char))
        else:
            parts.append(char)
    return "".join(parts)


def md(text: str) -> str:
    """Return ``text`` as one inline GFM code span that renders it literally.

    Inside a code span GitHub creates no mention, ``#123`` reference, autolink,
    link, image, emphasis or HTML element, and printable text is shown
    verbatim (AC-N3.10, AC-E.17, SC-2.51). The fence is one backtick longer
    than the longest backtick run in the mapped body, and a space pads each
    side when the body starts or ends with a backtick or space (CommonMark
    strips exactly one). The empty string stays empty.
    """
    if not text:
        return ""
    body = _visible_text(text)
    fence = "`" * (max((len(m) for m in _BACKTICK_RUN.findall(body)), default=0) + 1)
    if body.strip(" ") and (body[0] in "` " or body[-1] in "` "):
        body = f" {body} "
    return f"{fence}{body}{fence}"


def md_cell(text: str) -> str:
    """Return :func:`md` of ``text`` with ``|`` escaped as ``\\|`` for GFM table cells."""
    return md(text).replace("|", "\\|")


def workflow_cmd(text: str) -> str:
    """Escape the data part of ``::command props::data`` (R3.1, AC-N3.13, I-14).

    The I-14 mapping runs first, so CR and LF are already ``␍`` / ``␊``. Then
    ``%`` (first), CR and LF are percent-encoded the way the runner unescapes
    them; after the mapping the CR/LF replacements are a no-op.
    """
    return _visible_text(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def workflow_prop(text: str) -> str:
    """Escape a workflow-command property value: as :func:`workflow_cmd`, plus ``:`` and ``,``."""
    return workflow_cmd(text).replace(":", "%3A").replace(",", "%2C")


_OUTPUT_NAME: Final = re.compile(r"[a-z][a-z0-9-]{0,63}")  # fullmatch; linear
_DELIMITER_TRIES: Final = 8
# Replaceable in tests only (monkeypatch); production always uses ``secrets``.
_token: Callable[[int], str] = secrets.token_hex


def output_heredoc(name: str, value: str) -> str:
    """Return one ``GITHUB_OUTPUT`` entry, ``name<<D\\nvalue\\nD\\n`` (R3.1, AC-N3.13).

    I-14 applies the invisible-character mapping to every escape function and
    does not carve out this one, so ``value`` is mapped before the delimiter
    is chosen and the block is written. The block's own newlines (the
    heredoc syntax) stay real newlines. ``name`` is our own fixed output
    name and must be lowercase ``[a-z][a-z0-9-]*``; anything else is a
    programming error and raises ``ValueError``, as does failing to find an
    absent delimiter.
    """
    if not _OUTPUT_NAME.fullmatch(name):
        raise ValueError("invalid output name")
    mapped = _visible_text(value)
    for _ in range(_DELIMITER_TRIES):
        delimiter = f"ghadelimiter_{_token(16)}"
        if delimiter not in mapped:
            return f"{name}<<{delimiter}\n{mapped}\n{delimiter}\n"
    raise ValueError("no heredoc delimiter absent from the value")


def sarif_text(text: str) -> str:
    """Return ``text`` for a SARIF plain-text ``message.text`` (R3.1, AC-N3.10, I-14).

    The I-14 mapping is applied first. Then backslash, ``[`` and ``]`` are
    backslash-escaped so no ``[text](id)`` embedded link (SARIF 2.1.0
    §3.11.6) can form from repo text; a viewer that undoes those escapes
    sees the documented visible form. JSON encoding is left to the
    serializer, and no Markdown field is ever built from repo text.
    """
    return _visible_text(text).replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
