"""The only escaping code in conventiondrift (DESIGN §3a, SECURITY-RULES R3).

One function per sink (R3.2). Everything shown to a user that comes from the
repo, the event payload or another user goes through exactly one of these:

* :func:`md` - comment and job summary (GitHub Flavored Markdown), outside tables.
* :func:`md_cell` - same as :func:`md`, then each ``\\`` becomes ``\\\\``,
  then each ``|`` becomes ``\\|``.
* :func:`workflow_cmd` - the message part of a workflow command (annotations).
* :func:`workflow_prop` - a property value of a workflow command (``file=``, ``title=``).
* :func:`output_heredoc` - one ``GITHUB_OUTPUT`` entry with a random delimiter.
* :func:`sarif_text` - a SARIF ``message.text`` (plain text, never Markdown).
* :func:`sarif_uri` - a SARIF ``artifactLocation.uri`` (RFC 3986 URI reference, D-TL-97).
* :func:`md_codeblock` - text inside a fenced code block in the comment or job summary.
* :func:`text_field` - a repo-derived field in the ``--format text`` report.

Nothing in this package ever writes ``GITHUB_ENV`` or ``GITHUB_PATH``.
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from collections.abc import Callable, Sequence
from typing import Final
from urllib.parse import quote

__all__ = [
    "md",
    "md_cell",
    "md_codeblock",
    "output_heredoc",
    "sarif_text",
    "sarif_uri",
    "text_field",
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
    """Return :func:`md` of ``text``, then double each ``\\``, then escape ``|`` as ``\\|``.

    The backslash pass runs first so a source ``\\|`` cannot close a GFM
    table cell early (I-14, SR F1). A doubled backslash may show inside
    the code span; that is accepted.
    """
    return md(text).replace("\\", "\\\\").replace("|", "\\|")


_FENCE_MIN: Final = 3
MAX_CODEBLOCK_LINE: Final = 1000
"""The most characters one ``md_codeblock`` line keeps after mapping (SR, INTERFACES I-14)."""
_INFO: Final = re.compile(r"[a-z0-9-]{0,32}")  # fullmatch; linear


def _cap_line(mapped: str) -> str:
    """Cut a mapped line to ``MAX_CODEBLOCK_LINE`` characters plus a visible marker."""
    if len(mapped) <= MAX_CODEBLOCK_LINE:
        return mapped
    return f"{mapped[:MAX_CODEBLOCK_LINE]} [\u2026{len(mapped) - MAX_CODEBLOCK_LINE} more chars]"


def md_codeblock(lines: Sequence[str], info: str = "") -> str:
    """Return ``lines`` as one whole fenced code block (INTERFACES I-14, option A).

    GFM renders nothing inside a fence (no mention, link, image, HTML, emphasis or ``#123``
    reference), so the only risk is text that closes the fence. Each line gets the
    invisible-character mapping and nothing else; LF, CR and every other line separator
    become visible symbols, so one input line is always one output line. A mapped line longer
    than ``MAX_CODEBLOCK_LINE`` is cut and ends with `` [\u2026N more chars]``. The fence is
    backticks, ``max(3, longest backtick run in any cut line + 1)`` long, so no line can close
    it whatever its indentation. ``info`` must match ``[a-z0-9-]{0,32}``, otherwise
    ``ValueError``. Returns ``fence + info + LF + lines joined by LF + LF + fence``; the caller
    adds no fence of its own.
    """
    if not _INFO.fullmatch(info):
        raise ValueError("invalid code block info string")
    kept = [_cap_line(_visible_text(line)) for line in lines]
    longest = max((len(run) for line in kept for run in _BACKTICK_RUN.findall(line)), default=0)
    fence = "`" * max(_FENCE_MIN, longest + 1)
    return f"{fence}{info}\n" + "\n".join(kept) + f"\n{fence}"


def _reject_residual_controls(text: str) -> str:
    """Fail closed if any control, format, separator or surrogate char remains.

    After :func:`_visible_text` this cannot happen for normal input. The
    check is a guard against a later change that skips or reorders the
    mapping, which would otherwise let a workflow command leak through.
    The message is fixed and never includes the input.
    """
    for char in text:
        if unicodedata.category(char) in _LABEL_CATEGORIES:
            raise ValueError("residual control character after mapping")
    return text


def _workflow_escape(text: str) -> str:
    """Map, reject leftover controls, then apply the remaining ``%`` encoding."""
    return _reject_residual_controls(_visible_text(text)).replace("%", "%25")


def workflow_cmd(text: str) -> str:
    """Escape the data part of ``::command props::data`` (R3.1, AC-N3.13, I-14).

    The I-14 mapping runs first, so CR and LF are already ``␍`` / ``␊``. The
    remaining protocol encoding is ``%`` -> ``%25``. A residual CR, LF or
    other character in categories Cc, Cf, Zl, Zp or Cs raises
    ``ValueError``.
    """
    return _workflow_escape(text)


def workflow_prop(text: str) -> str:
    """Escape a workflow-command property value: as :func:`workflow_cmd`, plus ``:`` and ``,``."""
    return _workflow_escape(text).replace(":", "%3A").replace(",", "%2C")


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


_URI_SAFE: Final = "/"
"""The only character ``sarif_uri`` keeps besides RFC 3986 unreserved ``A-Z a-z 0-9 - . _ ~``."""
_LEADING_SLASHES: Final = re.compile(r"/+")  # anchored with match(); single quantifier, linear


def sarif_uri(path: str) -> str:
    """Return a repo-relative POSIX ``path`` as a SARIF ``artifactLocation.uri`` (D-TL-97).

    The I-14 mapping is applied first, as in every escape function, so control, format,
    separator and surrogate characters become their documented visible form (lone
    surrogates become ``U+D800``-style text and never reach the UTF-8 encoder). The result
    is then UTF-8 percent-encoded per RFC 3986 keeping only unreserved characters and
    ``/``: space, ``%``, ``#``, ``?``, ``:``, ``\\``, ``[``, ``]``, ``@`` and every non-ASCII
    character are encoded, so the output is pure ASCII, has no scheme, query or fragment,
    and is a valid relative URI reference. Leading ``/`` characters are encoded too so the
    value can never read as an absolute path or a ``//host`` network-path reference.
    """
    encoded = quote(_visible_text(path), safe=_URI_SAFE)
    lead = _LEADING_SLASHES.match(encoded)
    if lead is None:
        return encoded
    return quote(lead.group(), safe="") + encoded[lead.end() :]


def text_field(value: str, *, quoted: bool = False) -> str:
    """Escape a repo-derived field for ``--format text`` (SR T-01 b, layout §1.2).

    Values that contain a backslash, start with ``::``, or include a character
    in :data:`_LABEL_CATEGORIES` (Cc, Cf, Zl, Zp, Cs) are returned as
    ``repr(value)``. Otherwise a quoted field is wrapped in double quotes and
    a plain field is returned unchanged.
    """
    if "\\" in value or value.startswith("::") or _has_special(value):
        return repr(value)
    if quoted:
        return f'"{value}"'
    return value


def _has_special(value: str) -> bool:
    """True when ``value`` contains a character in :data:`_LABEL_CATEGORIES`."""
    return any(unicodedata.category(char) in _LABEL_CATEGORIES for char in value)
