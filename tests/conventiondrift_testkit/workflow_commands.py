"""Parse the GitHub workflow commands C11 writes to stdout (CON-29, AC-N3.13).

Wire format: ``::kind key=value,key2=value2::data``. One command per line; anything that does
not start with ``::`` or has no ``::`` separator after the kind is ignored, so a captured stdout
can be parsed whole.

**Unescape order matters.** ``render.escape.workflow_prop`` escapes ``,`` as ``%2C`` and ``:`` as
``%3A``, so properties are split on **raw** commas first and each value is unescaped afterwards.
Splitting after unescaping would split a path that contains a comma into two properties.

**Decode set and order.** We invert this repo's own escapers, in this order: ``%2C`` and ``%3A``
(property escapes) first, then ``%25`` once. A single left-to-right pass over
``%(25|2C|3A)`` is exactly that order and cannot double-decode, so ``%250A`` becomes the literal
text ``%0A``, never a newline.

``%0A``/``%0D`` are deliberately **not** decoded. ``render.escape`` maps CR/LF through the I-14
visible-text mapping *before* escaping, so this repo's commands never contain them - controls
arrive as Control Pictures (``␊``, U+240A). Decoding them could only corrupt a value that
legitimately contains the literal text ``%0A``, so they stay as written; that is a documented
trade-off for a foreign producer, not a gap. The Control-Pictures inverse *is* applied, which is
what turns ``a␊b`` back into ``a`` newline ``b``: the inverse cannot distinguish a mapped
newline from a source that already contained U+240A, so that one input is ambiguous by
construction and is documented rather than hidden. The one-way ``U+XXXX`` label form (Cf/Zl/Zp/
Cs) is never inverted.

Unknown kinds and properties are kept rather than rejected, so a future GitHub command cannot
break a suite that only wants the warnings.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from conventiondrift_testkit.github_env import control_pictures_inverse

__all__ = [
    "Command",
    "parse_commands",
    "split_properties",
    "unescape",
    "unescape_property",
]

_KIND: Final = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_UNESCAPE: Final = re.compile(r"%(25|2C|3A)")
_UNESCAPE_DATA: Final = re.compile(r"%(25)")
_MAP: Final[Mapping[str, str]] = MappingProxyType({"25": "%", "2C": ",", "3A": ":"})
_INT: Final = re.compile(r"[0-9]+")


def unescape(text: str) -> str:
    """Undo the **data** escaping (``%25``, one pass) and the Control-Pictures mapping.

    ``%2C``/``%3A`` are property escapes and stay literal here; ``%0A``/``%0D`` stay literal by
    design (see the module docstring).
    """
    return control_pictures_inverse(_UNESCAPE_DATA.sub(lambda m: _MAP[m.group(1)], text))


def unescape_property(text: str) -> str:
    """Undo the **property** escaping: ``%2C`` and ``%3A`` before ``%25``, then the pictures."""
    return control_pictures_inverse(_UNESCAPE.sub(lambda m: _MAP[m.group(1)], text))


def split_properties(text: str) -> dict[str, str]:
    """Split ``key=value,key2=value2`` on raw commas, then unescape each value.

    A value containing ``%2C`` keeps its comma. A segment without ``=``, or with an empty key,
    is dropped: it is not a property, and inventing one would hide a malformed command.
    """
    if not text:
        return {}
    out: dict[str, str] = {}
    for part in text.split(","):
        key, sep, value = part.partition("=")
        if not sep or not key:
            continue
        out[key] = unescape_property(value)
    return out


def _int_or_none(value: str | None) -> int | None:
    return int(value) if value is not None and _INT.fullmatch(value) else None


@dataclass(frozen=True, slots=True)
class Command:
    """One parsed workflow command. Fields absent from the line are ``None``."""

    kind: str
    message: str
    file: str | None = None
    line: int | None = None
    col: int | None = None
    end_line: int | None = None
    title: str | None = None
    properties: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    """Every property, unescaped, including the ones named above and any future one."""
    raw: str = ""
    """The original line, for a diagnostic or an unknown-kind assertion."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "properties", MappingProxyType(dict(self.properties)))


def parse_commands(
    source: str | Iterable[str] | Iterable[Iterable[str]],
) -> tuple[Command, ...]:
    """Every command in ``source``, in order. ``source`` may be text, lines, or sink records.

    ``MemorySinks.annotation_lines`` is a tuple of tuples of lines, so nested iterables are
    flattened one level and each item is split into lines.
    """
    lines: list[str] = []
    if isinstance(source, str):
        lines = source.splitlines()
    else:
        for item in source:
            if isinstance(item, str):
                lines.extend(item.splitlines())
            else:
                for sub in item:
                    lines.extend(str(sub).splitlines())
    commands: list[Command] = []
    for line in lines:
        command = _parse_line(line)
        if command is not None:
            commands.append(command)
    return tuple(commands)


def _parse_line(line: str) -> Command | None:
    if not line.startswith("::"):
        return None
    body = line[2:]
    separator = body.find("::")
    if separator < 0:
        return None
    head, message = body[:separator], body[separator + 2 :]
    kind, _, prop_text = head.partition(" ")
    if not _KIND.fullmatch(kind):
        return None
    properties = split_properties(prop_text)
    return Command(
        kind=kind,
        message=unescape(message),
        file=properties.get("file"),
        line=_int_or_none(properties.get("line")),
        col=_int_or_none(properties.get("col")),
        end_line=_int_or_none(properties.get("endLine")),
        title=properties.get("title"),
        properties=properties,
        raw=line,
    )
