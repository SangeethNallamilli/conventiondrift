"""C5 ``load_yaml``: the only way repo YAML is parsed (T-011, I-6, SECURITY-RULES R1.3).

This is the one module that may import the vendored PyYAML
(``conventiondrift._vendor.yaml``; ADR-0002 Amendment 2, R1.3). A
``.conventiondrift.yml`` is untrusted repo content, so it is checked in two
passes (THREAT-MODEL T-02, T-09; SEC-T02, SEC-T09):

1. **Size and text.** At most :data:`MAX_BYTES` (64 KiB, R2.3) and valid UTF-8
   (a UTF-8 BOM is dropped), checked before any YAML code runs.
2. **Event scan.** The parser's event stream, which never builds objects and is
   iterative, is read to the end. It rejects any alias, any anchor, any explicit
   tag outside :data:`CORE_TAGS`, collection nesting deeper than
   :data:`MAX_DEPTH`, and more than one document. It stops at the first problem,
   so an alias bomb or a deep flow sequence costs no more than its prefix.
3. **Load.** Only then is the text loaded with :class:`CoreLoader`, a
   ``SafeLoader`` subclass whose implicit resolvers are cut down to the core
   scalars (null, bool, int, float; anything else is a string). So
   ``2024-01-01`` stays a string, and ``<<`` and ``=`` are plain keys rather
   than merge or value markers.

Every failure is a :class:`YamlRejected` carrying one fixed note from
:data:`REJECTION_NOTES`. No note, and no exception that leaves this module,
contains file content or a parser message (R4.2, renderers still escape notes).
No file I/O happens here: callers pass bytes they read through C3 or safefs.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, ClassVar, Final, Literal

from conventiondrift._vendor import yaml

__all__ = [
    "CORE_TAGS",
    "MAX_BYTES",
    "MAX_DEPTH",
    "REJECTION_NOTES",
    "CoreLoader",
    "Rejection",
    "YamlRejected",
    "load_yaml",
]

MAX_BYTES: Final = 65_536
"""I-6, SECURITY-RULES R2.3: the config file is limited to 64 KiB."""

MAX_DEPTH: Final = 10
"""I-6, T-09: collection nesting depth at most 10. The top-level mapping is depth 1."""

_CORE: Final = "tag:yaml.org,2002:"
CORE_TAGS: Final = frozenset(
    _CORE + name for name in ("null", "bool", "int", "float", "str", "seq", "map")
)
"""The YAML core schema tags. Any other explicit tag (``!!python/...``, ``!!set``,
``!!binary``, ``!!timestamp``, ``!local``, the non-specific ``!``) is rejected."""

Rejection = Literal["size", "encoding", "syntax", "anchor", "alias", "tag", "depth", "documents"]

REJECTION_NOTES: Final[Mapping[Rejection, str]] = MappingProxyType(
    {
        "size": "The config file is larger than 64 KiB, so it was ignored",
        "encoding": "The config file is not valid UTF-8, so it was ignored",
        "syntax": "The config file is not valid YAML, so it was ignored",
        "anchor": "The config file uses a YAML anchor, which is not allowed, so it was ignored",
        "alias": "The config file uses a YAML alias, which is not allowed, so it was ignored",
        "tag": "The config file uses a YAML tag that is not allowed, so it was ignored",
        "depth": "The config file nests deeper than 10 levels, so it was ignored",
        "documents": "The config file holds more than one YAML document, so it was ignored",
    }
)
"""One fixed summary note per rejection class (AC-F9.11: a note, never a crash)."""

_IMPLICIT_CORE: Final = frozenset(_CORE + name for name in ("null", "bool", "int", "float"))


class YamlRejected(ValueError):
    """The config text was refused; ``note`` is the fixed summary text for ``reason``."""

    def __init__(self, reason: Rejection) -> None:
        super().__init__(REJECTION_NOTES[reason])
        self.reason: Rejection = reason
        self.note: str = REJECTION_NOTES[reason]


def _core_resolvers(
    resolvers: dict[str, list[tuple[str, Any]]],
) -> dict[str, list[tuple[str, Any]]]:
    """A copy of ``resolvers`` keeping only the core implicit tags; empty lists are dropped."""
    kept = {
        first: [(tag, regexp) for tag, regexp in entries if tag in _IMPLICIT_CORE]
        for first, entries in resolvers.items()
    }
    return {first: entries for first, entries in kept.items() if entries}


class CoreLoader(yaml.SafeLoader):  # type: ignore[misc]  # vendored module is untyped
    """``SafeLoader`` with only the core-schema implicit resolvers (null, bool, int, float).

    Explicit tags never reach it: the event scan has refused every non-core tag.
    """

    yaml_implicit_resolvers: ClassVar[dict[str, list[tuple[str, Any]]]] = _core_resolvers(
        yaml.SafeLoader.yaml_implicit_resolvers
    )


def _text(data: bytes | str) -> str:
    raw = data.encode("utf-8", errors="surrogatepass") if isinstance(data, str) else data
    if len(raw) > MAX_BYTES:
        raise YamlRejected("size")
    if isinstance(data, str):
        if any("\ud800" <= ch <= "\udfff" for ch in data):
            raise YamlRejected("encoding")
        return data.removeprefix("\ufeff")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise YamlRejected("encoding") from None


def _scan(text: str) -> None:
    """Read the whole event stream; raise on the first anchor, alias, tag, depth or document."""
    loader = None
    try:
        # The reader refuses non-printable characters as soon as it is built.
        loader = CoreLoader(text)
        depth = 0
        documents = 0
        while loader.check_event():
            event = loader.get_event()
            if isinstance(event, yaml.AliasEvent):
                raise YamlRejected("alias")
            if isinstance(event, yaml.NodeEvent) and event.anchor is not None:
                raise YamlRejected("anchor")
            if isinstance(event, (yaml.ScalarEvent, yaml.CollectionStartEvent)) and (
                event.tag is not None and event.tag not in CORE_TAGS
            ):
                raise YamlRejected("tag")
            if isinstance(event, yaml.CollectionStartEvent):
                depth += 1
                if depth > MAX_DEPTH:
                    raise YamlRejected("depth")
            elif isinstance(event, yaml.CollectionEndEvent):
                depth -= 1
            elif isinstance(event, yaml.DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise YamlRejected("documents")
    except yaml.YAMLError:
        raise YamlRejected("syntax") from None
    finally:
        if loader is not None:
            loader.dispose()


def _load(text: str) -> object:
    # The scan already built a loader on the same text, so this one can't fail to build.
    loader = CoreLoader(text)
    try:
        return loader.get_single_data()
    # ValueError: an explicit core tag on a bad value (``!!int x``) or an int past
    # sys.int_info.str_digits_check_threshold; LookupError: ``!!bool maybe`` (KeyError)
    # and an empty ``!!int`` or ``!!float`` (IndexError); TypeError: a collection used as
    # a key; ArithmeticError: kept for safety on numeric construction.
    except (yaml.YAMLError, ValueError, LookupError, TypeError, ArithmeticError):
        raise YamlRejected("syntax") from None
    finally:
        loader.dispose()


def load_yaml(data: bytes | str) -> object:
    """Parse one config document safely (I-6, SEC-T02, SEC-T09). Raises only ``YamlRejected``.

    ``data`` is the file's bytes; ``str`` is accepted for callers that already
    hold text (the mutation-job guard calls ``load_yaml("key: value\\n")``), and
    the size cap then applies to its UTF-8 encoding. An empty document gives
    ``None``. The result holds only dicts, lists, str, int, float, bool and None.
    """
    text = _text(data)
    _scan(text)
    return _load(text)
