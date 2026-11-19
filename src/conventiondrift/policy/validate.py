"""C5 I-6 validation: one side's ``.conventiondrift.yml`` bytes to a ``SideConfig`` (T-011).

:func:`parse_side_config` runs :func:`~conventiondrift.policy.yamlsafe.load_yaml`
and then :func:`validate_document`. Neither ever raises for bad content
(AC-F9.11): each problem becomes one summary note, and the setting it affects
keeps its default (``None`` or empty in the ``SideConfig``, which T-012 fills in):

- A file that is refused by ``load_yaml``, isn't a mapping, or doesn't set
  ``version: 1`` is ignored as a whole (I-6): every setting is unset and the
  only note says why.
- An unknown key, at any level I-6 defines, is ignored with a note naming it.
- A bad value gets its default with a note naming the setting. Each threshold
  is checked on its own, then the **threshold order** (DESIGN §10 S1):
  ``stale.overall <= migrating.overall <= holds`` and ``stale.recent <=
  migrating.recent``. If it fails, the whole ``thresholds`` block falls back to
  the defaults, with a note.
- ``limits.max-file-bytes`` is 1024..1048576, so it can only lower the 1 MiB
  default (I-6, R2.3).
- ``exclude`` and ``ignore[].file`` entries that would leave the repository
  (absolute, ``..``, drive, backslash forms, NUL) are dropped and listed (I-6,
  AC-N3.8, R2.1).

Notes name settings by their I-6 key. Notes for unknown keys and rejected
paths quote that repo text, cut to :data:`SHOWN_MAX` characters; renderers
escape every note (R3). Unknown-key notes stop after :data:`UNKNOWN_KEY_NOTES_MAX`
and one more note counts the rest, so a file can't flood the summary.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, TypeGuard, get_args

from conventiondrift.core import FailOn
from conventiondrift.model import CheckerId, CheckerPolicy, IgnoreEntry, Thresholds
from conventiondrift.policy import DEFAULT_CONFIG_PATH
from conventiondrift.policy.config import (
    DEFAULT_CHECKERS,
    DEFAULT_HISTORY_DAYS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_THRESHOLDS,
    HISTORY_DAYS_RANGE,
    THRESHOLD_RANGES,
    SideConfig,
)
from conventiondrift.policy.yamlsafe import YamlRejected, load_yaml

__all__ = [
    "CHECKER_KEYS",
    "IGNORE_KEYS",
    "LIMIT_KEYS",
    "MAX_FILE_BYTES_RANGE",
    "NOTE_NOT_MAPPING",
    "NOTE_THRESHOLD_ORDER",
    "NOTE_VERSION",
    "SHOWN_MAX",
    "THRESHOLD_KEYS",
    "TOP_LEVEL_KEYS",
    "UNKNOWN_KEY_NOTES_MAX",
    "checked_config_path",
    "contained_path",
    "parse_side_config",
    "validate_document",
]

TOP_LEVEL_KEYS: Final = (
    "version",
    "fail-on",
    "history-days",
    "thresholds",
    "exclude",
    "limits",
    "checkers",
    "ignore",
)
"""Every I-6 top-level key."""

THRESHOLD_KEYS: Final = ("holds", "stale", "migrating", "min-sites")
"""I-6 keys under ``thresholds``; ``stale`` and ``migrating`` hold ``overall`` and ``recent``."""

PAIR_KEYS: Final = ("overall", "recent")
LIMIT_KEYS: Final = ("max-file-bytes",)
CHECKER_KEYS: Final[Mapping[CheckerId, tuple[str, ...]]] = {
    cid: ("enabled", "script-paths") if cid == "logging" else ("enabled",)
    for cid in get_args(CheckerId)
}
"""I-6 keys under each ``checkers.<id>``: ``script-paths`` exists for ``logging`` only."""

IGNORE_KEYS: Final = ("file", "line", "text")

MAX_FILE_BYTES_RANGE: Final = (1024, DEFAULT_MAX_FILE_BYTES)
"""I-6 ``limits.max-file-bytes``: 1024..1048576. The top is the default: it may only be lowered."""

SHOWN_MAX: Final = 80
"""Repo text quoted in a note (an unknown key, a rejected path) is cut to this many characters."""

UNKNOWN_KEY_NOTES_MAX: Final = 20
"""At most this many unknown-key notes per file; one more note counts the rest."""

NOTE_VERSION: Final = "The config file must set version: 1, so it was ignored"
NOTE_NOT_MAPPING: Final = "The config file is not a YAML mapping, so it was ignored"
NOTE_THRESHOLD_ORDER: Final = (
    "thresholds must satisfy stale.overall <= migrating.overall <= holds and "
    "stale.recent <= migrating.recent; the default thresholds are used"
)

_FAIL_ON_VALUES: Final[tuple[FailOn, ...]] = get_args(FailOn)


def _shown(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= SHOWN_MAX else text[: SHOWN_MAX - 1] + "\u2026"


def _is_int(value: object) -> TypeGuard[int]:
    # bool is an int subclass, but ``true`` is not a number in I-6.
    return type(value) is int


def _range_note(key: str, low: int, high: int, default: int) -> str:
    # Same text as config.check_ranges, so a value reads the same whichever check caught it.
    return f"{key} must be an integer from {low} to {high}; the default {default} is used"


def contained_path(value: str) -> str | None:
    """``value`` as a normalized repo-relative path, or ``None`` if it could leave the repo.

    Refused (I-6, AC-N3.8, SECURITY-RULES R2.1): empty, a NUL, a leading ``/``,
    any ``..`` segment, a backslash, a ``:`` (drive letters such as ``C:x``,
    NTFS streams), a lone surrogate, or nothing left after dropping ``.`` and
    empty segments. Glob characters are left alone. Plain string tests, no
    regex, linear in ``value``. This mirrors the typed-value branch of
    ``discover.safefs.validate_relpath`` (T-009), which isn't on main yet.
    """
    if not value or "\x00" in value or value.startswith("/") or "\\" in value or ":" in value:
        return None
    if any("\ud800" <= ch <= "\udfff" for ch in value):
        return None
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def checked_config_path(value: str | None) -> tuple[str | None, str | None]:
    """The config file to read for a ``config`` input or flag, and a note (SR #35 L3).

    Unset or empty gives the I-5 default. A value that could leave the
    repository (``contained_path``) gives ``None``, meaning no config file is
    read and the defaults apply, with a note listing it (AC-N3.8: "A rejected
    ``config`` path means defaults are used"). Otherwise the normalized path.
    Not following a symlinked config is the reader's job (safefs, AC-N3.9).
    """
    if not value:
        return DEFAULT_CONFIG_PATH, None
    path = contained_path(value)
    if path is None:
        return None, (
            f'config path "{_shown(value)}" is outside the repository; the defaults are used'
        )
    return path, None


class _Notes:
    """Collects notes in order; unknown-key notes are capped (``UNKNOWN_KEY_NOTES_MAX``)."""

    def __init__(self) -> None:
        self.items: list[str] = []
        self._unknown = 0

    def add(self, note: str) -> None:
        self.items.append(note)

    def unknown_keys(
        self, mapping: Mapping[object, object], known: tuple[str, ...], at: str
    ) -> None:
        for key in mapping:
            if key in known:
                continue
            self._unknown += 1
            if self._unknown <= UNKNOWN_KEY_NOTES_MAX:
                self.add(f'Unknown config key "{at}{_shown(key)}" was ignored')

    def done(self) -> tuple[str, ...]:
        extra = self._unknown - UNKNOWN_KEY_NOTES_MAX
        if extra > 0:
            self.add(f"{extra} more unknown config keys were ignored")
        return tuple(self.items)


def _mapping(value: object, key: str, notes: _Notes, then: str) -> Mapping[object, object] | None:
    if isinstance(value, dict):
        return value
    notes.add(f"{key} must be a mapping; {then}")
    return None


def _fail_on(doc: Mapping[object, object], notes: _Notes) -> FailOn | None:
    if "fail-on" not in doc:
        return None
    value = doc["fail-on"]
    for allowed in _FAIL_ON_VALUES:
        if value == allowed:
            return allowed
    notes.add("fail-on must be none, new-stale or any-stale; the default none is used")
    return None


def _history_days(doc: Mapping[object, object], notes: _Notes) -> int | None:
    if "history-days" not in doc:
        return None
    value = doc["history-days"]
    low, high = HISTORY_DAYS_RANGE
    if _is_int(value) and low <= value <= high:
        return value
    notes.add(_range_note("history-days", low, high, DEFAULT_HISTORY_DAYS))
    return None


def _thresholds(doc: Mapping[object, object], notes: _Notes) -> Thresholds | None:
    if "thresholds" not in doc:
        return None
    block = _mapping(doc["thresholds"], "thresholds", notes, "the default thresholds are used")
    if block is None:
        return None
    notes.unknown_keys(block, THRESHOLD_KEYS, "thresholds.")
    groups: dict[str, Mapping[object, object]] = {}
    for group in ("stale", "migrating"):
        if group in block:
            sub = _mapping(
                block[group], f"thresholds.{group}", notes, "the defaults are used for it"
            )
            if sub is not None:
                notes.unknown_keys(sub, PAIR_KEYS, f"thresholds.{group}.")
                groups[group] = sub
    values: dict[str, int] = {}
    for name, (key, low, high) in THRESHOLD_RANGES.items():
        default: int = getattr(DEFAULT_THRESHOLDS, name)
        head, _, leaf = key.removeprefix("thresholds.").partition(".")
        source: Mapping[object, object] | None = groups.get(head) if leaf else block
        field = leaf or head
        if source is None or field not in source:
            values[name] = default
            continue
        value = source[field]
        if _is_int(value) and low <= value <= high:
            values[name] = value
        else:
            values[name] = default
            notes.add(_range_note(key, low, high, default))
    result = Thresholds(**values)
    if not (
        result.stale_overall <= result.migrating_overall <= result.holds
        and result.stale_recent <= result.migrating_recent
    ):
        notes.add(NOTE_THRESHOLD_ORDER)
        return None
    return result


def _exclude(doc: Mapping[object, object], notes: _Notes) -> tuple[str, ...]:
    if "exclude" not in doc:
        return ()
    entries = doc["exclude"]
    if not isinstance(entries, list):
        notes.add("exclude must be a list of paths; it was ignored")
        return ()
    kept: list[str] = []
    for number, entry in enumerate(entries, start=1):
        if not isinstance(entry, str):
            notes.add(f"exclude entry {number} is not a string and was ignored")
        # A leading "!" (gitignore negation) is not part of the path.
        elif contained_path(entry.removeprefix("!")) is None:
            notes.add(f'exclude entry "{_shown(entry)}" is outside the repository and was ignored')
        else:
            kept.append(entry)
    return tuple(dict.fromkeys(kept))


def _max_file_bytes(doc: Mapping[object, object], notes: _Notes) -> int | None:
    if "limits" not in doc:
        return None
    block = _mapping(doc["limits"], "limits", notes, "the defaults are used")
    if block is None:
        return None
    notes.unknown_keys(block, LIMIT_KEYS, "limits.")
    if "max-file-bytes" not in block:
        return None
    value = block["max-file-bytes"]
    low, high = MAX_FILE_BYTES_RANGE
    if _is_int(value) and low <= value <= high:
        return value
    if _is_int(value) and value > high:
        notes.add(
            f"limits.max-file-bytes can only be lowered (at most {high}); "
            f"the default {DEFAULT_MAX_FILE_BYTES} is used"
        )
    else:
        notes.add(_range_note("limits.max-file-bytes", low, high, DEFAULT_MAX_FILE_BYTES))
    return None


def _string_list(value: object) -> tuple[str, ...] | None:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    return None


def _checkers(doc: Mapping[object, object], notes: _Notes) -> dict[CheckerId, CheckerPolicy]:
    if "checkers" not in doc:
        return {}
    block = _mapping(doc["checkers"], "checkers", notes, "the defaults are used")
    if block is None:
        return {}
    notes.unknown_keys(block, tuple(CHECKER_KEYS), "checkers.")
    result: dict[CheckerId, CheckerPolicy] = {}
    for cid, keys in CHECKER_KEYS.items():
        if cid not in block:
            continue
        default = DEFAULT_CHECKERS[cid]
        settings = _mapping(block[cid], f"checkers.{cid}", notes, "its defaults are used")
        if settings is None:
            result[cid] = default
            continue
        notes.unknown_keys(settings, keys, f"checkers.{cid}.")
        enabled = default.enabled
        if "enabled" in settings:
            if type(settings["enabled"]) is bool:
                enabled = settings["enabled"]
            else:
                notes.add(
                    f"checkers.{cid}.enabled must be true or false; "
                    f"the default {str(default.enabled).lower()} is used"
                )
        script_paths = default.script_paths
        if "script-paths" in keys and "script-paths" in settings:
            given = _string_list(settings["script-paths"])
            if given is None:
                notes.add(
                    f"checkers.{cid}.script-paths must be a list of strings; "
                    "the default list is used"
                )
            else:
                script_paths = given
        result[cid] = CheckerPolicy(enabled=enabled, script_paths=script_paths)
    return result


def _ignore_entry(entry: object, number: int, notes: _Notes) -> IgnoreEntry | None:
    invalid = f"ignore entry {number} must have file and line, or text; it was ignored"
    if not isinstance(entry, dict):
        notes.add(invalid)
        return None
    notes.unknown_keys(entry, IGNORE_KEYS, f"ignore[{number}].")
    by_file = "file" in entry or "line" in entry
    if by_file == ("text" in entry):
        notes.add(invalid)
        return None
    if not by_file:
        text = entry["text"]
        if not isinstance(text, str) or not text.strip():
            notes.add(invalid)
            return None
        return IgnoreEntry(file=None, line=None, text=text)
    file, line = entry.get("file"), entry.get("line")
    if not isinstance(file, str) or not _is_int(line) or line < 1:
        notes.add(invalid)
        return None
    path = contained_path(file)
    if path is None:
        notes.add(
            f'ignore entry {number} file "{_shown(file)}" is outside the repository; it was ignored'
        )
        return None
    return IgnoreEntry(file=path, line=line, text=None)


def _ignores(doc: Mapping[object, object], notes: _Notes) -> tuple[IgnoreEntry, ...]:
    if "ignore" not in doc:
        return ()
    entries = doc["ignore"]
    if not isinstance(entries, list):
        notes.add("ignore must be a list of entries; it was ignored")
        return ()
    found = (_ignore_entry(entry, n, notes) for n, entry in enumerate(entries, start=1))
    return tuple(dict.fromkeys(e for e in found if e is not None))


def validate_document(document: object) -> SideConfig:
    """The ``SideConfig`` for one loaded config document (I-6). Never raises for bad content."""
    if not isinstance(document, dict):
        return SideConfig(notes=(NOTE_NOT_MAPPING if document is not None else NOTE_VERSION,))
    version = document.get("version")
    if not (_is_int(version) and version == 1):
        return SideConfig(notes=(NOTE_VERSION,))
    notes = _Notes()
    notes.unknown_keys(document, TOP_LEVEL_KEYS, "")
    fail_on = _fail_on(document, notes)
    history_days = _history_days(document, notes)
    thresholds = _thresholds(document, notes)
    exclude = _exclude(document, notes)
    max_file_bytes = _max_file_bytes(document, notes)
    checkers = _checkers(document, notes)
    ignores = _ignores(document, notes)
    return SideConfig(
        fail_on=fail_on,
        history_days=history_days,
        thresholds=thresholds,
        exclude=exclude,
        max_file_bytes=max_file_bytes,
        checkers=checkers,
        ignores=ignores,
        notes=notes.done(),
    )


def parse_side_config(data: bytes) -> SideConfig:
    """One side's ``SideConfig`` from the config file's bytes (T-011 to T-012 handoff, I-13).

    The caller has already found the file (a missing file is ``PolicySide.config
    = None`` in T-012) and read it within the 64 KiB limit; ``load_yaml`` checks
    the size again. A refused file is ignored as a whole with its one note.
    """
    try:
        document = load_yaml(data)
    except YamlRejected as rejected:
        return SideConfig(notes=(rejected.note,))
    return validate_document(document)
