"""C5 config values: defaults, one side's validated config, and the I-6 range backstop.

T-011 parses ``.conventiondrift.yml`` (``load_yaml``) and validates it against
the I-6 schema into a ``SideConfig``. T-012 (this module and
``conventiondrift.policy``) combines the two sides with the Action inputs.

``check_ranges`` re-applies the I-6 numeric ranges to a ``SideConfig`` before
it is used (SR F1 on #25): ``thresholds.holds`` 1..100, every stale and
migrating percentage 0..100, ``min-sites`` 1..1000 and ``history-days``
1..3650. An out-of-range value gets that setting's default and a note
(AC-F9.11), so C9 never sees one, whatever produced the ``SideConfig``.
"""

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, get_args

from conventiondrift.core import FailOn
from conventiondrift.model import CheckerId, CheckerPolicy, IgnoreEntry, Thresholds

__all__ = [
    "DEFAULT_CHECKERS",
    "DEFAULT_HISTORY_DAYS",
    "DEFAULT_LOGGING_SCRIPT_PATHS",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_THRESHOLDS",
    "HISTORY_DAYS_RANGE",
    "THRESHOLD_RANGES",
    "SideConfig",
    "check_ranges",
]

DEFAULT_HISTORY_DAYS: Final = 90
"""I-5 and I-6 ``history-days`` default."""

HISTORY_DAYS_RANGE: Final = (1, 3650)
"""I-5 and I-6: ``history-days`` is an integer from 1 to 3650."""

DEFAULT_MAX_FILE_BYTES: Final = 1048576
"""I-6 ``limits.max-file-bytes`` default (1 MiB, SECURITY-RULES R2.3)."""

DEFAULT_THRESHOLDS: Final = Thresholds(
    holds=80,
    stale_overall=20,
    stale_recent=20,
    migrating_overall=50,
    migrating_recent=70,
    min_sites=5,
)
"""The I-6 example values, which are the defaults."""

THRESHOLD_RANGES: Final[Mapping[str, tuple[str, int, int]]] = MappingProxyType(
    {
        "holds": ("thresholds.holds", 1, 100),
        "stale_overall": ("thresholds.stale.overall", 0, 100),
        "stale_recent": ("thresholds.stale.recent", 0, 100),
        "migrating_overall": ("thresholds.migrating.overall", 0, 100),
        "migrating_recent": ("thresholds.migrating.recent", 0, 100),
        "min_sites": ("thresholds.min-sites", 1, 1000),
    }
)
"""``Thresholds`` field -> (I-6 key, lowest, highest), both ends inclusive."""

DEFAULT_LOGGING_SCRIPT_PATHS: Final = (
    "**/tests/**",
    "**/test/**",
    "**/scripts/**",
    "**/bin/**",
    "**/test_*.py",
    "**/*_test.py",
    "**/conftest.py",
)
"""I-6 ``checkers.logging.script-paths`` default (B2)."""

DEFAULT_CHECKERS: Final[Mapping[CheckerId, CheckerPolicy]] = MappingProxyType(
    {
        cid: CheckerPolicy(
            enabled=cid != "money",
            script_paths=DEFAULT_LOGGING_SCRIPT_PATHS if cid == "logging" else (),
        )
        for cid in get_args(CheckerId)
    }
)
"""I-6: every checker is on except ``money`` (AC-F3.14)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SideConfig:
    """One side's config file after I-6 validation (T-011). ``None`` means "not set".

    ``checkers`` holds only the checkers the file configures, each fully
    resolved. ``notes`` are T-011's notes for invalid values and unknown keys.
    """

    fail_on: FailOn | None = None
    history_days: int | None = None
    thresholds: Thresholds | None = None
    exclude: tuple[str, ...] = ()
    max_file_bytes: int | None = None
    checkers: Mapping[CheckerId, CheckerPolicy] = field(
        default_factory=lambda: MappingProxyType({})
    )
    ignores: tuple[IgnoreEntry, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "checkers", MappingProxyType(dict(self.checkers)))


def _in_range(value: object, low: int, high: int) -> bool:
    # bool is an int subclass; True is not a valid threshold (I-6: integers).
    return type(value) is int and low <= value <= high


def _range_note(key: str, low: int, high: int, default: int) -> str:
    return f"{key} must be an integer from {low} to {high}; the default {default} is used"


def check_ranges(config: SideConfig) -> tuple[SideConfig, tuple[str, ...]]:
    """``config`` with every out-of-range I-6 number replaced by its default, plus notes.

    Each threshold is checked on its own, so one bad value doesn't reset the
    others (AC-F9.11: "defaults are used for it").
    """
    notes: list[str] = []
    changes: dict[str, object] = {}
    if config.thresholds is not None:
        fixed: dict[str, int] = {}
        for name, (key, low, high) in THRESHOLD_RANGES.items():
            if not _in_range(getattr(config.thresholds, name), low, high):
                default = getattr(DEFAULT_THRESHOLDS, name)
                fixed[name] = default
                notes.append(_range_note(key, low, high, default))
        if fixed:
            changes["thresholds"] = dataclasses.replace(config.thresholds, **fixed)
    if config.history_days is not None and not _in_range(config.history_days, *HISTORY_DAYS_RANGE):
        changes["history_days"] = DEFAULT_HISTORY_DAYS
        notes.append(_range_note("history-days", *HISTORY_DAYS_RANGE, DEFAULT_HISTORY_DAYS))
    if not changes:
        return config, ()
    return dataclasses.replace(config, **changes), tuple(notes)  # type: ignore[arg-type]
