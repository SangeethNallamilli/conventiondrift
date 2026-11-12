"""C5 policy, part 2: the effective ``Policy`` for a run (T-012; DESIGN §2 step 3, §10 B7).

``build_policy`` combines the Action inputs (or CLI flags) with the config of
each side and the I-7 markers of each side's instruction files:

- **Precedence** (I-5, AC-F9.15): an input beats the config file, and the
  config file beats the defaults.
- **Effective ``fail-on``** (D-PM-12, D-PM-32, I-14 Q5): the same order as
  ``core.error_fail_on``, which this reuses: a valid input, else the
  policy-side config's ``fail-on``, else ``none``.
- **Policy source** (D-PM-12, D-PM-22, I-4, I-7): in compare mode the
  base-branch tip when gated, otherwise head. In head-only mode the analyzed
  commit and in scan mode the scanned tree, each passed as ``head``.
- **Effective excludes** (I-5, SC-2.41): the ``exclude`` input when given,
  which replaces the defaults, else the defaults; the policy side's config
  entries are added on top. The hard exclusions are C4's and aren't listed.
- **Per-rule ignores and markers** come from the policy side only.
- **after_merge_notes** (B7): when a compare run is gated, every policy
  difference between base and head is listed; it takes effect after merge.
  Under ``none`` head policy applies and nothing is listed.
- Invalid ``history-days``, ``comment`` or ``sarif`` inputs get a note and the
  next value in precedence order (DESIGN §4, §10 S2); I-6 ranges are
  re-checked on the policy-side config (``check_ranges``, SR F1 on #25).

Notes are plain text and never contain an input value. Marker notes name the
instruction file path, which is repo content: renderers escape every note.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Literal

from conventiondrift.core import FailOn, error_fail_on
from conventiondrift.model import CheckerId, CheckerPolicy, IgnoreEntry, Policy, Thresholds
from conventiondrift.policy.config import (
    DEFAULT_CHECKERS,
    DEFAULT_EXCLUDES,
    DEFAULT_HISTORY_DAYS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_THRESHOLDS,
    HISTORY_DAYS_RANGE,
    SideConfig,
    check_ranges,
)
from conventiondrift.policy.ignores import markers_by_file

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "Inputs",
    "Mode",
    "PolicySide",
    "build_policy",
    "config_path",
]

Mode = Literal["compare", "head-only", "scan"]

DEFAULT_CONFIG_PATH: Final = ".conventiondrift.yml"
"""I-5 ``config`` default (AC-F9.7)."""

_BOOLS: Final[Mapping[str, bool]] = MappingProxyType({"true": True, "false": False})
"""I-5 ``comment`` and ``sarif`` values, matched exactly."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Inputs:
    """The raw Action inputs (I-5) or CLI flags (I-4). ``None`` or empty means "not set".

    ``exclude`` and ``paths`` are already split into entries; an empty tuple
    counts as not given. The CLI passes ``None`` for ``comment`` and ``sarif``.
    """

    fail_on: str | None = None
    exclude: tuple[str, ...] | None = None
    paths: tuple[str, ...] | None = None
    comment: str | None = None
    sarif: str | None = None
    history_days: str | None = None
    config: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicySide:
    """One side's policy material: its config (``None``: no config file) and instruction files."""

    config: SideConfig | None
    instruction_files: Mapping[str, bytes] = field(default_factory=lambda: MappingProxyType({}))


def config_path(inputs: Inputs) -> str:
    """The config file to read: the ``config`` input when set, else the default (AC-F9.7)."""
    return inputs.config or DEFAULT_CONFIG_PATH


def _history_days_input(value: str | None) -> tuple[int | None, str | None]:
    if not value:
        return None, None
    low, high = HISTORY_DAYS_RANGE
    # ASCII digits only: int() would also accept signs, spaces, "_" and non-ASCII digits.
    if value.isascii() and value.isdigit() and low <= int(value) <= high:
        return int(value), None
    return None, f"history-days input must be an integer from {low} to {high}; it was ignored"


def _bool_input(name: str, value: str | None) -> tuple[bool | None, str | None]:
    if not value:
        return None, None
    if value in _BOOLS:
        return _BOOLS[value], None
    return None, f"{name} input must be true or false; the default true is used"


@dataclass(frozen=True, slots=True)
class _Resolved:
    """One side's config with defaults filled in, for use and for base/head comparison."""

    fail_on: FailOn
    history_days: int
    thresholds: Thresholds
    exclude: tuple[str, ...]
    max_file_bytes: int
    checkers: Mapping[CheckerId, CheckerPolicy]
    ignores: frozenset[IgnoreEntry]


def _resolve(config: SideConfig) -> _Resolved:
    return _Resolved(
        fail_on=config.fail_on or "none",
        history_days=config.history_days or DEFAULT_HISTORY_DAYS,
        thresholds=config.thresholds or DEFAULT_THRESHOLDS,
        exclude=config.exclude,
        max_file_bytes=config.max_file_bytes or DEFAULT_MAX_FILE_BYTES,
        checkers={**DEFAULT_CHECKERS, **config.checkers},
        ignores=frozenset(config.ignores),
    )


def _after_merge(text: str) -> str:
    return f"This PR changes {text}; the change takes effect after merge"


def _after_merge_notes(
    base: _Resolved,
    head: _Resolved,
    base_markers: Mapping[str, tuple[tuple[int, bool], ...]],
    head_markers: Mapping[str, tuple[tuple[int, bool], ...]],
    *,
    fail_on_input: bool,
    history_days_input: bool,
) -> tuple[str, ...]:
    """Every base/head policy difference (DESIGN §10 B7), in a fixed order."""
    notes: list[str] = []
    # A setting the input overrides stays overridden after merge, so its config change
    # doesn't take effect then either.
    if not fail_on_input and base.fail_on != head.fail_on:
        notes.append(_after_merge("fail-on in the config file"))
    if not history_days_input and base.history_days != head.history_days:
        notes.append(_after_merge("history-days in the config file"))
    if base.thresholds != head.thresholds:
        notes.append(_after_merge("thresholds in the config file"))
    if base.exclude != head.exclude:
        notes.append(_after_merge("exclude in the config file"))
    if base.max_file_bytes != head.max_file_bytes:
        notes.append(_after_merge("limits.max-file-bytes in the config file"))
    for cid in sorted(base.checkers):
        if base.checkers[cid] != head.checkers[cid]:
            notes.append(_after_merge(f"checkers.{cid} in the config file"))
    if base.ignores != head.ignores:
        notes.append(_after_merge("ignore in the config file"))
    for path in sorted(base_markers.keys() | head_markers.keys()):
        if base_markers.get(path, ()) != head_markers.get(path, ()):
            notes.append(_after_merge(f"the inline ignore markers in {path}"))
    return tuple(notes)


def build_policy(
    mode: Mode, inputs: Inputs, *, head: PolicySide, base: PolicySide | None = None
) -> Policy:
    """The effective ``Policy`` (I-11 C5). Never raises for bad values: they become notes.

    ``base`` is required in compare mode and must be ``None`` otherwise. In
    head-only mode ``head`` is the analyzed commit; in scan mode it is the
    scanned working tree.
    """
    if (mode == "compare") != (base is not None):
        raise ValueError("build_policy needs a base side in compare mode and only then")
    notes: list[str] = []
    history_days, note = _history_days_input(inputs.history_days)
    notes.extend(n for n in (note,) if n)
    comment, note = _bool_input("comment", inputs.comment)
    notes.extend(n for n in (note,) if n)
    sarif, note = _bool_input("sarif", inputs.sarif)
    notes.extend(n for n in (note,) if n)

    # The fail-on side is base in compare mode, else the analyzed tree (I-4 B7, D-PM-22).
    fail_on_side = base if base is not None else head
    fail_on_config = fail_on_side.config.fail_on if fail_on_side.config else None
    effective_fail_on = error_fail_on(inputs.fail_on, fail_on_config)
    gated = effective_fail_on != "none"
    source: Literal["base", "head"] = "base" if base is not None and gated else "head"
    side = base if base is not None and gated else head

    config, range_notes = check_ranges(side.config or SideConfig())
    notes.extend(config.notes)
    notes.extend(range_notes)
    resolved = _resolve(config)
    markers = markers_by_file(side.instruction_files)

    after_merge_notes: tuple[str, ...] = ()
    if base is not None and gated:
        head_config, _ = check_ranges(head.config or SideConfig())
        after_merge_notes = _after_merge_notes(
            resolved,
            _resolve(head_config),
            markers,
            markers_by_file(head.instruction_files),
            fail_on_input=inputs.fail_on == effective_fail_on,
            history_days_input=history_days is not None,
        )

    user_excludes = inputs.exclude or DEFAULT_EXCLUDES
    excludes = tuple(dict.fromkeys((*user_excludes, *resolved.exclude)))
    return Policy(
        effective_fail_on=effective_fail_on,
        gated=gated,
        source=source,
        history_days=history_days if history_days is not None else resolved.history_days,
        thresholds=resolved.thresholds,
        excludes=excludes,
        max_file_bytes=resolved.max_file_bytes,
        checkers=resolved.checkers,
        ignores=config.ignores,
        markers=markers,
        paths=inputs.paths or None,
        comment=True if comment is None else comment,
        sarif=True if sarif is None else sarif,
        after_merge_notes=after_merge_notes,
        notes=tuple(notes),
    )
