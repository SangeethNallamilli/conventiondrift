"""C11 JSON report: INTERFACES I-9, ``--format json`` and ``report-path`` (T-026).

The report is one JSON object with sorted keys, 2-space indentation, LF line endings and one
final newline. It has no wall-clock timestamp and no absolute path, so the same input gives
the same bytes (AC-N4.1). ``Result`` maps to I-9 one-to-one (I-13): field names follow I-9,
``percent`` is computed here for display only, and instruction files are listed as paths.

Repository text (rule text, paths, options, ``new_text``) is data here, not markup: the
serializer encodes it as JSON strings with ``ensure_ascii``, so every non-ASCII character,
including bidi, zero-width, separator and lone-surrogate code points, is written as a
``\\uXXXX`` escape and the output is pure ASCII (valid UTF-8). Nothing in this module
escapes text itself (SECURITY-RULES R3.2). Internal errors pass the same I-14 validation as
every other sink, so only fixed messages are written.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Final, TypeAlias

from conventiondrift import __version__
from conventiondrift.checkers import REGISTRY
from conventiondrift.fallback import _safe
from conventiondrift.model import (
    Alternative,
    CausingFile,
    Conflict,
    Counts,
    InternalError,
    Result,
    RuleResult,
    SideResult,
    SiteResult,
    SkippedFile,
    Suggestion,
    Window,
)
from conventiondrift.render.display import display_rule

__all__ = [
    "EXPERIMENTAL_CHECKERS",
    "REPORT_SCHEMA",
    "dump_json",
    "percent",
    "render_json",
    "report_object",
]

REPORT_SCHEMA: Final = "conventiondrift-report/1"
"""I-9 ``schema``."""

EXPERIMENTAL_CHECKERS: Final = frozenset(c.id for c in REGISTRY if c.experimental)
"""Built-in checkers marked ``experimental`` (I-10); drives the I-9 ``experimental`` flag."""

JsonValue: TypeAlias = (
    bool | int | float | str | Sequence["JsonValue"] | Mapping[str, "JsonValue"] | None
)


def dump_json(obj: Mapping[str, JsonValue]) -> str:
    """The I-9 JSON style: sorted keys, 2-space indent, ASCII only, LF, one final newline.

    ``allow_nan=False`` keeps the output strict JSON; no value here can be NaN or infinite.
    """
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def percent(following: int, relevant: int) -> float | None:
    """``following / relevant`` as a percentage, rounded half-even to 1 decimal (I-9).

    Exact integer arithmetic, so a tie is a real tie and never a binary-float artefact.
    ``None`` when ``relevant`` is 0, because there is no share to show.
    """
    if relevant <= 0:
        return None
    tenths, rest = divmod(following * 1000, relevant)
    twice = rest * 2
    if twice > relevant or (twice == relevant and tenths % 2 == 1):
        tenths += 1
    return tenths / 10


def _counts(counts: Counts) -> dict[str, JsonValue]:
    return {
        "following": counts.following,
        "contradicting": counts.contradicting,
        "relevant": counts.relevant,
        "percent": percent(counts.following, counts.relevant),
    }


def _site(item: SiteResult) -> dict[str, JsonValue]:
    site = item.site
    return {
        "file": site.file,
        "line": site.line,
        "col": site.col,
        "option": site.option,
        "follows": item.follows,
        "recent": item.recent,
    }


def _side(side: SideResult | None) -> dict[str, JsonValue] | None:
    if side is None:
        return None
    return {
        "verdict": str(side.verdict.value),
        "sites": [_site(item) for item in side.sites],
        "overall": _counts(side.overall),
        "recent": _counts(side.recent) if side.recent is not None else None,
        "recent_unavailable_reason": side.recent_unavailable_reason,
    }


def _causing(item: CausingFile) -> dict[str, JsonValue]:
    return {
        "file": item.file,
        "following_delta": item.following_delta,
        "contradicting_delta": item.contradicting_delta,
    }


def _alternative(item: Alternative) -> dict[str, JsonValue]:
    return {"option": item.option, "sites": item.sites}


def _suggestion(suggestion: Suggestion) -> dict[str, JsonValue]:
    """I-9 ``suggestion``. ``new_text`` stays ``null`` when C10 gave none (D-PM-38)."""
    return {
        "kind": suggestion.kind,
        "named_option": suggestion.named_option,
        "alternatives": [_alternative(item) for item in suggestion.alternatives],
        "new_text": suggestion.new_text,
    }


def _rule(item: RuleResult) -> dict[str, JsonValue]:
    rule = display_rule(item)
    return {
        "id": item.rule_id,
        "file": rule.file,
        "line": rule.line,
        "also_at": list(rule.also_at),
        "text": rule.text,
        "checker": rule.checker,
        "experimental": rule.checker in EXPERIMENTAL_CHECKERS,
        "ignored": rule.ignored,
        "disabled": rule.disabled,
        "conflict_with": list(item.conflict_with),
        "conflict_with_total": item.conflict_with_total,
        "conflict_incomplete": item.conflict_incomplete,
        "base": _side(item.base),
        "head": _side(item.head),
        "case": item.case,
        "causing_files": [_causing(entry) for entry in item.causing_files],
        "suggestion": _suggestion(item.suggestion),
    }


def _window(window: Window) -> dict[str, JsonValue]:
    return {
        "end": window.end.isoformat() if window.end is not None else None,
        "days": window.days,
        "available": window.available,
        "unavailable_reason": window.unavailable_reason,
    }


def _skipped(item: SkippedFile) -> dict[str, JsonValue]:
    return {"path": item.path, "reason": item.reason}


def _conflict(item: Conflict) -> dict[str, JsonValue]:
    return {"rules": list(item.rules), "checker": item.checker}


def _internal_error(error: InternalError) -> dict[str, JsonValue]:
    """Only the I-14 validated component and fixed message are written (CR1 S1 on #84)."""
    component, message = _safe(error)
    return {"component": component, "message": message}


def report_object(result: Result) -> dict[str, JsonValue]:
    """The I-9 object for ``result``, before serialization.

    Sort orders (I-9): ``rules`` by (file, line), ``sites`` by (file, line, col, option) and
    ``skipped_files`` by path. ``rules`` and ``sites`` arrive sorted (I-13 invariants);
    instruction files and skipped files are sorted here so file-system order never leaks
    into the bytes. ``analyzer_python`` is never written (DESIGN §10 B3).
    """
    counts = result.counts
    return {
        "schema": REPORT_SCHEMA,
        "tool_version": __version__,
        "mode": result.mode,
        "base": result.base_sha,
        "head": result.head_sha,
        "window": _window(result.window),
        "policy": {"source": result.policy.source, "notes": list(result.policy.notes)},
        "instruction_files": sorted(item.path for item in result.instruction_files),
        "skipped_files": [
            _skipped(item)
            for item in sorted(result.skipped_files, key=lambda s: (s.path, s.reason))
        ],
        "rules": [_rule(item) for item in result.rule_results],
        "conflicts": [_conflict(item) for item in result.conflicts],
        "internal_errors": [_internal_error(error) for error in result.internal_errors],
        "counts": {
            "stale": counts.stale,
            "new_stale": counts.new_stale,
            "rules_changed": counts.rules_changed,
            "rules_unchanged": counts.rules_unchanged,
            "conflicts_unlisted": counts.conflicts_unlisted,
            "conflicts_incomplete": counts.conflicts_incomplete,
        },
    }


def render_json(result: Result) -> str:
    """The I-9 report text for ``--format json`` and ``report-path``."""
    return dump_json(report_object(result))
