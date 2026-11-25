"""Frozen C11 render inputs built by T-028 (D-TL-85, D-TL-86). ``Result`` is unchanged."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = ["RenderContext", "WindowAnchor"]


@dataclass(frozen=True, slots=True)
class WindowAnchor:
    """The recent-window display fields, or absent in head-only mode (D-TL-85)."""

    sha: str
    iso: str
    """ISO 8601 timestamp with a UTC offset, already formatted by T-028."""
    days: int


@dataclass(frozen=True, slots=True, kw_only=True)
class RenderContext:
    """What T-028 decided about the run; C11 only words it (D-TL-85, D-TL-86)."""

    mode: Literal["compare", "head-only", "scan"]
    analyzed_sha: str
    head_kind: Literal["pr_head", "checkout"] | None
    """Set only in head-only mode; otherwise ``None``."""
    read_only_reason: Literal["fork", "dependabot"] | None
    analyzer_python: str
    policy_source: Literal["base", "head"]
    window_anchor: WindowAnchor | None
    """``None`` in head-only mode, and when the window is unavailable."""
    python_files_found: bool
    """From C4 discovery; C11 does not infer this (D-TL-86 #3)."""
