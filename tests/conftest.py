"""Shared pytest configuration for the whole test tree."""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    # D-TL-59b: wall-clock time-budget tests. CI runs `-m timing` without coverage and
    # `-m "not timing"` under coverage; tests/unit/test_timing_marker_guard.py keeps the
    # mark on every such test.
    config.addinivalue_line(
        "markers",
        "timing: checks how fast code runs against a wall-clock budget; run without coverage",
    )
