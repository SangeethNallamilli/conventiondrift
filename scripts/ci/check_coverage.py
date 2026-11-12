#!/usr/bin/env python3
"""Enforce GATES.md coverage thresholds on a coverage.py JSON report.

Overall: >=90% lines and >=85% branches (exclude _vendor/).
Critical modules, when present: >=95% branches (GATES.md #3, DESIGN §12 A-1/A-2).
Thresholds are never lowered.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

LINE_MIN = 90.0
BRANCH_MIN = 85.0
CRITICAL_BRANCH_MIN = 95.0

# DESIGN §12 / TEST-STRATEGY.md. checkers/<id>/match.py is added when those paths exist.
CRITICAL_SUFFIXES = (
    "/rules/extract.py",
    "/rules/mapping.py",
    "/verdicts.py",
    "/compare.py",
    "/render/escape.py",
)


def pct(covered: int, total: int) -> float:
    if total == 0:
        return 100.0
    return 100.0 * covered / total


def is_critical(filename: str) -> bool:
    path = filename.replace("\\", "/")
    if path.endswith(CRITICAL_SUFFIXES):
        return True
    if "/checkers/" in path and path.endswith("/match.py"):
        return True
    return False


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_coverage.py coverage.json", file=sys.stderr)
        return 2
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    totals = report["totals"]
    line = pct(totals["covered_lines"], totals["num_statements"])
    branch = pct(totals["covered_branches"], totals["num_branches"])
    print(f"overall lines: {line:.2f}% ({totals['covered_lines']}/{totals['num_statements']})")
    print(
        f"overall branches: {branch:.2f}% ({totals['covered_branches']}/{totals['num_branches']})"
    )

    errors: list[str] = []
    if line < LINE_MIN:
        errors.append(f"line coverage {line:.2f}% is below the {LINE_MIN:.0f}% gate")
    if branch < BRANCH_MIN:
        errors.append(f"branch coverage {branch:.2f}% is below the {BRANCH_MIN:.0f}% gate")

    critical_seen = 0
    for filename, data in sorted(report.get("files", {}).items()):
        if not is_critical(filename):
            continue
        critical_seen += 1
        summary = data["summary"]
        cbranch = pct(summary["covered_branches"], summary["num_branches"])
        print(f"critical {filename}: branch {cbranch:.2f}%")
        if cbranch < CRITICAL_BRANCH_MIN:
            errors.append(
                f"{filename}: branch {cbranch:.2f}% < {CRITICAL_BRANCH_MIN:.0f}% critical gate"
            )

    if critical_seen == 0:
        print("no critical modules present yet; skipping the 95% branch gate")

    if errors:
        print("coverage gate failed:", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print("ok: coverage gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
