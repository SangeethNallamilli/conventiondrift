#!/usr/bin/env python3
"""Run mutmut and enforce GATES.md mutation thresholds.

Overall: killed / (killed + survived) >= 80%.
Critical modules, when present: >= 90% (GATES.md #2 and #3, TEST-STRATEGY.md §2,
D-TL-17). Thresholds are never lowered. Equivalent mutants are excluded only
with a logged justification (none are excluded here).

mutmut is a new dependency and this job needs Security Review.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OVERALL_MIN = 80.0
CRITICAL_MIN = 90.0
CICD_STATS = REPO / "mutants" / "mutmut-cicd-stats.json"

# Same critical paths as scripts/ci/check_coverage.py (DESIGN §12 / TEST-STRATEGY).
CRITICAL_SUFFIXES = (
    "/rules/extract.py",
    "/rules/mapping.py",
    "/verdicts.py",
    "/compare.py",
    "/render/escape.py",
)


def is_critical(filename: str) -> bool:
    path = filename.replace("\\", "/")
    if path.endswith(CRITICAL_SUFFIXES):
        return True
    if "/checkers/" in path and path.endswith("/match.py"):
        return True
    return False


def score(killed: int, survived: int) -> float:
    denom = killed + survived
    if denom == 0:
        return 100.0
    return 100.0 * killed / denom


def main() -> int:
    print("running mutmut (needs SR review: new dependency mutmut==3.8.1)", file=sys.stderr)
    subprocess.run(["mutmut", "run"], cwd=REPO, check=True)
    subprocess.run(["mutmut", "export-cicd-stats"], cwd=REPO, check=True)
    if not CICD_STATS.is_file():
        print(f"missing {CICD_STATS}", file=sys.stderr)
        return 1
    data = json.loads(CICD_STATS.read_text(encoding="utf-8"))
    killed = int(data["killed"])
    survived = int(data["survived"])
    overall = score(killed, survived)
    print(
        f"overall mutation: {overall:.2f}% "
        f"(killed={killed}, survived={survived}, total={data.get('total')})"
    )
    errors: list[str] = []
    if overall < OVERALL_MIN:
        errors.append(f"overall mutation {overall:.2f}% is below the {OVERALL_MIN:.0f}% gate")

    # Per-file stats from mutmut meta, for the critical-module gate when those files exist.
    critical_seen = 0
    meta_root = REPO / "mutants"
    if meta_root.is_dir():
        # Lazy import of mutmut internals only to read per-file results already produced.
        try:
            from mutmut.mutation.data import SourceFileMutationData
            from mutmut.stats import collect_stat
            from mutmut.utils.file_utils import walk_mutatable_files
        except ImportError:
            SourceFileMutationData = None  # type: ignore[assignment]
        else:
            for path in walk_mutatable_files():
                name = str(path)
                if not is_critical(name):
                    continue
                meta_path = meta_root / (name + ".meta")
                if not meta_path.exists():
                    continue
                m = SourceFileMutationData(path=path)
                m.load()
                if not m.exit_code_by_key:
                    continue
                stat = collect_stat(m)
                critical_seen += 1
                cscore = score(stat.killed, stat.survived)
                print(
                    f"critical {name}: {cscore:.2f}%"
                    f" (killed={stat.killed}, survived={stat.survived})"
                )
                if cscore < CRITICAL_MIN:
                    errors.append(
                        f"{name}: mutation {cscore:.2f}% < {CRITICAL_MIN:.0f}% critical gate"
                    )

    if critical_seen == 0:
        print("no critical modules present yet; skipping the 90% mutation gate")

    if errors:
        print("mutation gate failed:", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print("ok: mutation gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
