#!/usr/bin/env python3
"""Run the benchmark suite for the `bench` CI job (D-TL-78 #4, D-TL-80 #2, DESIGN §5).

Usage: python scripts/ci/run_bench.py WORKDIR [PYTEST_TARGET ...]

1. Runs pytest once over the targets (default: the A-3 #7 near-cap bench) with
   CD_BENCH=1 and CD_BENCH_REQUIRE=1, `-rs`, and a JUnit XML report.
2. Fails if no test ran, or if any test was skipped (D-TL-78 #4).
3. Re-run rule (D-TL-80 #2): a near-cap set is one parametrized case of
   `test_a3_7_b10k_near_cap_discovery_stage_within_125pct[<set>]`, with
   benchlib.RUNS timed runs against benchlib.NEAR_CAP_DISCOVER_S (5 s). When a set
   fails and its only problem is exactly one run over that limit, that set alone is
   run once more, and every run of the re-run must pass. Any other failure, a set
   with more than one run over, or a re-run that fails (a set that fails twice) fails
   the job. Errors are never re-run.

The limit and run count are the test's own; this script only reads the test's
failure lines and the results JSON it writes to CD_BENCH_RESULTS. Standard library
only. Never imported by src/ or tests/.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TARGETS = ("tests/bench/test_bench_near_cap.py",)
MARKERS = "timing and not network"  # -m replaces addopts' "not network", so restate it
SET_TEST = "test_a3_7_b10k_near_cap_discovery_stage_within_125pct"
SET_NAME_RE = re.compile(rf"^{SET_TEST}\[(?P<set>[A-Za-z0-9_-]+)\]$")
# The near-cap test's problem lines (tests/bench/test_bench_near_cap.py).
PROBLEM_RE = re.compile(r"^\s*run (?P<n>\d+): (?P<what>.*)$")
OVER_LIMIT_RE = re.compile(r"^discovery \d+(?:\.\d+)? s > \d+(?:\.\d+)? s ")


@dataclass
class Case:
    nodeid: str
    name: str
    outcome: str  # passed | failed | error | skipped
    message: str = ""


@dataclass
class Report:
    tests: int = 0
    cases: list[Case] = field(default_factory=list)

    def by_outcome(self, outcome: str) -> list[Case]:
        return [c for c in self.cases if c.outcome == outcome]


def parse_junit(path: Path) -> Report:
    root = ET.parse(path).getroot()  # noqa: S314 - our own pytest output, not untrusted XML
    report = Report()
    for case in root.iter("testcase"):
        name = case.get("name", "")
        classname = case.get("classname", "")
        module = classname.replace(".", "/") + ".py"
        nodeid = f"{module}::{name}"
        outcome, message = "passed", ""
        for tag in ("failure", "error", "skipped"):
            child = case.find(tag)
            if child is not None:
                outcome = {"failure": "failed"}.get(tag, tag)
                message = child.get("message", "") or (child.text or "")
                break
        report.cases.append(Case(nodeid, name, outcome, message))
    report.tests = len(report.cases)
    return report


def run_pytest(targets: list[str], junit: Path, results: Path, env: dict[str, str]) -> int:
    # Never let a stale report or results file from an earlier run be read as this run's.
    junit.unlink(missing_ok=True)
    shutil.rmtree(results, ignore_errors=True)
    results.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "pytest", *targets, "-m", MARKERS, "-rs", f"--junitxml={junit}"]
    run_env = {**env, "CD_BENCH_RESULTS": str(results)}
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, env=run_env, check=False).returncode


def runs_over_limit_in_results(results: Path, set_name: str) -> int | None:
    """How many runs the results JSON records over its own limit_s (None if no file)."""
    path = results / f"b10k-a3-7-near-cap-{set_name}.json"
    if not path.is_file():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    print(f"  {set_name}: discover_s={doc.get('discover_s')} limit_s={doc.get('limit_s')}")
    return sum(1 for s in doc.get("discover_s", []) if s > doc["limit_s"])


def rerun_reason(case: Case, results: Path) -> str | None:
    """Return why `case` may be re-run once under D-TL-80, or None if it may not."""
    m = SET_NAME_RE.match(case.name)
    if case.outcome != "failed" or not m:
        return None
    set_name = m.group("set")
    first, _, rest = case.message.partition("\n")
    if not first.startswith(f"AssertionError: {set_name} (median "):
        return None  # failed before the per-run checks (setup or overlay assert)
    problems = [p for p in (PROBLEM_RE.match(line) for line in rest.splitlines()) if p]
    over = [p for p in problems if OVER_LIMIT_RE.match(p.group("what"))]
    if len(problems) != 1 or len(over) != 1:
        return None  # more than one run over, or another kind of problem
    recorded = runs_over_limit_in_results(results, set_name)
    if recorded is not None and recorded > 1:
        return None
    return f"{set_name}: one run over the limit ({over[0].group(0).strip()})"


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    work = Path(argv[1]).resolve()
    targets = argv[2:] or list(DEFAULT_TARGETS)
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["CD_BENCH"] = "1"
    env["CD_BENCH_REQUIRE"] = "1"
    # Keep the generated B10k checkout so a re-run of one set reuses it.
    env.setdefault("CD_BENCH_REPOS_DIR", str(work / "repos"))

    junit = work / "junit-1.xml"
    results = work / "results-1"
    rc = run_pytest(targets, junit, results, env)
    if not junit.is_file():
        print("bench: pytest wrote no JUnit report", file=sys.stderr)
        return 1
    report = parse_junit(junit)
    failed: list[str] = []
    if report.tests == 0:
        failed.append("no bench tests ran (0 collected)")
    for c in report.by_outcome("skipped"):
        failed.append(f"skipped (D-TL-78 #4: any skip fails the job): {c.nodeid}: {c.message}")
    for c in report.by_outcome("error"):
        failed.append(f"error (not re-run): {c.nodeid}")
    # pytest's exit status must agree with the report: 0 with no failures or errors,
    # or 1 with at least one. Anything else (a session-hook error, a usage or internal
    # error) fails the job and is never re-run.
    bad = bool(report.by_outcome("failed") or report.by_outcome("error"))
    if rc not in (0, 1) or (rc == 0) == bad:
        failed.append(f"pytest exit status {rc} does not match the JUnit report (failures: {bad})")

    reruns: list[Case] = []
    for c in report.by_outcome("failed"):
        why = rerun_reason(c, results)
        if why is None:
            failed.append(f"failed (not eligible for a re-run): {c.nodeid}")
        else:
            print(f"bench: eligible for one re-run (D-TL-80): {why}", flush=True)
            reruns.append(c)

    rerun_count = 0
    if not failed:  # a skip or a hard failure already fails the job; don't spend the time
        for n, c in enumerate(reruns, start=1):
            rerun_count += 1
            print(f"bench: re-running once (D-TL-80): {c.nodeid}", flush=True)
            junit2 = work / f"junit-rerun-{n}.xml"
            results2 = work / f"results-rerun-{n}"
            rc2 = run_pytest([c.nodeid], junit2, results2, env)
            again = parse_junit(junit2) if junit2.is_file() else Report()
            if rc2 != 0 or again.tests != 1 or again.by_outcome("passed") != again.cases:
                outcomes = [x.outcome for x in again.cases] or ["no report"]
                failed.append(f"failed twice (D-TL-80): {c.nodeid} re-run: {outcomes}, exit {rc2}")
                m = SET_NAME_RE.match(c.name)
                if m:
                    runs_over_limit_in_results(results2, m.group("set"))
            else:
                print(f"bench: re-run passed: {c.nodeid}", flush=True)
    elif reruns:
        failed += [f"not re-run because the job already failed: {c.nodeid}" for c in reruns]

    passed = len(report.by_outcome("passed"))
    print(
        f"bench: {report.tests} collected, {passed} passed first time, "
        f"{rerun_count} re-run, {len(report.by_outcome('skipped'))} skipped"
    )
    if failed:
        print("bench: FAILED", file=sys.stderr)
        for line in failed:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("bench: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
