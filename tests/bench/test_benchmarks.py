"""Benchmark driver for AC-N2.1, AC-N2.2, AC-N2.3 and AC-E.12 timing (T-052).

Method (TEST-STRATEGY.md §4): 5 runs of the CLI compare on the seeded B10k/B500
repos; every run must be under the hard limit (no median for the limit); every
run's `--stats-out` (I-12) must match the pinned schema and stay within 125% of
each DESIGN §5 stage budget; AC-N2.3 compares the median of the 5 PR runs with
the median of the last 5 main runs.

Runs only in the benchmark job: set CD_BENCH=1. CD_BENCH_REQUIRE=1 turns
"tool not available yet" skips into failures. Optional: CD_BENCH_REPOS_DIR
(pre-generated repos), CD_BENCH_RESULTS (results dir for T-039),
CD_BENCH_BASELINE (JSON {"b10k": [5 main medians], "b500": [...]} for N2.3).

The local CLI wall time stands in for the Action step; the real AC-N2.1/N2.2
evidence is the sandbox run on fresh ubuntu-latest jobs (T-040).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from bench import benchlib

pytestmark = pytest.mark.skipif(
    os.environ.get("CD_BENCH") != "1", reason="benchmark job only (set CD_BENCH=1)"
)


def _skip_or_fail(reason: str) -> None:
    if os.environ.get("CD_BENCH_REQUIRE") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


_CACHE: dict[tuple[str, str], tuple[dict, list[benchlib.Run]]] = {}


def _runs(profile: str, head_ref: str, tmp_root: Path) -> tuple[dict, list[benchlib.Run]]:
    key = (profile, head_ref)
    if key in _CACHE:
        return _CACHE[key]
    reason = benchlib.tool_unavailable_reason()
    if reason:
        _skip_or_fail(reason)
    reason = benchlib.probe_cli(tmp_root)
    if reason:
        _skip_or_fail(reason)
    repo, manifest = benchlib.provision(profile, tmp_root)
    assert manifest["composition_errors"] == [], manifest["composition_errors"]
    runs = []
    for n in range(benchlib.RUNS):
        run = benchlib.run_check(repo, head_ref, tmp_root / f"out-{profile}-{head_ref}", n)
        runs.append(run)
    benchlib.write_results(profile, head_ref, manifest, runs)
    _CACHE[key] = (manifest, runs)
    return manifest, runs


@pytest.fixture(scope="module")
def bench_tmp(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("bench")


def _assert_runs(profile: str, head_ref: str, manifest: dict, runs: list[benchlib.Run]) -> None:
    limit = benchlib.HARD_LIMIT_S[profile]
    problems = []
    for n, run in enumerate(runs):
        if run.exit_code != 0:
            problems.append(f"run {n}: exit {run.exit_code}: {run.stderr.strip()[:200]}")
            continue
        if run.wall_s >= limit:
            problems.append(f"run {n}: {run.wall_s:.2f}s >= {limit}s hard limit")
        try:
            benchlib.validate_stats(run.stats)
        except benchlib.StatsSchemaError as exc:
            problems.append(f"run {n}: I-12 stats: {exc}")
            continue
        problems += [f"run {n}: {v}" for v in benchlib.stage_budget_violations(run.stats, profile)]
        expected_changed = manifest["composition"]["prs"][head_ref]["files_changed"]
        if run.stats["counts"]["changed_files"] != expected_changed:
            problems.append(
                f"run {n}: counts.changed_files "
                f"{run.stats['counts']['changed_files']} != {expected_changed}"
            )
    assert not problems, "\n".join(problems)


def test_ac_n2_1_b10k_under_60s(bench_tmp: Path) -> None:
    manifest, runs = _runs("b10k", "bench-pr", bench_tmp)
    _assert_runs("b10k", "bench-pr", manifest, runs)


def test_ac_n2_2_b500_under_15s(bench_tmp: Path) -> None:
    manifest, runs = _runs("b500", "bench-pr", bench_tmp)
    _assert_runs("b500", "bench-pr", manifest, runs)


def test_ac_e_12_large_pr_under_60s(bench_tmp: Path) -> None:
    manifest, runs = _runs("b10k", "bench-pr-5000", bench_tmp)
    _assert_runs("b10k", "bench-pr-5000", manifest, runs)


@pytest.mark.parametrize("profile", ["b10k", "b500"])
def test_ac_n2_3_regression_gate(profile: str, bench_tmp: Path) -> None:
    baseline_path = os.environ.get("CD_BENCH_BASELINE")
    if not baseline_path:
        _skip_or_fail("no main-branch baseline given (CD_BENCH_BASELINE)")
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    _, runs = _runs(profile, "bench-pr", bench_tmp)
    ok, why = benchlib.regression_verdict([r.wall_s for r in runs], baseline[profile])
    assert ok, why
