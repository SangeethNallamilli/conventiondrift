"""DESIGN A-3 #7 near-cap case on B10k (D-TL-72, D-TL-73): scan-mode discovery stage.

A-3 #7: "a repo near every cap finishes inside the B10k stage budget". DESIGN §5 gives
discovery 4 s on B10k; D-TL-71 (3) keeps that as an absolute limit for A-3 #7. The
seeded B10k checkout (10,000 tracked `.py` files) gets the `gen_bench_repo --near-cap`
overlay: 10,000 untracked `.py` files six deep, a deep tree at depth 62 with paths of
about 12k characters, and 2,000 patterns (the A-3 #4 cap) that the rule index can't
narrow, in `.git/info/exclude` and `.gitignore`. Sets: TE `[q]N`, CR `[x]*N*q/`, SR
seven `**` segments, CR's deep-path set (2,000 x `[x]/[y]*`), and (D-TL-74) 90 x
`[x]*N*q`, a mid-size set that stays under the per-path allowance and so is matched on
every path. None of them matches any file, so every file must still be found.

Only the stage time and the found files are asserted, never the match budget's
internals (D-TL-73). The stock-Python case puts GitHub's `Python.gitignore` on a tree
near the 500,000-entry walk cap and asserts no note at all and that the files the
template ignores stay out; its time is recorded, not asserted (it is not a B10k figure).

Runs only in the benchmark job (CD_BENCH=1), like test_benchmarks.py. The CLI has no
scan mode yet, so the stage is timed in process (`benchlib.time_scan_discovery`).
"""

from __future__ import annotations

import os
import statistics
from collections.abc import Iterator
from pathlib import Path

import pytest

from bench import benchlib

pytestmark = pytest.mark.skipif(
    os.environ.get("CD_BENCH") != "1", reason="benchmark job only (set CD_BENCH=1)"
)


@pytest.fixture(scope="module")
def b10k(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, dict, frozenset[str]]]:
    reason = benchlib.tool_unavailable_reason()
    if reason:
        if os.environ.get("CD_BENCH_REQUIRE") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    repo, manifest = benchlib.provision("b10k", tmp_path_factory.mktemp("near_cap"))
    assert manifest["composition_errors"] == [], manifest["composition_errors"]
    exclude = repo / ".git" / "info" / "exclude"
    saved = exclude.read_bytes() if exclude.is_file() else None
    gen = benchlib.load_generator()
    try:
        yield repo, manifest, benchlib.tracked_py_paths(repo)
    finally:  # a CD_BENCH_REPOS_DIR checkout is shared with the CLI benchmarks
        gen.clear_near_cap(repo)
        if saved is not None:
            exclude.write_bytes(saved)


def _overlay(repo: Path, pattern_set: str) -> dict:
    return benchlib.load_generator().write_near_cap(repo, pattern_set)


@pytest.mark.timing
@pytest.mark.parametrize("pattern_set", benchlib.NEAR_CAP_SETS)
def test_a3_7_b10k_near_cap_discovery_stage_under_4s(
    pattern_set: str, b10k: tuple[Path, dict, frozenset[str]]
) -> None:
    repo, manifest, tracked = b10k
    info = _overlay(repo, pattern_set)
    assert info["patterns"] == (90 if pattern_set == "cr-k90" else 2_000)
    assert 60 <= info["deep_depth"] <= 64 and 11_000 <= info["deep_max_path"] <= 13_000, info
    expected = len(tracked) + info["untracked_py"]
    runs = [benchlib.time_scan_discovery(repo) for _ in range(benchlib.RUNS)]
    benchlib.write_near_cap_results(pattern_set, manifest, info, runs)
    problems = []
    for n, run in enumerate(runs):
        if run.seconds >= benchlib.NEAR_CAP_DISCOVER_S:
            problems.append(f"run {n}: discovery {run.seconds:.2f} s >= 4 s (DESIGN §5, A-3 #7)")
        if run.stats["gitignore_patterns_loaded"] != info["patterns"]:
            problems.append(f"run {n}: {run.stats['gitignore_patterns_loaded']} patterns loaded")
        if run.walk_limit_skips:
            problems.append(f"run {n}: {run.walk_limit_skips} walk-limit skips below the caps")
        if len(run.py_paths) != expected or not tracked <= run.py_paths:
            problems.append(f"run {n}: {len(run.py_paths)} .py files found, expected {expected}")
    median = statistics.median(r.seconds for r in runs)
    assert not problems, f"{pattern_set} (median {median:.2f} s):\n" + "\n".join(problems)


@pytest.mark.timing
def test_a3_7_stock_python_gitignore_near_walk_cap_has_no_note(
    b10k: tuple[Path, dict, frozenset[str]],
) -> None:
    repo, manifest, tracked = b10k
    info = _overlay(repo, benchlib.NEAR_CAP_PYTHON)
    run = benchlib.time_scan_discovery(repo)
    benchlib.write_near_cap_results(benchlib.NEAR_CAP_PYTHON, manifest, info, [run])
    entries = run.stats["scan_walk_entries"]
    assert 450_000 <= entries < 500_000, f"{entries} walk entries: not near the cap"
    assert run.walk_limit_skips == 0
    assert run.notes == (), run.notes  # D-TL-73: no budget note below the 500k walk cap
    leaked = sorted(set(info["ignored_py"]) & run.py_paths)
    assert not leaked, f"{len(leaked)} .py files Python.gitignore ignores were found: {leaked[:3]}"
    assert len(run.py_paths) == len(tracked) + info["untracked_py"], len(run.py_paths)
    assert run.stats["gitignore_patterns_loaded"] == info["patterns"]
