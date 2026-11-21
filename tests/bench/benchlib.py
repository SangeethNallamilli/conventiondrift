"""Shared benchmark helpers (T-052): repo provisioning, I-12 stats checks, N2.3 statistic.

Method: TEST-STRATEGY.md §4. Budgets: DESIGN.md §5. Stats schema: INTERFACES.md I-12.
"""

from __future__ import annotations

import importlib.util
import json
import os
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "tools" / "gen_bench_repo.py"
BENCH_SEED = 20261112  # fixed; recorded with every result (TEST-STRATEGY §4)
RUNS = 5  # TEST-STRATEGY §4: 5 runs, every one under the hard limit
STAGE_TOLERANCE = 1.25  # DESIGN §5: fail if any stage exceeds 125% of its budget
REGRESSION_LIMIT = 1.20  # AC-N2.3: more than 20% slower than main fails

# I-12: names and order are fixed and map one-to-one to the DESIGN §5 rows.
STAGES = ("startup", "discover", "head-analyze", "base-analyze", "history", "report")
# INTERFACES I-12: every counter is always present.
SCAN_COUNT_KEYS = frozenset(
    {
        "scan_all_recent_line_limit",
        "scan_all_recent_diff_budget",
        "scan_diff_work",
        "scan_walk_entries",
        "scan_walk_skipped",
        "gitignore_patterns_loaded",
        "gitignore_patterns_skipped",
    }
)
COUNT_KEYS = (
    frozenset({"files_parsed", "ast_nodes", "git_calls", "changed_files", "workers"})
    | SCAN_COUNT_KEYS
)
STAGE_BUDGET_S = {  # DESIGN §5 table
    "b10k": {
        "startup": 2,
        "discover": 4,
        "head-analyze": 25,
        "base-analyze": 5,
        "history": 6,
        "report": 3,
    },
    "b500": {
        "startup": 1,
        "discover": 1,
        "head-analyze": 4,
        "base-analyze": 1,
        "history": 2,
        "report": 2,
    },
}
TOTAL_BUDGET_S = {"b10k": 45, "b500": 11}  # DESIGN §5 (informational)
HARD_LIMIT_S = {"b10k": 60.0, "b500": 15.0}  # AC-N2.1, AC-N2.2 (and AC-E.12 for b10k)


class StatsSchemaError(AssertionError):
    pass


def validate_stats(doc: object, *, scan_mode: bool = False) -> dict:
    """Strict I-12 check. A renamed, missing, extra or reordered stage is a schema break."""
    if not isinstance(doc, dict):
        raise StatsSchemaError("stats file is not a JSON object")
    if set(doc) != {"schema", "stages", "counts"}:
        raise StatsSchemaError(f"top-level keys {sorted(doc)}")
    if doc["schema"] != "conventiondrift-stats/1":
        raise StatsSchemaError(f"schema {doc['schema']!r}")
    stages = doc["stages"]
    if not isinstance(stages, list) or [
        s.get("name") for s in stages if isinstance(s, dict)
    ] != list(STAGES):
        raise StatsSchemaError(f"stages must be exactly {STAGES} in order")
    for s in stages:
        if set(s) != {"name", "seconds"}:
            raise StatsSchemaError(f"stage keys {sorted(s)}")
        sec = s["seconds"]
        if isinstance(sec, bool) or not isinstance(sec, (int, float)) or sec < 0:
            raise StatsSchemaError(f"stage {s['name']}: seconds {sec!r}")
        if round(float(sec), 3) != float(sec):
            raise StatsSchemaError(f"stage {s['name']}: seconds not rounded to 3 decimals")
    counts = doc["counts"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise StatsSchemaError(
            f"counts keys {sorted(counts) if isinstance(counts, dict) else counts}"
        )
    for k, v in counts.items():
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise StatsSchemaError(f"count {k}={v!r}")
    if not scan_mode:
        nonzero = sorted(k for k in SCAN_COUNT_KEYS if counts[k] != 0)
        if nonzero:
            raise StatsSchemaError(
                f"scan/gitignore counters must be 0 outside scan mode: {nonzero}"
            )
    return doc


def stage_seconds(doc: dict) -> dict[str, float]:
    return {s["name"]: float(s["seconds"]) for s in doc["stages"]}


def stage_budget_violations(doc: dict, profile: str) -> list[str]:
    budget = STAGE_BUDGET_S[profile]
    return [
        f"{name}: {sec:.3f}s > {STAGE_TOLERANCE:.0%} of {budget[name]}s budget"
        for name, sec in stage_seconds(doc).items()
        if sec > budget[name] * STAGE_TOLERANCE
    ]


def regression_verdict(pr_runs: list[float], main_runs: list[float]) -> tuple[bool, str]:
    """AC-N2.3 statistic (TEST-STRATEGY §4): median of the PR runs vs median of the last
    main runs on the same runner label. Returns (ok, explanation)."""
    if len(pr_runs) < RUNS or len(main_runs) < RUNS:
        raise ValueError(
            f"need {RUNS} PR runs and {RUNS} main runs, got {len(pr_runs)} and {len(main_runs)}"
        )
    pr = statistics.median(pr_runs)
    base = statistics.median(main_runs[-RUNS:])
    ratio = pr / base if base > 0 else float("inf")
    ok = ratio <= REGRESSION_LIMIT
    return ok, f"PR median {pr:.3f}s vs main median {base:.3f}s: {ratio:.3f}x (limit 1.20x)"


# ---------------------------------------------------------------------- repo provisioning
def generator_sha256() -> str:
    import hashlib

    return hashlib.sha256(GENERATOR.read_bytes()).hexdigest()


def provision(profile: str, workdir: Path) -> tuple[Path, dict]:
    """Return (repo, manifest). Reuses CD_BENCH_REPOS_DIR/<profile> when its manifest has the
    same seed and generator hash; otherwise generates into `workdir`."""
    cache = os.environ.get("CD_BENCH_REPOS_DIR")
    if cache:
        repo = Path(cache) / profile
        man = repo.with_name(repo.name + ".manifest.json")
        if man.is_file():
            m = json.loads(man.read_text(encoding="utf-8"))
            if m.get("seed") == BENCH_SEED and m.get("script_sha256") == generator_sha256():
                return repo, m
    else:
        repo = workdir / profile
    subprocess.run(  # noqa: S603 - argv list, no shell
        [
            sys.executable,
            str(GENERATOR),
            "--profile",
            profile,
            "--seed",
            str(BENCH_SEED),
            "--out",
            str(repo),
        ],
        check=True,
    )
    man = repo.with_name(repo.name + ".manifest.json")
    return repo, json.loads(man.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------- tool availability
def tool_unavailable_reason() -> str | None:
    """Why the benchmark can't run yet, or None. Never guesses past the I-4 contract."""
    if importlib.util.find_spec("conventiondrift") is None:
        return "conventiondrift package is not importable yet"
    return None


@dataclass
class Run:
    wall_s: float
    exit_code: int
    stats: dict
    report: dict | None
    stderr: str


def run_check(repo: Path, head_ref: str, outdir: Path, n: int, fmt: str = "json") -> Run:
    """One CLI compare run: `check --base main --head <ref> --stats-out` (I-4, I-12)."""
    outdir.mkdir(parents=True, exist_ok=True)
    stats_path = outdir / f"stats-{n}.json"
    report_path = outdir / f"report-{n}.json"
    cmd = [
        sys.executable,
        "-m",
        "conventiondrift",
        "check",
        "--repo",
        str(repo),
        "--base",
        "main",
        "--head",
        head_ref,
        "--format",
        fmt,
        "--output",
        str(report_path),
        "--stats-out",
        str(stats_path),
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "GIT_"))}
    t0 = time.monotonic()
    proc = subprocess.run(  # noqa: S603 - argv list, no shell
        cmd,
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    wall = time.monotonic() - t0
    stats = json.loads(stats_path.read_text(encoding="utf-8")) if stats_path.is_file() else {}
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else None
    return Run(wall, proc.returncode, stats, report, proc.stderr)


SKELETON_MARKER = "not implemented yet"  # T-001 cli.py stderr; T-031/T-033 replace this


def not_implemented_reason(run: Run) -> str | None:
    """Return a reason only for the T-001 skeleton (`check`/`--stats-out` not built yet).

    The skeleton exits 2, writes no stats, and prints `not implemented yet` on stderr.
    A later regression that also exits 2 without stats (for example a usage error) is
    *not* treated as the skeleton, so AC-E.12 fails instead of being skipped or xfails.
    Under CD_BENCH_REQUIRE=1 (the CI benchmark job) a skeleton result is a failure.
    """
    if run.exit_code == 2 and not run.stats and SKELETON_MARKER in run.stderr:
        return (
            "`conventiondrift check --stats-out` is not implemented yet (T-031/T-033); "
            f"stderr: {run.stderr.strip()[:200]}"
        )
    return None


def probe_cli(workdir: Path) -> str | None:
    """Cheap check, before generating a large repo, that `check --stats-out` exists: a compare
    run on a one-commit repo. Returns a skip reason or None."""
    repo = workdir / "probe"
    repo.mkdir(parents=True, exist_ok=True)
    from fixtures.gitrepo import base_git_env

    env = base_git_env(workdir)
    env.update(
        {
            "GIT_AUTHOR_NAME": "p",
            "GIT_AUTHOR_EMAIL": "p@example.invalid",
            "GIT_COMMITTER_NAME": "p",
            "GIT_COMMITTER_EMAIL": "p@example.invalid",
            "GIT_AUTHOR_DATE": "@1780000000 +0000",
            "GIT_COMMITTER_DATE": "@1780000000 +0000",
        }
    )
    if not (repo / ".git").exists():
        from fixtures.gitrepo import init_with_branch

        def _git(*args: str) -> None:
            subprocess.run(  # noqa: S603 - argv list, no shell
                ["git", *args],  # noqa: S607 - git from PATH by design
                cwd=repo,
                env=env,
                check=True,
                capture_output=True,
            )

        init_with_branch(_git, "main")
        _git("commit", "-q", "--allow-empty", "-m", "p")
    return not_implemented_reason(run_check(repo, "main", workdir / "probe-out", 0))


def write_results(profile: str, head_ref: str, manifest: dict, runs: list[Run]) -> None:
    """Results for the T-039 regression job, with the seed and script hash (TEST-STRATEGY §4)."""
    dest = os.environ.get("CD_BENCH_RESULTS")
    if not dest:
        return
    Path(dest).mkdir(parents=True, exist_ok=True)
    payload = {
        "profile": profile,
        "head_ref": head_ref,
        "seed": manifest["seed"],
        "script_sha256": manifest["script_sha256"],
        "refs": manifest["composition"]["refs"],
        "wall_s": [round(r.wall_s, 3) for r in runs],
        "median_s": round(statistics.median(r.wall_s for r in runs), 3),
        "stages": [stage_seconds(r.stats) for r in runs if r.stats],
    }
    (Path(dest) / f"{profile}-{head_ref}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


# ------------------------------------------------------------- A-3 #7 near-cap discovery
# DESIGN A-3 #7: "a repo near every cap finishes inside the B10k stage budget"; DESIGN §5:
# discovery 4 s on B10k. D-TL-71 (3): the A-3 #7 limit is the absolute 4 s, not 125%.
# D-TL-73: only the stage time is asserted, never the match budget's internals.
NEAR_CAP_DISCOVER_S = 4.0
NEAR_CAP_SETS = ("te", "cr", "sr", "cr-deep")  # gen_bench_repo.NEAR_CAP_SETS
NEAR_CAP_PYTHON = "python"


def load_generator() -> Any:
    """tools/gen_bench_repo.py as a module (it is a script, not a package)."""
    spec = importlib.util.spec_from_file_location("gen_bench_repo", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("gen_bench_repo", module)
    spec.loader.exec_module(module)
    return module


@dataclass
class DiscoverRun:
    seconds: float  # the discovery stage: HEAD tree read, walk, .gitignore, file reads
    py_paths: frozenset[str]
    notes: tuple[str, ...]
    walk_limit_skips: int
    stats: dict[str, int]


def tracked_py_paths(repo: Path) -> frozenset[str]:
    """The `.py` files C4 finds in HEAD's tree (commit mode), not timed."""
    from conventiondrift.core import BasePhaseDone
    from conventiondrift.discover import discover_tree
    from conventiondrift.gitread import GitReader

    git = GitReader(repo)
    try:
        found = discover_tree(BasePhaseDone(base_config_known=True), git, git.resolve("HEAD"))
    finally:
        git.close()
    return frozenset(f.path for f in found.py_files)


def time_scan_discovery(repo: Path) -> DiscoverRun:
    """One scan-mode discovery stage on the checkout at `repo`, timed end to end.

    The CLI has no scan mode or `--stats-out` "discover" stage yet (T-031/T-033), so
    this times C3 + C4 in process: open the reader, resolve HEAD, `discover_worktree`.
    When the CLI reports the stage, this should read `stages.discover` instead."""
    from conventiondrift.core import BasePhaseDone
    from conventiondrift.discover.safefs import REASON_WALK_LIMIT
    from conventiondrift.discover.scan import discover_worktree
    from conventiondrift.gitread import GitReader

    started = time.perf_counter()
    git = GitReader(repo)
    try:
        head = git.resolve("HEAD")
        found = discover_worktree(BasePhaseDone(base_config_known=True), repo, git, head)
    finally:
        git.close()
    seconds = time.perf_counter() - started
    return DiscoverRun(
        seconds=seconds,
        py_paths=frozenset(f.path for f in found.discovery.py_files),
        notes=tuple(found.discovery.notes),
        walk_limit_skips=sum(1 for s in found.discovery.skipped if s.reason == REASON_WALK_LIMIT),
        stats=dict(found.stats),
    )


def write_near_cap_results(pattern_set: str, manifest: dict, info: dict, runs: list) -> None:
    """Near-cap timings next to the CLI results (CD_BENCH_RESULTS), with seed and hash."""
    dest = os.environ.get("CD_BENCH_RESULTS")
    if not dest:
        return
    Path(dest).mkdir(parents=True, exist_ok=True)
    payload = {
        "profile": "b10k",
        "case": f"a3-7-near-cap-{pattern_set}",
        "seed": manifest["seed"],
        "script_sha256": manifest["script_sha256"],
        "overlay": {k: v for k, v in info.items() if k != "ignored_py"},
        "discover_s": [round(r.seconds, 3) for r in runs],
        "median_s": round(statistics.median(r.seconds for r in runs), 3),
        "budget_s": NEAR_CAP_DISCOVER_S,
        "walk_entries": [r.stats.get("scan_walk_entries") for r in runs],
    }
    (Path(dest) / f"b10k-a3-7-near-cap-{pattern_set}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
