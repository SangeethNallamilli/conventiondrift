"""Unit tests for the benchmark checks themselves (run in the fast stage, no tool needed)."""

from __future__ import annotations

import copy
import subprocess
from pathlib import Path

import pytest

from bench import benchlib


def _stats(**overrides: float) -> dict:
    stages = [{"name": n, "seconds": overrides.get(n, 0.5)} for n in benchlib.STAGES]
    return {
        "schema": "conventiondrift-stats/1",
        "stages": stages,
        "counts": {
            "files_parsed": 10,
            "ast_nodes": 100,
            "git_calls": 3,
            "changed_files": 50,
            "workers": 4,
            **dict.fromkeys(sorted(benchlib.SCAN_COUNT_KEYS), 0),
        },
    }


def test_valid_stats_accepted() -> None:
    benchlib.validate_stats(_stats())


@pytest.mark.parametrize(
    "mutate",
    [
        "wrong_schema",
        "missing_stage",
        "renamed_stage",
        "reordered",
        "extra_stage",
        "extra_top_key",
        "negative_seconds",
        "unrounded",
        "missing_count",
        "float_count",
        "bool_seconds",
    ],
)
def test_stats_schema_breaks_rejected(mutate: str) -> None:
    d = copy.deepcopy(_stats())
    if mutate == "wrong_schema":
        d["schema"] = "conventiondrift-stats/2"
    elif mutate == "missing_stage":
        d["stages"].pop(3)
    elif mutate == "renamed_stage":
        d["stages"][1]["name"] = "discovery"
    elif mutate == "reordered":
        d["stages"][0], d["stages"][1] = d["stages"][1], d["stages"][0]
    elif mutate == "extra_stage":
        d["stages"].append({"name": "upload", "seconds": 0.0})
    elif mutate == "extra_top_key":
        d["timestamp"] = "2026-11-12"
    elif mutate == "negative_seconds":
        d["stages"][0]["seconds"] = -0.1
    elif mutate == "unrounded":
        d["stages"][0]["seconds"] = 0.12345
    elif mutate == "missing_count":
        del d["counts"]["workers"]
    elif mutate == "float_count":
        d["counts"]["git_calls"] = 3.0
    elif mutate == "bool_seconds":
        d["stages"][0]["seconds"] = True
    with pytest.raises(benchlib.StatsSchemaError):
        benchlib.validate_stats(d)


def test_stage_budget_125_percent_boundary() -> None:
    # head-analyze budget on B10k is 25 s, so 31.25 s is the limit (DESIGN §5).
    assert benchlib.stage_budget_violations(_stats(**{"head-analyze": 31.25}), "b10k") == []
    v = benchlib.stage_budget_violations(_stats(**{"head-analyze": 31.251}), "b10k")
    assert len(v) == 1 and v[0].startswith("head-analyze")
    # B500 startup budget 1 s -> 1.25 s.
    assert benchlib.stage_budget_violations(_stats(startup=1.251), "b500")


def test_budget_tables_match_design_totals() -> None:
    for profile, budget in benchlib.STAGE_BUDGET_S.items():
        assert tuple(budget) == benchlib.STAGES
        assert sum(budget.values()) == benchlib.TOTAL_BUDGET_S[profile]


def test_regression_statistic_median_vs_median() -> None:
    main = [10.0, 10.0, 10.0, 10.0, 10.0]
    assert benchlib.regression_verdict([12.0] * 5, main)[0]  # exactly 20% slower passes
    assert not benchlib.regression_verdict([12.01] * 5, main)[0]
    # One slow outlier does not fail the median.
    assert benchlib.regression_verdict([10, 10, 10, 30, 30], main)[0]
    # Only the last 5 main runs count.
    history = [100.0] * 5 + main  # median of all 10 would be 55 s; of the last 5, 10 s
    assert not benchlib.regression_verdict([12.5] * 5, history)[0]
    with pytest.raises(ValueError):
        benchlib.regression_verdict([1.0] * 4, main)


def test_counts_has_all_twelve_i12_keys() -> None:
    assert len(benchlib.COUNT_KEYS) == 12
    doc = _stats()
    del doc["counts"]["gitignore_patterns_skipped"]
    with pytest.raises(benchlib.StatsSchemaError, match="counts keys"):
        benchlib.validate_stats(doc)


@pytest.mark.parametrize("key", sorted(benchlib.SCAN_COUNT_KEYS))
def test_scan_counters_must_be_zero_in_compare_mode(key: str) -> None:
    doc = _stats()
    doc["counts"][key] = 1
    with pytest.raises(benchlib.StatsSchemaError, match="outside scan mode"):
        benchlib.validate_stats(doc)
    benchlib.validate_stats(doc, scan_mode=True)


def test_not_implemented_reason_requires_skeleton_marker() -> None:
    """Only the T-001 skeleton is an xfail/skip reason; a plain exit 2 is a failure."""
    skeleton = benchlib.Run(
        0.0, 2, {}, None, "conventiondrift: not implemented yet (package skeleton)\n"
    )
    reason = benchlib.not_implemented_reason(skeleton)
    assert reason is not None and "T-031/T-033" in reason

    regression = benchlib.Run(0.0, 2, {}, None, "conventiondrift: error: unknown flag\n")
    assert benchlib.not_implemented_reason(regression) is None

    # Stats were written: not the skeleton, even if stderr mentions the marker.
    with_stats = benchlib.Run(
        0.0, 2, {"schema": "conventiondrift-stats/1"}, None, "not implemented yet"
    )
    assert benchlib.not_implemented_reason(with_stats) is None

    success = benchlib.Run(0.1, 0, {"schema": "conventiondrift-stats/1"}, {}, "")
    assert benchlib.not_implemented_reason(success) is None


def test_probe_cli_init_without_dash_b_for_old_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git < 2.28 has no `git init -b`; probe_cli uses the same symbolic-ref fallback."""
    from fixtures import gitrepo

    monkeypatch.setattr(gitrepo, "git_version", lambda: (2, 27, 0))
    calls: list[tuple[str, ...]] = []
    real = gitrepo.init_with_branch

    def wrapped(run, default_branch="main", *, version=None):  # type: ignore[no-untyped-def]
        def spy(*args: str) -> object:
            calls.append(args)
            return run(*args)

        return real(spy, default_branch, version=version)

    monkeypatch.setattr(gitrepo, "init_with_branch", wrapped)
    reason = benchlib.probe_cli(tmp_path)
    assert reason is not None and "not implemented yet" in reason
    repo = tmp_path / "probe"
    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],  # noqa: S607
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert branch == "main"
    assert ("init", "-q", ".") in calls
    assert not any(args[:2] == ("init", "-q") and "-b" in args for args in calls)
    assert any(args[:1] == ("symbolic-ref",) for args in calls)
