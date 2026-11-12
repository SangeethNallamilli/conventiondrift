"""AC-E.12 local part: 10,000-file repo, PR changing 5,000 Python files (T-052 test code).

The fixture is B10k's `bench-pr-5000` from tools/gen_bench_repo.py; its expected findings are
labeled by construction in the manifest (one case-1 finding on "Use requests for HTTP calls.":
base Contested on overall adherence alone, head 0% requests). The timing half is
tests/bench/test_benchmarks.py::test_ac_e_12_large_pr_under_60s.
"""

from __future__ import annotations

import pytest

from bench import benchlib

FINDING_CASES = {"made-stale-by-code", "stale-rule-added", "fixed"}  # cases 1-3 (I-9)


def test_ac_e_12_large_pr_expected_findings(tmp_path_factory: pytest.TempPathFactory) -> None:
    reason = benchlib.tool_unavailable_reason()
    if reason:
        pytest.skip(reason)
    work = tmp_path_factory.mktemp("e12")
    reason = benchlib.probe_cli(work)
    if reason:
        # Strict xfail only while the T-001 skeleton marker is present (T-031/T-033).
        # probe_cli returns a reason only for that skeleton; any other exit 2 falls
        # through and the assertions below fail the test.
        pytest.xfail(reason)
    repo, manifest = benchlib.provision("b10k", work)
    run = benchlib.run_check(repo, "bench-pr-5000", work / "out", 0)
    assert run.exit_code == 0, run.stderr
    assert run.report is not None
    rules = {r["id"]: r for r in run.report["rules"]}
    found = sorted((rid, r["case"]) for rid, r in rules.items() if r["case"] in FINDING_CASES)
    expected = manifest["expected_findings"]["bench-pr-5000"]
    assert found == sorted((e["id"], e["case"]) for e in expected)
    for e in expected:
        r = rules[e["id"]]
        assert r["base"]["verdict"] == e["base_verdict"]
        assert r["head"]["verdict"] == e["head_verdict"]
        assert r["head"]["overall"]["following"] == e["head_following"]
