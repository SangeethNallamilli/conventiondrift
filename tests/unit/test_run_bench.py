"""Unit tests for scripts/ci/run_bench.py (D-TL-78 #4, D-TL-80 #2, D-TL-87 #2, TE N1/N4).

The script is not a package import (it is never imported by src/ or production tests).
These tests load it by path and drive it with crafted JUnit XML plus results JSON,
using a fake ``subprocess.run`` so they stay fast, deterministic, and OS-portable.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast
from xml.etree.ElementTree import ParseError

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci" / "run_bench.py"
_spec = importlib.util.spec_from_file_location("run_bench", SCRIPT)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
sys.modules["run_bench"] = _module
_spec.loader.exec_module(_module)


class _Case(Protocol):
    nodeid: str
    name: str
    outcome: str
    message: str


class _Report(Protocol):
    tests: int
    cases: list[_Case]

    def by_outcome(self, outcome: str) -> list[_Case]: ...


class _RunBench(Protocol):
    DEFAULT_TARGETS: tuple[str, ...]
    MARKERS: str
    SET_TEST: str
    subprocess: Any

    def Case(self, nodeid: str, name: str, outcome: str, message: str = "") -> _Case: ...

    def parse_junit(self, path: Path) -> _Report: ...

    def print_results_table(self, label: str, results: Path) -> None: ...

    def runs_over_limit_in_results(self, results: Path, set_name: str) -> int | None: ...

    def rerun_reason(self, case: _Case, results: Path) -> str | None: ...

    def main(self, argv: list[str]) -> int: ...


rb: _RunBench = cast(_RunBench, _module)

SET_TEST = "test_a3_7_b10k_near_cap_discovery_stage_within_125pct"
CLASSNAME = "tests.bench.test_bench_near_cap"
DEFAULT_TARGET = "tests/bench/test_bench_near_cap.py"
STOCK_NAME = "test_a3_7_stock_python_gitignore_near_walk_cap_has_no_note"
OVER_LIMIT_TAIL = "discovery {seconds} s > 5 s (125% of the 4 s B10k budget, DESIGN §5; A-3 #7)"
MARKERS = "timing and not network"
XFAIL_STRICT = "xfail_strict=true"


def _set_name(set_name: str) -> str:
    return f"{SET_TEST}[{set_name}]"


def _nodeid(name: str, classname: str = CLASSNAME) -> str:
    return f"{classname.replace('.', '/')}.py::{name}"


def _xml_attr(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "&#10;")
    )


def _xml_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def over_limit_line(run_n: int = 3, seconds: str = "5.20") -> str:
    return f"run {run_n}: {OVER_LIMIT_TAIL.format(seconds=seconds)}"


def assertion_message(
    set_name: str,
    problems: Sequence[str],
    *,
    median: str = "4.10",
    prefix: bool = True,
) -> str:
    """Build a pytest-style JUnit ``message`` for the near-cap assertion.

    Real pytest 9 JUnit output starts with ``AssertionError: {set} (median …):``,
    then each problem line indented two spaces, then an ``assert not […]`` line.
    """
    body = "\n".join(f"  {p}" for p in problems)
    head = f"{set_name} (median {median} s):\n{body}"
    shown = f"AssertionError: {head}" if prefix else head
    return f"{shown}\nassert not {list(problems)!r}"


def one_over_message(set_name: str, run_n: int = 3, seconds: str = "5.20") -> str:
    return assertion_message(set_name, [over_limit_line(run_n, seconds)])


def results_doc(
    discover_s: Sequence[float],
    *,
    median_s: float | None = None,
    limit_s: float = 5.0,
    baseline_median_s: float | None = 3.5,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "discover_s": list(discover_s),
        "limit_s": limit_s,
    }
    if median_s is None and discover_s:
        ordered = sorted(discover_s)
        mid = len(ordered) // 2
        median_s = ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2
    if median_s is not None:
        doc["median_s"] = median_s
    if baseline_median_s is not None:
        doc["baseline_median_s"] = baseline_median_s
    return doc


def one_over_results() -> dict[str, Any]:
    return results_doc([3.5, 3.6, 5.2, 3.7, 3.55], median_s=3.6)


def all_under_results() -> dict[str, Any]:
    return results_doc([3.58, 3.64, 3.64, 3.63, 3.66], median_s=3.64, baseline_median_s=3.4)


@dataclass(frozen=True)
class CaseSpec:
    name: str
    outcome: str = "passed"
    message: str = ""
    text: str = ""
    classname: str = CLASSNAME


def junit_xml(cases: Sequence[CaseSpec]) -> str:
    parts = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<testsuites name="pytest tests">',
        '<testsuite name="pytest" tests="' + str(len(cases)) + '">',
    ]
    for case in cases:
        parts.append(
            f'<testcase classname="{_xml_attr(case.classname)}" '
            f'name="{_xml_attr(case.name)}" time="0.1">'
        )
        if case.outcome != "passed":
            tag = {"failed": "failure", "error": "error", "skipped": "skipped"}[case.outcome]
            parts.append(f'<{tag} message="{_xml_attr(case.message)}">')
            if case.text:
                parts.append(_xml_text(case.text))
            parts.append(f"</{tag}>")
        parts.append("</testcase>")
    parts.extend(["</testsuite>", "</testsuites>"])
    return "".join(parts)


def passed(*set_names: str) -> list[CaseSpec]:
    return [CaseSpec(name=_set_name(s)) for s in set_names]


def failed_set(set_name: str, message: str) -> CaseSpec:
    return CaseSpec(name=_set_name(set_name), outcome="failed", message=message)


def skipped_set(set_name: str, message: str = "unconditional skip") -> CaseSpec:
    return CaseSpec(name=_set_name(set_name), outcome="skipped", message=message)


def error_set(set_name: str, message: str = "setup error") -> CaseSpec:
    return CaseSpec(name=_set_name(set_name), outcome="error", message=message)


@dataclass
class PlannedPytest:
    """One scripted pytest invocation."""

    rc: int
    cases: Sequence[CaseSpec] = ()
    results: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    write_junit: bool = True
    junit_body: str | None = None
    # When True, leave a leftover file in the results dir to confirm it was emptied first
    # (checked, not written). Extra XML written instead of the planned cases.
    skip_results: bool = False


@dataclass
class LoggedCall:
    cmd: list[str]
    env: dict[str, str]
    junit: Path
    results: Path


def _junit_from_cmd(cmd: Sequence[str]) -> Path:
    for arg in cmd:
        if arg.startswith("--junitxml="):
            return Path(arg.removeprefix("--junitxml="))
    raise AssertionError(f"pytest command missing --junitxml=: {cmd}")


def assert_pytest_cmd(cmd: Sequence[str], *, targets: Sequence[str], junit: Path) -> None:
    assert cmd[0] == sys.executable
    assert list(cmd[1:3]) == ["-m", "pytest"]
    assert list(cmd[3 : 3 + len(targets)]) == list(targets)
    rest = list(cmd[3 + len(targets) :])
    assert rest[:2] == ["-m", MARKERS]
    assert rest[2:4] == ["-o", XFAIL_STRICT]
    assert rest[4] == "-rs"
    assert rest[5] == f"--junitxml={junit}"
    assert len(rest) == 6


def install_fake(
    monkeypatch: pytest.MonkeyPatch, plans: Sequence[PlannedPytest]
) -> list[LoggedCall]:
    calls: list[LoggedCall] = []
    remaining = iter(plans)

    def fake_run(
        cmd: Sequence[str],
        env: Mapping[str, str] | None = None,
        check: bool = False,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        assert check is False
        assert env is not None
        plan = next(remaining, None)
        assert plan is not None, f"unexpected extra pytest invocation: {cmd}"
        junit = _junit_from_cmd(cmd)
        # Stale reports from an earlier run must already have been removed.
        assert not junit.exists(), f"stale JUnit still present: {junit}"
        results = Path(env["CD_BENCH_RESULTS"])
        assert results.is_dir()
        leftovers = list(results.iterdir())
        assert leftovers == [], f"stale results still present: {leftovers}"
        if plan.write_junit:
            body = plan.junit_body if plan.junit_body is not None else junit_xml(plan.cases)
            junit.write_text(body, encoding="utf-8")
        if not plan.skip_results:
            for set_name, doc in plan.results.items():
                path = results / f"b10k-a3-7-near-cap-{set_name}.json"
                path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        calls.append(LoggedCall(cmd=list(cmd), env=dict(env), junit=junit, results=results))
        return subprocess.CompletedProcess(list(cmd), plan.rc)

    monkeypatch.setattr(rb.subprocess, "run", fake_run)
    return calls


def run_main(work: Path, *targets: str) -> int:
    argv = ["run_bench.py", str(work), *targets]
    return rb.main(argv)


def table_header(label: str) -> list[str]:
    return [
        f"bench: per-set summary ({label}):",
        f"  {'set':<20} {'median_s':>8} {'base_med':>8} {'limit_s':>7}  discover_s",
    ]


def table_row(
    set_name: str,
    median: str,
    base: str,
    limit: str,
    discover_s: Sequence[float],
) -> str:
    return f"  {set_name:<20} {median:>8} {base:>8} {limit:>7}  {list(discover_s)}"


# --- CLI / env ----------------------------------------------------------------


def test_missing_workdir_prints_usage_and_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert rb.main(["run_bench.py"]) == 2
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert "run_bench.py" in captured.err
    assert "WORKDIR" in captured.err
    assert captured.out == ""


def test_workdir_is_created_and_default_target_is_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "bench" / "nested"
    assert not work.exists()
    calls = install_fake(
        monkeypatch,
        [PlannedPytest(rc=0, cases=passed("te"), results={"te": all_under_results()})],
    )
    monkeypatch.delenv("CD_BENCH_REPOS_DIR", raising=False)
    assert run_main(work) == 0
    assert work.is_dir()
    assert len(calls) == 1
    assert_pytest_cmd(calls[0].cmd, targets=[DEFAULT_TARGET], junit=work / "junit-1.xml")
    assert calls[0].results == work / "results-1"
    assert calls[0].env["CD_BENCH"] == "1"
    assert calls[0].env["CD_BENCH_REQUIRE"] == "1"
    assert calls[0].env["CD_BENCH_RESULTS"] == str(work / "results-1")
    assert calls[0].env["CD_BENCH_REPOS_DIR"] == str(work / "repos")
    out = capsys.readouterr().out
    assert "bench: 1 collected, 1 passed first time, 0 re-run, 0 skipped" in out
    assert "bench: ok" in out


def test_existing_repos_dir_env_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    preset = str(tmp_path / "cached-repos")
    monkeypatch.setenv("CD_BENCH_REPOS_DIR", preset)
    calls = install_fake(
        monkeypatch,
        [PlannedPytest(rc=0, cases=passed("te"), results={"te": all_under_results()})],
    )
    assert run_main(work) == 0
    assert calls[0].env["CD_BENCH_REPOS_DIR"] == preset


def test_custom_targets_are_forwarded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    targets = ["tests/bench/test_bench_near_cap.py", "tests/bench/test_other.py"]
    calls = install_fake(
        monkeypatch,
        [PlannedPytest(rc=0, cases=passed("te"), results={"te": all_under_results()})],
    )
    assert run_main(work, *targets) == 0
    assert_pytest_cmd(calls[0].cmd, targets=targets, junit=work / "junit-1.xml")


# --- N4: xfail_strict on the initial run and on every re-run ------------------


def test_xfail_strict_is_passed_on_initial_run_and_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    node = _nodeid(_set_name("cr-k90"))
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("cr-k90", one_over_message("cr-k90"))],
                results={"cr-k90": one_over_results()},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("cr-k90"))],
                results={"cr-k90": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 0
    assert len(calls) == 2
    assert_pytest_cmd(calls[0].cmd, targets=[DEFAULT_TARGET], junit=work / "junit-1.xml")
    assert_pytest_cmd(calls[1].cmd, targets=[node], junit=work / "junit-rerun-1.xml")
    assert calls[1].env["CD_BENCH_RESULTS"] == str(work / "results-rerun-1")
    assert calls[1].env["CD_BENCH"] == "1"
    assert calls[1].env["CD_BENCH_REQUIRE"] == "1"


# --- First-run outcomes -------------------------------------------------------


def test_all_pass_exits_0_and_does_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    docs = {
        "cr": all_under_results(),
        "te": results_doc([3.58, 3.64, 3.64, 3.63, 3.66], median_s=3.64, baseline_median_s=3.4),
    }
    calls = install_fake(
        monkeypatch,
        [PlannedPytest(rc=0, cases=passed("cr", "te"), results=docs)],
    )
    assert run_main(work) == 0
    assert len(calls) == 1
    out = capsys.readouterr().out
    assert "bench: eligible for one re-run" not in out
    assert "bench: re-running once" not in out
    assert "bench: 2 collected, 2 passed first time, 0 re-run, 0 skipped" in out
    assert "bench: per-set summary (run 1):" in out
    assert "bench: ok" in out


def test_one_run_over_rerun_pass_exits_0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    node = _nodeid(_set_name("cr-k90"))
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[
                    CaseSpec(name=_set_name("te")),
                    failed_set("cr-k90", one_over_message("cr-k90")),
                ],
                results={"te": all_under_results(), "cr-k90": one_over_results()},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("cr-k90"))],
                results={"cr-k90": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 0
    captured = capsys.readouterr()
    assert "bench: eligible for one re-run (D-TL-80): cr-k90:" in captured.out
    assert f"bench: re-running once (D-TL-80): {node}" in captured.out
    assert f"bench: re-run passed: {node}" in captured.out
    assert "bench: 2 collected, 1 passed first time, 1 re-run, 0 skipped" in captured.out
    assert "bench: per-set summary (run 1):" in captured.out
    assert "bench: per-set summary (re-run 1):" in captured.out
    assert "bench: ok" in captured.out
    assert "bench: FAILED" not in captured.err


def test_one_run_over_rerun_fail_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    node = _nodeid(_set_name("te"))
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te", run_n=0, seconds="5.05"))],
                results={"te": one_over_results()},
            ),
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te", run_n=2, seconds="6.00"))],
                results={"te": one_over_results()},
            ),
        ],
    )
    assert run_main(work) == 1
    captured = capsys.readouterr()
    assert "bench: per-set summary (run 1):" in captured.out
    assert "bench: per-set summary (re-run 1):" in captured.out
    assert "bench: FAILED" in captured.err
    assert f"failed twice (D-TL-80): {node} re-run: ['failed'], exit 1" in captured.err
    assert "bench: ok" not in captured.out


def test_one_run_over_rerun_skip_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    node = _nodeid(_set_name("sr"))
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("sr", one_over_message("sr"))],
                results={"sr": one_over_results()},
            ),
            PlannedPytest(
                rc=0,
                cases=[skipped_set("sr", "tool not available")],
                results={"sr": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 1
    err = capsys.readouterr().err
    assert f"failed twice (D-TL-80): {node} re-run: ['skipped'], exit 0" in err


def test_two_eligible_sets_each_get_one_rerun_and_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D-TL-87 #2: each set gets its own single re-run when both are one-run-over."""
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[
                    failed_set("cr", one_over_message("cr")),
                    failed_set("te", one_over_message("te")),
                ],
                results={"cr": one_over_results(), "te": one_over_results()},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("cr"))],
                results={"cr": all_under_results()},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("te"))],
                results={"te": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 0
    assert len(calls) == 3
    assert_pytest_cmd(
        calls[1].cmd, targets=[_nodeid(_set_name("cr"))], junit=work / "junit-rerun-1.xml"
    )
    assert_pytest_cmd(
        calls[2].cmd, targets=[_nodeid(_set_name("te"))], junit=work / "junit-rerun-2.xml"
    )
    assert calls[2].env["CD_BENCH_RESULTS"] == str(work / "results-rerun-2")
    out = capsys.readouterr().out
    assert "bench: per-set summary (re-run 1):" in out
    assert "bench: per-set summary (re-run 2):" in out
    assert "bench: 2 collected, 0 passed first time, 2 re-run, 0 skipped" in out
    assert "bench: ok" in out
    for call in calls:
        assert "-o" in call.cmd and call.cmd[call.cmd.index("-o") + 1] == XFAIL_STRICT


def test_two_eligible_sets_still_rerun_the_second_after_the_first_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[
                    failed_set("cr", one_over_message("cr")),
                    failed_set("te", one_over_message("te")),
                ],
                results={"cr": one_over_results(), "te": one_over_results()},
            ),
            PlannedPytest(
                rc=1,
                cases=[failed_set("cr", one_over_message("cr"))],
                results={"cr": one_over_results()},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("te"))],
                results={"te": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 3
    err = capsys.readouterr().err
    assert f"failed twice (D-TL-80): {_nodeid(_set_name('cr'))}" in err
    assert "bench: FAILED" in err


def test_two_runs_over_the_limit_fails_without_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    message = assertion_message(
        "cr-k150",
        [over_limit_line(1, "5.20"), over_limit_line(4, "6.10")],
        median="5.50",
    )
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("cr-k150", message)],
                results={
                    "cr-k150": results_doc([3.5, 5.2, 3.6, 3.7, 6.1], median_s=3.7, limit_s=5.0)
                },
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    captured = capsys.readouterr()
    assert "bench: re-running once" not in captured.out
    assert "bench: per-set summary (run 1):" in captured.out
    assert f"failed (not eligible for a re-run): {_nodeid(_set_name('cr-k150'))}" in captured.err


def test_one_over_plus_another_problem_fails_without_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    message = assertion_message(
        "cr-deep",
        [over_limit_line(1, "5.20"), "run 2: 1999 patterns loaded"],
    )
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("cr-deep", message)],
                results={"cr-deep": one_over_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    assert "not eligible for a re-run" in capsys.readouterr().err


def test_json_cross_check_blocks_rerun_when_more_than_one_run_is_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """JUnit shows one over-limit line, but results JSON records two overs."""
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": results_doc([3.5, 5.2, 3.6, 3.7, 6.1], median_s=3.7)},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    assert "not eligible for a re-run" in capsys.readouterr().err


def test_ineligible_failure_plus_eligible_set_reruns_neither(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    stock = CaseSpec(name=STOCK_NAME, outcome="failed", message="AssertionError: walk entries")
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[stock, failed_set("te", one_over_message("te"))],
                results={"python": all_under_results(), "te": one_over_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    err = capsys.readouterr().err
    assert f"failed (not eligible for a re-run): {_nodeid(STOCK_NAME)}" in err
    assert f"not re-run because the job already failed: {_nodeid(_set_name('te'))}" in err


def test_stock_python_failure_is_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[
                    CaseSpec(
                        name=STOCK_NAME,
                        outcome="failed",
                        message="AssertionError: 400000 walk entries: not near the cap",
                    )
                ],
                results={"python": all_under_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    assert "not eligible for a re-run" in capsys.readouterr().err


# --- Skips and errors (D-TL-78 #4, D-TL-80) -----------------------------------


def test_any_skip_on_first_run_fails_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    node = _nodeid(_set_name("te"))
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=0,
                cases=[skipped_set("te", "CD_BENCH not set")],
                results={"te": all_under_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    err = capsys.readouterr().err
    assert "bench: FAILED" in err
    assert f"skipped (D-TL-78 #4: any skip fails the job): {node}: CD_BENCH not set" in err


def test_skip_plus_eligible_failure_does_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[
                    skipped_set("cr", "xfail"),
                    failed_set("te", one_over_message("te")),
                ],
                results={"cr": all_under_results(), "te": one_over_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    err = capsys.readouterr().err
    assert "skipped (D-TL-78 #4" in err
    assert "not re-run because the job already failed" in err


def test_error_is_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    node = _nodeid(_set_name("te"))
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[error_set("te", "fixture setup failed")],
                results={"te": one_over_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    captured = capsys.readouterr()
    assert f"error (not re-run): {node}" in captured.err
    assert "bench: re-running once" not in captured.out


def test_error_plus_eligible_failure_does_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[
                    error_set("cr"),
                    failed_set("te", one_over_message("te")),
                ],
                results={"cr": all_under_results(), "te": one_over_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    err = capsys.readouterr().err
    assert "error (not re-run)" in err
    assert "not re-run because the job already failed" in err


# --- Exit status vs JUnit -----------------------------------------------------


def test_no_tests_collected_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [PlannedPytest(rc=5, cases=[], results={})],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    err = capsys.readouterr().err
    assert "no bench tests ran (0 collected)" in err
    assert "pytest exit status 5 does not match the JUnit report (failures: False)" in err


def test_empty_junit_with_exit_0_fails_as_no_tests_ran(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(monkeypatch, [PlannedPytest(rc=0, cases=[], results={})])
    assert run_main(work) == 1
    err = capsys.readouterr().err
    assert "no bench tests ran (0 collected)" in err


@pytest.mark.parametrize("rc", [2, 3, 4, 5])
def test_nonzero_pytest_exit_other_than_1_fails_even_if_junit_is_all_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rc: int, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(
        monkeypatch,
        [PlannedPytest(rc=rc, cases=passed("te"), results={"te": all_under_results()})],
    )
    assert run_main(work) == 1
    captured = capsys.readouterr()
    assert (
        f"pytest exit status {rc} does not match the JUnit report (failures: False)" in captured.err
    )
    assert "bench: re-running once" not in captured.out


def test_exit_1_with_all_pass_junit_is_a_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(
        monkeypatch,
        [PlannedPytest(rc=1, cases=passed("te"), results={"te": all_under_results()})],
    )
    assert run_main(work) == 1
    assert "pytest exit status 1 does not match the JUnit report (failures: False)" in (
        capsys.readouterr().err
    )


def test_exit_0_with_failure_in_junit_is_a_mismatch_and_does_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=0,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": one_over_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    err = capsys.readouterr().err
    assert "pytest exit status 0 does not match the JUnit report (failures: True)" in err
    assert "not re-run because the job already failed" in err


def test_missing_junit_fails_even_when_pytest_exits_0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=0, cases=passed("te"), results={"te": all_under_results()}, write_junit=False
            )
        ],
    )
    assert run_main(work) == 1
    captured = capsys.readouterr()
    assert "bench: pytest wrote no JUnit report" in captured.err
    assert "bench: ok" not in captured.out


@pytest.mark.parametrize("rc", [1, 2, 3, 4, 5])
def test_missing_junit_fails_for_nonzero_pytest_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rc: int, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(monkeypatch, [PlannedPytest(rc=rc, write_junit=False, results={})])
    assert run_main(work) == 1
    assert "bench: pytest wrote no JUnit report" in capsys.readouterr().err


def test_stale_all_pass_junit_is_deleted_and_cannot_mask_a_missing_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    stale = work / "junit-1.xml"
    stale.write_text(junit_xml(passed("te", "cr")), encoding="utf-8")
    stale_results = work / "results-1"
    stale_results.mkdir()
    (stale_results / "b10k-a3-7-near-cap-te.json").write_text(
        json.dumps(all_under_results()), encoding="utf-8"
    )
    install_fake(monkeypatch, [PlannedPytest(rc=0, write_junit=False, results={})])
    assert run_main(work) == 1
    assert "bench: pytest wrote no JUnit report" in capsys.readouterr().err
    assert not stale.exists()


def test_stale_rerun_junit_is_deleted_and_cannot_mask_a_failed_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    stale = work / "junit-rerun-1.xml"
    stale.write_text(junit_xml([CaseSpec(name=_set_name("te"))]), encoding="utf-8")
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": one_over_results()},
            ),
            PlannedPytest(rc=0, write_junit=False, results={}),
        ],
    )
    assert run_main(work) == 1
    err = capsys.readouterr().err
    assert (
        f"failed twice (D-TL-80): {_nodeid(_set_name('te'))} re-run: ['no report'], exit 0" in err
    )
    assert not stale.exists()


def test_malformed_junit_does_not_exit_0(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    install_fake(
        monkeypatch,
        [PlannedPytest(rc=0, write_junit=True, junit_body="<not-xml", results={})],
    )
    with pytest.raises(ParseError):
        run_main(work)


def test_unexpected_junit_root_with_no_testcases_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(
        monkeypatch,
        [PlannedPytest(rc=0, junit_body="<testsuites/>", results={})],
    )
    assert run_main(work) == 1
    assert "no bench tests ran (0 collected)" in capsys.readouterr().err


# --- N1 per-set timing summary table ------------------------------------------


def test_results_table_format_and_filename_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results = tmp_path / "results-1"
    results.mkdir()
    docs = {
        "te": results_doc([3.58, 3.64, 3.64, 3.63, 3.66], median_s=3.64, baseline_median_s=3.4),
        "cr-k90": results_doc([4.05, 4.08, 4.10, 3.99, 4.02], median_s=4.05, baseline_median_s=3.7),
        "cr": results_doc([3.44, 3.40, 3.46, 3.60, 3.58], median_s=3.46, baseline_median_s=3.2),
    }
    for name, doc in docs.items():
        (results / f"b10k-a3-7-near-cap-{name}.json").write_text(json.dumps(doc), encoding="utf-8")
    # Unrelated files must be ignored.
    (results / "other.json").write_text("{}", encoding="utf-8")
    (results / "b10k-a3-7-near-cap-te.txt").write_text("nope", encoding="utf-8")
    rb.print_results_table("run 1", results)
    lines = capsys.readouterr().out.splitlines()
    # Sort is by filename. "b10k-a3-7-near-cap-cr-k90.json" sorts before
    # "b10k-a3-7-near-cap-cr.json" because "-" precedes ".".
    expected = [
        *table_header("run 1"),
        table_row("cr-k90", "4.050", "3.700", "5.00", docs["cr-k90"]["discover_s"]),
        table_row("cr", "3.460", "3.200", "5.00", docs["cr"]["discover_s"]),
        table_row("te", "3.640", "3.400", "5.00", docs["te"]["discover_s"]),
    ]
    assert lines == expected


def test_results_table_uses_dash_for_missing_or_non_numeric_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results = tmp_path / "results-1"
    results.mkdir()
    (results / "b10k-a3-7-near-cap-te.json").write_text(
        json.dumps({"discover_s": [1, 2], "median_s": "na", "limit_s": None}),
        encoding="utf-8",
    )
    (results / "b10k-a3-7-near-cap-cr.json").write_text(json.dumps({}), encoding="utf-8")
    rb.print_results_table("re-run 1", results)
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "bench: per-set summary (re-run 1):"
    assert table_row("cr", "-", "-", "-", []) in lines
    assert table_row("te", "-", "-", "-", [1, 2]) in lines


def test_results_table_is_silent_when_dir_is_missing_or_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rb.print_results_table("run 1", tmp_path / "no-such-dir")
    empty = tmp_path / "empty"
    empty.mkdir()
    rb.print_results_table("run 1", empty)
    assert capsys.readouterr().out == ""


def test_results_table_printed_on_first_run_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    doc = results_doc([3.5, 5.2, 3.6, 3.7, 6.1], median_s=3.7, baseline_median_s=3.1)
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[
                    failed_set(
                        "te",
                        assertion_message("te", [over_limit_line(1), over_limit_line(4, "6.10")]),
                    )
                ],
                results={"te": doc},
            )
        ],
    )
    assert run_main(work) == 1
    out = capsys.readouterr().out
    for line in table_header("run 1"):
        assert line in out.splitlines()
    assert table_row("te", "3.700", "3.100", "5.00", doc["discover_s"]) in out.splitlines()
    assert "bench: per-set summary (re-run 1):" not in out


def test_results_table_printed_on_pass_after_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    first = one_over_results()
    second = all_under_results()
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": first},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("te"))],
                results={"te": second},
            ),
        ],
    )
    assert run_main(work) == 0
    lines = capsys.readouterr().out.splitlines()
    assert table_header("run 1")[0] in lines
    assert table_row("te", "3.600", "3.500", "5.00", first["discover_s"]) in lines
    assert table_header("re-run 1")[0] in lines
    assert table_row("te", "3.640", "3.400", "5.00", second["discover_s"]) in lines


def test_results_table_printed_on_failed_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    second = one_over_results()
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": one_over_results()},
            ),
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": second},
            ),
        ],
    )
    assert run_main(work) == 1
    lines = capsys.readouterr().out.splitlines()
    assert "bench: per-set summary (re-run 1):" in lines
    assert table_row("te", "3.600", "3.500", "5.00", second["discover_s"]) in lines


def test_main_with_empty_results_dir_does_not_print_a_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(monkeypatch, [PlannedPytest(rc=0, cases=passed("te"), results={})])
    assert run_main(work) == 0
    out = capsys.readouterr().out
    assert "bench: per-set summary" not in out
    assert "bench: ok" in out


# --- parse_junit / rerun_reason / runs_over_limit -----------------------------


def test_parse_junit_maps_outcomes_nodeids_and_prefers_message_attribute(
    tmp_path: Path,
) -> None:
    path = tmp_path / "junit.xml"
    cases = [
        CaseSpec(name=_set_name("te")),
        failed_set("cr", one_over_message("cr")),
        error_set("sr", "boom"),
        skipped_set("cr-deep", "not now"),
        CaseSpec(
            name="test_msg_from_text",
            classname="pkg.mod",
            outcome="failed",
            message="",
            text="body-only message",
        ),
    ]
    path.write_text(junit_xml(cases), encoding="utf-8")
    report = rb.parse_junit(path)
    assert report.tests == 5
    by_name = {c.name: c for c in report.cases}
    assert by_name[_set_name("te")].outcome == "passed"
    assert by_name[_set_name("te")].nodeid == _nodeid(_set_name("te"))
    assert by_name[_set_name("cr")].outcome == "failed"
    assert by_name[_set_name("cr")].message == one_over_message("cr")
    assert by_name[_set_name("sr")].outcome == "error"
    assert by_name[_set_name("cr-deep")].outcome == "skipped"
    text_case = by_name["test_msg_from_text"]
    assert text_case.nodeid == "pkg/mod.py::test_msg_from_text"
    assert text_case.message == "body-only message"
    assert [c.name for c in report.by_outcome("failed")] == [_set_name("cr"), "test_msg_from_text"]


def test_parse_junit_failure_tag_wins_over_skipped_when_both_present(tmp_path: Path) -> None:
    path = tmp_path / "junit.xml"
    path.write_text(
        '<?xml version="1.0"?><testsuite>'
        f'<testcase classname="{CLASSNAME}" name="{_set_name("te")}">'
        '<failure message="failed first"/><skipped message="also skipped"/>'
        "</testcase></testsuite>",
        encoding="utf-8",
    )
    report = rb.parse_junit(path)
    assert report.cases[0].outcome == "failed"
    assert report.cases[0].message == "failed first"


def _case(set_name: str, message: str, outcome: str = "failed", name: str | None = None) -> _Case:
    test_name = name if name is not None else _set_name(set_name)
    return rb.Case(nodeid=_nodeid(test_name), name=test_name, outcome=outcome, message=message)


def test_rerun_reason_accepts_one_over_limit_and_missing_results_json(
    tmp_path: Path,
) -> None:
    case = _case("cr-k90", one_over_message("cr-k90", run_n=0, seconds="5.01"))
    why = rb.rerun_reason(case, tmp_path)
    assert why is not None
    assert why.startswith("cr-k90: one run over the limit (")
    assert "run 0: discovery 5.01 s > 5 s " in why


def test_rerun_reason_rejects_ineligible_failures(tmp_path: Path) -> None:
    results = tmp_path / "results-1"
    results.mkdir()
    (results / "b10k-a3-7-near-cap-te.json").write_text(
        json.dumps(one_over_results()), encoding="utf-8"
    )
    cases = [
        _case("te", one_over_message("te"), outcome="passed"),
        _case("te", one_over_message("te"), outcome="error"),
        _case("te", one_over_message("te"), outcome="skipped"),
        rb.Case(nodeid=_nodeid(STOCK_NAME), name=STOCK_NAME, outcome="failed", message="x"),
        _case("te", "AssertionError: setup exploded\n  run 1: discovery 5.20 s > 5 s x "),
        _case("te", assertion_message("te", [over_limit_line(), over_limit_line(4, "6.1")])),
        _case("te", assertion_message("te", ["run 1: 1999 patterns loaded"])),
        _case("te", assertion_message("te", [])),
        _case("cr", one_over_message("te")),  # set name in the message does not match the case
        _case("weird.set", one_over_message("weird.set"), name=f"{SET_TEST}[weird.set]"),
    ]
    for case in cases:
        assert rb.rerun_reason(case, results) is None, case


def test_rerun_reason_uses_results_json_count_as_a_cross_check(tmp_path: Path) -> None:
    results = tmp_path / "results-1"
    results.mkdir()
    case = _case("te", one_over_message("te"))
    (results / "b10k-a3-7-near-cap-te.json").write_text(
        json.dumps(results_doc([5.1, 5.2, 3.0, 3.0, 3.0], median_s=3.0)), encoding="utf-8"
    )
    assert rb.rerun_reason(case, results) is None
    (results / "b10k-a3-7-near-cap-te.json").write_text(
        json.dumps(one_over_results()), encoding="utf-8"
    )
    assert rb.rerun_reason(case, results) is not None


def test_runs_over_limit_in_results_counts_and_returns_none_when_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results = tmp_path / "results-1"
    results.mkdir()
    assert rb.runs_over_limit_in_results(results, "te") is None
    assert capsys.readouterr().out == ""
    doc = results_doc([3.5, 5.2, 3.6, 3.7, 6.1], median_s=3.7, limit_s=5.0)
    (results / "b10k-a3-7-near-cap-te.json").write_text(json.dumps(doc), encoding="utf-8")
    assert rb.runs_over_limit_in_results(results, "te") == 2
    out = capsys.readouterr().out
    assert "  te: discover_s=[3.5, 5.2, 3.6, 3.7, 6.1] limit_s=5.0" in out
    doc_one = results_doc([3.5, 3.6, 5.2, 3.7, 3.55], median_s=3.6)
    (results / "b10k-a3-7-near-cap-te.json").write_text(json.dumps(doc_one), encoding="utf-8")
    assert rb.runs_over_limit_in_results(results, "te") == 1
    (results / "b10k-a3-7-near-cap-te.json").write_text(
        json.dumps(results_doc([3.0, 3.0, 3.0], median_s=3.0)), encoding="utf-8"
    )
    assert rb.runs_over_limit_in_results(results, "te") == 0


def test_rerun_with_no_results_json_is_still_eligible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("te"))],
                results={"te": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 0
    assert len(calls) == 2


def test_rerun_nonzero_exit_with_passing_junit_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """D-TL-80: every re-run must pass, including a matching pytest exit status."""
    work = tmp_path / "work"
    node = _nodeid(_set_name("te"))
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": one_over_results()},
            ),
            PlannedPytest(
                rc=1,
                cases=[CaseSpec(name=_set_name("te"))],
                results={"te": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 1
    err = capsys.readouterr().err
    assert f"failed twice (D-TL-80): {node} re-run: ['passed'], exit 1" in err


def test_rerun_rejects_when_rerun_junit_has_the_wrong_number_of_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("te", one_over_message("te"))],
                results={"te": one_over_results()},
            ),
            PlannedPytest(
                rc=0,
                cases=[CaseSpec(name=_set_name("te")), CaseSpec(name=_set_name("cr"))],
                results={"te": all_under_results(), "cr": all_under_results()},
            ),
        ],
    )
    assert run_main(work) == 1
    assert "re-run: ['passed', 'passed'], exit 0" in capsys.readouterr().err


def test_failure_before_per_run_checks_is_not_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    # Overlay / pattern-count assertion happens before the per-run block.
    message = "AssertionError: assert 90 == 2000"
    calls = install_fake(
        monkeypatch,
        [
            PlannedPytest(
                rc=1,
                cases=[failed_set("cr-k90", message)],
                results={"cr-k90": one_over_results()},
            )
        ],
    )
    assert run_main(work) == 1
    assert len(calls) == 1
    assert "not eligible for a re-run" in capsys.readouterr().err


def test_default_targets_constant_matches_the_near_cap_module() -> None:
    assert rb.DEFAULT_TARGETS == (DEFAULT_TARGET,)
    assert rb.SET_TEST == SET_TEST
    assert rb.MARKERS == MARKERS
