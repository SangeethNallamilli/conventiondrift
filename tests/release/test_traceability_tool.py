"""Tests for tools/check_test_traceability.py (T-044, merge gate #6)."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import cast

import pytest

TOOL = Path(__file__).resolve().parents[2] / "tools" / "check_test_traceability.py"
_spec = importlib.util.spec_from_file_location("check_test_traceability", TOOL)
assert _spec and _spec.loader
ctt = importlib.util.module_from_spec(_spec)
sys.modules["check_test_traceability"] = ctt
_spec.loader.exec_module(ctt)

SPEC = """# SPEC
- **AC-F1.1** [REQ-7.1.1] text
- **AC-F1.2** [REQ-7.1.2] text
- **AC-R.1** The LICENSE.
"""
HEAD = "| AC ID | REQ ID | Summary | Level | Tests | Fixture | Owner | Env | QA | Status |\n|---|\n"


def _trace(rows: list[str], sec: str = "") -> str:
    return (
        "# T\n## 2. AC traceability table (spec order)\n\n"
        + HEAD
        + "\n".join(rows)
        + "\n\n## 3. Security tests\n\n| Sec ID | Threat | Rules | Tests | Level | ACs |\n"
        + sec
        + "\n### 3.1 Mapping\n"
    )


ROW1 = (
    "| AC-F1.1 | REQ-7.1.1 | s | unit | `tests/unit/test_a.py::test_ac_f1_1_x[a\\|b]`<br>"
    "`…::test_ac_f1_1_y` | fx | TE | local | S-01 | planned |"
)
ROW2 = (
    "| AC-F1.2 | REQ-7.1.2 | s | unit | `tests/unit/test_b.py::test_ac_f1_2_z` "
    "| fx | TE | l | S | planned |"
)
ROWR = (
    "| AC-R.1 | REQ-6.R | s | unit | `tests/release/test_r.py::test_ac_r_1_l` "
    "| x | TE | l | S | planned |"
)


def run(trace: str, repo: Path, enforce: bool = False) -> list[str]:
    fails, _meta = ctt.check(SPEC, trace, repo, enforce)
    return cast(list[str], fails)


def test_pass(tmp_path: Path) -> None:
    assert run(_trace([ROW1, ROW2, ROWR]), tmp_path) == []


def test_missing_extra_duplicate_order(tmp_path: Path) -> None:
    assert any("not in TRACEABILITY" in f for f in run(_trace([ROW1, ROWR]), tmp_path))
    extra = ROW2.replace("AC-F1.2", "AC-F1.9")
    assert any("not SPEC ACs" in f for f in run(_trace([ROW1, ROW2, extra, ROWR]), tmp_path))
    assert any(
        "lists AC-F1.1 2 times" in f for f in run(_trace([ROW1, ROW1, ROW2, ROWR]), tmp_path)
    )
    assert any("order differs" in f for f in run(_trace([ROW2, ROW1, ROWR]), tmp_path))


def test_spec_duplicate(tmp_path: Path) -> None:
    fails = ctt.check(
        SPEC + "- **AC-F1.2** [REQ-7.1.2] again\n", _trace([ROW1, ROW2, ROWR]), tmp_path, False
    )[0]
    assert any("defines AC-F1.2 2 times" in f for f in fails)


def test_req_mismatch(tmp_path: Path) -> None:
    bad = ROW2.replace("REQ-7.1.2", "REQ-7.1.3")
    assert any(
        "REQ 'REQ-7.1.3' != SPEC 'REQ-7.1.2'" in f for f in run(_trace([ROW1, bad, ROWR]), tmp_path)
    )


def test_escaped_pipes_and_ellipsis_refs() -> None:
    cells = ctt.table_rows(_trace([ROW1]), ctt.re.compile(r"^AC-"))
    assert len(cells[0]) == 10  # `\\|` inside a cell does not split it
    assert ctt.test_refs(cells[0][4]) == [
        ("tests/unit/test_a.py", "test_ac_f1_1_x"),
        ("tests/unit/test_a.py", "test_ac_f1_1_y"),
    ]


def test_enforce_requires_defined_tests(tmp_path: Path) -> None:
    trace = _trace([ROW1, ROW2, ROWR])
    fails = run(trace, tmp_path, enforce=True)
    assert sum("does not exist" in f for f in fails) == 4
    (tmp_path / "tests/unit").mkdir(parents=True)
    (tmp_path / "tests/release").mkdir(parents=True)
    (tmp_path / "tests/unit/test_a.py").write_text(
        "def test_ac_f1_1_x(p):\n    pass\n\ndef test_ac_f1_1_y():\n    pass\n"
    )
    (tmp_path / "tests/unit/test_b.py").write_text("def test_other():\n    pass\n")
    (tmp_path / "tests/release/test_r.py").write_text("def test_ac_r_1_l():\n    pass\n")
    fails = run(trace, tmp_path, enforce=True)
    assert fails == ["AC-F1.2: tests/unit/test_b.py does not define test_ac_f1_2_z"]
    assert any(
        "status" in f
        for f in run(_trace([ROW1, ROW2, ROWR.replace("planned", "done")]), tmp_path, enforce=True)
    )


def test_enforce_security_table(tmp_path: Path) -> None:
    sec = "| SEC-T01 | t | R1 | `tests/security/test_s.py::test_sec_t01_x` | unit | AC |\n"
    fails = run(_trace([ROW1, ROW2, ROWR], sec), tmp_path, enforce=True)
    assert any("SEC-T01: tests/security/test_s.py does not exist" in f for f in fails)


@pytest.mark.skipif(
    not os.environ.get("CD_TEAM_DOCS"),
    reason="set CD_TEAM_DOCS to the folder holding SPEC.md and TRACEABILITY.md",
)
def test_planned_mode_on_real_docs() -> None:
    assert ctt.main(["--planned", "--docs", os.environ["CD_TEAM_DOCS"]]) == 0


def test_enforce_interface_contract_rows(tmp_path: Path) -> None:
    """§2.1 IC rows: their test IDs must exist and their status must be valid."""
    ic = (
        "\n\n### 2.1 Interface contract tests\n\n"
        "| IC ID | Interface | Summary | Tests | Tasks | Owner | Status |\n|---|\n"
        "| IC-I4.1 | I-4 | s | `tests/spec/test_c.py::test_ic_x[a]` | T-031 | TE | written |\n"
        "| IC-I4.2 | I-4 | s | `tests/spec/test_c.py::test_ic_y` | T-032 | TE | done |"
    )
    trace = _trace([ROW1, ROW2, ROWR + ic])
    assert run(trace, tmp_path) == []  # --planned ignores test IDs
    fails = run(trace, tmp_path, enforce=True)
    assert any("IC-I4.1: tests/spec/test_c.py does not exist" in f for f in fails)
    assert any("IC-I4.2: status 'done'" in f for f in fails)
    assert ctt.check(SPEC, trace, tmp_path, False)[1]["interface_rows"] == 2
