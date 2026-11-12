#!/usr/bin/env python3
"""Test traceability check (TRACEABILITY.md §4; merge gate #6). Test tooling, not shipped.

  --planned  (before code exists) checks 1 and 2 only:
     1. The AC IDs defined in SPEC.md and the AC IDs in column 1 of TRACEABILITY.md §2 are the
        same set, in the same order, with no duplicates on either side.
     2. Each row's REQ ID equals the AC's `[REQ-...]` tag in SPEC.md (`REQ-6.R` for AC-R.x).
  --enforce  additionally:
     3. Every planned test ID `tests/<path>.py::<name>` (§2 and the §3 security table) exists:
        the file exists and defines `def <name>` (pytest `[...]` parameters stripped; a
        `…::<name>` entry refers to the previous file in the same cell). Each
        `tests/manual/CHECKLIST.md#<anchor>` exists. `ci matrix job` / `ci-demo PR` entries
        are named in `.github/workflows/` or RELEASING.md.
     4. Each row's status is one of planned, written, passing, failing, blocked.

Exit 0 = pass, 1 = fail, 2 = usage error.
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

AC_DEF = re.compile(r"^- \*\*(AC-[A-Z0-9]+\.\d+)\*\*(?: \[(REQ-[0-9.]+)\])?", re.M)
CELL_SPLIT = re.compile(r"(?<!\\)\|")
TEST_REF = re.compile(r"`((?:tests/[^`\s]+?\.py|…)::([A-Za-z_][A-Za-z0-9_]*)(?:\[[^`]*\])?)`")
MANUAL_REF = re.compile(r"`?(tests/manual/CHECKLIST\.md)#([A-Za-z0-9_\-]+)`?")
CI_REF = re.compile(r"(ci matrix job|ci-demo PR)\s+([`'\"])([^`'\"]+)\2")
STATUSES = {"planned", "written", "passing", "failing", "blocked"}


def parse_spec(text: str) -> list[tuple[str, str | None]]:
    return [(m.group(1), m.group(2)) for m in AC_DEF.finditer(text)]


def _section(text: str, start: str, end: str | None) -> str:
    i = text.find(start)
    if i < 0:
        raise SystemExit(f"TRACEABILITY.md: section {start!r} not found")
    j = text.find(end, i + len(start)) if end else -1
    return text[i : j if j > 0 else len(text)]


def table_rows(section: str, first_col: re.Pattern[str]) -> list[list[str]]:
    rows = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in CELL_SPLIT.split(line.strip())[1:-1]]
        if cells and first_col.match(cells[0]):
            rows.append(cells)
    return rows


def test_refs(cell: str) -> list[tuple[str, str]]:
    """(file, function) pairs; `…::name` inherits the previous file in the cell."""
    out, current = [], None
    for m in TEST_REF.finditer(cell.replace("\\|", "|")):
        path = m.group(1).split("::", 1)[0]
        if path == "…":
            if current is None:
                out.append(("<no file before …>", m.group(2)))
                continue
            path = current
        current = path
        out.append((path, m.group(2)))
    return out


def check(spec_text: str, trace_text: str, repo: Path, enforce: bool) -> tuple[list[str], dict]:
    fail: list[str] = []
    spec = parse_spec(spec_text)
    spec_ids = [a for a, _ in spec]
    req_of = dict(spec)
    for a, n in collections.Counter(spec_ids).items():
        if n > 1:
            fail.append(f"SPEC.md defines {a} {n} times")

    sec2 = _section(trace_text, "## 2. AC traceability table", "\n## 3.")
    rows = table_rows(sec2, re.compile(r"^AC-[A-Z0-9]+\.\d+$"))
    row_ids = [r[0] for r in rows]
    for a, n in collections.Counter(row_ids).items():
        if n > 1:
            fail.append(f"TRACEABILITY.md §2 lists {a} {n} times")
    missing = [a for a in spec_ids if a not in set(row_ids)]
    extra = [a for a in row_ids if a not in set(spec_ids)]
    if missing:
        fail.append(f"ACs in SPEC.md but not in TRACEABILITY.md: {missing}")
    if extra:
        fail.append(f"rows in TRACEABILITY.md that are not SPEC ACs: {extra}")
    if (
        not missing
        and not extra
        and row_ids != spec_ids
        and len(row_ids) == len(spec_ids)
        and len(set(row_ids)) == len(row_ids)
    ):
        first = next(i for i, (x, y) in enumerate(zip(row_ids, spec_ids, strict=True)) if x != y)
        fail.append(
            f"order differs from SPEC.md at row {first + 1}: {row_ids[first]} vs {spec_ids[first]}"
        )

    # check 2: REQ IDs
    for r in rows:
        ac, req = r[0], (r[1] if len(r) > 1 else "")
        if ac not in req_of:
            continue
        want = req_of[ac] or ("REQ-6.R" if ac.startswith("AC-R.") else None)
        if want is None:
            fail.append(f"{ac}: SPEC.md has no [REQ-...] tag")
        elif req != want:
            fail.append(f"{ac}: TRACEABILITY REQ {req!r} != SPEC {want!r}")

    stats = {"spec_acs": len(spec_ids), "rows": len(rows), "test_refs": 0, "missing_tests": 0}
    sec3 = _section(trace_text, "## 3. Security tests", "\n### 3.1")
    sec_rows = table_rows(sec3, re.compile(r"^SEC-[A-Z0-9]+$"))
    refs = [(r[0], f, n) for r in rows for f, n in test_refs(r[4] if len(r) > 4 else "")]
    refs += [(r[0], f, n) for r in sec_rows for f, n in test_refs(r[3] if len(r) > 3 else "")]
    stats["test_refs"] = len(refs)
    stats["security_rows"] = len(sec_rows)
    if enforce:
        cache: dict[str, str | None] = {}
        for owner, f, name in refs:
            if f not in cache:
                p = repo / f
                cache[f] = p.read_text(encoding="utf-8") if p.is_file() else None
            src = cache[f]
            if src is None:
                fail.append(f"{owner}: {f} does not exist (for {name})")
                stats["missing_tests"] += 1
            elif not re.search(rf"^\s*(?:async\s+)?def {re.escape(name)}\(", src, re.M):
                fail.append(f"{owner}: {f} does not define {name}")
                stats["missing_tests"] += 1
        checklist = repo / "tests/manual/CHECKLIST.md"
        ctext = checklist.read_text(encoding="utf-8") if checklist.is_file() else ""
        ci_text = "".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in [*sorted((repo / ".github/workflows").glob("*.y*ml")), repo / "RELEASING.md"]
            if p.is_file()
        )
        for r in rows:
            cell = r[4] if len(r) > 4 else ""
            for _, anchor in MANUAL_REF.findall(cell):
                if (
                    not re.search(
                        rf"(?:id=\"|name=\"|\{{#|^#+ .*?){re.escape(anchor)}", ctext, re.M
                    )
                    and anchor not in ctext
                ):
                    fail.append(f"{r[0]}: tests/manual/CHECKLIST.md#{anchor} not found")
            for kind, _, label in CI_REF.findall(cell):
                if label not in ci_text:
                    fail.append(
                        f"{r[0]}: {kind} '{label}' not named in .github/workflows/ or RELEASING.md"
                    )
            status = r[-1]
            if status not in STATUSES:
                fail.append(f"{r[0]}: status {status!r} not in {sorted(STATUSES)}")
    return fail, stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="TRACEABILITY.md vs SPEC.md vs tests/")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--planned", action="store_true", help="checks 1-2 only")
    mode.add_argument("--enforce", action="store_true", help="checks 1-4 (merge gate #6)")
    ap.add_argument("--spec", type=Path, help="default: SPEC.md in --docs")
    ap.add_argument("--traceability", type=Path, help="default: TRACEABILITY.md in --docs")
    ap.add_argument(
        "--docs",
        type=Path,
        default=None,
        help="folder holding SPEC.md and TRACEABILITY.md (default: repo root)",
    )
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    a = ap.parse_args(argv)
    docs = a.docs or a.repo
    spec_p = a.spec or docs / "SPEC.md"
    trace_p = a.traceability or docs / "TRACEABILITY.md"
    for p in (spec_p, trace_p):
        if not p.is_file():
            print(f"error: {p} not found", file=sys.stderr)
            return 2
    fail, stats = check(
        spec_p.read_text(encoding="utf-8"), trace_p.read_text(encoding="utf-8"), a.repo, a.enforce
    )
    print(f"mode: {'enforce' if a.enforce else 'planned'}")
    print(
        f"SPEC ACs: {stats['spec_acs']}; TRACEABILITY §2 rows: {stats['rows']}; "
        f"§3 security rows: {stats['security_rows']}; planned test IDs: {stats['test_refs']}"
    )
    if a.enforce:
        print(f"planned test IDs missing from tests/: {stats['missing_tests']}")
    if fail:
        print(f"FAIL ({len(fail)} problems)")
        for f in fail:
            print(f"  - {f}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
