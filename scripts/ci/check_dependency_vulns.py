#!/usr/bin/env python3
"""Query OSV for locked dependencies and the vendored PyYAML 6.0.3 (R7.4, covers _vendor/)."""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOCKFILES = (
    REPO / "requirements" / "build.txt",
    REPO / "requirements" / "dev.txt",
    REPO / "requirements" / "mutation.txt",
)
# Always scan the vendored library, even though it is not a lockfile entry (ADR-0002).
VENDOR_PACKAGES = (("PyYAML", "6.0.3"),)
OSV_URL = "https://api.osv.dev/v1/querybatch"
PKG_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)")


def parse_lock(path: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("#") or raw.startswith(" ") or raw.startswith("\t") or not raw.strip():
            continue
        match = PKG_RE.match(raw)
        if match:
            found.append((match.group(1), match.group(2)))
    return found


def query_osv(packages: list[tuple[str, str]]) -> list[dict]:
    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in packages
    ]
    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "conventiondrift-ci"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("results", [])


def main() -> int:
    packages: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for lock in LOCKFILES:
        for item in parse_lock(lock):
            key = (item[0].lower(), item[1])
            if key not in seen:
                seen.add(key)
                packages.append(item)
    for item in VENDOR_PACKAGES:
        key = (item[0].lower(), item[1])
        if key not in seen:
            seen.add(key)
            packages.append(item)

    print(f"querying OSV for {len(packages)} package versions (lockfiles + vendored PyYAML)")
    results = query_osv(packages)
    if len(results) != len(packages):
        print(
            f"OSV returned {len(results)} results for {len(packages)} queries",
            file=sys.stderr,
        )
        return 2

    findings: list[str] = []
    for (name, version), result in zip(packages, results, strict=True):
        vulns = result.get("vulns") or []
        for vuln in vulns:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = (vuln.get("summary") or "").strip()
            findings.append(f"{name}=={version}: {vuln_id} {summary}".rstrip())

    if findings:
        print("dependency vulnerability scan failed:", file=sys.stderr)
        for item in findings:
            print(item, file=sys.stderr)
        return 1

    print("ok: no OSV vulnerabilities for locked dependencies or vendored PyYAML 6.0.3")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
