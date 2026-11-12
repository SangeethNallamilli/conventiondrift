#!/usr/bin/env python3
"""Fail if any commit in the PR range is missing a Signed-off-by trailer (AC-R.2)."""

from __future__ import annotations

import os
import subprocess
import sys

SIGNED_OFF = "signed-off-by:"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def main() -> int:
    base = os.environ.get("DCO_BASE_SHA", "").strip()
    head = os.environ.get("DCO_HEAD_SHA", "").strip()
    if not base or not head:
        print("DCO_BASE_SHA and DCO_HEAD_SHA must be set", file=sys.stderr)
        return 2

    # Make sure both ends exist in the local clone.
    subprocess.run(["git", "rev-parse", "--verify", base], check=True, capture_output=True)
    subprocess.run(["git", "rev-parse", "--verify", head], check=True, capture_output=True)

    shas = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not shas:
        print(f"ok: no commits in {base[:12]}..{head[:12]}")
        return 0

    missing: list[str] = []
    for sha in shas:
        body = git("log", "-1", "--format=%B", sha)
        trailers = [line for line in body.splitlines() if line.lower().startswith(SIGNED_OFF)]
        if not trailers:
            subject = git("log", "-1", "--format=%s", sha)
            missing.append(f"{sha} {subject}")

    if missing:
        print("DCO check failed: these commits have no Signed-off-by line:", file=sys.stderr)
        for line in missing:
            print(line, file=sys.stderr)
        return 1

    print(f"ok: {len(shas)} commit(s) in {base[:12]}..{head[:12]} have Signed-off-by")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
