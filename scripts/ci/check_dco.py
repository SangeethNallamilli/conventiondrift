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

    # Uniform exclusion rule (2026-11-26): a commit that already exists
    # on an exclusion ref (e.g. main, release/develop) needs no new
    # trailer — only commits the PR introduces (reachable from neither
    # the base nor any exclusion ref) are checked. The caller passes
    # space-separated refs via DCO_EXCLUDE_REFS; fail closed if any of
    # them cannot be resolved.
    exclude_refs = os.environ.get("DCO_EXCLUDE_REFS", "").split()
    for ref in exclude_refs:
        subprocess.run(["git", "rev-parse", "--verify", ref], check=True, capture_output=True)

    # Make sure both ends exist in the local clone.
    subprocess.run(["git", "rev-parse", "--verify", base], check=True, capture_output=True)
    subprocess.run(["git", "rev-parse", "--verify", head], check=True, capture_output=True)

    shas = git("rev-list", "--reverse", head, "--not", base, *exclude_refs).splitlines()
    if not shas:
        print(f"ok: no commits in {base[:12]}..{head[:12]} beyond the exclusion refs")
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

    print(f"ok: {len(shas)} checked commit(s) in {base[:12]}..{head[:12]} have Signed-off-by")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
