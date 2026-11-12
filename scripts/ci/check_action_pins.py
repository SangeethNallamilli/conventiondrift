#!/usr/bin/env python3
"""Static lint: every third-party uses: is pinned to a 40-char SHA plus a version comment.

Also fails if a workflow uses pull_request_target or workflow_run (R5.2, AC-N3.5).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
USES_RE = re.compile(
    r"^(?P<indent>\s*)uses:\s*['\"]?(?P<value>[^'\"\s#]+)['\"]?\s*(?P<comment>#.*)?\s*$"
)
BANNED_TRIGGERS = ("pull_request_target", "workflow_run")


def iter_workflow_files() -> list[Path]:
    files = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    files += sorted((REPO / ".github" / "workflows").glob("*.yaml"))
    action = REPO / "action.yml"
    if action.is_file():
        files.append(action)
    action2 = REPO / "action.yaml"
    if action2.is_file():
        files.append(action2)
    return files


def is_local(value: str) -> bool:
    return value.startswith("./") or value.startswith(".\\")


def is_docker(value: str) -> bool:
    return value.startswith("docker://")


def check_uses(path: Path, line_no: int, value: str, comment: str | None) -> list[str]:
    errors: list[str] = []
    loc = f"{path.relative_to(REPO)}:{line_no}"
    if is_local(value):
        return errors
    if is_docker(value):
        if "@sha256:" not in value:
            errors.append(f"{loc}: docker uses: must be pinned to a sha256 digest: {value}")
        return errors
    if "@" not in value:
        errors.append(f"{loc}: uses: is unpinned (no ref): {value}")
        return errors
    action, ref = value.rsplit("@", 1)
    if not SHA_RE.fullmatch(ref):
        errors.append(
            f"{loc}: uses: {action} is not pinned to a 40-character commit SHA (got {ref!r})"
        )
        return errors
    if not comment or not comment.strip().lstrip("#").strip():
        errors.append(f"{loc}: uses: {action}@{ref} is missing a version comment on the same line")
    return errors


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for banned in BANNED_TRIGGERS:
            # Word-ish match so we catch keys and values.
            if re.search(rf"(^|[^\w]){banned}([^\w]|$)", stripped):
                errors.append(
                    f"{path.relative_to(REPO)}:{i}: forbidden {banned!r} (R5.2 / AC-N3.5)"
                )
        match = USES_RE.match(raw)
        if match:
            errors.extend(check_uses(path, i, match.group("value"), match.group("comment")))
    return errors


def main() -> int:
    files = iter_workflow_files()
    if not files:
        print("no workflow files found", file=sys.stderr)
        return 1
    errors: list[str] = []
    for path in files:
        errors.extend(check_file(path))
    if errors:
        print("pin lint failed:", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print(f"ok: {len(files)} file(s) have SHA-pinned uses: and no forbidden triggers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
