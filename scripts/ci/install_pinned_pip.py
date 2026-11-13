#!/usr/bin/env python3
"""Install pip from requirements/build.txt with --require-hashes, before other locks.

The bundled pip CLI rejects --hash as a command-line option. Hashes must be
written to a temporary requirements file and consumed with -r.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUILD_LOCK = REPO / "requirements" / "build.txt"
PIP_NAME = "pip"
PIP_VERSION = "26.3"


def pip_requirement_text(lock: Path) -> str:
    text = lock.read_text(encoding="utf-8")
    # Block starting at pip==26.3, including following --hash lines.
    match = re.search(
        rf"^{re.escape(PIP_NAME)}=={re.escape(PIP_VERSION)}[ \t]*\\?\n"
        r"(?:[ \t]+--hash=sha256:[0-9a-f]+[ \t]*\\?\n)+",
        text,
        flags=re.MULTILINE,
    )
    if not match:
        raise SystemExit(f"{lock}: could not find {PIP_NAME}=={PIP_VERSION} with hashes")
    block = match.group(0)
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", block)
    if not hashes:
        raise SystemExit(f"{lock}: {PIP_NAME}=={PIP_VERSION} has no sha256 hashes")
    lines = [f"{PIP_NAME}=={PIP_VERSION} \\"]
    for i, digest in enumerate(hashes):
        suffix = " \\" if i < len(hashes) - 1 else ""
        lines.append(f"    --hash=sha256:{digest}{suffix}")
    return "\n".join(lines) + "\n"


def main() -> int:
    requirement = pip_requirement_text(BUILD_LOCK)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        suffix="-pip-require-hashes.txt",
        prefix="pinned-pip-",
        delete=False,
    ) as fh:
        fh.write(requirement)
        tmp = Path(fh.name)
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--require-hashes",
        "--no-deps",
        "--only-binary=:all:",
        "-r",
        str(tmp),
    ]
    print("installing hash-pinned", f"{PIP_NAME}=={PIP_VERSION}", file=sys.stderr)
    try:
        subprocess.run(cmd, check=True)
    finally:
        tmp.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
