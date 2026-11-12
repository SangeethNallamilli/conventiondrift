#!/usr/bin/env python3
"""Install pip from requirements/build.txt with --require-hashes, before other locks."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUILD_LOCK = REPO / "requirements" / "build.txt"
PIP_NAME = "pip"
PIP_VERSION = "26.3"


def pip_requirement(lock: Path) -> list[str]:
    text = lock.read_text(encoding="utf-8")
    # Block starting at pip==26.3, including following --hash lines.
    match = re.search(
        rf"^{re.escape(PIP_NAME)}=={re.escape(PIP_VERSION)}[ 	]*\\?\n"
        r"(?:[ 	]+--hash=sha256:[0-9a-f]+[ 	]*\\?\n)+",
        text,
        flags=re.MULTILINE,
    )
    if not match:
        raise SystemExit(f"{lock}: could not find {PIP_NAME}=={PIP_VERSION} with hashes")
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", match.group(0))
    if not hashes:
        raise SystemExit(f"{lock}: {PIP_NAME}=={PIP_VERSION} has no sha256 hashes")
    args = [f"{PIP_NAME}=={PIP_VERSION}"]
    for digest in hashes:
        args.append(f"--hash=sha256:{digest}")
    return args


def main() -> int:
    spec = pip_requirement(BUILD_LOCK)
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--require-hashes",
        "--no-deps",
        *spec,
    ]
    print("installing hash-pinned", f"{PIP_NAME}=={PIP_VERSION}", file=sys.stderr)
    subprocess.run(cmd, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
