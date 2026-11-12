#!/usr/bin/env python3
"""Re-run uv pip compile (universal, 3.11, hashes) and require a match."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UV_CMD = [
    "uv",
    "pip",
    "compile",
    "--universal",
    "--python-version",
    "3.11",
    "--generate-hashes",
]
PAIRS = (
    ("requirements/build.in", "requirements/build.txt"),
    ("requirements/dev.in", "requirements/dev.txt"),
)


def compile_one(work: Path, src_in: str, src_out: str) -> None:
    # Relative -o paths keep the header and "# via -r" lines identical.
    cmd = [*UV_CMD, src_in, "-o", src_out]
    print("running:", " ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, check=True, cwd=work)


def main() -> int:
    if shutil.which("uv") is None:
        print("uv is not on PATH", file=sys.stderr)
        return 2

    # Compile with the same relative -o paths as the committed headers, in a temp tree.
    with tempfile.TemporaryDirectory(prefix="lockcheck-") as tmp:
        tmp_path = Path(tmp)
        for src_in, _src_out in PAIRS:
            in_path = tmp_path / src_in
            in_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / src_in, in_path)
        for src_in, src_out in PAIRS:
            compile_one(tmp_path, src_in, src_out)
            expected = (REPO / src_out).read_text(encoding="utf-8")
            actual = (tmp_path / src_out).read_text(encoding="utf-8")
            if expected != actual:
                print(f"lockfile stale: {src_out} does not match a fresh compile", file=sys.stderr)
                subprocess.run(["diff", "-u", str(REPO / src_out), str(tmp_path / src_out)])
                return 1
            print(f"ok: {src_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
