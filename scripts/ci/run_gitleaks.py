#!/usr/bin/env python3
"""Download a checksum-pinned gitleaks release and scan the repository."""

from __future__ import annotations

import hashlib
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VERSION = "8.30.1"
URL = (
    f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/"
    f"gitleaks_{VERSION}_linux_x64.tar.gz"
)
SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"


def download(url: str, dest: Path) -> None:
    print(f"downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=60) as resp, dest.open("wb") as out:
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gitleaks-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "gitleaks.tar.gz"
        download(URL, archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != SHA256:
            print(f"gitleaks sha256 mismatch: expected {SHA256}, got {digest}", file=sys.stderr)
            return 1
        with tarfile.open(archive, "r:gz") as tf:
            try:
                tf.extractall(tmp_path, filter="data")
            except TypeError:
                tf.extractall(tmp_path)
        binary = tmp_path / "gitleaks"
        if not binary.is_file():
            print("gitleaks binary missing from the archive", file=sys.stderr)
            return 1
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        proc = subprocess.run(
            [str(binary), "detect", "--source", str(REPO), "--verbose", "--redact"],
            check=False,
        )
        return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
