#!/usr/bin/env python3
"""Build and install Git 2.24.4 (minimum supported version) from a checksum-pinned tarball.

Architect (T-003): the floor is 2.24, needed for --end-of-options, with no runtime check.
The official tarball and sha256 come from kernel.org sha256sums.asc.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "2.24.4"
URL = f"https://www.kernel.org/pub/software/scm/git/git-{VERSION}.tar.xz"
SHA256 = "9b80e7707db22c932b7a3d56ef8a7cde7db04a2f329830b2c06a9a248f9e6b83"


def download(url: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise SystemExit(f"refusing non-https URL: {url}")
    print(f"downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=60) as resp, dest.open("wb") as out:
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)


def main() -> int:
    prefix = Path(os.environ.get("GIT_MIN_PREFIX") or Path.home() / f"git-{VERSION}").resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="git-src-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / f"git-{VERSION}.tar.xz"
        download(URL, archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != SHA256:
            print(f"git tarball sha256 mismatch: expected {SHA256}, got {digest}", file=sys.stderr)
            return 1
        with tarfile.open(archive, "r:xz") as tf:
            try:
                tf.extractall(tmp_path, filter="data")
            except TypeError:
                tf.extractall(tmp_path)
        src = tmp_path / f"git-{VERSION}"
        if not src.is_dir():
            print(f"missing source directory {src}", file=sys.stderr)
            return 1
        jobs = os.cpu_count() or 2
        subprocess.run(
            ["make", f"prefix={prefix}", f"-j{jobs}", "all"],
            cwd=src,
            check=True,
        )
        subprocess.run(
            ["make", f"prefix={prefix}", "install"],
            cwd=src,
            check=True,
        )
    binary = prefix / "bin" / "git"
    if not binary.is_file():
        print(f"git binary missing at {binary}", file=sys.stderr)
        return 1
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    proc = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True)
    version = proc.stdout.strip()
    print(version)
    if f"git version {VERSION}" not in version:
        print(f"expected git version {VERSION}, got {version!r}", file=sys.stderr)
        return 1
    # Tell the caller (and GitHub Actions) to put this git first on PATH.
    print(f"GIT_MIN_BIN={prefix / 'bin'}")
    path_file = os.environ.get("GITHUB_PATH")
    if path_file:
        with open(path_file, "a", encoding="utf-8") as fh:
            fh.write(f"{prefix / 'bin'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
