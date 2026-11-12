#!/usr/bin/env python3
"""Build and install the minimum supported Git from a checksum-pinned tarball.

Version and sha256 come from the environment (GIT_MIN_VERSION, GIT_MIN_SHA256)
so the CI job is the single place to change them. Official checksums:
https://www.kernel.org/pub/software/scm/git/sha256sums.asc
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

KERNEL_ORG = "https://www.kernel.org/pub/software/scm/git"


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} must be set")
    return value


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
    version = required_env("GIT_MIN_VERSION")
    expected = required_env("GIT_MIN_SHA256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        print(f"GIT_MIN_SHA256 is not a 64-char sha256: {expected!r}", file=sys.stderr)
        return 1
    url = f"{KERNEL_ORG}/git-{version}.tar.xz"
    prefix = Path(os.environ.get("GIT_MIN_PREFIX") or Path.home() / f"git-{version}").resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="git-src-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / f"git-{version}.tar.xz"
        download(url, archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != expected:
            print(
                f"git tarball sha256 mismatch: expected {expected}, got {digest}", file=sys.stderr
            )
            return 1
        with tarfile.open(archive, "r:xz") as tf:
            try:
                tf.extractall(tmp_path, filter="data")
            except TypeError:
                tf.extractall(tmp_path)
        src = tmp_path / f"git-{version}"
        if not src.is_dir():
            print(f"missing source directory {src}", file=sys.stderr)
            return 1
        jobs = os.cpu_count() or 2
        subprocess.run(["make", f"prefix={prefix}", f"-j{jobs}", "all"], cwd=src, check=True)
        subprocess.run(["make", f"prefix={prefix}", "install"], cwd=src, check=True)
    binary = prefix / "bin" / "git"
    if not binary.is_file():
        print(f"git binary missing at {binary}", file=sys.stderr)
        return 1
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    proc = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True)
    reported = proc.stdout.strip()
    print(reported)
    if f"git version {version}" not in reported:
        print(f"expected git version {version}, got {reported!r}", file=sys.stderr)
        return 1
    print(f"GIT_MIN_BIN={prefix / 'bin'}")
    path_file = os.environ.get("GITHUB_PATH")
    if path_file:
        with open(path_file, "a", encoding="utf-8") as fh:
            fh.write(f"{prefix / 'bin'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
