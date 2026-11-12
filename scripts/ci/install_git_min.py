#!/usr/bin/env python3
"""Download, GPG-verify, and install the minimum supported Git from kernel.org.

Version, tarball sha256, and signer fingerprint come from the environment
(GIT_MIN_VERSION, GIT_MIN_SHA256, GIT_MIN_SIGNER_FPR) so the CI job is the
single place to change them.

The clearsigned sha256sums.asc is verified with only the pinned autosigner
key in a temporary GNUPGHOME. There is no keyserver fetch at runtime.
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
REPO = Path(__file__).resolve().parents[2]
PINNED_KEY = REPO / "scripts" / "ci" / "keys" / "kernelorg-autosigner.asc"
FPR_RE = re.compile(r"^[0-9A-F]{40}$")


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"{name} must be set")
    return value


def normalize_fpr(value: str) -> str:
    return re.sub(r"\s+", "", value).upper()


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 256)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256sums_asc(asc_path: Path, expected_fpr: str) -> str:
    """Verify the clearsigned checksums file. Return the VALIDSIG status line."""
    if not PINNED_KEY.is_file():
        raise SystemExit(f"pinned OpenPGP key missing: {PINNED_KEY}")
    if not FPR_RE.fullmatch(expected_fpr):
        raise SystemExit(f"GIT_MIN_SIGNER_FPR is not a 40-char fingerprint: {expected_fpr!r}")

    with tempfile.TemporaryDirectory(prefix="gnupg-git-min-") as home:
        os.chmod(home, 0o700)
        gpg_home = Path(home)
        # Never fetch keys at runtime.
        (gpg_home / "gpg.conf").write_text(
            "no-auto-key-retrieve\nkeyserver-options no-auto-key-retrieve,no-honor-keyserver-url\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["GNUPGHOME"] = home
        imported = subprocess.run(
            ["gpg", "--batch", "--import", str(PINNED_KEY)],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            sys.stderr.write(imported.stderr)
            raise SystemExit("failed to import the pinned autosigner key")
        # Confirm we imported exactly the pinned fingerprint.
        listed = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--list-keys", "--fingerprint"],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        fps = [
            line.split(":")[9].upper()
            for line in listed.stdout.splitlines()
            if line.startswith("fpr:")
        ]
        if expected_fpr not in fps:
            raise SystemExit(
                f"pinned key fingerprint not in imported keyring (want {expected_fpr}, got {fps})"
            )
        verified = subprocess.run(
            ["gpg", "--batch", "--status-fd", "1", "--verify", str(asc_path)],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        sys.stderr.write(verified.stderr)
        if verified.returncode != 0:
            raise SystemExit("gpg --verify of sha256sums.asc failed")
        validsigs = [
            line for line in verified.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")
        ]
        if len(validsigs) != 1:
            raise SystemExit(f"expected exactly one VALIDSIG line, got {validsigs!r}")
        fields = validsigs[0].split()
        # VALIDSIG <fpr> ... <primary_fpr>
        sig_fpr = fields[2].upper()
        primary_fpr = fields[-1].upper()
        if sig_fpr != expected_fpr or primary_fpr != expected_fpr:
            raise SystemExit(
                f"VALIDSIG fingerprint mismatch: got sig={sig_fpr} primary={primary_fpr}, "
                f"expected {expected_fpr}"
            )
        print(validsigs[0])
        return validsigs[0]


def checksum_line(asc_text: str, filename: str) -> str:
    for raw in asc_text.splitlines():
        if raw.endswith(f"  {filename}") or raw.endswith(f" {filename}"):
            digest = raw.split()[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    raise SystemExit(f"{filename} not found in sha256sums.asc")


def main() -> int:
    version = required_env("GIT_MIN_VERSION")
    expected = required_env("GIT_MIN_SHA256").lower()
    signer = normalize_fpr(required_env("GIT_MIN_SIGNER_FPR"))
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        print(f"GIT_MIN_SHA256 is not a 64-char sha256: {expected!r}", file=sys.stderr)
        return 1

    filename = f"git-{version}.tar.xz"
    url = f"{KERNEL_ORG}/{filename}"
    sums_url = f"{KERNEL_ORG}/sha256sums.asc"
    prefix = Path(os.environ.get("GIT_MIN_PREFIX") or Path.home() / f"git-{version}").resolve()
    prefix.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="git-src-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / filename
        sums = tmp_path / "sha256sums.asc"
        download(sums_url, sums)
        verify_sha256sums_asc(sums, signer)
        listed = checksum_line(sums.read_text(encoding="utf-8", errors="replace"), filename)
        if listed != expected:
            print(
                f"sha256sums.asc line for {filename} is {listed}, "
                f"pinned GIT_MIN_SHA256 is {expected}",
                file=sys.stderr,
            )
            return 1
        download(url, archive)
        digest = sha256_file(archive)
        if digest != expected:
            print(
                f"git tarball sha256 mismatch: expected {expected}, got {digest}", file=sys.stderr
            )
            return 1
        print(f"tarball sha256 ok: {digest}")
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
            fh.write(str(prefix / "bin") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
