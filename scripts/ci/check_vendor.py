#!/usr/bin/env python3
"""Re-extract the pinned PyYAML 6.0.3 sdist and compare it to src/conventiondrift/_vendor/.

SR-011 / T-004: compare the 16 pure-Python lib/yaml/*.py files (not cyaml.py) plus
LICENSE. Fail if cyaml.py or any _yaml* file appears under _vendor/yaml/. The set
of hashed MANIFEST paths must equal the set of vendored payload files, with no
extras.

Owned by Release / DevOps until the Test Engineer moves this into tests/release/.
"""

from __future__ import annotations

import hashlib
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VENDOR = REPO / "src" / "conventiondrift" / "_vendor"
MANIFEST = VENDOR / "MANIFEST"

# ADR-0002 Amendment 2 / SR-005. The hash, not the URL, is authoritative.
EXPECTED_SDIST_SHA256 = "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"
DEFAULT_SDIST_URL = (
    "https://files.pythonhosted.org/packages/"
    "05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/"
    "pyyaml-6.0.3.tar.gz"
)

# Wrapper files that live in _vendor/ but are ours, not sdist payload.
OWN_FILES = frozenset({"MANIFEST", "__init__.py"})

BANNED_YAML_NAMES = frozenset({"cyaml.py"})
BANNED_YAML_PREFIXES = ("_yaml",)
BANNED_SUFFIXES = {".so", ".pyc", ".pyx", ".pxd", ".c", ".h"}
# cyaml.py is present in the sdist's lib/yaml/; it must not be vendored (SR-011).
SDIST_YAML_EXCLUDED = frozenset({"cyaml.py"})

HASH_LINE = __import__("re").compile(r"^([0-9a-f]{64})  ([^\s]+)\s*$")


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def parse_manifest(text: str) -> tuple[dict[str, str], dict[str, str]]:
    headers: dict[str, str] = {}
    files: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            body = line[1:].strip()
            if ":" in body:
                key, value = body.split(":", 1)
                headers[key.strip().lower()] = value.strip()
            continue
        match = HASH_LINE.match(raw)
        if not match:
            raise SystemExit(f"MANIFEST: unrecognised line: {raw!r}")
        digest, rel = match.group(1), match.group(2)
        if rel in files:
            raise SystemExit(f"MANIFEST: duplicate path {rel}")
        files[rel] = digest
    return headers, files


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def download_sdist(url: str, dest: Path) -> None:
    print(f"downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=60) as resp, dest.open("wb") as out:
        shutil_copy = out.write
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            shutil_copy(chunk)


def banned_yaml_reason(name: str) -> str | None:
    if name in BANNED_YAML_NAMES or name in SDIST_YAML_EXCLUDED:
        return f"banned vendored file {name} (SR-011)"
    if name.startswith(BANNED_YAML_PREFIXES):
        return f"banned _yaml* file {name}"
    if name == "__pycache__" or Path(name).suffix in BANNED_SUFFIXES:
        return f"banned compiled or C-extension artifact {name}"
    return None


def payload_files_on_disk() -> dict[str, Path]:
    """Payload paths relative to _vendor/, excluding our wrapper files."""
    found: dict[str, Path] = {}
    yaml_dir = VENDOR / "yaml"
    if yaml_dir.exists():
        for path in sorted(yaml_dir.rglob("*")):
            rel = path.relative_to(VENDOR).as_posix()
            if path.is_dir():
                if path.name == "__pycache__":
                    raise SystemExit(banned_yaml_reason(path.name))
                continue
            found[rel] = path
    license_path = VENDOR / "LICENSE"
    if license_path.is_file():
        found["LICENSE"] = license_path
    return found


def check_banned_on_disk() -> list[str]:
    errors: list[str] = []
    yaml_dir = VENDOR / "yaml"
    if (VENDOR / "_yaml").exists():
        errors.append("banned path _vendor/_yaml is present")
    if not yaml_dir.exists():
        return errors
    for path in yaml_dir.rglob("*"):
        reason = banned_yaml_reason(path.name)
        if reason:
            errors.append(f"{path.relative_to(REPO)}: {reason}")
    return errors


def main() -> int:
    if not MANIFEST.is_file():
        return fail(f"missing {MANIFEST}")

    headers, manifest_files = parse_manifest(MANIFEST.read_text(encoding="utf-8"))
    header_hash = headers.get("sdist-sha256", "").lower()
    if header_hash and header_hash != EXPECTED_SDIST_SHA256:
        return fail(
            "MANIFEST sdist-sha256 does not match the ADR-0002 / SR-005 pin "
            f"{EXPECTED_SDIST_SHA256} (got {header_hash})"
        )
    url = headers.get("sdist-url") or DEFAULT_SDIST_URL

    # MANIFEST must not list banned files, even as "included".
    for rel in manifest_files:
        name = Path(rel).name
        reason = banned_yaml_reason(name)
        if reason:
            return fail(f"MANIFEST lists {rel}: {reason}")

    errors = check_banned_on_disk()
    if errors:
        return fail("\n".join(errors))

    on_disk = payload_files_on_disk()
    manifest_set = set(manifest_files)
    disk_set = set(on_disk)
    extra_disk = sorted(disk_set - manifest_set)
    extra_manifest = sorted(manifest_set - disk_set)
    if extra_disk or extra_manifest:
        parts = ["MANIFEST paths and vendored payload files are not the same set"]
        if extra_disk:
            parts.append("on disk but not in MANIFEST: " + ", ".join(extra_disk))
        if extra_manifest:
            parts.append("in MANIFEST but missing on disk: " + ", ".join(extra_manifest))
        return fail("\n".join(parts))

    # Confirm no unexpected extras at the _vendor root.
    allowed_root = OWN_FILES | {"LICENSE", "yaml", "__pycache__"}
    for entry in VENDOR.iterdir():
        if entry.name in allowed_root or entry.name.startswith("."):
            continue
        return fail(f"unexpected path in _vendor/: {entry.name}")

    with tempfile.TemporaryDirectory(prefix="pyyaml-sdist-") as tmp:
        tmp_path = Path(tmp)
        sdist = tmp_path / "pyyaml-6.0.3.tar.gz"
        download_sdist(url, sdist)
        actual = sha256_file(sdist)
        if actual != EXPECTED_SDIST_SHA256:
            return fail(f"sdist sha256 mismatch: expected {EXPECTED_SDIST_SHA256}, got {actual}")
        print(f"sdist sha256 ok: {actual}", file=sys.stderr)

        extract = tmp_path / "extract"
        extract.mkdir()
        with tarfile.open(sdist, "r:gz") as tf:
            try:
                tf.extractall(extract, filter="data")
            except TypeError:
                tf.extractall(extract)

        sdist_root = extract / "pyyaml-6.0.3"
        sdist_yaml = sdist_root / "lib" / "yaml"
        if not sdist_yaml.is_dir():
            return fail("sdist is missing lib/yaml/")

        sdist_payload: dict[str, Path] = {}
        for path in sorted(sdist_yaml.iterdir()):
            if not path.is_file() or path.suffix != ".py":
                return fail(f"unexpected sdist lib/yaml entry: {path.name}")
            if path.name in SDIST_YAML_EXCLUDED:
                continue
            sdist_payload[f"yaml/{path.name}"] = path
        license_src = sdist_root / "LICENSE"
        if not license_src.is_file():
            return fail("sdist is missing LICENSE")
        sdist_payload["LICENSE"] = license_src

        if set(sdist_payload) != manifest_set:
            parts = [
                "vendored set must be 16 sdist lib/yaml/*.py files plus LICENSE, excluding cyaml.py"
            ]
            only_sdist = sorted(set(sdist_payload) - manifest_set)
            only_manifest = sorted(manifest_set - set(sdist_payload))
            if only_sdist:
                parts.append("in sdist (expected) but not in MANIFEST: " + ", ".join(only_sdist))
            if only_manifest:
                parts.append(
                    "in MANIFEST but not in expected sdist set: " + ", ".join(only_manifest)
                )
            return fail("\n".join(parts))

        yaml_count = sum(1 for k in manifest_set if k.startswith("yaml/") and k.endswith(".py"))
        if yaml_count != 16 or "LICENSE" not in manifest_set:
            return fail(
                f"expected 16 yaml/*.py files plus LICENSE in MANIFEST; "
                f"got {yaml_count} yaml files and LICENSE={'LICENSE' in manifest_set}"
            )

        mismatches: list[str] = []
        for rel, digest in sorted(manifest_files.items()):
            vendored = on_disk[rel]
            data = vendored.read_bytes()
            if sha256_bytes(data) != digest:
                mismatches.append(f"{rel}: MANIFEST hash does not match the file on disk")
            src = sdist_payload[rel]
            if src.read_bytes() != data:
                mismatches.append(f"{rel}: not byte-identical to the sdist counterpart")
        if mismatches:
            return fail("\n".join(mismatches))

    print(
        f"ok: {len(manifest_files)} vendored files match the PyYAML 6.0.3 sdist "
        f"and MANIFEST; cyaml.py / _yaml* absent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
