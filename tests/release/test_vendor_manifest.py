"""T-004 release check: vendored PyYAML matches its pinned sdist (ADR-0002 Amendment 2).

Traceability: SEC-T16 (vendored-hash test), AC-N3.11 (vendor manifest), PLAN T-004 / T-055.

Written from ADR-0002 Amendment 2 and PLAN T-004, not from the vendored code:
  * the pinned sdist is PyYAML 6.0.3 with SHA-256 d7662337...4190f;
  * only the pure-Python ``lib/yaml/`` package (plus the sdist LICENSE) is vendored;
  * every vendored file is byte-identical to its sdist counterpart and listed with its
    SHA-256 in ``_vendor/MANIFEST``.

MANIFEST syntax this test reads (test-chosen where the MANIFEST does not define one yet):
  * ``# key: value`` header lines; ``sdist-url`` and ``sdist-sha256`` are required.
  * ``<sha256>  <path>`` entries (sha256sum format), paths relative to ``_vendor/``.
  * ``# excluded: ...`` lines. An upstream ``lib/yaml/<name>`` file may be absent from the
    vendored tree only if an ``# excluded:`` line names it explicitly as ``yaml/<name>`` or
    ``lib/yaml/<name>`` (for example ``# excluded: yaml/cyaml.py (SR-011)``). Prose such as
    "C extension" does not exclude a ``lib/yaml/`` file.
  * ``# patched: <path> <reason>`` lines. A file declared this way may differ from the
    sdist (it must still exist upstream, actually differ, and match its MANIFEST hash).

Needs network access to the pinned ``sdist-url`` (PLAN T-004: "re-extracts the pinned
sdist") when no hash-verified cached sdist is present. Without a valid cache or
network the test fails with a clear message; it never skips. The module is marked
``network`` and deselected by default.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR_DIR = REPO_ROOT / "src" / "conventiondrift" / "_vendor"
MANIFEST = VENDOR_DIR / "MANIFEST"

# ADR-0002 Amendment 2, "Vendored libraries" table.
PINNED_NAME = "PyYAML"
PINNED_VERSION = "6.0.3"
PINNED_SDIST_SHA256 = "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"

# Files under _vendor/ that are ours, not vendored copies.
OWN_FILES = frozenset({"MANIFEST", "__init__.py"})

DOWNLOAD_TIMEOUT_S = 60
HASH_LINE = re.compile(r"^([0-9a-f]{64})  (\S+)$")
HEADER_LINE = re.compile(r"^#\s*([A-Za-z0-9-]+):\s*(.*)$")
PATCHED_LINE = re.compile(r"^#\s*patched:\s*(\S+)\s+(\S.*)$")
PATH_TOKEN = re.compile(r"[A-Za-z0-9_./-]+")


# Deselected by default (addopts -m "not network"). Fails, never skips, if run
# offline under ``pytest -m network`` with no valid cached sdist.
pytestmark = pytest.mark.network


@dataclass
class Manifest:
    header: dict[str, str] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)
    patched: dict[str, str] = field(default_factory=dict)
    excluded: set[str] = field(default_factory=set)
    bad_lines: list[str] = field(default_factory=list)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_manifest(text: str) -> Manifest:
    m = Manifest()
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("#"):
            patched = PATCHED_LINE.match(line)
            if patched:
                m.patched[patched.group(1)] = patched.group(2)
                continue
            header = HEADER_LINE.match(line)
            if header and header.group(1) == "excluded":
                for token in PATH_TOKEN.findall(header.group(2)):
                    token = token.rstrip(".")
                    if "/" in token:
                        m.excluded.add(token.removeprefix("lib/"))
                continue
            if header:
                m.header[header.group(1)] = header.group(2).strip()
            continue
        entry = HASH_LINE.match(line)
        if entry is None:
            m.bad_lines.append(line)
            continue
        if entry.group(2) in m.hashes:
            m.bad_lines.append(f"duplicate entry: {line}")
        m.hashes[entry.group(2)] = entry.group(1)
    return m


def files_on_disk() -> set[str]:
    found = set()
    for path in VENDOR_DIR.rglob("*"):
        rel = path.relative_to(VENDOR_DIR)
        # __pycache__ is never tracked (.gitignore); the wheel test checks it never ships.
        if "__pycache__" in rel.parts or not path.is_file():
            continue
        found.add(rel.as_posix())
    return found - OWN_FILES


def _sdist_counterpart(vendored: str) -> str | None:
    """Map a path under _vendor/ to its path inside the sdist (below the top directory)."""
    if vendored == "LICENSE":
        return "LICENSE"
    if vendored.startswith("yaml/") and vendored.endswith(".py"):
        return f"lib/{vendored}"
    return None


def load_manifest() -> Manifest:
    assert MANIFEST.is_file(), f"{MANIFEST} is missing"
    return parse_manifest(MANIFEST.read_text(encoding="utf-8"))


def _sdist_cache_path(filename: str) -> Path:
    """Persistent cache path for the pinned sdist; override with CONVENTIONDRIFT_SDIST_CACHE."""
    root = os.environ.get("CONVENTIONDRIFT_SDIST_CACHE")
    cache_dir = Path(root) if root else Path(tempfile.gettempdir()) / "conventiondrift-sdist-cache"
    return cache_dir / filename


def load_sdist(manifest: Manifest) -> dict[str, bytes]:
    """Regular files of the pinned sdist, keyed by path below its single top directory."""
    url = manifest.header.get("sdist-url", "")
    want = manifest.header.get("sdist-sha256", "")
    assert url.startswith("https://"), f"MANIFEST needs an https '# sdist-url:' line, got {url!r}"
    assert want == PINNED_SDIST_SHA256, (
        f"MANIFEST sdist-sha256 {want!r} is not the ADR-0002 pin {PINNED_SDIST_SHA256}"
    )
    cache = _sdist_cache_path(url.rsplit("/", 1)[-1])
    data: bytes | None = None
    if cache.is_file():
        cached = cache.read_bytes()
        if _sha256(cached) == want:
            data = cached
    if data is None:
        try:
            with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_S) as resp:  # noqa: S310
                data = resp.read()
        except OSError as exc:
            pytest.fail(
                f"test_vendor_manifest needs network access to download the pinned sdist {url} "
                f"(PLAN T-004 re-extracts it); download failed: {exc!r}"
            )
        got = _sha256(data)
        assert got == want, f"downloaded sdist {url} has sha256 {got}, MANIFEST pins {want}"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(data)
    else:
        got = _sha256(data)
        assert got == want, f"cached sdist {cache} has sha256 {got}, MANIFEST pins {want}"

    files: dict[str, bytes] = {}
    tops: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            top, _, rest = member.name.partition("/")
            tops.add(top)
            if member.isfile() and rest:
                extracted = tar.extractfile(member)
                assert extracted is not None
                files[rest] = extracted.read()
    assert len(tops) == 1, f"sdist should have one top directory, found {sorted(tops)}"
    return files


def test_vendor_manifest() -> None:
    manifest = load_manifest()
    sdist_files = load_sdist(manifest)
    problems: list[str] = []
    problems += [f"unparseable MANIFEST line: {line!r}" for line in manifest.bad_lines]

    if manifest.header.get("name") != PINNED_NAME:
        problems.append(f"MANIFEST name {manifest.header.get('name')!r} != {PINNED_NAME!r}")
    if manifest.header.get("version") != PINNED_VERSION:
        problems.append(
            f"MANIFEST version {manifest.header.get('version')!r} != {PINNED_VERSION!r}"
        )

    # MANIFEST lists exactly the files on disk.
    on_disk = files_on_disk()
    listed = set(manifest.hashes)
    problems += [f"on disk but not in MANIFEST: {p}" for p in sorted(on_disk - listed)]
    problems += [f"in MANIFEST but not on disk: {p}" for p in sorted(listed - on_disk)]
    if "LICENSE" not in listed:
        problems.append("the sdist LICENSE is not vendored and listed")

    # Every listed hash is correct, and every file matches the sdist unless declared patched.
    for rel, want in sorted(manifest.hashes.items()):
        path = VENDOR_DIR / rel
        if not path.is_file():
            continue
        data = path.read_bytes()
        if _sha256(data) != want:
            problems.append(f"MANIFEST hash wrong for {rel}: listed {want}, file {_sha256(data)}")
        upstream_rel = _sdist_counterpart(rel)
        if upstream_rel is None or upstream_rel not in sdist_files:
            problems.append(f"{rel} has no counterpart in the sdist (expected {upstream_rel})")
            continue
        identical = data == sdist_files[upstream_rel]
        if rel in manifest.patched:
            if identical:
                problems.append(f"{rel} is declared patched but is identical to the sdist")
        elif not identical:
            problems.append(f"{rel} differs from sdist {upstream_rel} and is not declared patched")

    for rel in sorted(manifest.patched):
        if rel not in manifest.hashes:
            problems.append(f"'# patched: {rel}' names a file with no MANIFEST hash entry")

    # Every upstream lib/yaml/ file is vendored, or explicitly excluded (and then absent).
    upstream_yaml = {p.removeprefix("lib/") for p in sdist_files if p.startswith("lib/yaml/")}
    for rel in sorted(upstream_yaml):
        if rel in manifest.excluded:
            if rel in on_disk:
                problems.append(f"{rel} is listed as excluded but is present")
        elif rel not in on_disk:
            problems.append(f"upstream lib/{rel} is missing and not listed under '# excluded:'")
    for rel in sorted(manifest.excluded):
        if rel.startswith("yaml/") and rel not in upstream_yaml:
            problems.append(f"'# excluded:' names {rel}, which is not in the sdist's lib/yaml/")

    assert not problems, "vendored PyYAML does not match its pinned sdist:\n" + "\n".join(problems)
