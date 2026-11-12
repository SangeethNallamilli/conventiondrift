"""T-004 release check: the built wheel ships the vendored PyYAML and nothing compiled.

Traceability: SEC-T16, AC-N3.11 (vendor manifest), PLAN T-004 / T-055.

From ADR-0002 Amendment 2 ("the pure-Python ``lib/yaml/`` package only, with no ``_yaml``
C extension or ``.pyx``") and the MANIFEST's own excluded list (C extension, ``_yaml``
package, ``.so``/``.pyc``/``__pycache__``, ``.pyx``/``.pxd``/``.c``/``.h``).

Builds offline with the repo's pinned backend in the current (hashed) venv:
``pip wheel --no-deps --no-build-isolation --no-index``. The source is copied to a temp
directory first so the build leaves nothing in the checkout.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR_DIR = REPO_ROOT / "src" / "conventiondrift" / "_vendor"
WHEEL_VENDOR = "conventiondrift/_vendor"
TIMEOUT_S = 300
FORBIDDEN_SUFFIXES = (".so", ".pyd", ".pyc", ".pyo", ".pyx", ".pxd", ".c", ".h")

VENDORED_TREE_ABSENT = not (VENDOR_DIR / "yaml").is_dir()


def _manifest_paths() -> list[str]:
    text = (VENDOR_DIR / "MANIFEST").read_text(encoding="utf-8")
    return [
        line.split("  ", 1)[1]
        for line in text.splitlines()
        if line and not line.startswith("#") and "  " in line
    ]


def build_wheel(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    shutil.copytree(
        REPO_ROOT / "src",
        project / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
    )
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(REPO_ROOT / name, project / name)
    wheel_dir = tmp_path / "wheels"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "PYTHON"))}
    env.update({"PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--no-index",
            "--wheel-dir",
            str(wheel_dir),
            str(project),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )
    assert proc.returncode == 0, (
        "offline wheel build failed (needs the hashed venv from requirements/build.txt):\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    wheels = sorted(wheel_dir.glob("conventiondrift-*.whl"))
    assert len(wheels) == 1, f"expected one conventiondrift wheel, found {wheels}"
    return wheels[0]


@pytest.mark.xfail(
    condition=VENDORED_TREE_ABSENT, strict=True, reason="T-004 (PR #9 / PR #11) not merged"
)
def test_wheel_vendor_contents(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        contents = {n: zf.read(n) for n in names if n.startswith(f"{WHEEL_VENDOR}/")}

    required = [f"{WHEEL_VENDOR}/LICENSE", f"{WHEEL_VENDOR}/MANIFEST"]
    required += [f"{WHEEL_VENDOR}/{p}" for p in _manifest_paths()]
    required.append(f"{WHEEL_VENDOR}/yaml/__init__.py")
    missing = sorted(set(required) - set(names))
    assert missing == [], f"wheel {wheel.name} is missing: {missing}"

    forbidden = []
    for name in names:
        parts = PurePosixPath(name).parts
        if (
            name.endswith(FORBIDDEN_SUFFIXES)
            or "__pycache__" in parts
            or "_yaml" in parts[:-1]
            or (parts and parts[-1].startswith("_yaml."))
        ):
            forbidden.append(name)
    assert forbidden == [], f"wheel {wheel.name} ships compiled or C-extension files: {forbidden}"

    # The shipped vendored files are the checked-in bytes.
    differing = sorted(
        n
        for n, data in contents.items()
        if not (VENDOR_DIR / n.removeprefix(f"{WHEEL_VENDOR}/")).is_file()
        or (VENDOR_DIR / n.removeprefix(f"{WHEEL_VENDOR}/")).read_bytes() != data
    )
    assert differing == [], f"wheel vendored files differ from (or are absent in) src/: {differing}"
