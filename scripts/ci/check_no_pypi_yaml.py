#!/usr/bin/env python3
"""Fail if a top-level PyPI yaml / yaml_ft is installed in this environment.

PyPI PyYAML and pyyaml-ft are allowed only in the mutation job (via libcst).
The test, lint, and vendor-network jobs must not have a top-level yaml.

A find_spec('yaml') that resolves under src/conventiondrift/_vendor/yaml/ is
accepted; any other origin (site-packages, dist-packages, etc.) fails.
yaml_ft is never vendored and always fails if present.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VENDOR_YAML = (REPO / "src" / "conventiondrift" / "_vendor" / "yaml").resolve()


def origin_path(spec) -> Path | None:
    origin = getattr(spec, "origin", None)
    if origin and origin not in {"built-in", "frozen"}:
        return Path(origin)
    # Namespace or package without origin: try submodule search locations.
    locs = getattr(spec, "submodule_search_locations", None) or []
    if locs:
        return Path(next(iter(locs)))
    return None


def is_vendored_yaml(path: Path) -> bool:
    try:
        path.resolve().relative_to(VENDOR_YAML)
        return True
    except ValueError:
        return False


def main() -> int:
    errors: list[str] = []
    for name in ("yaml", "yaml_ft"):
        spec = importlib.util.find_spec(name)
        if spec is None:
            print(f"ok: no top-level {name} spec")
            continue
        path = origin_path(spec)
        display = str(path) if path is not None else repr(spec)
        if name == "yaml" and path is not None and is_vendored_yaml(path):
            print(f"ok: {name} resolves to vendored {path}")
            continue
        errors.append(
            f"top-level {name} is installed at {display} (allowed only in the mutation job)"
        )
    banned_dists = ("PyYAML", "pyyaml-ft")
    for dist_name in banned_dists:
        try:
            dist = importlib.metadata.distribution(dist_name)
        except importlib.metadata.PackageNotFoundError:
            print(f"ok: no installed distribution named {dist_name}")
            continue
        loc = getattr(dist, "locate_file", None)
        display = str(dist.locate_file(".")) if callable(loc) else dist_name
        errors.append(
            f"installed distribution {dist.metadata['Name']} {dist.version} at {display} "
            "(allowed only in the mutation job)"
        )
    if errors:
        print("error: PyPI yaml leaked into this environment:", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
