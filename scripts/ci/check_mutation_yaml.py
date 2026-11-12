#!/usr/bin/env python3
"""Mutation-job guard: conventiondrift must use vendored yaml, never PyYAML C ext.

The mutation environment installs PyPI PyYAML / pyyaml-ft (via libcst). Before
mutmut runs, and again at pytest session start inside the mutated tree, this
check fails unless:

(a) conventiondrift's yaml import (policy.py's vendored import, or
    conventiondrift._vendor.yaml until policy.py exists) resolves to a file
    under src/conventiondrift/_vendor/yaml/;
(b) none of `_yaml`, `yaml._yaml`, `yaml.cyaml`,
    `conventiondrift._vendor.yaml.cyaml`, `yaml_ft`, or a stray top-level
    `yaml` is in sys.modules after importing conventiondrift and loading a
    policy when that API exists.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterable
from pathlib import Path

FORBIDDEN_MODULES = (
    "_yaml",
    "yaml",
    "yaml_ft",
    "yaml._yaml",
    "yaml.cyaml",
    "conventiondrift._vendor.yaml.cyaml",
)

REPO = Path(__file__).resolve().parents[2]
VENDOR_YAML = (REPO / "src" / "conventiondrift" / "_vendor" / "yaml").resolve()
# mutmut runs tests from a copy under mutants/; accept that tree too.
MUTANTS_VENDOR_YAML = (REPO / "mutants" / "src" / "conventiondrift" / "_vendor" / "yaml").resolve()


def _under_vendor(path: Path) -> bool:
    resolved = path.resolve()
    for root in (VENDOR_YAML, MUTANTS_VENDOR_YAML):
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def vendored_yaml_module():
    """Import yaml the way policy.py does (DESIGN §3a): conventiondrift._vendor.yaml."""
    try:
        policy = importlib.import_module("conventiondrift.policy")
    except ImportError:
        return importlib.import_module("conventiondrift._vendor.yaml")
    # Prefer an attribute the policy module already imported.
    for attr in ("yaml", "vendor_yaml"):
        mod = getattr(policy, attr, None)
        if getattr(mod, "__file__", None):
            return mod
    load = getattr(policy, "load_yaml", None) or getattr(policy, "load", None)
    if callable(load):
        load("key: value\n")
    return importlib.import_module("conventiondrift._vendor.yaml")


def check(modules: Iterable[str] | None = None) -> list[str]:
    import conventiondrift  # noqa: F401

    yaml_mod = vendored_yaml_module()
    origin = getattr(yaml_mod, "__file__", None)
    errors: list[str] = []
    if not origin:
        errors.append("conventiondrift yaml import has no __file__")
    else:
        path = Path(origin)
        if not _under_vendor(path):
            errors.append(
                f"conventiondrift yaml import resolved to {path}, "
                f"not under src/conventiondrift/_vendor/yaml/"
            )
        else:
            print(f"ok: conventiondrift yaml is {path}")

    present = modules if modules is not None else sys.modules
    leaked = [name for name in FORBIDDEN_MODULES if name in present]
    if leaked:
        errors.append(f"forbidden yaml modules in sys.modules after import: {leaked}")
    else:
        print("ok: no _yaml / cyaml / yaml_ft / top-level yaml in sys.modules")
    return errors


def pytest_sessionstart(session: object) -> None:
    # pluggy validates hookimpl argument names against the hookspec, so this
    # must be named `session` (it is unused).
    del session
    errors = check()
    if errors:
        raise RuntimeError("mutation yaml isolation failed: " + "; ".join(errors))


def main() -> int:
    errors = check()
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
