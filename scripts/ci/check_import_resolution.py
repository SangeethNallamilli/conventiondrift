#!/usr/bin/env python3
"""Runtime imports from the package must resolve only to stdlib, conventiondrift, and _vendor.

Run with `python3 -I` so site-packages and the script directory are off sys.path,
matching the Action launch (ADR-0002 Amendment 2, DESIGN §3a).

Owned by Release / DevOps until the Test Engineer moves this into tests/release/.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = (REPO / "src").resolve()

ALLOWED_PREFIXES = ("conventiondrift",)


def is_stdlib(mod) -> bool:
    name = getattr(mod, "__name__", "") or ""
    if name in sys.builtin_module_names:
        return True
    if getattr(mod, "__spec__", None) is not None and getattr(mod.__spec__, "origin", None) in {
        "built-in",
        "frozen",
    }:
        return True
    origin = getattr(mod, "__file__", None)
    if not origin:
        # Builtins and some frozen modules have no file.
        return name.split(".")[0] in sys.stdlib_module_names or name in sys.builtin_module_names
    # Do not Path.resolve() first: Debian sitecustomize.py is a symlink from
    # /usr/lib/pythonX/ into /etc/pythonX/.
    path = Path(origin)
    if "site-packages" in path.parts or "dist-packages" in path.parts:
        return False
    bases = [Path(sys.base_prefix), Path(sys.base_prefix).resolve()]
    for base in bases:
        try:
            path.relative_to(base)
            return True
        except ValueError:
            continue
    return False


def is_allowed_package(mod) -> bool:
    name = getattr(mod, "__name__", "") or ""
    if not name.startswith(ALLOWED_PREFIXES):
        return False
    origin = getattr(mod, "__file__", None)
    if not origin:
        return False
    path = Path(origin).resolve()
    try:
        path.relative_to(SRC / "conventiondrift")
        return True
    except ValueError:
        return False


def main() -> int:
    if SRC.as_posix() not in sys.path:
        sys.path.insert(0, str(SRC))

    # Isolated mode is required so a site-packages PyYAML cannot satisfy imports.
    if not sys.flags.isolated:
        print("error: re-run with python3 -I (isolated mode)", file=sys.stderr)
        return 2

    pkg = importlib.import_module("conventiondrift")
    if not is_allowed_package(pkg):
        print("error: conventiondrift did not resolve under src/", file=sys.stderr)
        return 1

    vendor_mod = importlib.import_module("conventiondrift._vendor")
    if not is_allowed_package(vendor_mod):
        print("error: conventiondrift._vendor did not resolve under src/", file=sys.stderr)
        return 1

    yaml_dir = SRC / "conventiondrift" / "_vendor" / "yaml"
    if yaml_dir.is_dir():
        importlib.import_module("conventiondrift._vendor.yaml")

    # Import every package module except __main__, which starts the CLI.
    package = importlib.import_module("conventiondrift")
    for module in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        if module.name.endswith(".__main__") or module.name == "conventiondrift.__main__":
            continue
        importlib.import_module(module.name)

    if "yaml" in sys.modules:
        mod = sys.modules["yaml"]
        origin = getattr(mod, "__file__", None)
        print(
            f"error: top-level yaml was imported from {origin!r}; "
            "imports must go through conventiondrift._vendor.yaml",
            file=sys.stderr,
        )
        return 1

    bad: list[str] = []
    for name, mod in sorted(sys.modules.items()):
        if mod is None:
            continue
        # Skip the check script itself if it somehow landed on the path.
        if name in {"__main__", "__mp_main__"}:
            continue
        if is_stdlib(mod) or is_allowed_package(mod):
            continue
        # Namespace leftovers or the script runner: ignore modules with no name.
        origin = getattr(mod, "__file__", None)
        bad.append(f"{name} -> {origin}")

    if bad:
        print(
            "error: imports resolved outside stdlib, conventiondrift, and _vendor:", file=sys.stderr
        )
        for item in bad:
            print(f"  {item}", file=sys.stderr)
        return 1

    yaml_mod = sys.modules.get("conventiondrift._vendor.yaml")
    if yaml_dir.is_dir():
        if yaml_mod is None:
            print("error: conventiondrift._vendor.yaml did not load", file=sys.stderr)
            return 1
        origin = Path(yaml_mod.__file__).resolve()
        expected = yaml_dir / "__init__.py"
        if origin != expected.resolve():
            print(
                f"error: conventiondrift._vendor.yaml loaded from {origin}, expected {expected}",
                file=sys.stderr,
            )
            return 1
        with_libyaml = getattr(yaml_mod, "__with_libyaml__", None)
        if with_libyaml:
            print(
                "error: vendored yaml set __with_libyaml__ True; C extension must be absent",
                file=sys.stderr,
            )
            return 1

    print("ok: imports resolve only to stdlib, conventiondrift, and _vendor")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
