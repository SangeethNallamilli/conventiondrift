"""T-004 / SR-011 release checks: importing the vendored PyYAML never reaches outside it.

Traceability: SEC-T16 (imports resolve only to stdlib, ``conventiondrift`` and ``_vendor``),
SECURITY-LOG SR-011, PLAN T-004 / T-055.

From ADR-0002 (the CI check "confirms ... that no import resolves outside the stdlib,
``conventiondrift`` and ``_vendor``") and Amendment 2 (launch with ``python -I``; only
``<action_path>/src`` goes on ``sys.path``). The runner's site-packages may hold any
``yaml`` package, so each case plants a decoy top-level ``yaml`` package (with ``yaml/_yaml``)
and a decoy top-level ``_yaml`` package, placed both before and after ``src`` on
``sys.path``. Every decoy module writes a marker file if it is ever executed.

Each probe runs in a fresh ``python -I -B`` subprocess (``-B`` so the probe writes no
``__pycache__`` into ``src/``).
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
TIMEOUT_S = 60

# Mutation testing (T-003, mutmut==3.8.1 pinned in requirements/mutation.txt): mutmut copies
# the repo into ``mutants/`` and rewrites every mutated module in ``src/`` to start with
# ``from mutmut.mutation.trampoline import ...``. Importing ``conventiondrift`` from the
# mutated tree therefore pulls in exactly these mutmut modules (job 131751953828). They are
# allowed only while mutmut itself is running: mutmut 3.8.1 always puts MUTANT_UNDER_TEST in
# the environment (``set_mutant_under_test``: "stats", "fail", "" for the clean run, or the
# mutant name), and the tests then run from the ``mutants/`` copy. In normal CI neither holds
# and the check stays strict.
MUTMUT_ENV_VAR = "MUTANT_UNDER_TEST"
MUTMUT_COPY_DIR = "mutants"
MUTMUT_TRAMPOLINE_MODULES = frozenset(
    {
        "mutmut",
        "mutmut.configuration",
        "mutmut.core",
        "mutmut.mutation",
        "mutmut.mutation.data",
        "mutmut.mutation.trampoline",
        "mutmut.mutation.trampoline_templates",
        "mutmut.state",
        "mutmut.stats",
        "mutmut.ui",
        "mutmut.ui.terminal",
        "mutmut.utils",
        "mutmut.utils.format_utils",
    }
)


DECOY_MODULE = textwrap.dedent(
    """\
    import pathlib as _p
    _p.Path({marker!r}).joinpath(__name__).write_text("executed", encoding="utf-8")


    class CParser:
        pass


    class CEmitter:
        pass
    """
)

PROBE = textwrap.dedent(
    """\
    import json
    import sys

    src, decoy, position, out = sys.argv[1:5]
    if position == "front":
        sys.path[:0] = [decoy, src]
    else:
        sys.path.insert(0, src)
        sys.path.append(decoy)
    before = set(sys.modules)

    import conventiondrift
    import conventiondrift._vendor.yaml as vendored
    import conventiondrift.cli as cli

    new = sorted(set(sys.modules) - before)
    result = {
        "path": sys.path,
        "new_modules": new,
        "all_modules": sorted(sys.modules),
        "module_files": {
            name: getattr(sys.modules[name], "__file__", None) for name in new
        },
        "with_libyaml": getattr(vendored, "__with_libyaml__", "MISSING"),
        "has_cloader": hasattr(vendored, "CLoader"),
        "vendored_file": vendored.__file__,
        "package_file": conventiondrift.__file__,
        "entry_point_callable": callable(getattr(cli, "main", None)),
        "stdlib": sorted(sys.stdlib_module_names),
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh)
    """
)


def _make_decoys(root: Path, marker_dir: Path) -> Path:
    """Write decoy ``yaml``, ``yaml._yaml`` and ``_yaml`` packages under ``root``."""
    body = DECOY_MODULE.format(marker=str(marker_dir))
    (root / "yaml").mkdir(parents=True)
    (root / "yaml" / "__init__.py").write_text(body, encoding="utf-8")
    (root / "yaml" / "_yaml.py").write_text(body, encoding="utf-8")
    (root / "_yaml").mkdir()
    (root / "_yaml" / "__init__.py").write_text(body, encoding="utf-8")
    return root


def run_probe(tmp_path: Path, position: str) -> tuple[dict[str, Any], list[str]]:
    """Import the vendored yaml and the package entry point; return (result, markers)."""
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    decoy = _make_decoys(tmp_path / "decoy", marker_dir)
    out = tmp_path / "probe.json"
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-B", "-c", PROBE, str(SRC), str(decoy), position, str(out)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=False,
    )
    markers = sorted(p.name for p in marker_dir.iterdir())
    assert proc.returncode == 0, (
        f"probe import failed (exit {proc.returncode}); decoy markers written: {markers}\n"
        f"stderr:\n{proc.stderr}"
    )
    result: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return result, markers


def _is_yaml_like(name: str) -> bool:
    if name.startswith("conventiondrift._vendor."):
        return False
    return name == "yaml" or name.startswith("yaml.") or name == "_yaml" or name.endswith("._yaml")


def _under(path: str | None, root: Path) -> bool:
    return path is not None and Path(path).resolve().is_relative_to(root.resolve())


def mutmut_allowance(environ: Mapping[str, str], repo_root: Path) -> frozenset[str]:
    """Module names mutmut's trampoline may add; empty unless mutmut is running."""
    if MUTMUT_ENV_VAR in environ and repo_root.name == MUTMUT_COPY_DIR:
        return MUTMUT_TRAMPOLINE_MODULES
    return frozenset()


def outside_modules(
    new_modules: Iterable[str], stdlib: set[str], allowed: frozenset[str]
) -> list[str]:
    """New modules that are not stdlib, not ``conventiondrift`` and not in ``allowed``."""
    return [
        n
        for n in new_modules
        if n.split(".")[0] not in stdlib
        and n != "conventiondrift"
        and not n.startswith("conventiondrift.")
        and n not in allowed
    ]


POSITIONS = pytest.mark.parametrize("position", ["front", "back"])


@POSITIONS
def test_vendor_import_resolution(tmp_path: Path, position: str) -> None:
    result, markers = run_probe(tmp_path, position)

    assert markers == [], f"decoy modules were executed: {markers}"
    assert "yaml" not in result["all_modules"], "a top-level 'yaml' module was imported"
    yaml_like = [n for n in result["all_modules"] if _is_yaml_like(n)]
    assert yaml_like == [], f"yaml/_yaml modules outside conventiondrift._vendor: {yaml_like}"
    assert result["with_libyaml"] is False, f"__with_libyaml__ is {result['with_libyaml']!r}"

    stdlib = set(result["stdlib"])
    allowed = mutmut_allowance(os.environ, REPO_ROOT)
    outside = outside_modules(result["new_modules"], stdlib, allowed)
    assert outside == [], f"imports resolved outside stdlib and conventiondrift: {outside}"
    used = sorted(allowed.intersection(result["new_modules"]))
    if used:
        # Under mutmut only: the allowed names must be the installed mutmut package itself.
        spec = importlib.util.find_spec("mutmut")
        assert spec is not None and spec.submodule_search_locations, "mutmut is not installed"
        mutmut_dir = Path(next(iter(spec.submodule_search_locations)))
        stray = {n: result["module_files"][n] for n in used}
        stray = {n: f for n, f in stray.items() if not _under(f, mutmut_dir)}
        assert stray == {}, f"mutmut module names loaded from outside {mutmut_dir}: {stray}"

    pkg_files = {
        n: f
        for n, f in result["module_files"].items()
        if (n == "conventiondrift" or n.startswith("conventiondrift.")) and not _under(f, SRC)
    }
    assert pkg_files == {}, f"conventiondrift modules loaded from outside {SRC}: {pkg_files}"
    assert _under(result["vendored_file"], SRC / "conventiondrift" / "_vendor" / "yaml")
    assert result["entry_point_callable"], "conventiondrift.cli:main is not callable"


@POSITIONS
def test_vendor_no_libyaml(tmp_path: Path, position: str) -> None:
    # The decoy yaml._yaml provides fake CParser/CEmitter classes (DECOY_MODULE).
    result, markers = run_probe(tmp_path, position)

    assert result["with_libyaml"] is False, (
        f"__with_libyaml__ is {result['with_libyaml']!r}; decoys executed: {markers}"
    )
    assert result["has_cloader"] is False, "vendored yaml exposes CLoader (C loaders loaded)"


def test_mutmut_allowance_off_in_normal_ci() -> None:
    # Without MUTANT_UNDER_TEST (normal CI), a mutmut import is still flagged, even from a
    # directory named like mutmut's copy.
    for root in (Path("/repo/conventiondrift"), Path("/repo/mutants")):
        allowed = mutmut_allowance({}, root)
        assert allowed == frozenset()
        flagged = outside_modules(["mutmut", "mutmut.mutation.trampoline"], set(), allowed)
        assert flagged == ["mutmut", "mutmut.mutation.trampoline"]
    # The env var alone is not enough: the tests must also run from mutmut's copy.
    assert mutmut_allowance({MUTMUT_ENV_VAR: "stats"}, Path("/repo/conventiondrift")) == (
        frozenset()
    )


def test_mutmut_allowance_is_exact_while_mutmut_runs() -> None:
    # The clean run sets MUTANT_UNDER_TEST to "", which still means mutmut is running.
    allowed = mutmut_allowance({MUTMUT_ENV_VAR: ""}, Path("/repo/mutants"))
    assert allowed == MUTMUT_TRAMPOLINE_MODULES
    new = [*sorted(MUTMUT_TRAMPOLINE_MODULES), "mutmut.__main__", "mutmutx", "yaml", "json"]
    assert outside_modules(new, {"json"}, allowed) == ["mutmut.__main__", "mutmutx", "yaml"]
