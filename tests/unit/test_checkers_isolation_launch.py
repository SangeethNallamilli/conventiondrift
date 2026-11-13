"""C-1 regression: planted repo modules never run in C7's processes (I-13 C7 ruling 8).

SR C-1 on #31: spawn workers and the resource tracker start as ``python -c`` in
the analyzed repo, so without ``-I``/``-P`` a repo's ``struct.py``,
``pickle.py``, ``multiprocessing/`` or ``concurrent/`` would be imported there.

How the CLI is launched here: the real console script (``conventiondrift =
conventiondrift.cli:main``) is still the T-001 placeholder and never reaches
C7, so it can't exercise the pool. Each test writes a wrapper in the exact form
pip generates for a console script, pointing at ``isolation_driver.main``,
outside the repo (as pip puts it in ``bin/``/``Scripts/``). Pip's file imports
the entry point from site-packages; here one extra line puts this tree's
``src`` and ``tests/unit`` on ``sys.path`` instead (first, so a test venv's own
install of another checkout can't win; neither folder holds a stdlib name), so
it also works under ``-I`` and ``-E``, which ignore ``PYTHONPATH``. The wrapper
is run as ``python <wrapper>`` with no ``-I``, just as the ``#!`` line or the
``.exe`` launcher runs it.

Each planted module writes ``<marker dir>/<module>-<pid>`` (outside the repo)
and then loads the real stdlib module, so a run that imports one still works
and only the marker gives it away.
"""

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from checker_standins import read_records

UNIT = Path(__file__).resolve().parent
SRC = UNIT.parents[1] / "src"
PLANTED = ("struct", "pickle", "multiprocessing", "concurrent")
FILES = 70
"""Python files analyzed: more than one 64-file batch, so the pool really starts."""

_WRAPPER = """\
# -*- coding: utf-8 -*-
import re
import sys
sys.path[0:0] = {paths!r}  # test only: stands in for site-packages
from isolation_driver import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])
    sys.exit(main())
"""

_PLANTED = """\
import os as _os
import sys as _sys

with open(_os.path.join({markers!r}, __name__ + "-" + str(_os.getpid())), "a"):
    pass

import importlib.machinery as _machinery
import importlib.util as _util

_repo = _os.path.normcase(_os.path.realpath({repo!r}))
_paths = [
    p for p in _sys.path
    if isinstance(p, str) and p and _os.path.normcase(_os.path.realpath(p)) != _repo
]
_spec = _machinery.PathFinder.find_spec(__name__, _paths)
_module = _util.module_from_spec(_spec)
_sys.modules[__name__] = _module
_spec.loader.exec_module(_module)
"""


def _repo(base: Path, *, hostile: bool, markers: Path) -> Path:
    repo = base / ("hostile" if hostile else "clean")
    (repo / "pkg").mkdir(parents=True)
    for i in range(FILES):
        src = f"print({i})\nrequests({i})\n" if i % 2 else f"print({i})\n"
        (repo / "pkg" / f"m{i:03}.py").write_text(src, encoding="utf-8")
    (repo / "pkg" / "broken.py").write_text("def (:\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=False, capture_output=True)  # noqa: S603, S607
    if hostile:
        planted = _PLANTED.format(markers=str(markers), repo=str(repo))
        for name in PLANTED:
            if name in {"struct", "pickle"}:
                (repo / f"{name}.py").write_text(planted, encoding="utf-8")
            else:
                (repo / name).mkdir()
                (repo / name / "__init__.py").write_text(planted, encoding="utf-8")
    return repo


def _wrapper(base: Path) -> Path:
    bin_dir = base / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "conventiondrift-c1"
    script.write_text(_WRAPPER.format(paths=[str(SRC), str(UNIT)]), encoding="utf-8")
    return script


def _env(pythonpath: Sequence[Path] = ()) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONSAFEPATH", "PYTHONPATH"}}
    if pythonpath:
        env["PYTHONPATH"] = os.pathsep.join(str(p) for p in pythonpath)
    return env


class Launch:
    """One finished driver run."""

    def __init__(self, out: dict[str, object], records: list[dict[str, object]]) -> None:
        self.report = out["report"]
        self.workers = out["workers"]
        self.pid = out["pid"]
        self.records = records

    def worker_pids(self) -> set[object]:
        return {r["pid"] for r in self.records} - {self.pid}


def _launch(
    argv: list[str], repo: Path, records: Path, env: dict[str, str], *, cwd: Path | None = None
) -> Launch:
    """Run the driver on ``repo``, from ``repo`` unless ``cwd`` is given."""
    markers = records.parent / "markers"
    records.mkdir()
    extra = [] if cwd is None else [str(repo)]
    done = subprocess.run(  # noqa: S603 -- fixed argv: this interpreter and test files
        [*argv, str(records), *extra],
        cwd=repo if cwd is None else cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert done.returncode == 0, f"{done.stderr}\nmarkers: {_markers(markers)}"
    return Launch(json.loads(done.stdout), read_records(str(records)))


def _markers(markers: Path) -> list[str]:
    return sorted(os.listdir(markers))


@pytest.fixture
def setup(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    markers = tmp_path / "markers"
    markers.mkdir()
    hostile = _repo(tmp_path, hostile=True, markers=markers)
    clean = _repo(tmp_path, hostile=False, markers=markers)
    return tmp_path, markers, hostile, clean


def _clean_report(base: Path, clean: Path) -> Launch:
    return _launch([sys.executable, str(_wrapper(base))], clean, base / "rec-clean", _env())


def _assert_pool(run: Launch) -> None:
    assert run.workers == 2
    assert run.worker_pids(), "no worker process ran the checkers"
    assert {r["pid"] for r in run.records} == run.worker_pids()
    for record in run.records:
        assert record["safe_path"] is True or record["isolated"] is True


def _assert_inline(run: Launch) -> None:
    assert run.workers == 0
    assert [r["pid"] for r in run.records] == [run.pid]


def test_the_console_script_without_dash_i_uses_isolated_workers(
    setup: tuple[Path, Path, Path, Path],
) -> None:
    base, markers, hostile, clean = setup
    script = str(_wrapper(base))
    plain = _launch([sys.executable, script], hostile, base / "rec-plain", _env())
    isolated = _launch([sys.executable, "-I", script], hostile, base / "rec-i", _env())
    assert _markers(markers) == []
    _assert_pool(plain)
    _assert_pool(isolated)
    assert all(r["PYTHONSAFEPATH"] == "1" and r["safe_path"] for r in plain.records)
    assert all(r["isolated"] for r in isolated.records)
    expected = _clean_report(base, clean)
    _assert_pool(expected)
    assert plain.report == isolated.report == expected.report
    assert _markers(markers) == []


def test_the_console_script_under_dash_e_runs_the_checkers_inline(
    setup: tuple[Path, Path, Path, Path],
) -> None:
    # -E: children would ignore PYTHONSAFEPATH, so the pre-check refuses the pool.
    base, markers, hostile, clean = setup
    run = _launch([sys.executable, "-E", str(_wrapper(base))], hostile, base / "rec-e", _env())
    assert _markers(markers) == []
    _assert_inline(run)
    assert run.report == _clean_report(base, clean).report


def test_python_dash_m_from_the_repo_runs_the_checkers_inline(
    setup: tuple[Path, Path, Path, Path],
) -> None:
    # ``python -m`` puts the repo first on the launcher's own sys.path, which
    # spawn would copy into every worker, so the pre-check refuses the pool.
    # The launcher process itself imports the repo's modules before C7 runs
    # (that is how ``-m`` works and C7 can't change it), so only markers from
    # processes other than the launcher are counted here.
    base, markers, hostile, clean = setup
    env = _env([UNIT, SRC])
    run = _launch([sys.executable, "-m", "isolation_driver"], hostile, base / "rec-m", env)
    _assert_inline(run)
    assert {m.rsplit("-", 1)[1] for m in _markers(markers)} <= {str(run.pid)}
    assert run.report == _clean_report(base, clean).report


def test_python_dash_m_conventiondrift_from_the_repo_imports_no_repo_module(
    setup: tuple[Path, Path, Path, Path],
) -> None:
    # The real ``python -m conventiondrift`` (still the T-001 placeholder).
    _, markers, hostile, _ = setup
    done = subprocess.run(
        [sys.executable, "-m", "conventiondrift", "--version"],
        cwd=hostile,
        env=_env([SRC]),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert _markers(markers) == []


@pytest.mark.parametrize("reach", ["symlink", "relative path"])
def test_pythonpath_reaching_the_repo_root_runs_the_checkers_inline(
    reach: str, setup: tuple[Path, Path, Path, Path]
) -> None:
    # Launched from another folder, so only the repo_root rule (realpath of the
    # root and of each sys.path entry) can see that PYTHONPATH names the repo.
    # The launcher itself imports the planted modules (PYTHONPATH says so, and
    # C7 can't change that), so only markers from other processes count.
    base, markers, hostile, clean = setup
    elsewhere = base / "elsewhere"
    elsewhere.mkdir()
    if reach == "symlink":
        entry = base / "repo-link"
        entry.symlink_to(hostile, target_is_directory=True)
        pythonpath = str(entry)
    else:
        pythonpath = os.path.join(os.pardir, hostile.name)
    env = dict(_env(), PYTHONPATH=pythonpath)
    script = str(_wrapper(base))
    run = _launch([sys.executable, script], hostile, base / "rec-pp", env, cwd=elsewhere)
    _assert_inline(run)
    assert {m.rsplit("-", 1)[1] for m in _markers(markers)} <= {str(run.pid)}
    assert run.report == _clean_report(base, clean).report
