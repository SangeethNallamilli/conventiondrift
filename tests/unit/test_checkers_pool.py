"""Unit tests for C7 analysis, conventiondrift.checkers.pool (T-014)."""

import concurrent.futures
import functools
import os
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from types import MappingProxyType

import pytest
from checker_standins import (
    CallChecker,
    ContextChecker,
    FaultyChecker,
    ManifestChecker,
    NodeCounter,
    RecordingChecker,
    read_records,
)
from hypothesis import given, settings
from hypothesis import strategies as st

from conventiondrift.checkers.base import Checker
from conventiondrift.checkers.pool import (
    BATCH_SIZE,
    Analysis,
    analyze,
    batches,
    context_changed_paths,
    incremental_base,
)
from conventiondrift.checkers.walk import FileJob
from conventiondrift.core import internal_error
from conventiondrift.errors import ComponentError
from conventiondrift.model import InternalError, ManifestFile, PyFile, Site, SkippedFile

PRINT = CallChecker("logging", frozenset({"print", "log"}))
HTTP = CallChecker("http-client", frozenset({"requests", "httpx"}))


def never(path: str) -> bool:
    return False


def reg(*checkers: Checker) -> Mapping[str, Checker]:
    return {c.id: c for c in checkers}


def py(path: str, src: str) -> PyFile:
    return PyFile(path, src.encode())


# --- batches (DESIGN §5) ------------------------------------------------------------------


def _jobs(n: int) -> list[FileJob]:
    return [FileJob(f"f{i:04}.py", b"", False, False) for i in range(n)]


@pytest.mark.parametrize(
    ("n", "sizes"),
    [(0, []), (1, [1]), (64, [64]), (65, [64, 1]), (129, [64, 64, 1])],
)
def test_batches_hold_at_most_64_files_in_order(n: int, sizes: list[int]) -> None:
    assert BATCH_SIZE == 64
    work = batches(_jobs(n))
    assert [len(b) for b in work] == sizes
    assert [j for b in work for j in b] == _jobs(n)


def test_batch_size_must_be_positive() -> None:
    with pytest.raises(ValueError, match="batch size"):
        batches(_jobs(3), 0)
    assert [len(b) for b in batches(_jobs(3), 1)] == [1, 1, 1]


# --- analyze: sites, sorting, skips (AC-F3.1, AC-F3.13, AC-E.14) --------------------------

FILES = [
    py("src/b.py", "print(1)\nrequests.get(x)\nrequests(1)\n"),
    py("src/a.py", "log(2)\nprint(3)\n"),
    py("src/broken.py", "def (:\n"),
    py("src/c.py", "x = 1\n"),
]


def test_analyze_sorts_sites_and_lists_unparseable_files_while_analyzing_the_rest() -> None:
    result = analyze(FILES, checkers=reg(PRINT, HTTP), is_script=never)
    assert result.sites("logging") == (
        Site("src/a.py", 1, 0, "log"),
        Site("src/a.py", 2, 0, "print"),
        Site("src/b.py", 1, 0, "print"),
    )
    assert result.sites("http-client") == (Site("src/b.py", 3, 0, "requests"),)
    assert result.skipped == (SkippedFile("src/broken.py", "syntax error"),)
    assert result.failed == ()
    assert result.errors() == ()
    assert result.files_parsed == 3
    assert result.checker_ids() == ("http-client", "logging")
    # A healthy checker with no sites in a file has no entry for it.
    assert list(result.py_sites["http-client"]) == ["src/b.py"]
    assert result.sites("money") == ()
    assert result.workers == 0


def test_analyze_counts_every_node_once() -> None:
    result = analyze([py("a.py", "x\n")], checkers=reg(NodeCounter()), is_script=never)
    # Module, Expr, Name, Load
    assert result.ast_nodes == 4


def test_the_result_is_read_only() -> None:
    result = analyze(FILES, checkers=reg(PRINT), is_script=never)
    assert isinstance(result.py_sites, MappingProxyType)
    assert isinstance(result.py_sites["logging"], MappingProxyType)
    assert isinstance(result.manifest_sites, MappingProxyType)


def test_no_files_gives_an_empty_healthy_result() -> None:
    result = analyze([], checkers=reg(PRINT), is_script=never)
    assert result == Analysis(MappingProxyType({"logging": MappingProxyType({})}), {}, (), ())
    assert result.checker_ids() == ("logging",)


def test_scope_flags_come_from_b2_the_script_predicate_and_entry_points() -> None:
    files = [
        py("tests/t.py", "x\n"),
        py("bin/tool.py", "x\n"),
        py("pkg/cli.py", "x\n"),
        py("tests/conftest.py", "x\n"),
        py("src/lib.py", "x\n"),
    ]
    result = analyze(
        files,
        checkers=reg(ContextChecker()),
        is_script=lambda p: p.startswith("bin/"),
        entry_points=frozenset({"pkg/cli.py", "not/analyzed.py"}),
    )
    assert result.sites("type-hints") == (
        Site("bin/tool.py", 1, 0, "script"),
        Site("pkg/cli.py", 1, 0, "script"),
        Site("src/lib.py", 1, 0, "plain"),
        Site("tests/conftest.py", 1, 0, "test"),
        Site("tests/t.py", 1, 0, "test"),
    )


# --- input validation ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "registry",
    [
        {"print": PRINT},  # not an I-10 id
        {"http-client": PRINT},  # key doesn't match checker.id
    ],
)
def test_a_malformed_registry_is_a_caller_bug(registry: Mapping[str, Checker]) -> None:
    with pytest.raises(ValueError, match="registry"):
        analyze(FILES, checkers=registry, is_script=never)


def test_duplicate_paths_and_bad_worker_counts_are_caller_bugs() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        analyze([py("a.py", ""), py("a.py", "")], checkers=reg(PRINT), is_script=never)
    with pytest.raises(ValueError, match="max_workers"):
        analyze(FILES, checkers=reg(PRINT), is_script=never, max_workers=0)


# --- failure isolation (I-11 C7, DESIGN §4, AC-F7.4 part) ---------------------------------


def test_a_checker_failing_on_one_file_is_dropped_everywhere_and_reported() -> None:
    files = [py("src/a.py", "f()\n"), py("src/poison.py", "f()\n"), py("src/z.py", "print(1)\n")]
    faulty = FaultyChecker("raises on one file")
    result = analyze(files, checkers=reg(faulty, PRINT), is_script=never)
    assert result.failed == ("exceptions",)
    assert "exceptions" not in result.py_sites
    assert result.sites("exceptions") == ()
    assert result.sites("logging") == (Site("src/z.py", 1, 0, "print"),)
    [error] = result.errors()
    assert isinstance(error, ComponentError)
    assert error.component == "checker:exceptions"
    assert internal_error(error) == InternalError(
        "checker:exceptions",
        "ComponentError: this part of the analysis could not finish; details are withheld",
    )


def test_a_testkit_fault_in_ast_handlers_is_isolated() -> None:
    testkit = pytest.importorskip("conventiondrift_testkit")  # under tests/, never shipped
    faulty = testkit.FaultyComponent(HTTP, fail_on={"ast_handlers"})
    result = analyze(FILES, checkers={"http-client": faulty, "logging": PRINT}, is_script=never)
    assert result.failed == ("http-client",)
    assert len(result.sites("logging")) == 3


def test_a_system_exit_from_a_checker_is_isolated_too() -> None:
    result = analyze(FILES, checkers=reg(FaultyChecker("system exit")), is_script=never)
    assert result.failed == ("exceptions",)


# --- the process pool (DESIGN §5, §3a) ----------------------------------------------------


@pytest.fixture
def outside_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Run from an empty folder that isn't on ``sys.path``, with ``PYTHONSAFEPATH`` restored.

    The isolation pre-check (I-13 C7 ruling 8) runs the checkers inline when the
    current folder is on ``sys.path``, as it is under ``python -m pytest``.
    The pool sets ``PYTHONSAFEPATH``; the monkeypatch undoes that afterwards.
    """
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    yield work


def _many(n: int) -> list[PyFile]:
    return [py(f"pkg/m{i:03}.py", f"print({i})\nrequests({i})\n") for i in range(n)]


@pytest.mark.usefixtures("outside_repo")
def test_the_pool_gives_the_same_result_as_inline() -> None:
    files = [*_many(130), py("pkg/broken.py", "def (:\n")]
    checkers = reg(PRINT, HTTP, FaultyChecker("raises on one file"))
    files.append(py("src/poison.py", "f()\n"))
    inline = analyze(files, checkers=checkers, is_script=never, max_workers=1)
    pooled = analyze(files, checkers=checkers, is_script=never, max_workers=2)
    assert inline.workers == 0
    assert pooled.workers == 2
    assert pooled.py_sites == inline.py_sites
    assert pooled.skipped == inline.skipped == (SkippedFile("pkg/broken.py", "syntax error"),)
    assert pooled.failed == inline.failed == ("exceptions",)
    assert (pooled.files_parsed, pooled.ast_nodes) == (inline.files_parsed, inline.ast_nodes)
    assert len(pooled.sites("logging")) == 130


@pytest.mark.usefixtures("outside_repo")
def test_the_pool_is_never_wider_than_the_batch_count() -> None:
    result = analyze(_many(65), checkers=reg(PRINT), is_script=never, max_workers=8)
    assert result.workers == 2


class _Unpicklable(CallChecker):
    def __init__(self) -> None:
        super().__init__("logging", frozenset({"print"}))
        self.hook: Callable[[], None] = lambda: None


@pytest.mark.usefixtures("outside_repo")
def test_a_broken_pool_fails_closed_as_a_checkers_component_error() -> None:
    with pytest.raises(ComponentError) as info:
        analyze(_many(65), checkers=reg(_Unpicklable()), is_script=never, max_workers=2)
    assert info.value.component == "checkers"


# Parser-stack overflow: MemoryError from parse, not a skip (I-13 C7 ruling 2).
_MEMORY_ERROR_SRC = "-" * 200_000 + "1"


def test_a_memory_error_on_the_inline_path_is_a_checkers_component_error() -> None:
    with pytest.raises(ComponentError) as info:
        analyze(
            [py("src/huge.py", _MEMORY_ERROR_SRC)],
            checkers=reg(PRINT),
            is_script=never,
            max_workers=1,
        )
    assert info.value.component == "checkers"


@pytest.mark.usefixtures("outside_repo")
def test_a_memory_error_on_the_pool_path_is_a_checkers_component_error() -> None:
    files = [*_many(64), py("src/huge.py", _MEMORY_ERROR_SRC)]
    with pytest.raises(ComponentError) as info:
        analyze(files, checkers=reg(PRINT), is_script=never, max_workers=2)
    assert info.value.component == "checkers"


# --- worker isolation (I-13 C7 ruling 8, SR C-1 on #31) ---------------------------------


def test_a_pool_run_sets_pythonsafepath_for_its_workers(outside_repo: Path) -> None:
    records = outside_repo.parent / "records"
    records.mkdir()
    result = analyze(_many(65), checkers=reg(RecordingChecker(str(records))), is_script=never)
    assert result.workers >= 1
    seen = read_records(str(records))
    assert seen
    assert os.getpid() not in {r["pid"] for r in seen}
    assert all(r["PYTHONSAFEPATH"] == "1" and r["safe_path"] is True for r in seen)
    assert os.environ["PYTHONSAFEPATH"] == "1"


def test_pythonsafepath_stays_set_when_the_pool_replaces_a_worker_mid_run(
    outside_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # max_tasks_per_child=1 makes the pool replace each worker after one batch,
    # so 3 batches on 2 workers need at least one replacement started mid-run.
    real = concurrent.futures.ProcessPoolExecutor
    monkeypatch.setattr(
        concurrent.futures, "ProcessPoolExecutor", functools.partial(real, max_tasks_per_child=1)
    )
    records = outside_repo.parent / "records"
    records.mkdir()
    checker = RecordingChecker(str(records))
    result = analyze(_many(130), checkers=reg(checker), is_script=never, max_workers=2)
    assert result.workers == 2
    seen = read_records(str(records))
    assert len({r["pid"] for r in seen}) == 3
    assert all(r["PYTHONSAFEPATH"] == "1" and r["safe_path"] is True for r in seen)
    assert len(result.sites("logging")) == 130


class _DropsSafePath(concurrent.futures.ProcessPoolExecutor):
    """A pool whose PYTHONSAFEPATH is removed while it is alive, after its last task.

    (Removed before a worker starts, that worker's backstop breaks the pool
    instead; see the backstop test below.)
    """

    def map(self, *args: object, **kwargs: object) -> Iterator[object]:  # type: ignore[override]
        done: list[object] = list(super().map(*args, **kwargs))  # type: ignore[arg-type]
        del os.environ["PYTHONSAFEPATH"]
        return iter(done)


def test_pythonsafepath_removed_while_the_pool_runs_fails_closed(
    outside_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", _DropsSafePath)
    with pytest.raises(ComponentError) as info:
        analyze(_many(65), checkers=reg(PRINT), is_script=never, max_workers=2)
    assert info.value.component == "checkers"
    assert info.value.message == "PYTHONSAFEPATH changed while the pool ran"


@pytest.mark.parametrize("unsafe", ["cwd on sys.path", "empty entry on sys.path"])
def test_an_unsafe_sys_path_runs_the_checkers_inline(
    unsafe: str, outside_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(outside_repo) if unsafe == "cwd on sys.path" else "")
    result = analyze(_many(65), checkers=reg(PRINT), is_script=never, max_workers=2)
    assert result.workers == 0
    assert len(result.sites("logging")) == 65
    assert "PYTHONSAFEPATH" not in os.environ


def test_the_worker_backstop_runs_in_every_worker_and_fails_closed(
    outside_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force the pool past the pre-check with the current folder on sys.path;
    # spawn copies that sys.path into each worker, whose initializer refuses it.
    monkeypatch.syspath_prepend(str(outside_repo))
    monkeypatch.setattr("conventiondrift.checkers.pool.pool_allowed", lambda root: True)
    monkeypatch.setenv("PYTHONSAFEPATH", "1")
    with pytest.raises(ComponentError) as info:
        analyze(_many(65), checkers=reg(PRINT), is_script=never, max_workers=2)
    assert info.value.component == "checkers"
    assert info.value.message == "process pool failed: BrokenProcessPool"


# --- manifests (I-10 manifest_sites) ------------------------------------------------------

MANIFESTS = [
    ManifestFile("pyproject.toml", b"[tool.uv]\n"),
    ManifestFile("sub/requirements.txt", b"pip\nuv\n"),
]


def test_manifest_sites_come_from_manifest_checkers_only() -> None:
    result = analyze(
        FILES, checkers=reg(ManifestChecker(), PRINT), is_script=never, manifests=MANIFESTS
    )
    assert result.sites("package-manager") == (
        Site("pyproject.toml", 1, 0, "uv"),
        Site("sub/requirements.txt", 1, 0, "pip"),
        Site("sub/requirements.txt", 1, 0, "uv"),
    )
    assert "package-manager" not in result.py_sites
    assert result.checker_ids() == ("logging", "package-manager")
    assert PRINT.manifest_sites({}) == ()


@pytest.mark.parametrize("fault", ["raises", "wrong file"])
def test_a_failing_manifest_checker_is_isolated(fault: str) -> None:
    checker = ManifestChecker("raises" if fault == "raises" else "wrong file")
    result = analyze(FILES, checkers=reg(checker, PRINT), is_script=never, manifests=MANIFESTS)
    assert result.failed == ("package-manager",)
    assert result.sites("package-manager") == ()
    assert len(result.sites("logging")) == 3


def test_a_checker_that_failed_on_python_files_is_not_asked_for_manifests() -> None:
    class Both(FaultyChecker):
        inputs = frozenset({"python-ast", "manifest"})

        def manifest_sites(self, files: Mapping[str, bytes]) -> list[Site]:
            raise AssertionError("must not be called after a failure")

    result = analyze(
        [py("a.py", "f()\n")],
        checkers=reg(Both("handler raises")),
        is_script=never,
        manifests=MANIFESTS,
    )
    assert result.failed == ("exceptions",)


# --- incremental base (ADR-0004) ----------------------------------------------------------

HEAD = [
    py("src/same.py", "print(1)\n"),
    py("src/mod.py", "print(1)\nprint(2)\n"),
    py("src/new.py", "log(1)\n"),
    py("src/renamed_new.py", "print(9)\n"),
    py("src/bad_same.py", "def (:\n"),
]
BASE_CHANGED = [  # base versions of the changed files: mod.py, deleted gone.py, renamed old path
    py("src/mod.py", "log(1)\n"),
    py("src/gone.py", "print(5)\nprint(6)\n"),
    py("src/renamed_old.py", "print(9)\n"),
]
CHANGED_HEAD = frozenset({"src/mod.py", "src/new.py", "src/renamed_new.py"})


def test_incremental_base_is_head_minus_changed_plus_base_changed() -> None:
    checkers = reg(PRINT, ManifestChecker())
    head = analyze(HEAD, checkers=checkers, is_script=never, manifests=MANIFESTS[:1])
    base_changed = analyze(BASE_CHANGED, checkers=checkers, is_script=never, manifests=MANIFESTS)
    base = incremental_base(head, base_changed, CHANGED_HEAD)
    # Written by hand: same.py reused from head; mod.py, gone.py, renamed_old.py from base.
    assert base.sites("logging") == (
        Site("src/gone.py", 1, 0, "print"),
        Site("src/gone.py", 2, 0, "print"),
        Site("src/mod.py", 1, 0, "log"),
        Site("src/renamed_old.py", 1, 0, "print"),
        Site("src/same.py", 1, 0, "print"),
    )
    assert base.skipped == (SkippedFile("src/bad_same.py", "syntax error"),)
    # Manifests always come from the base side in full.
    assert base.sites("package-manager") == base_changed.sites("package-manager")
    assert (base.files_parsed, base.ast_nodes) == (3, base_changed.ast_nodes)


def test_incremental_base_equals_a_full_base_analysis_here() -> None:
    base_files = [f for f in HEAD if f.path not in CHANGED_HEAD] + BASE_CHANGED
    full = analyze(base_files, checkers=reg(PRINT), is_script=never)
    head = analyze(HEAD, checkers=reg(PRINT), is_script=never)
    base_changed = analyze(BASE_CHANGED, checkers=reg(PRINT), is_script=never)
    inc = incremental_base(head, base_changed, CHANGED_HEAD)
    assert inc.py_sites == full.py_sites
    assert inc.skipped == full.skipped


_SRC = st.sampled_from(
    ["print(1)\n", "log(1)\nprint(2)\n", "def (:\n", "x = 1\n", "print(1); log(2)\n"]
)


@settings(max_examples=60, deadline=None)
@given(
    head_src=st.dictionaries(st.sampled_from("abcdef"), _SRC, max_size=6),
    base_src=st.dictionaries(st.sampled_from("abcdef"), _SRC, max_size=6),
)
def test_incremental_base_equals_full_base_on_random_trees(
    head_src: dict[str, str], base_src: dict[str, str]
) -> None:
    head_files = [py(f"{k}.py", v) for k, v in head_src.items()]
    base_files = [py(f"{k}.py", v) for k, v in base_src.items()]
    # The changed set as diff-tree would report it: every path whose bytes differ or that
    # exists on only one side.
    changed = {k for k in head_src.keys() | base_src.keys() if head_src.get(k) != base_src.get(k)}
    changed_head = frozenset(f"{k}.py" for k in changed if k in head_src)
    base_changed_files = [f for f in base_files if f.path[:-3] in changed]
    checkers = reg(PRINT)
    head = analyze(head_files, checkers=checkers, is_script=never)
    base_changed = analyze(base_changed_files, checkers=checkers, is_script=never)
    full = analyze(base_files, checkers=checkers, is_script=never)
    inc = incremental_base(head, base_changed, changed_head)
    assert inc.sites("logging") == full.sites("logging")
    assert inc.skipped == full.skipped


def test_incremental_base_drops_a_checker_that_failed_on_either_side() -> None:
    files = [py("src/a.py", "f()\nprint(1)\n")]
    failing = reg(PRINT, HTTP, FaultyChecker("not a site"))
    ok = analyze(files, checkers=failing, is_script=never)
    assert ok.failed == ("exceptions",)
    # Same checker set, but no files for the faulty checker to fail on.
    clean = analyze([], checkers=failing, is_script=never)
    assert clean.failed == ()
    broken = analyze(
        files, checkers=reg(PRINT, FaultyChecker("handler raises"), HTTP), is_script=never
    )
    assert incremental_base(ok, clean, frozenset()).failed == ("exceptions",)
    # Same ids as broken; a healthy stand-in keeps exceptions alive on head.
    head = analyze(
        files,
        checkers=reg(PRINT, HTTP, CallChecker("exceptions", frozenset({"print"}))),
        is_script=never,
    )
    assert head.failed == ()
    base = incremental_base(head, broken, frozenset({"src/a.py"}))
    assert base.failed == ("exceptions",)
    assert base.checker_ids() == ("http-client", "logging")


@pytest.mark.parametrize(
    ("head_checkers", "base_checkers"),
    [
        (reg(PRINT, HTTP), reg(PRINT)),  # http-client missing from base
        (reg(PRINT), reg(PRINT, HTTP)),  # http-client missing from head
        (reg(PRINT, ManifestChecker()), reg(PRINT)),  # package-manager extra on head
        (reg(PRINT), reg(PRINT, ManifestChecker())),  # package-manager extra on base
    ],
    ids=[
        "missing-from-base",
        "missing-from-head",
        "extra-on-head",
        "extra-on-base",
    ],
)
def test_incremental_base_rejects_a_mismatched_checker_set(
    head_checkers: Mapping[str, Checker], base_checkers: Mapping[str, Checker]
) -> None:
    files = [py("src/a.py", "print(1)\n")]
    head = analyze(files, checkers=head_checkers, is_script=never)
    base_changed = analyze(files, checkers=base_checkers, is_script=never)
    with pytest.raises(ComponentError) as info:
        incremental_base(head, base_changed, frozenset({"src/a.py"}))
    assert info.value.component == "checkers"


def test_an_incomplete_changed_set_is_a_caller_bug() -> None:
    head = analyze([py("src/a.py", "print(1)\n")], checkers=reg(PRINT), is_script=never)
    base_changed = analyze([py("src/a.py", "print(2)\n")], checkers=reg(PRINT), is_script=never)
    with pytest.raises(ValueError, match="overlaps"):
        incremental_base(head, base_changed, frozenset())
    skipped_head = analyze([py("src/a.py", "def (:\n")], checkers=reg(PRINT), is_script=never)
    with pytest.raises(ValueError, match="overlaps"):
        incremental_base(skipped_head, base_changed, frozenset())


def test_context_changed_paths_are_the_files_whose_entry_point_status_flipped() -> None:
    paths = ["a.py", "b.py", "c.py", "d.py"]
    head = frozenset({"a.py", "b.py", "x.py"})
    base = frozenset({"b.py", "c.py"})
    assert context_changed_paths(paths, head, base) == frozenset({"a.py", "c.py"})
    assert context_changed_paths(paths, head, head) == frozenset()


def test_an_entry_point_flip_handled_as_changed_matches_a_full_base() -> None:
    files = [py("pkg/cli.py", "x\n"), py("src/lib.py", "x\n")]
    checkers = reg(ContextChecker())
    head_ep, base_ep = frozenset({"pkg/cli.py"}), frozenset[str]()
    head = analyze(files, checkers=checkers, is_script=never, entry_points=head_ep)
    flipped = context_changed_paths([f.path for f in files], head_ep, base_ep)
    base_changed = analyze(
        [f for f in files if f.path in flipped],
        checkers=checkers,
        is_script=never,
        entry_points=base_ep,
    )
    full = analyze(files, checkers=checkers, is_script=never, entry_points=base_ep)
    assert incremental_base(head, base_changed, flipped).py_sites == full.py_sites
