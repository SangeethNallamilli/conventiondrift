"""C7 analysis: the process pool, merging, failure isolation and the incremental base.

(INTERFACES I-10, I-11 C7; ADR-0003, ADR-0004; DESIGN §2 step 5, §4, §5.)

Files go to a ``ProcessPoolExecutor`` in batches of about 64, in path order.
Workers only parse and check the bytes they are handed: no git, no network,
no file reads (DESIGN §3a). The pool uses the ``spawn`` start method on every
platform, so a worker never inherits the main process's threads, locks or git
pipes. Results are merged and sorted by (path, line, col, option), so the
output doesn't depend on scheduling.

A checker that raises, or returns an invalid site, on any file is dropped as
a whole and reported as ``ComponentError("checker:<id>")``; the others carry
on (DESIGN §4). A file that doesn't parse is skipped and listed (AC-E.14).
"""

import multiprocessing
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from types import MappingProxyType
from typing import get_args

from conventiondrift.checkers.base import Checker
from conventiondrift.checkers.walk import (
    FileJob,
    FileOutcome,
    Walker,
    collect,
    is_test_file,
    site_key,
)
from conventiondrift.errors import ComponentError
from conventiondrift.model import CheckerId, ManifestFile, PyFile, Site, SkippedFile

BATCH_SIZE = 64
"""Files per pool task (DESIGN §5: about 64, to cut pickling)."""

_CHECKER_IDS = frozenset(get_args(CheckerId))
_EMPTY: Mapping[str, tuple[Site, ...]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class BatchOutcome:
    """One batch's results and the checkers that failed while running it."""

    files: tuple[FileOutcome, ...]
    failed: tuple[tuple[str, str], ...]
    """(checker id, exception class name), sorted by id."""


def analyze_batch(checkers: tuple[Checker, ...], jobs: tuple[FileJob, ...]) -> BatchOutcome:
    """Walk each file of one batch once (the pool's task; also run inline)."""
    walker = Walker(checkers)
    files = tuple(walker.walk(job) for job in jobs)
    return BatchOutcome(files, tuple(sorted(walker.failed.items())))


def batches(jobs: Sequence[FileJob], size: int = BATCH_SIZE) -> list[tuple[FileJob, ...]]:
    """Split ``jobs`` into consecutive batches of at most ``size`` (``size`` >= 1)."""
    if size < 1:
        raise ValueError("batch size must be at least 1")
    return [tuple(jobs[i : i + size]) for i in range(0, len(jobs), size)]


def _run_batches(
    checkers: tuple[Checker, ...], work: list[tuple[FileJob, ...]], max_workers: int | None
) -> tuple[list[BatchOutcome], int]:
    """Run the batches inline (one batch or ``max_workers=1``) or in a spawn pool.

    Returns the outcomes in batch order and the number of pool workers (0 inline).
    """
    if max_workers is not None and max_workers < 1:
        raise ValueError("max_workers must be at least 1")
    if len(work) <= 1 or max_workers == 1:
        return [analyze_batch(checkers, batch) for batch in work], 0
    context = multiprocessing.get_context("spawn")
    workers = min(len(work), max_workers or context.cpu_count())
    try:
        with ProcessPoolExecutor(max_workers=workers, mp_context=context) as pool:
            return list(pool.map(analyze_batch, [checkers] * len(work), work)), workers
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001 -- a broken pool fails closed as C7's own error
        raise ComponentError("checkers", f"process pool failed: {type(exc).__name__}") from None


@dataclass(frozen=True, slots=True)
class Analysis:
    """C7's output for one side (I-11 C7).

    ``py_sites`` maps each healthy checker id to its sites per Python file, and
    ``manifest_sites`` to its manifest sites; a checker in ``failed`` has no
    entry in either. Every site list is sorted (file, line, col, option) and
    unique (SR F3 on #25).
    """

    py_sites: Mapping[str, Mapping[str, tuple[Site, ...]]]
    manifest_sites: Mapping[str, tuple[Site, ...]]
    skipped: tuple[SkippedFile, ...]
    """Sorted by path (I-9)."""
    failed: tuple[str, ...]
    """Ids of the checkers dropped because they failed, sorted."""
    files_parsed: int = 0
    """Python files parsed on this side (I-12 ``files_parsed``)."""
    ast_nodes: int = 0
    """AST nodes visited, each exactly once (I-12 ``ast_nodes``; ADR-0003 walk count)."""
    workers: int = 0
    """Pool workers used; 0 when the batches ran inline (I-12 ``workers``)."""

    def checker_ids(self) -> tuple[str, ...]:
        """Ids of the healthy checkers, sorted."""
        return tuple(sorted(set(self.py_sites) | set(self.manifest_sites)))

    def sites(self, checker_id: str) -> tuple[Site, ...]:
        """All of one checker's sites on this side, sorted (file, line, col, option)."""
        files = self.py_sites.get(checker_id, _EMPTY)
        merged = [s for per_file in files.values() for s in per_file]
        merged.extend(self.manifest_sites.get(checker_id, ()))
        return tuple(sorted(set(merged), key=site_key))

    def errors(self) -> tuple[ComponentError, ...]:
        """One ``ComponentError("checker:<id>")`` per failed checker, for T-028 to report."""
        return tuple(ComponentError(f"checker:{cid}", "checker failed") for cid in self.failed)


def _validate(checkers: Mapping[str, Checker]) -> tuple[Checker, ...]:
    ordered: list[Checker] = []
    for key in sorted(checkers):
        checker = checkers[key]
        if key not in _CHECKER_IDS or checker.id != key:
            raise ValueError("checker registry keys must be I-10 ids matching checker.id")
        ordered.append(checker)
    return tuple(ordered)


def _manifest_sites(
    checkers: tuple[Checker, ...], manifests: Sequence[ManifestFile], failed: dict[str, str]
) -> dict[str, tuple[Site, ...]]:
    files = MappingProxyType({m.path: m.data for m in manifests})
    allowed = frozenset(files)
    out: dict[str, tuple[Site, ...]] = {}
    for checker in checkers:
        if "manifest" not in checker.inputs or checker.id in failed:
            continue
        try:
            found = collect(checker.manifest_sites(files), allowed, checker.options)
        except KeyboardInterrupt:
            raise
        except BaseException as exc:  # noqa: BLE001 -- I-11: a failing checker is isolated
            failed[checker.id] = type(exc).__name__
            continue
        out[checker.id] = tuple(sorted(set(found), key=site_key))
    return out


def analyze(
    py_files: Sequence[PyFile],
    *,
    checkers: Mapping[str, Checker],
    is_script: Callable[[str], bool],
    entry_points: frozenset[str] = frozenset(),
    manifests: Sequence[ManifestFile] = (),
    max_workers: int | None = None,
) -> Analysis:
    """Run every checker over one side's files (I-11 C7).

    ``checkers`` is the registry, keyed by I-10 id (I-11; T-028 passes only the
    enabled ones). ``is_script(path)`` says whether a path matches the effective
    logging ``script-paths`` (I-6, B2); a path in ``entry_points`` (console
    scripts, A-4) is a script too. ``max_workers=None`` sizes the pool to the
    CPU count; ``1`` runs inline. Paths must be unique.

    Raises ``ValueError`` for a malformed registry or duplicate paths (caller
    bugs) and ``ComponentError("checkers")`` if the pool itself breaks.
    """
    ordered = _validate(checkers)
    paths = [f.path for f in py_files]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate Python file paths")
    jobs = [
        FileJob(f.path, f.data, is_test_file(f.path), f.path in entry_points or is_script(f.path))
        for f in sorted(py_files, key=lambda f: f.path.encode("utf-8", "surrogateescape"))
    ]
    outcomes, workers = _run_batches(ordered, batches(jobs), max_workers)

    failed: dict[str, str] = {}
    for outcome in outcomes:
        for cid, name in outcome.failed:
            failed.setdefault(cid, name)
    manifest = _manifest_sites(ordered, manifests, failed)

    ast_ids = [c.id for c in ordered if "python-ast" in c.inputs and c.id not in failed]
    per_checker: dict[str, dict[str, tuple[Site, ...]]] = {cid: {} for cid in ast_ids}
    skipped: list[SkippedFile] = []
    parsed = nodes = 0
    for outcome in outcomes:
        for file in outcome.files:
            if file.skipped is not None:
                skipped.append(SkippedFile(file.path, file.skipped))
                continue
            parsed += 1
            nodes += file.nodes
            for cid, sites in file.sites:
                if cid in per_checker and sites:
                    per_checker[cid][file.path] = sites
    return _build(per_checker, manifest, skipped, failed, parsed, nodes, workers)


def _build(
    py: Mapping[str, Mapping[str, tuple[Site, ...]]],
    manifest: Mapping[str, tuple[Site, ...]],
    skipped: Iterable[SkippedFile],
    failed: Iterable[str],
    files_parsed: int,
    ast_nodes: int,
    workers: int,
) -> Analysis:
    dropped = frozenset(failed)
    return Analysis(
        py_sites=MappingProxyType(
            {
                cid: MappingProxyType(dict(sorted(files.items())))
                for cid, files in sorted(py.items())
                if cid not in dropped
            }
        ),
        manifest_sites=MappingProxyType(
            {cid: sites for cid, sites in sorted(manifest.items()) if cid not in dropped}
        ),
        skipped=tuple(sorted(skipped, key=lambda s: s.path)),
        failed=tuple(sorted(dropped)),
        files_parsed=files_parsed,
        ast_nodes=ast_nodes,
        workers=workers,
    )


def context_changed_paths(
    paths: Iterable[str], head_entry_points: frozenset[str], base_entry_points: frozenset[str]
) -> frozenset[str]:
    """Paths among ``paths`` whose console-script status differs between base and head.

    T-028 owns the reparse set: git-changed ``.py`` files plus every ``.py``
    whose ``FileContext`` differs between base and head (I-13 C7 ruling 3,
    ADR-0004 Amendment 1). C7 exposes ``walk.file_context`` for that
    comparison. This helper only covers the entry-point half of
    ``is_script`` and is kept as a convenience.
    """
    flipped = head_entry_points ^ base_entry_points
    return frozenset(p for p in paths if p in flipped)


def incremental_base(
    head: Analysis, base_changed: Analysis, changed_head_paths: frozenset[str]
) -> Analysis:
    """Base = head - head(changed) + base(changed) (ADR-0004, FEASIBILITY F-3).

    ``base_changed`` is ``analyze()`` over the base side's versions of the
    changed Python files (old paths for renames, deleted files included) plus
    **all** base manifests, since manifest sites are not per file and are always
    recomputed (ADR-0004). ``changed_head_paths`` holds every head path whose
    sites may differ: added, modified, renamed-to and copied-to paths, plus
    every ``.py`` whose ``FileContext`` differs between the two sides
    (I-13 C7 ruling 3, ADR-0004 Amendment 1). Head Python sites and skips
    outside that set are reused as they are. A checker that failed on either
    side is dropped.

    Raises ``ValueError`` if ``base_changed`` covers a path that head reuses,
    which means the changed set is incomplete (a caller bug).
    """
    reused_paths = {
        path for files in head.py_sites.values() for path in files if path not in changed_head_paths
    } | {s.path for s in head.skipped if s.path not in changed_head_paths}
    base_paths = {p for files in base_changed.py_sites.values() for p in files} | {
        s.path for s in base_changed.skipped
    }
    if reused_paths & base_paths:
        raise ValueError("base_changed overlaps files reused from head")
    ids = set(head.py_sites) | set(base_changed.py_sites)
    py: dict[str, dict[str, tuple[Site, ...]]] = {}
    for cid in ids:
        merged = {
            p: s
            for p, s in head.py_sites.get(cid, MappingProxyType({})).items()
            if p not in changed_head_paths
        }
        merged.update(base_changed.py_sites.get(cid, MappingProxyType({})))
        py[cid] = merged
    skipped = [s for s in head.skipped if s.path not in changed_head_paths]
    skipped.extend(base_changed.skipped)
    return _build(
        py,
        base_changed.manifest_sites,
        skipped,
        set(head.failed) | set(base_changed.failed),
        base_changed.files_parsed,
        base_changed.ast_nodes,
        base_changed.workers,
    )
