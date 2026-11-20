"""Helpers shared by the real-checker tests (T-016): run the registry on sources and count sites.

``counts`` is the I-10 rule: a site follows when its option is preferred, or when nothing
is preferred and the option isn't prohibited; relevant sites are every site of the checker.
"""

import time
from collections.abc import Callable, Mapping
from functools import partial
from types import MappingProxyType
from typing import TypeVar

from conventiondrift.checkers import registry
from conventiondrift.checkers.pool import analyze
from conventiondrift.discover.globmatch import GlobSet
from conventiondrift.model import (
    CheckerId,
    InstructionFile,
    Policy,
    PyFile,
    Rule,
    RuleMatch,
    Site,
    Thresholds,
)
from conventiondrift.policy.config import DEFAULT_CHECKERS, DEFAULT_LOGGING_SCRIPT_PATHS
from conventiondrift.rules.mapping import extract_rules

REGISTRY_UNDER_TEST = registry()


def default_is_script() -> Callable[[str], bool]:
    """The effective default ``script-paths`` (B2), the way T-028 builds the predicate."""
    return GlobSet(DEFAULT_LOGGING_SCRIPT_PATHS).excludes


def sites_of(
    checker: CheckerId,
    files: Mapping[str, str],
    *,
    entry_points: frozenset[str] = frozenset(),
    max_workers: int | None = 1,
    is_script: Callable[[str], bool] | None = None,
) -> list[Site]:
    """All of ``checker``'s sites over ``files`` ({path: source}), in the walk's order."""
    result = analyze(
        [PyFile(path, text.encode()) for path, text in files.items()],
        checkers=REGISTRY_UNDER_TEST,
        is_script=is_script or default_is_script(),
        entry_points=entry_points,
        max_workers=max_workers,
    )
    assert not result.failed
    return [site for sites in result.py_sites[checker].values() for site in sites]


def counts(match: RuleMatch, sites: list[Site]) -> tuple[int, int]:
    """(following, contradicting) of ``sites`` under ``match``."""
    following = sum(
        1
        for s in sites
        if s.option in match.preferred or (not match.preferred and s.option not in match.prohibited)
    )
    return following, len(sites) - following


def policy() -> Policy:
    return Policy(
        effective_fail_on="none",
        gated=False,
        source="head",
        history_days=90,
        thresholds=Thresholds(80, 20, 20, 50, 70, 5),
        excludes=(),
        max_file_bytes=1048576,
        checkers=DEFAULT_CHECKERS,
        ignores=(),
        markers=MappingProxyType({}),
        paths=None,
        comment=True,
        sarif=False,
        after_merge_notes=(),
        notes=(),
    )


def extracted(text: str) -> list[Rule]:
    """Every rule in an ``AGENTS.md`` with this text, as C6 extracts and maps it."""
    file = InstructionFile("AGENTS.md", text.encode(), "", False)
    return list(extract_rules([file], policy(), REGISTRY_UNDER_TEST).rules)


def rules_of(text: str) -> list[tuple[int, str | None]]:
    """(line, checker id or None) for every rule in an ``AGENTS.md`` with this text."""
    return [(rule.line, rule.checker) for rule in extracted(text)]


_T = TypeVar("_T")
MIB = 1 << 20
RATIO_FLOOR_S = 1.0
LINEAR_SIZES = (1 << 17, 1 << 18, 1 << 19, 1 << 20)
"""128 KiB up to 1 MiB, the instruction-file size cap (R2.3). A quadratic path takes minutes at
the top and several seconds already at the bottom, so it fails at the first size."""


def best_time(
    func: Callable[[], object],
    repeat: int = 3,
    *,
    stop_above: float = float("inf"),
    stop_below: float = 0.0,
) -> float:
    """The fastest of ``repeat`` runs, as in the extraction tests: one slow run on a loaded
    runner doesn't count. A run slower than ``stop_above`` ends the repeats (it is far too
    slow for noise, and a quadratic path would otherwise take three times as long to fail).
    A run at or under ``stop_below`` ends them too: the best can only be lower, and the caller
    asked for no more precision than that."""
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        func()
        elapsed = time.perf_counter() - start
        best = min(best, elapsed)
        if elapsed > stop_above or elapsed <= stop_below:
            break
    return best


def assert_linear(
    make: Callable[[int], _T],
    run: Callable[[_T], object],
    *,
    sizes: tuple[int, ...] = LINEAR_SIZES,
    label: str = "",
) -> None:
    """``run(make(n))`` is linear in ``n`` for each size, in the repo's ReDoS-test style.

    The check is an absolute budget that grows from 1.0 s with 4 s per MiB, with the best of
    three runs at every size (a run over five times the budget ends the repeats early). Linear
    code takes milliseconds to a few hundred ms here, so the budget is generous, and a
    quadratic path misses it at the smallest size.

    Doubling the size must also not much more than triple the time, but only once the
    previous step took over ``RATIO_FLOOR_S`` (1 s, so in practice only for code that is already
    far from linear): below that, scheduler and cache noise moves the ratio far more than any
    algorithm does (a Windows runner saw 3.65x from 0.19 s to 0.69 s, and the guards test flaked
    about 1 run in 12 under load at 0.26 s, on linear code). The 5 s cap at 1 MiB stays.

    A first run of ``RATIO_FLOOR_S`` or less ends the repeats at that size, because the other
    two could not change a verdict: the run is under the budget (at least 1 s), it is under any
    ratio limit that applies (a ratio is only checked above the floor, and then against three
    times a previous step over the floor), and the next size skips its ratio check either way,
    since its ``previous`` is at most the floor with this run or with a faster best. Only a size
    that takes over a second keeps the best of three.
    """
    previous = 0.0
    for n in sizes:
        data = make(n)
        budget = 1.0 + 4.0 * n / MIB
        elapsed = best_time(
            partial(run, data), repeat=3, stop_above=5 * budget, stop_below=RATIO_FLOOR_S
        )
        assert elapsed < budget, (label, n, elapsed)
        if previous > RATIO_FLOOR_S:
            assert elapsed < 3 * previous + 0.05, (label, n, elapsed, previous)
        previous = elapsed


__all__ = [
    "LINEAR_SIZES",
    "MIB",
    "RATIO_FLOOR_S",
    "assert_linear",
    "best_time",
    "counts",
    "default_is_script",
    "extracted",
    "policy",
    "rules_of",
    "sites_of",
]
