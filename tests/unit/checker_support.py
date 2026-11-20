"""Helpers shared by the real-checker tests (T-016): run the registry on sources and count sites.

``counts`` is the I-10 rule: a site follows when its option is preferred, or when nothing
is preferred and the option isn't prohibited; relevant sites are every site of the checker.
"""

from collections.abc import Callable, Mapping
from types import MappingProxyType

from conventiondrift.checkers import registry
from conventiondrift.checkers.pool import analyze
from conventiondrift.discover.globmatch import GlobSet
from conventiondrift.model import (
    CheckerId,
    InstructionFile,
    Policy,
    PyFile,
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
) -> list[Site]:
    """All of ``checker``'s sites over ``files`` ({path: source}), in the walk's order."""
    result = analyze(
        [PyFile(path, text.encode()) for path, text in files.items()],
        checkers=REGISTRY_UNDER_TEST,
        is_script=default_is_script(),
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


def rules_of(text: str) -> list[tuple[int, str | None]]:
    """(line, checker id or None) for every rule in an ``AGENTS.md`` with this text."""
    file = InstructionFile("AGENTS.md", text.encode(), "", False)
    extraction = extract_rules([file], policy(), REGISTRY_UNDER_TEST)
    return [(rule.line, rule.checker) for rule in extraction.rules]


__all__ = ["counts", "default_is_script", "policy", "rules_of", "sites_of"]
