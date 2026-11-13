"""Shared immutable boundary types (INTERFACES I-10, I-11, I-13; DESIGN §12 A-1).

Every component boundary carries these frozen, slotted dataclasses. Collections
are tuples or frozensets and ``Mapping`` fields hold read-only mappings
(``types.MappingProxyType``). Paths are repo-relative POSIX strings. Field
names and value sets follow I-13, which C11 maps one-to-one to the I-9 report.
``__post_init__`` checks the structural invariants I-13 lists and the I-10
``RuleMatch`` validity conditions, and raises ``ValueError`` when one is broken.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from itertools import pairwise
from types import MappingProxyType
from typing import Any, Literal, cast, get_args

CheckerId = Literal[
    "logging",
    "http-client",
    "test-framework",
    "money",
    "string-format",
    "exceptions",
    "type-hints",
    "package-manager",
]
SkipReason = Literal[
    "syntax error",
    "not decodable",
    "binary",
    "size limit",
    "symlink",
    "outside repository",
    "syntax newer than analyzer",
    "special file",
    "cap exceeded",
    "walk limit",
    "manifest parse error",
    "unsupported path",
    "unreadable",
]
Case = Literal["made-stale-by-code", "stale-rule-added", "fixed", "pre-existing-stale", "removed"]

_CHECKER_IDS = frozenset(get_args(CheckerId))


def _check_sorted(keys: Iterable[Any], what: str) -> None:
    """Raise ValueError unless ``keys`` is in non-decreasing order (one linear pass)."""
    for prev, cur in pairwise(keys):
        if cur < prev:
            raise ValueError(f"{what} must be sorted")


def _check_marker_pairs(pairs: object) -> None:
    """I-13 ``Policy.markers`` values: ``(line, alone_on_line)`` pairs (SR #32 C-1, L2).

    ``line`` is an int >= 1 (not a bool), ``alone_on_line`` a real bool, and the
    lines are strictly increasing: sorted, one entry per line. Messages are fixed.
    """
    if not isinstance(pairs, tuple):
        raise ValueError("Policy.markers values must be tuples of pairs")
    previous = 0
    for pair in pairs:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise ValueError("Policy.markers entries must be (line, alone_on_line) pairs")
        line, alone = pair
        if type(line) is not int or line < 1:
            raise ValueError("Policy.markers lines must be integers >= 1")
        if type(alone) is not bool:
            raise ValueError("Policy.markers alone_on_line must be a bool")
        if line <= previous:
            raise ValueError("Policy.markers must be sorted with no duplicate lines")
        previous = line


def _read_only(value: Mapping[Any, Any]) -> Mapping[Any, Any]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """Result of mapping one rule sentence to a checker (I-10)."""

    preferred: frozenset[str]
    prohibited: frozenset[str]
    specificity: int

    def __post_init__(self) -> None:
        # A wrong type is a TypeError, an invalid value a ValueError (I-10 validity). A plain
        # set would also pass the checks below but leave the match unhashable (I-13).
        if not (isinstance(self.preferred, frozenset) and isinstance(self.prohibited, frozenset)):
            raise TypeError("RuleMatch preferred and prohibited must be frozensets")
        if not (self.preferred | self.prohibited):
            raise ValueError("RuleMatch preferred and prohibited must not both be empty")
        if self.preferred & self.prohibited:
            raise ValueError("RuleMatch preferred and prohibited must be disjoint")


@dataclass(frozen=True, slots=True)
class Site:
    """One place in the code where a checker's option is used (I-10)."""

    file: str
    line: int
    col: int
    option: str


@dataclass(frozen=True, slots=True)
class FileContext:
    """What a checker may know about the file it is looking at (I-10, I-13 Q10)."""

    path: str
    is_test_file: bool
    is_script: bool
    main_guard_spans: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class InstructionFile:
    """An instruction file found by C4, with the scope C4 gave it (I-13 Q3)."""

    path: str
    data: bytes
    scope_dir: str
    via_paths_input: bool


@dataclass(frozen=True, slots=True)
class PyFile:
    """A Python file in scope (I-11 C4)."""

    path: str
    data: bytes


@dataclass(frozen=True, slots=True)
class ManifestFile:
    """A package-manager manifest in scope (I-11 C4, I-13 Q2)."""

    path: str
    data: bytes


@dataclass(frozen=True, slots=True)
class SkippedFile:
    """A file that was not analyzed, with the reason shown in the report (I-9, I-13 Q5)."""

    path: str
    reason: SkipReason


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Verdict thresholds in percent, plus the minimum relevant sites (I-6, I-13)."""

    holds: int
    stale_overall: int
    stale_recent: int
    migrating_overall: int
    migrating_recent: int
    min_sites: int


@dataclass(frozen=True, slots=True)
class CheckerPolicy:
    """One checker's settings; ``script_paths`` is empty except for logging (I-13)."""

    enabled: bool
    script_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IgnoreEntry:
    """One config ``ignore`` entry: by file and line, or by rule text (I-6, I-13)."""

    file: str | None
    line: int | None
    text: str | None


@dataclass(frozen=True, slots=True, eq=True)
class Policy:
    """C5 output: the effective settings for the run (I-11, I-13 Q6). Not hashable (A1)."""

    __hash__ = None  # type: ignore[assignment]  # unhashable by design (I-13, A1)

    effective_fail_on: Literal["none", "new-stale", "any-stale"]
    gated: bool
    source: Literal["base", "head"]
    history_days: int
    thresholds: Thresholds
    excludes: tuple[str, ...]
    max_file_bytes: int
    checkers: Mapping[CheckerId, CheckerPolicy]
    ignores: tuple[IgnoreEntry, ...]
    markers: Mapping[str, tuple[tuple[int, bool], ...]]
    """File -> sorted ``(line, alone_on_line)`` pairs, from the policy side (I-7, I-13)."""
    paths: tuple[str, ...] | None
    comment: bool
    sarif: bool
    after_merge_notes: tuple[str, ...]
    notes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "checkers", _read_only(self.checkers))
        object.__setattr__(self, "markers", _read_only(self.markers))
        if self.checkers.keys() != _CHECKER_IDS:
            raise ValueError("Policy.checkers must have exactly the 8 checker ids")
        if any(p.script_paths for cid, p in self.checkers.items() if cid != "logging"):
            raise ValueError('CheckerPolicy.script_paths must be () except for "logging"')
        if self.gated != (self.effective_fail_on != "none"):
            raise ValueError('Policy.gated must equal effective_fail_on != "none"')
        for pairs in self.markers.values():
            _check_marker_pairs(pairs)


@dataclass(frozen=True, slots=True)
class Rule:
    """One extracted rule (I-11 C6, I-13). ``scope_dir`` "" means the whole repo."""

    id: str
    file: str
    line: int
    also_at: tuple[int, ...]
    text: str
    normalized_text: str
    checker: CheckerId | None
    match: RuleMatch | None
    scope_dir: str
    ignored: bool
    disabled: bool

    def __post_init__(self) -> None:
        if self.scope_dir.startswith("/") or self.scope_dir.endswith("/"):
            raise ValueError("Rule.scope_dir must have no leading or trailing slash")


@dataclass(frozen=True, slots=True)
class Conflict:
    """Two conflicting rules, by sorted rule id (I-9 ``conflicts``, I-13)."""

    rules: tuple[str, str]
    checker: CheckerId

    def __post_init__(self) -> None:
        _check_sorted(self.rules, "Conflict.rules")


class Verdict(StrEnum):
    """The six verdicts; values are the exact I-9 strings (I-13 Q7)."""

    HOLDS = "Holds"
    STALE = "Stale"
    MIGRATING = "Migrating"
    CONTESTED = "Contested"
    INSUFFICIENT = "Insufficient data"
    NOT_VERIFIABLE = "Not verifiable"


@dataclass(frozen=True, slots=True)
class Counts:
    """Site counts; the percentage is computed only for display, by C11."""

    following: int
    contradicting: int
    relevant: int


@dataclass(frozen=True, slots=True)
class SiteResult:
    """A site with whether it follows the rule and whether it is recent."""

    site: Site
    follows: bool
    recent: bool


@dataclass(frozen=True, slots=True)
class SideResult:
    """C9 output for one rule on one side (I-13 Q7)."""

    verdict: Verdict
    sites: tuple[SiteResult, ...]
    overall: Counts
    recent: Counts | None
    recent_unavailable_reason: Literal["no history", "no relevant sites in the window"] | None

    def __post_init__(self) -> None:
        _check_sorted(
            ((s.site.file, s.site.line, s.site.col, s.site.option) for s in self.sites),
            "SideResult.sites",
        )


@dataclass(frozen=True, slots=True)
class CausingFile:
    """A changed file whose sites for a rule changed (I-9 ``causing_files``)."""

    file: str
    following_delta: int
    contradicting_delta: int


@dataclass(frozen=True, slots=True)
class Alternative:
    """A candidate option and its head site count (I-9 ``suggestion.alternatives``)."""

    option: str
    sites: int


@dataclass(frozen=True, slots=True)
class Suggestion:
    """Suggested rewording for a rule (I-9 ``suggestion``, I-13 Q8)."""

    kind: Literal["replace", "tie", "remove-or-rewrite", "none"]
    named_option: str | None
    alternatives: tuple[Alternative, ...]
    new_text: str | None


@dataclass(frozen=True, slots=True)
class RuleResult:
    """C10 output, one per rule identity (I-11, I-13 Q8)."""

    rule_id: str
    base_rule: Rule | None
    head_rule: Rule | None
    base: SideResult | None
    head: SideResult | None
    conflict_with: tuple[str, ...]
    case: Case | None
    causing_files: tuple[CausingFile, ...]
    suggestion: Suggestion

    def __post_init__(self) -> None:
        if self.base_rule is None and self.head_rule is None:
            raise ValueError("RuleResult must have at least one of base_rule/head_rule")


@dataclass(frozen=True, slots=True)
class Window:
    """The recent-adherence window; ``end`` is timezone-aware (I-9, I-13)."""

    end: datetime | None
    days: int
    available: bool
    unavailable_reason: Literal["no history", "internal error"] | None

    def __post_init__(self) -> None:
        if self.end is not None and self.end.utcoffset() is None:
            raise ValueError("Window.end must be timezone-aware")


@dataclass(frozen=True, slots=True)
class InternalError:
    """An internal error as reported: component and fixed message only (DESIGN §4)."""

    component: str
    message: str


@dataclass(frozen=True, slots=True)
class ReportCounts:
    """Report-level counts (I-9 ``counts``)."""

    stale: int
    new_stale: int
    rules_changed: int
    rules_unchanged: int


@dataclass(frozen=True, slots=True, eq=True)
class Result:
    """Everything C11 renders from (I-11 C11, I-13 Q9). Not hashable (A1)."""

    __hash__ = None  # type: ignore[assignment]  # unhashable by design (I-13, A1)

    mode: Literal["compare", "head-only", "scan"]
    base_sha: str | None
    head_sha: str
    head_only_reason: Literal["shallow clone", "missing object", "no merge base"] | None
    window: Window
    policy: Policy
    instruction_files: tuple[InstructionFile, ...]
    skipped_files: tuple[SkippedFile, ...]
    rule_results: tuple[RuleResult, ...]
    conflicts: tuple[Conflict, ...]
    unattached_markers: tuple[tuple[str, int], ...]
    internal_errors: tuple[InternalError, ...]
    counts: ReportCounts
    notes: tuple[str, ...]
    analyzer_python: str

    def __post_init__(self) -> None:
        _check_sorted(map(_rule_result_key, self.rule_results), "Result.rule_results")


def _rule_result_key(result: RuleResult) -> tuple[str, int]:
    # RuleResult.__post_init__ guarantees at least one of the two rules.
    rule = cast(Rule, result.head_rule or result.base_rule)
    return (rule.file, rule.line)
