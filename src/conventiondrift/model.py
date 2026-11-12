"""Shared immutable boundary types (INTERFACES I-10, I-11; DESIGN §12 A-1).

Every component boundary carries these frozen dataclasses. Collections are
tuples or frozensets so a value can't change after it is built. Field names
and value sets follow I-10, I-11 and the I-9 report shapes.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

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
FailOn = Literal["none", "new-stale", "any-stale"]
PolicySource = Literal["base", "head"]
Case = Literal["made-stale-by-code", "stale-rule-added", "fixed", "pre-existing-stale", "removed"]
SuggestionKind = Literal["replace", "tie", "remove-or-rewrite", "none"]


@dataclass(frozen=True)
class InstructionFile:
    """An instruction file found by C4 (AGENTS.md, CLAUDE.md, ...)."""

    path: str
    data: bytes


@dataclass(frozen=True)
class PyFile:
    """A Python file in scope: repo-relative POSIX path and its bytes (I-11 C4)."""

    path: str
    data: bytes


@dataclass(frozen=True)
class SkippedFile:
    """A file that was not analyzed, with the reason shown in the report (I-9)."""

    path: str
    reason: str


@dataclass(frozen=True)
class Policy:
    """C5 output (I-11). Notes are summary lines; ``source`` says which side applied."""

    effective_fail_on: FailOn
    source: PolicySource
    after_merge_notes: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class RuleMatch:
    """Result of mapping one rule sentence to a checker (I-10)."""

    preferred: frozenset[str]
    prohibited: frozenset[str]
    specificity: int


@dataclass(frozen=True)
class Site:
    """One place in the code where a checker's option is used (I-10)."""

    file: str
    line: int
    col: int
    option: str


@dataclass(frozen=True)
class FileContext:
    """What a checker may know about the file it is looking at (I-10)."""

    path: str
    is_test_file: bool
    is_script: bool


@dataclass(frozen=True)
class Rule:
    """One extracted rule (I-11 C6). ``checker`` and ``match`` are None when not verifiable."""

    id: str
    file: str
    line: int
    also_at: tuple[int, ...]
    text: str
    checker: CheckerId | None
    match: RuleMatch | None
    scope_dir: str
    ignored: bool


@dataclass(frozen=True)
class Conflict:
    """Rules with overlapping scope whose options clash, by rule id (I-9 ``conflicts``)."""

    rules: tuple[str, ...]
    checker: CheckerId


class Verdict(StrEnum):
    """The six verdicts; values are the exact I-9 strings."""

    HOLDS = "Holds"
    STALE = "Stale"
    MIGRATING = "Migrating"
    CONTESTED = "Contested"
    INSUFFICIENT_DATA = "Insufficient data"
    NOT_VERIFIABLE = "Not verifiable"


@dataclass(frozen=True)
class CausingFile:
    """A changed file whose sites for a rule changed (I-9 ``causing_files``)."""

    file: str
    following_delta: int
    contradicting_delta: int


@dataclass(frozen=True)
class Alternative:
    """A candidate option and its head site count (I-9 ``suggestion.alternatives``)."""

    option: str
    sites: int


@dataclass(frozen=True)
class Suggestion:
    """Suggested rewording for a rule (I-9 ``suggestion``)."""

    kind: SuggestionKind
    named_option: str | None
    alternatives: tuple[Alternative, ...]
    new_text: str | None


@dataclass(frozen=True)
class RuleResult:
    """C10 output per rule (I-11): the before/after case, causing files and suggestion."""

    case: Case | None
    causing_files: tuple[CausingFile, ...]
    suggestion: Suggestion


@dataclass(frozen=True)
class Result:
    """Everything C11 renders from (I-11 C11)."""

    policy: Policy
    instruction_files: tuple[InstructionFile, ...]
    skipped_files: tuple[SkippedFile, ...]
    rule_results: tuple[RuleResult, ...]
    conflicts: tuple[Conflict, ...]
