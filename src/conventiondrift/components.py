"""The replaceable component seam (INTERFACES I-2, I-11, I-14; DESIGN §12 A-1).

These are the Protocols for each replaceable part and the ``Components``
bundle that tests pass to ``core.run``. Every field left as ``None`` means
"use the production default"; T-028 wires the defaults.
"""

import ast
from collections.abc import Callable, Generator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol

from conventiondrift.model import (
    CheckerId,
    Extraction,
    FileContext,
    HistoryResult,
    InstructionFile,
    Policy,
    PyFile,
    Result,
    RuleMatch,
    Site,
    TrackedState,
    Window,
)
from conventiondrift.model import (
    Side as Side,
)

TreeEntry = tuple[str, str, int | None, str]
"""(mode, oid, size, path); size is None for gitlinks."""
ChangedFile = tuple[str, str | None, str]
"""(status letter, old path or None, new path)."""
PublishOutcome = Literal["posted", "updated", "skipped"]


class Checker(Protocol):
    """One convention family (e.g. logging) compared across its options (I-10, ADR-0003).

    Internal in v1, shaped as a future plugin API. The Protocol lives here, with the
    other I-11 Protocols, so importing this module never loads a checker
    (I-13 C6 item 8). ``checkers.base`` re-exports it.
    """

    id: CheckerId
    experimental: bool
    options: frozenset[str]
    inputs: frozenset[Literal["python-ast", "manifest"]]

    def match_rule(self, normalized_text: str) -> RuleMatch | None: ...

    def ast_handlers(
        self,
    ) -> Mapping[type[ast.AST], Callable[[ast.AST, FileContext], Iterable[Site]]]: ...

    def manifest_sites(self, files: Mapping[str, bytes]) -> Iterable[Site]: ...


class GitReaderProtocol(Protocol):
    """C3, the read-only git reader. ``gitread.GitReader`` satisfies it."""

    def resolve(self, rev: str) -> str: ...

    def is_shallow(self) -> bool: ...

    def has_object(self, sha: str) -> bool: ...

    def merge_base(self, a: str, b: str) -> str | None: ...

    def commit_date(self, sha: str) -> datetime: ...

    def first_parent_chain(self, sha: str, limit: int) -> Sequence[tuple[str, datetime]]: ...

    def patches(self, from_sha: str | None, to_sha: str) -> Generator[bytes, None, None]:
        """Newest commit first, chunks of at most 1 MiB; C8 enforces the byte cap (I-14 item 9).

        A generator, so C8 can ``.close()`` it at its cap without a cast.
        """
        ...

    def tree(self, sha: str) -> Sequence[TreeEntry]: ...

    def blob(self, oid: str, max_bytes: int) -> bytes: ...

    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]: ...

    def close(self) -> None:
        """Kill and reap the long-lived cat-file processes; idempotent (I-14 item 9)."""
        ...


class Extractor(Protocol):
    """C6, instruction files to the full ``Extraction`` (I-13 C6 item 3)."""

    def extract(
        self,
        files: Sequence[InstructionFile],
        policy: Policy,
        checkers: Mapping[str, Checker],
    ) -> Extraction: ...


class History(Protocol):
    """C8, recent-line dating (I-14).

    PR mode: ``tips`` has the commit each side analyzes (base: merge base, head: PR head).
    Scan mode: ``git`` is the HEAD reader (None without a HEAD), ``tips`` is empty,
    ``scan_files`` are the working-tree files and ``scan_tracked`` has one entry per
    tracked scan file, from C4 (A-3).
    """

    def recent(
        self,
        git: GitReaderProtocol | None,
        window: Window,
        sites: Mapping[Side, Mapping[str, frozenset[int]]],
        *,
        tips: Mapping[Side, str] = {},
        scan_files: Sequence[PyFile] = (),
        scan_tracked: Mapping[str, TrackedState] = {},
    ) -> HistoryResult: ...


@dataclass(frozen=True, slots=True)
class Rendered:
    """Everything C11 renders from one ``Result``."""

    comment: str | None
    summary: str
    annotations: tuple[str, ...]
    sarif: str | None
    json: str
    text: str


class Renderer(Protocol):
    """C11, the single renderer."""

    def render(self, result: Result, *, previous_comment: bool) -> Rendered: ...


class GitHubClient(Protocol):
    """C12. Never raises for HTTP errors; returns (outcome, note).

    ``sarif_commit_sha`` / ``sarif_ref`` are ``GITHUB_SHA`` / ``GITHUB_REF``
    (I-5), passed unchanged by T-028 (I-13 C12 ruling 7). ``lookup`` returns
    (our comment exists, note). It is read-only and never raises; T-028 calls
    it before rendering (I-13 C12 ruling 1).
    """

    def publish(
        self,
        *,
        repo: str,
        pr_number: int,
        run_head_sha: str,
        comment: str | None,
        sarif: str | None,
        sarif_commit_sha: str,
        sarif_ref: str,
    ) -> tuple[PublishOutcome, str | None]: ...

    def lookup(self, *, repo: str, pr_number: int) -> tuple[bool, str | None]: ...


@dataclass(frozen=True, kw_only=True)
class Components:
    """Replaceable parts for tests (I-2). ``None`` means the production default."""

    git_reader: Callable[[Path], GitReaderProtocol] | None = None
    checkers: Mapping[str, Checker] | None = None
    extractor: Extractor | None = None
    history: History | None = None
    renderer: Renderer | None = None
    github_client: Callable[[str, str], GitHubClient] | None = None
    github_base_url: str | None = None
