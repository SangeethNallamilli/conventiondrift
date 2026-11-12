"""The replaceable component seam (INTERFACES I-2, I-11, I-14; DESIGN §12 A-1).

These are the Protocols for each replaceable part and the ``Components``
bundle that tests pass to ``core.run``. Every field left as ``None`` means
"use the production default"; T-028 wires the defaults.
"""

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol

from conventiondrift.checkers.base import Checker
from conventiondrift.model import Conflict, InstructionFile, Policy, PyFile, Result, Rule, Window

Side = Literal["base", "head"]
TreeEntry = tuple[str, str, int | None, str]
"""(mode, oid, size, path); size is None for gitlinks."""
ChangedFile = tuple[str, str | None, str]
"""(status letter, old path or None, new path)."""
PublishOutcome = Literal["posted", "updated", "skipped"]


class GitReaderProtocol(Protocol):
    """C3, the read-only git reader. ``gitread.GitReader`` satisfies it."""

    def resolve(self, rev: str) -> str: ...

    def is_shallow(self) -> bool: ...

    def has_object(self, sha: str) -> bool: ...

    def merge_base(self, a: str, b: str) -> str | None: ...

    def commit_date(self, sha: str) -> datetime: ...

    def first_parent_chain(self, sha: str, limit: int) -> Sequence[tuple[str, datetime]]: ...

    def patches(self, from_sha: str | None, to_sha: str) -> Iterator[bytes]:
        """Newest commit first, chunks of at most 1 MiB; C8 enforces the byte cap (I-14 item 9)."""
        ...

    def tree(self, sha: str) -> Sequence[TreeEntry]: ...

    def blob(self, oid: str, max_bytes: int) -> bytes: ...

    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]: ...

    def close(self) -> None:
        """Kill and reap the long-lived cat-file processes; idempotent (I-14 item 9)."""
        ...


class Extractor(Protocol):
    """C6, instruction files to rules and conflicts."""

    def extract(
        self,
        files: Sequence[InstructionFile],
        policy: Policy,
        checkers: Mapping[str, Checker],
    ) -> tuple[Sequence[Rule], Sequence[Conflict]]: ...


class History(Protocol):
    """C8, recent-line dating. In scan mode ``git`` is the HEAD reader (None without a HEAD)."""

    def recent(
        self,
        git: GitReaderProtocol | None,
        window: Window,
        sites: Mapping[Side, Mapping[str, frozenset[int]]],
        scan_files: Sequence[PyFile] = (),
    ) -> frozenset[tuple[Side, str, int]]: ...


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
    """C12. Never raises for HTTP errors; returns (outcome, note)."""

    def publish(
        self,
        *,
        repo: str,
        pr_number: int,
        run_head_sha: str,
        comment: str | None,
        sarif: str | None,
    ) -> tuple[PublishOutcome, str | None]: ...


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
