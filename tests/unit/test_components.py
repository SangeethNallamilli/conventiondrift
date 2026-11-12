"""Unit tests for the component seam in conventiondrift.components (T-006a, I-14)."""

import dataclasses
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import get_args

import pytest

from conventiondrift.checkers.base import Checker
from conventiondrift.components import (
    ChangedFile,
    Components,
    GitHubClient,
    GitReaderProtocol,
    PublishOutcome,
    Rendered,
    Side,
    TreeEntry,
)
from conventiondrift.model import (
    CheckerId,
    CheckerPolicy,
    Policy,
    ReportCounts,
    Result,
    Thresholds,
    Window,
)

FIELDS = (
    "git_reader",
    "checkers",
    "extractor",
    "history",
    "renderer",
    "github_client",
    "github_base_url",
)


class _MemoryGit:
    """An in-memory C3 stand-in written only against GitReaderProtocol."""

    def resolve(self, rev: str) -> str:
        return "a" * 40

    def is_shallow(self) -> bool:
        return False

    def has_object(self, sha: str) -> bool:
        return True

    def merge_base(self, a: str, b: str) -> str | None:
        return None

    def commit_date(self, sha: str) -> datetime:
        return datetime(2026, 11, 12, tzinfo=UTC)

    def first_parent_chain(self, sha: str, limit: int) -> Sequence[tuple[str, datetime]]:
        return [(sha, self.commit_date(sha))][:limit]

    def patches(self, from_sha: str, to_sha: str) -> Iterator[bytes]:
        yield b""

    def tree(self, sha: str) -> Sequence[TreeEntry]:
        return [("100644", "b" * 40, 3, "a.py")]

    def blob(self, oid: str, max_bytes: int) -> bytes:
        return b"x=1"[:max_bytes]

    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]:
        return [("M", None, "a.py")]


class _History:
    def recent(
        self,
        git: GitReaderProtocol | None,
        window: Window,
        sites: Mapping[Side, Mapping[str, frozenset[int]]],
        scan_files: Sequence[object] = (),
    ) -> frozenset[tuple[Side, str, int]]:
        return frozenset(("head", f, n) for f, lines in sites["head"].items() for n in lines)


class _Client:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url

    def publish(
        self,
        *,
        repo: str,
        pr_number: int,
        run_head_sha: str,
        comment: str | None,
        sarif: str | None,
    ) -> tuple[PublishOutcome, str | None]:
        return ("skipped", "read-only token")


def test_components_default_to_none() -> None:
    components = Components()
    assert tuple(f.name for f in dataclasses.fields(components)) == FIELDS
    assert all(getattr(components, name) is None for name in FIELDS)


def test_components_are_frozen_and_keyword_only() -> None:
    components = Components()
    with pytest.raises(dataclasses.FrozenInstanceError):
        components.checkers = {}  # type: ignore[misc]
    with pytest.raises(TypeError):
        Components(None)  # type: ignore[misc]


def test_components_take_factories_and_stand_ins() -> None:
    def git_factory(repo: Path) -> GitReaderProtocol:
        return _MemoryGit()

    def client_factory(base_url: str, token: str) -> GitHubClient:
        return _Client(base_url, token)

    checkers: Mapping[str, Checker] = {}
    components = Components(
        git_reader=git_factory,
        checkers=checkers,
        history=_History(),
        github_client=client_factory,
        github_base_url="http://127.0.0.1:8080",
    )
    git = components.git_reader(Path("/repo")) if components.git_reader else None
    assert git is not None
    assert git.tree("a" * 40)[0][3] == "a.py"
    assert git.blob("b" * 40, 1) == b"x"
    assert git.changed_files("a", "b") == [("M", None, "a.py")]
    window = Window(end=None, days=90, available=False, unavailable_reason="no history")
    assert components.history is not None
    assert components.history.recent(git, window, {"head": {"a.py": frozenset({2})}}) == frozenset(
        {("head", "a.py", 2)}
    )
    assert components.github_client is not None
    client = components.github_client("http://127.0.0.1:8080", "fake-token")
    assert client.publish(
        repo="o/r", pr_number=1, run_head_sha="a" * 40, comment=None, sarif=None
    ) == ("skipped", "read-only token")
    variant = dataclasses.replace(components, github_base_url=None)
    assert variant.git_reader is git_factory
    assert variant.github_base_url is None


def test_rendered_fields_and_immutability() -> None:
    rendered = Rendered(
        comment=None, summary="s", annotations=("a",), sarif=None, json="{}", text="t"
    )
    assert tuple(f.name for f in dataclasses.fields(rendered)) == (
        "comment",
        "summary",
        "annotations",
        "sarif",
        "json",
        "text",
    )
    assert not hasattr(rendered, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        rendered.summary = "x"  # type: ignore[misc]
    assert rendered == dataclasses.replace(rendered)
    assert hash(rendered) == hash(dataclasses.replace(rendered))


def test_renderer_protocol_shape() -> None:
    class _Renderer:
        def render(self, result: Result, *, previous_comment: bool) -> Rendered:
            return Rendered(
                comment=None if previous_comment else "c",
                summary="",
                annotations=(),
                sarif=None,
                json="",
                text="",
            )

    components = Components(renderer=_Renderer())
    assert components.renderer is not None
    rendered = components.renderer.render(_minimal_result(), previous_comment=False)
    assert isinstance(rendered, Rendered)
    assert rendered.comment == "c"
    again = components.renderer.render(_minimal_result(), previous_comment=True)
    assert again.comment is None


def _minimal_result() -> Result:
    policy = Policy(
        effective_fail_on="none",
        gated=False,
        source="base",
        history_days=90,
        thresholds=Thresholds(80, 20, 20, 50, 70, 5),
        excludes=(),
        max_file_bytes=1048576,
        checkers=MappingProxyType({cid: CheckerPolicy(True, ()) for cid in get_args(CheckerId)}),
        ignores=(),
        markers=MappingProxyType({}),
        paths=None,
        comment=True,
        sarif=False,
        after_merge_notes=(),
        notes=(),
    )
    return Result(
        mode="scan",
        base_sha=None,
        head_sha="b" * 40,
        head_only_reason=None,
        window=Window(end=None, days=90, available=False, unavailable_reason="no history"),
        policy=policy,
        instruction_files=(),
        skipped_files=(),
        rule_results=(),
        conflicts=(),
        unattached_markers=(),
        internal_errors=(),
        counts=ReportCounts(stale=0, new_stale=0, rules_changed=0, rules_unchanged=0),
        notes=(),
        analyzer_python="3.13.5",
    )
