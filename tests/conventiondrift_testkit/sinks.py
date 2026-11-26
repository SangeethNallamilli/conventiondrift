"""An in-memory ``Sinks`` (I-2, CON-73) for tests: records every write, touches no runner path.

It is a plain object with the ``Sinks`` surface, so a test can replace the whole output side of
a run through ``Components(sinks=MemorySinks())`` or inject it into the fallback writer, with no
environment variables and no filesystem. The recorded lists are the assertion surface; the
``*_status`` knobs let a test drive a refused or unavailable destination.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from conventiondrift.components import Outputs, PublishOutcome, SinkStatus

__all__ = ["MemorySinks"]

_FAKE_TEMP = Path("/memory/runner-temp")


class MemorySinks:
    """A ``Sinks`` that keeps every write in memory; statuses are configurable per method."""

    def __init__(
        self,
        *,
        summary_status: SinkStatus = "written",
        outputs_status: SinkStatus = "written",
        annotations_status: SinkStatus = "written",
        artifact_result: Path | None = None,
        publish_result: tuple[PublishOutcome, str | None] = ("skipped", None),
    ) -> None:
        self._summary_status = summary_status
        self._outputs_status = outputs_status
        self._annotations_status = annotations_status
        self._artifact_result = artifact_result
        self._publish_result = publish_result
        self.published: list[dict[str, object]] = []
        self.outputs_written: list[Outputs] = []
        self.summaries: list[str] = []
        self.annotation_lines: list[tuple[str, ...]] = []
        self.artifacts: dict[str, bytes] = {}
        self.calls: list[str] = []
        """The method names, in call order, for tests that pin the write sequence."""

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
    ) -> tuple[PublishOutcome, str | None]:
        self.calls.append("publish")
        self.published.append(
            {
                "repo": repo,
                "pr_number": pr_number,
                "run_head_sha": run_head_sha,
                "comment": comment,
                "sarif": sarif,
                "sarif_commit_sha": sarif_commit_sha,
                "sarif_ref": sarif_ref,
            }
        )
        return self._publish_result

    def outputs(self, outputs: Outputs) -> SinkStatus:
        self.calls.append("outputs")
        self.outputs_written.append(outputs)
        return self._outputs_status

    def summary_section(self, text: str) -> SinkStatus:
        self.calls.append("summary_section")
        self.summaries.append(text)
        return self._summary_status

    def annotations(self, lines: Sequence[str]) -> SinkStatus:
        self.calls.append("annotations")
        self.annotation_lines.append(tuple(lines))
        return self._annotations_status

    def artifact(self, *, name: str, data: bytes) -> Path | None:
        self.calls.append("artifact")
        self.artifacts[name] = data
        if self._artifact_result is not None:
            return self._artifact_result
        return _FAKE_TEMP / name
