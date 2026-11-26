"""The production output sinks (I-2 ``Sinks``; CON-73).

``EnvSinks`` writes the runner-side outputs: the four ``GITHUB_OUTPUT`` values, the
``GITHUB_STEP_SUMMARY`` sections (the fallback writer's last path, I-14), the workflow-command
annotations on stdout, and ``$RUNNER_TEMP`` artifacts. It never raises for a refused or
unavailable destination: every method returns a ``SinkStatus`` (or ``None`` from ``artifact``),
so the fallback can call it last without losing the stderr report. ``ActionSinks`` adds
``publish``, which delegates unchanged to the C12 ``GitHubClient.publish``; this module never
imports ``github`` at runtime, so the fallback path does not load the HTTP stack.

The file rules are the ones the summary writer already had (SR ruling on T-006b): open without
following a symlink where ``O_NOFOLLOW`` exists, ``lstat`` first where it does not (Windows),
refuse anything that is not a regular file, append, and never inherit the descriptor. The flags
are injectable so ``fallback`` can pass its own module-level values, which the existing tests
monkeypatch to simulate a platform without ``O_NOFOLLOW``.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, cast

from conventiondrift.components import Outputs, SinkStatus
from conventiondrift.render.escape import output_heredoc

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps ``github`` out of this import path
    from conventiondrift.components import GitHubClient, PublishOutcome

__all__ = [
    "ARTIFACT_DIR",
    "NOFOLLOW",
    "OUTPUT_ENV",
    "OUTPUT_NAMES",
    "REPARSE_POINT",
    "SUMMARY_ENV",
    "SUMMARY_OPEN_FLAGS",
    "SUMMARY_REFUSED",
    "TEMP_ENV",
    "ActionSinks",
    "EnvSinks",
]

SUMMARY_ENV: Final = "GITHUB_STEP_SUMMARY"
OUTPUT_ENV: Final = "GITHUB_OUTPUT"
TEMP_ENV: Final = "RUNNER_TEMP"
ARTIFACT_DIR: Final = "conventiondrift"
"""The subdirectory of ``RUNNER_TEMP`` that holds the run's artifacts."""

SUMMARY_REFUSED: Final = (
    "conventiondrift: the job summary file could not be used; writing to stderr instead"
)
"""The warning when the summary file is refused or can't be written; never the path or OS text."""

NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
"""The platform's ``O_NOFOLLOW`` (0 where there is none, as on Windows)."""
REPARSE_POINT: Final[int] = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
"""The Windows reparse-point attribute bit, checked where ``O_NOFOLLOW`` is missing."""

_APPEND_FLAGS: Final = (
    os.O_WRONLY
    | os.O_APPEND
    | os.O_CREAT
    | NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)
SUMMARY_OPEN_FLAGS: Final = _APPEND_FLAGS
"""How the summary and output files are opened (SR ruling on T-006b).

Append, created if missing; a symlink is refused where ``O_NOFOLLOW`` exists; the fd is not
inherited. ``O_NONBLOCK`` keeps a FIFO from blocking the open (it fails, or is refused by the
regular-file check); it changes nothing for a regular file. ``O_BINARY`` matters on Windows.
"""

_OUTPUT_NAMES: Final = ("stale-count", "new-stale-count", "report-path", "sarif-path")
OUTPUT_NAMES: Final = _OUTPUT_NAMES
"""The four ``GITHUB_OUTPUT`` names, in the order they are written."""

_ARTIFACT_NAME: Final = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_ARTIFACT_OPEN_FLAGS: Final = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_TRUNC
    | NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)


def _no_link_before_open(path: str, *, nofollow: int) -> bool:
    """False if ``path`` must be refused before the open (SR ruling for Windows).

    Only where the open flags have no ``O_NOFOLLOW``: ``lstat`` the path; a missing file is
    created as before, any other error refuses, and so does a symlink or a reparse point.
    """
    if nofollow:
        return True
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True
    except (OSError, ValueError):  # ValueError: a NUL byte in the path
        return False
    if stat.S_ISLNK(st.st_mode):
        return False
    return not getattr(st, "st_file_attributes", 0) & REPARSE_POINT


def _append_bytes(path: str, data: bytes, *, flags: int, nofollow: int) -> bool:
    """Append ``data`` to ``path`` as a regular file; False if it was refused.

    The file must open with ``flags`` and ``fstat`` as a regular file; the descriptor is always
    closed. Without ``O_NOFOLLOW``, ``_no_link_before_open`` runs first. A write that fails
    part-way can leave a truncated file; the caller still reports through another path.
    """
    if not _no_link_before_open(path, nofollow=nofollow):
        return False
    try:
        fd = os.open(path, flags, 0o666)
    except (OSError, ValueError):  # ValueError: a NUL byte in the path
        return False
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except OSError:
        regular = False
    if not regular:
        os.close(fd)
        return False
    try:
        # Bytes, so the encoding is UTF-8 whatever the locale. ``fdopen`` owns and closes ``fd``.
        with os.fdopen(fd, "ab") as target:
            target.write(data)
    except (OSError, ValueError):  # ValueError too (e.g. a closed file): never raise, fall back
        return False
    return True


def _stdout_binary() -> BinaryIO | None:
    """``sys.stdout``'s byte stream, or None when the current stdout has no buffer."""
    buffer: object = getattr(sys.stdout, "buffer", None)
    return cast("BinaryIO", buffer) if buffer is not None else None


class EnvSinks:
    """The runner-side sinks of one run: real env paths, never raising (CON-73).

    ``open_flags`` / ``nofollow`` default to this module's constants; ``fallback`` passes its
    own module-level values, so the tests that simulate a platform without ``O_NOFOLLOW`` by
    patching them keep driving this code.
    """

    def __init__(
        self,
        env: Mapping[str, str],
        *,
        stdout: BinaryIO | None = None,
        open_flags: int | None = None,
        nofollow: int | None = None,
    ) -> None:
        self._env = env
        self._stdout = stdout
        self._open_flags = SUMMARY_OPEN_FLAGS if open_flags is None else open_flags
        self._nofollow = NOFOLLOW if nofollow is None else nofollow

    def outputs(self, outputs: Outputs) -> SinkStatus:
        """Append the four ``GITHUB_OUTPUT`` entries as one heredoc block each (AC-N3.13)."""
        path = self._env.get(OUTPUT_ENV)
        if not path:
            return "unavailable"
        values = (
            str(outputs.stale_count),
            str(outputs.new_stale_count),
            outputs.report_path,
            outputs.sarif_path,
        )
        try:
            block = "".join(
                output_heredoc(name, value)
                for name, value in zip(_OUTPUT_NAMES, values, strict=True)
            )
        except ValueError:  # a value the delimiter search could not fit: report, never raise
            return "refused"
        if _append_bytes(
            path, block.encode("utf-8"), flags=self._open_flags, nofollow=self._nofollow
        ):
            return "written"
        return "refused"

    def summary_section(self, text: str) -> SinkStatus:
        """Append one Markdown section to ``GITHUB_STEP_SUMMARY`` (the fallback writer's sink)."""
        path = self._env.get(SUMMARY_ENV)
        if not path:
            return "unavailable"
        if _append_bytes(
            path, text.encode("utf-8"), flags=self._open_flags, nofollow=self._nofollow
        ):
            return "written"
        return "refused"

    def annotations(self, lines: Sequence[str]) -> SinkStatus:
        """Write the workflow commands, one per line, to the binary stdout (C11 already escaped)."""
        if not lines:
            return "written"
        payload = "".join(line + "\n" for line in lines).encode("utf-8")
        stream = self._stdout if self._stdout is not None else _stdout_binary()
        try:
            if stream is not None:
                stream.write(payload)
                stream.flush()
            else:  # a text-only stdout (some test captures); write the same text
                sys.stdout.write(payload.decode("utf-8"))
                sys.stdout.flush()
        except (OSError, ValueError):
            return "refused"
        return "written"

    def artifact(self, *, name: str, data: bytes) -> Path | None:
        """Write ``data`` to ``$RUNNER_TEMP/conventiondrift/<name>``; None if it was not written.

        None means "no ``RUNNER_TEMP``" or "refused" (a bad name, a symlinked directory, an
        unwritable path); the caller writes an empty path into ``Outputs`` either way.
        """
        if not _ARTIFACT_NAME.fullmatch(name):
            return None
        temp = self._env.get(TEMP_ENV)
        if not temp:
            return None
        root = Path(temp) / ARTIFACT_DIR
        try:
            root.mkdir(mode=0o700, exist_ok=True)
            info = os.lstat(root)
        except (OSError, ValueError):
            return None
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return None
        path = root / name
        try:
            fd = os.open(path, _ARTIFACT_OPEN_FLAGS, 0o600)
        except (OSError, ValueError):
            return None
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
        except (OSError, ValueError):
            return None
        return path


class ActionSinks(EnvSinks):
    """``EnvSinks`` plus the C12 publish call: the production default for ``Components.sinks``."""

    def __init__(
        self,
        env: Mapping[str, str],
        client: GitHubClient,
        *,
        stdout: BinaryIO | None = None,
        open_flags: int | None = None,
        nofollow: int | None = None,
    ) -> None:
        super().__init__(env, stdout=stdout, open_flags=open_flags, nofollow=nofollow)
        self._client = client

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
        """The PR comment write and the SARIF upload, unchanged from C12 (I-13 C12 ruling 7)."""
        return self._client.publish(
            repo=repo,
            pr_number=pr_number,
            run_head_sha=run_head_sha,
            comment=comment,
            sarif=sarif,
            sarif_commit_sha=sarif_commit_sha,
            sarif_ref=sarif_ref,
        )
