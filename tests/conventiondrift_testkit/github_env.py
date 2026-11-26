"""Emulate the runner's GitHub environment for one test scope (CON-29).

``with github_env(event=..., inputs=...) as gh:`` gives a test the same files and variables the
Action gets on a runner: ``GITHUB_EVENT_PATH`` (the event JSON on disk), ``GITHUB_OUTPUT``,
``GITHUB_STEP_SUMMARY``, ``$RUNNER_TEMP``, ``GITHUB_SHA``/``GITHUB_REF``/``GITHUB_REPOSITORY``/
``GITHUB_WORKSPACE`` and one ``INPUT_*`` per input. Nothing reads the real ``GITHUB_*`` values
and nothing survives the scope.

**Exact restore.** Entry keeps ``dict(os.environ)``; exit clears and re-fills it from that
snapshot, which is the only way to also remove keys the test itself introduced. A defensive
comparison after the restore raises :class:`EnvironmentLeak` instead of letting a future bug
pollute the next test.

**Control Pictures inverse.** ``render.escape.output_heredoc`` writes an output value through
the I-14 visible-text mapping, so a newline in a value arrives in the file as ``␊`` (U+240A).
:meth:`GitHubEnv.outputs` inverts that mapping for values (U+2400 to U+241F back to the C0 code
point, U+2421 back to DEL) and leaves the one-way ``U+XXXX`` labels (Cf/Zl/Zp/Cs) exactly as
written, because the original code point is not recoverable from them. The inverse cannot tell a
mapped character from a literal Control Picture that was in the source: that ambiguity is
inherent to the mapping and is documented, not hidden.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Any, Final

__all__ = [
    "ARTIFACT_DIR",
    "DEFAULT_REF",
    "DEFAULT_REPO",
    "DEFAULT_SHA",
    "EnvironmentLeak",
    "GitHubEnv",
    "control_pictures_inverse",
    "github_env",
]

ARTIFACT_DIR: Final = "conventiondrift"
DEFAULT_SHA: Final = "c" * 40
DEFAULT_REF: Final = "refs/pull/7/merge"
DEFAULT_REPO: Final = "octo/demo"
DEFAULT_WORKSPACE: Final = "/workspace"

_INPUT_NAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,127}")
_OUTPUT_LINE: Final = re.compile(r"([A-Za-z][A-Za-z0-9_-]{0,127})<<(\S+)")


class EnvironmentLeak(RuntimeError):
    """``os.environ`` did not come back byte-identical; the message names only the keys."""


def control_pictures_inverse(text: str) -> str:
    """Undo the I-14 Control-Pictures part of the visible-text mapping (one pass).

    U+2400 to U+241F become U+0000 to U+001F and U+2421 becomes DEL. Every other character,
    including
    a ``U+XXXX`` label for an invisible code point, is left as written: the label is one-way.
    """
    out: list[str] = []
    for char in text:
        code = ord(char)
        if 0x2400 <= code <= 0x241F:
            out.append(chr(code - 0x2400))
        elif code == 0x2421:
            out.append(chr(0x7F))
        else:
            out.append(char)
    return "".join(out)


class GitHubEnv:
    """One emulated runner environment. Use :func:`github_env`; nesting is refused."""

    _active: int = 0

    def __init__(
        self,
        *,
        event: Mapping[str, Any] | None = None,
        event_name: str = "pull_request",
        inputs: Mapping[str, str] | None = None,
        sha: str = DEFAULT_SHA,
        ref: str = DEFAULT_REF,
        repo: str = DEFAULT_REPO,
        workspace: str | None = None,
    ) -> None:
        self._event = {} if event is None else dict(event)
        self._event_name = event_name
        self._inputs = {str(k): str(v) for k, v in (inputs or {}).items()}
        self._sha, self._ref, self._repo = sha, ref, repo
        self._workspace = workspace
        self._root: Path | None = None
        self._snapshot: dict[str, str] = {}
        self._entered = False

    # -- lifecycle ------------------------------------------------------------

    def __enter__(self) -> GitHubEnv:
        if GitHubEnv._active:
            raise RuntimeError("github_env is not re-entrant: exit the outer scope first")
        for name in self._inputs:
            if not _INPUT_NAME.fullmatch(name):
                raise ValueError(f"invalid input name: {name!r}")
        self._snapshot = dict(os.environ)
        GitHubEnv._active += 1
        self._entered = True
        self._root = Path(tempfile.mkdtemp(prefix="conventiondrift-gh-")).resolve()
        self._materialize()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            # Diff-based restore (TE finding 1): no ``clear()``, so ``PATH`` and every other
            # key stay present for the whole restore - on Windows an empty environment for even
            # one call can break a child process or a DLL lookup. Only the keys this scope
            # touched are reverted, and the leak is computed from the pre-restore state.
            current = dict(os.environ)
            added = [key for key in current if key not in self._snapshot]
            changed = [key for key, value in self._snapshot.items() if current.get(key) != value]
            for key in added:
                del os.environ[key]
            for key in changed:
                os.environ[key] = self._snapshot[key]
            if exc_type is None and dict(os.environ) != self._snapshot:
                raise EnvironmentLeak(
                    f"environment not restored; keys differ: {sorted(added + changed)}"
                )
        finally:
            GitHubEnv._active -= 1
            self._entered = False
            if self._root is not None:
                shutil.rmtree(self._root, ignore_errors=True)
                self._root = None

    # -- the environment ------------------------------------------------------

    def _materialize(self) -> None:
        root = self.root
        (root / "output").write_text("", encoding="utf-8")
        (root / "summary").write_text("", encoding="utf-8")
        (root / "temp").mkdir()
        workspace = Path(self._workspace) if self._workspace else root / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        event_file = root / "event.json"
        event_file.write_text(json.dumps(self._event), encoding="utf-8")
        values = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": self._event_name,
            "GITHUB_EVENT_PATH": str(event_file),
            "GITHUB_OUTPUT": str(root / "output"),
            "GITHUB_STEP_SUMMARY": str(root / "summary"),
            "GITHUB_SHA": self._sha,
            "GITHUB_REF": self._ref,
            "GITHUB_REPOSITORY": self._repo,
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(root / "temp"),
            "RUNNER_OS": "Linux",
        }
        for name, value in self._inputs.items():
            key = f"INPUT_{name.upper().replace('-', '_').replace(' ', '_')}"
            values[key] = value
        os.environ.update(values)

    @property
    def root(self) -> Path:
        if self._root is None:
            raise RuntimeError("github_env is not entered")
        return self._root

    @property
    def env(self) -> Mapping[str, str]:
        """The whole emulated environment, for ``run(..., env=...)`` or ``EnvSinks(gh.env)``."""
        return dict(os.environ)

    @property
    def temp(self) -> Path:
        return self.root / "temp"

    @property
    def workspace(self) -> Path:
        return Path(os.environ["GITHUB_WORKSPACE"])

    @property
    def event_file(self) -> Path:
        return Path(os.environ["GITHUB_EVENT_PATH"])

    def path(self, kind: str) -> Path:
        """The output, summary or event file; ``kind`` is ``"output"``/``"summary"``/``"event"``."""
        if kind == "output":
            return Path(os.environ["GITHUB_OUTPUT"])
        if kind == "summary":
            return Path(os.environ["GITHUB_STEP_SUMMARY"])
        if kind == "event":
            return self.event_file
        raise ValueError(f"unknown path kind: {kind!r}")

    # -- what the run wrote ---------------------------------------------------

    def outputs(self) -> dict[str, str]:
        """The ``GITHUB_OUTPUT`` entries, heredoc-parsed, with the Control-Pictures inverse."""
        return parse_outputs(self.path("output").read_text(encoding="utf-8"))

    def summary(self) -> str:
        """The current ``GITHUB_STEP_SUMMARY`` text (``""`` when nothing was written)."""
        return self.path("summary").read_text(encoding="utf-8")

    def artifacts(self) -> dict[str, bytes]:
        """``$RUNNER_TEMP/conventiondrift/*`` by name, as bytes (``{}`` when none)."""
        folder = self.temp / ARTIFACT_DIR
        if not folder.is_dir():
            return {}
        return {p.name: p.read_bytes() for p in sorted(folder.iterdir()) if p.is_file()}

    def event(self) -> Any:
        """The event payload as read back from ``GITHUB_EVENT_PATH``."""
        return json.loads(self.event_file.read_text(encoding="utf-8"))


def parse_outputs(text: str) -> dict[str, str]:
    """Parse ``name<<delimiter`` heredoc blocks written by ``output_heredoc``.

    The value is the lines between the header and the delimiter, joined with newlines and then
    passed through :func:`control_pictures_inverse`, because ``output_heredoc`` wrote it through
    the visible-text mapping. A header with no closing delimiter keeps the rest of the file, so
    a truncated write is visible as a value instead of being silently dropped.
    """
    lines = text.splitlines()
    out: dict[str, str] = {}
    index = 0
    while index < len(lines):
        match = _OUTPUT_LINE.fullmatch(lines[index])
        index += 1
        if match is None:
            continue
        name, delimiter = match.group(1), match.group(2)
        value: list[str] = []
        while index < len(lines) and lines[index] != delimiter:
            value.append(lines[index])
            index += 1
        if index < len(lines):
            index += 1
        out[name] = control_pictures_inverse("\n".join(value))
    return out


def github_env(
    *,
    event: Mapping[str, Any] | None = None,
    event_name: str = "pull_request",
    inputs: Mapping[str, str] | None = None,
    sha: str = DEFAULT_SHA,
    ref: str = DEFAULT_REF,
    repo: str = DEFAULT_REPO,
    workspace: str | None = None,
) -> GitHubEnv:
    """A fresh emulated runner environment (context manager); see the module docstring."""
    return GitHubEnv(
        event=event,
        event_name=event_name,
        inputs=inputs,
        sha=sha,
        ref=ref,
        repo=repo,
        workspace=workspace,
    )
