"""The minimal fallback writer (DESIGN §4 and §12 A-8; INTERFACES I-2 and I-14 Q6; T-006b).

``core.run`` calls it when an exception ended the run, for both entries, so an Internal
error is reported even when the renderer is the thing that failed. It needs no renderer:
it imports nothing from ``render`` except ``render/escape.py`` (A-8).

* **Action:** one ``Internal error`` section appended to the file named by
  ``GITHUB_STEP_SUMMARY``, and nothing else (no comment, annotation, SARIF or stdout).
  Each error is one line, ``Internal error in `<component>`: <message>``, with the
  component escaped by ``md()``. It is never silent (I-14 "Fallback writer details" 2): if the
  variable is unset or empty, or the append raises ``OSError`` (or ``ValueError``, as for a
  path with a NUL byte), the CLI stderr lines are written instead. The file is opened without
  following a symlink and must be a regular file (SR ruling); where ``O_NOFOLLOW`` is missing
  (Windows), an ``lstat`` before the open refuses a symlink or reparse point instead. If it is
  refused, a fixed warning naming neither the path nor the OS error comes first. A write that
  fails part-way can leave a truncated section in the summary before the stderr fallback.
* **CLI:** one line per error on stderr,
  ``conventiondrift: internal error in <component>: <message>``. The summary file is not
  touched, because ``GITHUB_*`` variables can also be set when the CLI runs in CI.

Text follows I-14 Q6: a component name and ``<ExceptionClass>: <fixed message>``, never an
exception message, a traceback, file content or an environment value. ``core.internal_error``
builds those; here each field is checked again, because this is the last writer: a component
that doesn't match the I-14 pattern is written as ``core``, and a message that isn't exactly one
of the two fixed forms is written as the generic fixed text for ``Exception``. Both forms are
Markdown-inert and hold no control character, so only the component goes through ``md()`` and
the validated message is written as is; there is no plain-text escaper.

The writer catches its own exceptions and writes nothing more (I-14); it never changes the exit
status. Only ``KeyboardInterrupt`` propagates, as in ``run``.
"""

import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from typing import Final, Literal, TextIO

from conventiondrift.model import InternalError
from conventiondrift.render.escape import md

__all__ = [
    "GIT_TOO_OLD_TEXT",
    "SECTION_HEADING",
    "SUMMARY_ENV",
    "SUMMARY_OPEN_FLAGS",
    "SUMMARY_REFUSED",
    "WITHHELD",
    "action_section",
    "cli_lines",
    "write_internal_errors",
]

SUMMARY_ENV: Final = "GITHUB_STEP_SUMMARY"
SECTION_HEADING: Final = "## Internal error"
WITHHELD: Final = "this part of the analysis could not finish; details are withheld"
"""The fixed part of every ``InternalError`` message (I-14 Q6)."""
GIT_TOO_OLD_TEXT: Final = "git 2.30 or newer is required"
"""The one other fixed public message (I-14, ``GitTooOld``)."""

_COMPONENT: Final = re.compile(r"[a-z][a-z0-9_]*(:[a-z0-9_-]+)?")
_MESSAGE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*: " + re.escape(WITHHELD))
_GENERIC: Final = f"Exception: {WITHHELD}"
_CORE: Final = "core"


def _safe(error: InternalError) -> tuple[str, str]:
    """The component and message to write: the I-14 forms, or the generic fixed ones."""
    component = error.component if _COMPONENT.fullmatch(error.component) else _CORE
    message = error.message
    if message != GIT_TOO_OLD_TEXT and not _MESSAGE.fullmatch(message):
        message = _GENERIC
    return component, message


def action_section(errors: Sequence[InternalError]) -> str:
    """The Markdown section for the job summary: a heading and one line per error."""
    lines = []
    for error in errors:
        component, message = _safe(error)
        lines.append(f"Internal error in {md(component)}: {message}")
    return "\n" + SECTION_HEADING + "\n\n" + "\n\n".join(lines) + "\n"


def cli_lines(errors: Sequence[InternalError]) -> list[str]:
    """The stderr lines, one per error."""
    out = []
    for error in errors:
        component, message = _safe(error)
        out.append(f"conventiondrift: internal error in {component}: {message}")
    return out


_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
_REPARSE_POINT: Final[int] = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

SUMMARY_OPEN_FLAGS: Final = (
    os.O_WRONLY
    | os.O_APPEND
    | os.O_CREAT
    | _NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)
"""How the summary file is opened (SR ruling on T-006b).

Append, created if missing as before; a symlink is refused where ``O_NOFOLLOW`` exists; the fd
is not inherited. ``O_NONBLOCK`` keeps a FIFO from blocking the open (it fails, or is refused by
the regular-file check); it changes nothing for a regular file. ``O_BINARY`` matters on Windows.
"""

SUMMARY_REFUSED: Final = (
    "conventiondrift: the job summary file could not be used; writing to stderr instead"
)
"""The warning when the summary file is refused or can't be written; never the path or OS text."""


def _no_link_before_open(path: str) -> bool:
    """False if ``path`` must be refused before the open (SR ruling for Windows).

    Only where ``SUMMARY_OPEN_FLAGS`` has no ``O_NOFOLLOW``: ``lstat`` the path; a missing file is
    created as before, any other error refuses, and so does a symlink or a reparse point.
    """
    if SUMMARY_OPEN_FLAGS & _NOFOLLOW:
        return True
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True
    except (OSError, ValueError):  # ValueError: a NUL byte in the path
        return False
    if stat.S_ISLNK(st.st_mode):
        return False
    return not getattr(st, "st_file_attributes", 0) & _REPARSE_POINT


def _append_to_summary(path: str, errors: Sequence[InternalError]) -> bool:
    """Append the section to ``path``; False if it was refused (the caller then uses stderr).

    The file must open with ``SUMMARY_OPEN_FLAGS`` and ``fstat`` as a regular file (SR ruling);
    the descriptor is always closed. Without ``O_NOFOLLOW``, ``_no_link_before_open`` runs first.
    A write that fails part-way can leave a truncated section in the file; the caller still
    writes the stderr lines, so the report is never lost.
    """
    if not _no_link_before_open(path):
        return False
    try:
        fd = os.open(path, SUMMARY_OPEN_FLAGS, 0o666)
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
        with os.fdopen(fd, "ab") as summary:
            summary.write(action_section(errors).encode("utf-8"))
    except (OSError, ValueError):
        return False
    return True


def write_internal_errors(
    errors: Sequence[InternalError],
    *,
    entry: Literal["action", "cli"],
    env: Mapping[str, str],
    stderr: TextIO | None = None,
) -> None:
    """Report ``errors`` for ``entry``; see the module docstring. Writes nothing for no errors."""
    if not errors:
        return
    try:
        stream = sys.stderr if stderr is None else stderr
        if entry == "action":
            path = env.get(SUMMARY_ENV)
            if path:
                if _append_to_summary(path, errors):
                    return
                stream.write(SUMMARY_REFUSED + "\n")
        # The CLI, or an Action run with no usable summary file: never silent (I-14).
        stream.write("".join(line + "\n" for line in cli_lines(errors)))
    except KeyboardInterrupt:
        raise
    except BaseException:  # noqa: BLE001, S110 -- I-14: the fallback catches its own exceptions
        pass
