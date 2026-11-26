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

import re
import sys
from collections.abc import Mapping, Sequence
from typing import Final, Literal, TextIO

from conventiondrift.model import InternalError, SummarySink
from conventiondrift.render.escape import md
from conventiondrift.sinks import (
    NOFOLLOW as _NOFOLLOW,
)
from conventiondrift.sinks import (
    SUMMARY_ENV,
    SUMMARY_OPEN_FLAGS,
    SUMMARY_REFUSED,
    EnvSinks,
)

__all__ = [
    "GIT_TOO_OLD_TEXT",
    "SECTION_HEADING",
    "SUMMARY_ENV",
    "SUMMARY_OPEN_FLAGS",
    "SUMMARY_REFUSED",
    "WITHHELD",
    # Re-exported from ``sinks``: the writer receives it at call time, so the platform tests
    # that patch ``fallback._NOFOLLOW`` keep driving the real code.
    "_NOFOLLOW",
    "action_section",
    "cli_lines",
    "safe_error",
    "write_internal_errors",
]

SECTION_HEADING: Final = "## Internal error"
WITHHELD: Final = "this part of the analysis could not finish; details are withheld"
"""The fixed part of every ``InternalError`` message (I-14 Q6)."""
GIT_TOO_OLD_TEXT: Final = "git 2.30 or newer is required"
"""The one other fixed public message (I-14, ``GitTooOld``)."""

_COMPONENT: Final = re.compile(r"[a-z][a-z0-9_]*(:[a-z0-9_-]+)?")
_MESSAGE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*: " + re.escape(WITHHELD))
_GENERIC: Final = f"Exception: {WITHHELD}"
_CORE: Final = "core"


def safe_error(error: InternalError) -> tuple[str, str]:
    """The public form of one ``InternalError``: the I-14 component and message.

    Returns ``(component, message)``, both validated: an unusable component becomes ``"core"``
    and any message that is neither the fixed git-too-old text nor a ``Class: <withheld>``
    line becomes the generic fixed line. Every writer (the summary section, the CLI lines,
    the text format and the JSON report) uses this, so the rule lives in one place; the
    function is public for exactly that reason (CR1 S2 on #90).
    """
    component = error.component if _COMPONENT.fullmatch(error.component) else _CORE
    message = error.message
    if message != GIT_TOO_OLD_TEXT and not _MESSAGE.fullmatch(message):
        message = _GENERIC
    return component, message


def action_section(errors: Sequence[InternalError]) -> str:
    """The Markdown section for the job summary: a heading and one line per error."""
    lines = []
    for error in errors:
        component, message = safe_error(error)
        lines.append(f"Internal error in {md(component)}: {message}")
    return "\n" + SECTION_HEADING + "\n\n" + "\n\n".join(lines) + "\n"


def cli_lines(errors: Sequence[InternalError]) -> list[str]:
    """The stderr lines, one per error."""
    out = []
    for error in errors:
        component, message = safe_error(error)
        out.append(f"conventiondrift: internal error in {component}: {message}")
    return out


def _summary_sink(env: Mapping[str, str], summary_sink: SummarySink | None) -> SummarySink:
    """The sink the fallback writes the section through (CON-73).

    The module-level flags are read here, at call time, so a test that simulates a platform
    without ``O_NOFOLLOW`` by patching ``fallback.SUMMARY_OPEN_FLAGS`` / ``fallback._NOFOLLOW``
    keeps driving the real writer, including the ``lstat`` branch Windows takes.
    """
    if summary_sink is not None:
        return summary_sink
    return EnvSinks(env, open_flags=SUMMARY_OPEN_FLAGS, nofollow=_NOFOLLOW)


def write_internal_errors(
    errors: Sequence[InternalError],
    *,
    entry: Literal["action", "cli"],
    env: Mapping[str, str],
    stderr: TextIO | None = None,
    summary_sink: SummarySink | None = None,
) -> None:
    """Report ``errors`` for ``entry``; see the module docstring. Writes nothing for no errors.

    The Action's summary section goes through the ``Sinks`` seam (CON-73): ``summary_sink``
    defaults to ``sinks.EnvSinks`` over ``env``, so a test can inject a recording sink and the
    last writer still owns the refusal warning and the stderr fallback.
    """
    if not errors:
        return
    try:
        stream = sys.stderr if stderr is None else stderr
        if entry == "action":
            path = env.get(SUMMARY_ENV)
            if path:
                if _summary_sink(env, summary_sink).summary_section(action_section(errors)) == (
                    "written"
                ):
                    return
                stream.write(SUMMARY_REFUSED + "\n")
        # The CLI, or an Action run with no usable summary file: never silent (I-14).
        stream.write("".join(line + "\n" for line in cli_lines(errors)))
    except KeyboardInterrupt:
        raise
    except BaseException:  # noqa: BLE001, S110 -- I-14: the fallback catches its own exceptions
        pass
