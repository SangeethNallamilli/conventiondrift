"""Typed errors shared by all components (INTERFACES I-11, DESIGN §12 A-1).

``FileSkipped`` is a normal outcome, ``ComponentError`` is an internal error
caught at the entrypoint, and ``GitUnavailable`` switches the run to
head-only mode.
"""

from conventiondrift.model import SkipReason


class FileSkipped(Exception):
    """A file was not analyzed; ``reason`` is the reason listed in the report."""

    def __init__(self, reason: SkipReason) -> None:
        super().__init__(reason)
        self.reason = reason


class ComponentError(Exception):
    """An internal error raised by one component, e.g. ``"gitread"`` or ``"checker:logging"``."""

    def __init__(self, component: str, message: str) -> None:
        super().__init__(component, message)
        self.component = component
        self.message = message


class GitUnavailable(Exception):
    """Git or a needed object is unavailable; the run falls back to head-only mode."""


class UnresolvableRevision(Exception):
    """A user revision could not be resolved to one commit; C1/C2 exit 2 (I-4, I-11 C3).

    Raised only by ``gitread.GitReader.resolve``. The message is fixed text and
    never contains the revision.
    """

    def __init__(self) -> None:
        super().__init__("unresolvable revision")
