"""Typed errors shared by all components (INTERFACES I-11, DESIGN §12 A-1).

``FileSkipped`` is a normal outcome, ``ComponentError`` is an internal error
caught at the entrypoint, and ``GitUnavailable`` switches the run to
head-only mode.
"""


class FileSkipped(Exception):
    """A file was not analyzed; ``reason`` is the reason listed in the report."""

    def __init__(self, reason: str) -> None:
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
