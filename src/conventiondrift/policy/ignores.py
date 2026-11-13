"""C5 inline ignore markers (INTERFACES I-7, I-13 "C6 rulings" item 3).

C5 reads the markers from the policy side's instruction files and records, for
each one, whether it is alone on its line. C6 (T-015) attaches them to rules:
on the rule's start line, or, when alone, on the line directly above it.
Plain string operations only; no regex runs on repo text here (R2.5).
"""

from collections.abc import Mapping
from typing import Final

__all__ = ["MARKER", "find_markers", "markers_by_file"]

MARKER: Final = "<!-- conventiondrift: ignore -->"
"""The exact I-7 marker: case-sensitive, single spaces."""


def _lines(text: str) -> list[str]:
    # Only LF (and CRLF) end a line, as in git and GitHub line numbers;
    # str.splitlines() would also split on VT, FF, U+2028 and others.
    return [line.removesuffix("\r") for line in text.split("\n")]


def find_markers(data: bytes) -> tuple[tuple[int, bool], ...]:
    """Sorted ``(line, alone_on_line)`` pairs for every line holding the I-7 marker.

    One pair per line (1-based). ``alone_on_line`` is True when the marker is
    the only non-whitespace content of the line (I-13).
    """
    # C4 has already refused binary and undecodable files (I-13); "replace"
    # keeps this total on any bytes. A UTF-8 BOM is stripped (I-13).
    text = data.decode("utf-8-sig", errors="replace")
    return tuple(
        (number, line.strip() == MARKER)
        for number, line in enumerate(_lines(text), start=1)
        if MARKER in line
    )


def markers_by_file(files: Mapping[str, bytes]) -> dict[str, tuple[tuple[int, bool], ...]]:
    """``find_markers`` for each instruction file; files without a marker are left out."""
    found = {path: find_markers(data) for path, data in files.items()}
    return {path: pairs for path, pairs in sorted(found.items()) if pairs}
