"""C4 ``discover/globmatch.py``: a gitignore-style glob matcher that runs in linear time
in the pattern times the path (T-010a, DESIGN §12 A-3 condition 4, ruling 2026-11-12).

No regular expressions and no recursion, so no pattern can make it backtrack
exponentially. A pattern is split on ``/`` into segments. A ``**`` segment matches
zero or more whole path components. Every other segment is matched against one
component by a greedy two-pointer matcher that backs up to the last ``*`` only.
C5 (excludes, script paths) and T-010b (``.gitignore``) import this module.

Pattern rules, as in ``gitignore(5)``: case-sensitive; ``*`` and ``?`` never match ``/``;
``[...]`` classes (``!`` or ``^`` negates); ``\\`` escapes; a leading ``!`` negates; a
trailing ``/`` matches folders only; a pattern with a ``/`` before its end, or a leading
``/``, is anchored to the root, and any other pattern matches at any depth. ``**/x``,
``x/**`` (at least one component) and ``x/**/y`` have their gitignore meaning. Paths are
repo-relative POSIX strings with no empty segments. Blank lines, comments and trailing
spaces are for the ``.gitignore`` loader to handle before it calls :func:`compile_glob`.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

__all__ = ["Glob", "GlobSet", "compile_glob"]

_STAR: Final = object()  # one "*" in a segment, or a "**" segment
_ANY_ONE: Final = object()  # one "?"


class _Class:
    """A ``[...]`` bracket expression: single characters and inclusive ranges."""

    __slots__ = ("negate", "ranges", "singles")

    def __init__(self, negate: bool, singles: str, ranges: tuple[tuple[str, str], ...]) -> None:
        self.negate = negate
        self.singles = singles
        self.ranges = ranges

    def matches(self, ch: str) -> bool:
        hit = ch in self.singles or any(lo <= ch <= hi for lo, hi in self.ranges)
        return hit != self.negate


_Token = str | _Class | object
_Segment = str | tuple[_Token, ...]  # a plain string is an all-literal segment


def _parse_class(text: str, start: int) -> tuple[_Class, int] | None:
    """Parse ``text[start]`` (a ``[``) to its ``]``; ``None`` if it is not closed."""
    i = start + 1
    negate = i < len(text) and text[i] in "!^"
    i += negate
    singles: list[str] = []
    ranges: list[tuple[str, str]] = []
    first = True
    while i < len(text):
        ch = text[i]
        if ch == "]" and not first:
            return _Class(negate, "".join(singles), tuple(ranges)), i + 1
        first = False
        if ch == "\\" and i + 1 < len(text):
            i += 1
            ch = text[i]
        if i + 2 < len(text) and text[i + 1] == "-" and text[i + 2] != "]":
            hi = text[i + 2]
            i += 2
            if hi == "\\" and i + 1 < len(text):
                i += 1
                hi = text[i]
            ranges.append((ch, hi))
        else:
            singles.append(ch)
        i += 1
    return None


def _compile_segment(text: str) -> _Segment:
    tokens: list[_Token] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "*":
            if not tokens or tokens[-1] is not _STAR:  # "**" inside a segment is one "*"
                tokens.append(_STAR)
        elif ch == "?":
            tokens.append(_ANY_ONE)
        elif ch == "[" and (cls := _parse_class(text, i)) is not None:
            tokens.append(cls[0])
            i = cls[1]
            continue
        elif ch == "\\" and i + 1 < len(text):
            i += 1
            tokens.append(text[i])
        else:
            tokens.append(ch)
        i += 1
    if all(isinstance(t, str) for t in tokens):
        return "".join(str(t) for t in tokens)
    return tuple(tokens)


def _token_matches(token: _Token, ch: str) -> bool:
    if token is _ANY_ONE:
        return True
    if isinstance(token, _Class):
        return token.matches(ch)
    return token == ch


def _segment_matches(segment: _Segment, name: str) -> bool:
    if isinstance(segment, str):
        return segment == name
    t = n = 0
    star_t = star_n = -1
    while n < len(name):
        if t < len(segment) and segment[t] is _STAR:
            star_t, star_n = t, n
            t += 1
        elif t < len(segment) and _token_matches(segment[t], name[n]):
            t += 1
            n += 1
        elif star_t >= 0:
            star_n += 1
            n = star_n
            t = star_t + 1
        else:
            return False
    while t < len(segment) and segment[t] is _STAR:
        t += 1
    return t == len(segment)


_ONE_COMPONENT: Final[_Segment] = (_STAR,)
_PatternSegment = _Segment | None  # None is a "**" segment: zero or more whole components


class Glob:
    """One compiled pattern. Build it with :func:`compile_glob`."""

    __slots__ = ("_segments", "dir_only", "negated")

    def __init__(
        self, segments: tuple[_PatternSegment, ...], *, negated: bool, dir_only: bool
    ) -> None:
        self._segments = segments
        self.negated = negated
        self.dir_only = dir_only

    def match(self, path: str, is_dir: bool = False) -> bool:
        """True if the pattern matches exactly ``path`` (not a parent of it).

        ``is_dir`` says whether ``path`` is a folder; a folder-only pattern
        (trailing ``/``) never matches a file. The sign of ``negated`` is ignored here.
        """
        if (self.dir_only and not is_dir) or not path:
            return False
        parts = path.split("/")
        segs = self._segments
        s = p = 0
        star_s = star_p = -1
        while p < len(parts):
            at_end = s >= len(segs)
            seg = None if at_end else segs[s]
            if seg is None and not at_end:
                star_s, star_p = s, p
                s += 1
            elif seg is not None and _segment_matches(seg, parts[p]):
                s += 1
                p += 1
            elif star_s >= 0:
                star_p += 1
                p = star_p
                s = star_s + 1
            else:
                return False
        while s < len(segs) and segs[s] is None:
            s += 1
        return s == len(segs)


def compile_glob(pattern: str) -> Glob:
    """Compile one gitignore-style pattern line. An empty pattern never matches."""
    negated = pattern.startswith("!")
    body = pattern[1:] if negated else pattern
    dir_only = body.endswith("/")
    body = body.rstrip("/") if dir_only else body
    anchored = body.startswith("/") or "/" in body
    parts = [p for p in body.split("/") if p]
    if not parts:
        return Glob((), negated=negated, dir_only=dir_only)
    segments: list[_PatternSegment] = [] if anchored else [None]
    for part in parts:
        if part == "**":
            if not segments or segments[-1] is not None:
                segments.append(None)
        else:
            segments.append(_compile_segment(part))
    if segments[-1] is None and len(segments) > 1:
        # "x/**" means everything inside x: at least one component.
        segments.insert(len(segments) - 1, _ONE_COMPONENT)
    return Glob(tuple(segments), negated=negated, dir_only=dir_only)


class GlobSet:
    """Ordered patterns with gitignore semantics: the last matching pattern decides
    (a ``!`` pattern re-includes), a folder that is excluded excludes everything
    below it, and no pattern can re-include a file below an excluded folder.

    The hard ``.git/`` and ``node_modules/`` exclusions are not part of this class;
    callers apply them first and a ``!`` pattern never reaches them (I-5).
    """

    def __init__(self, patterns: Iterable[str]) -> None:
        self._globs = tuple(compile_glob(p) for p in patterns)
        self._folders: dict[str, bool] = {}

    def _verdict(self, path: str, is_dir: bool) -> bool:
        result = False
        for glob in self._globs:
            if glob.match(path, is_dir):
                result = not glob.negated
        return result

    def _folder_excluded(self, folder: str) -> bool:
        cached = self._folders.get(folder)
        if cached is None:
            cached = self._verdict(folder, True)
            self._folders[folder] = cached
        return cached

    def excludes(self, path: str, is_dir: bool = False) -> bool:
        """True if ``path`` (or a folder above it) is excluded."""
        parts = path.split("/")
        folder = ""
        for part in parts[:-1]:
            folder = f"{folder}/{part}" if folder else part
            if self._folder_excluded(folder):
                return True
        return self._verdict(path, is_dir)
