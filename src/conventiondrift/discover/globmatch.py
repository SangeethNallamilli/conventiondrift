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

Differences from git (the rest of the bracket rules, including an unclosed ``[`` matching
nothing and a reversed range such as ``[c-a]`` matching only ``c``, were checked against
``git check-ignore``):

* POSIX classes such as ``[[:alpha:]]`` are not supported. They read as the plain
  characters ``[:alph`` followed by a literal ``]``.
* The pattern is split on ``/`` before any ``[`` is read, so a class that contains a ``/``
  is cut in two. ``[a-c/]x`` becomes an unclosed ``[a-c`` and matches nothing here, while
  git reads it as the class ``a-c`` plus a ``/`` that never matches, so it matches ``ax``.
* A segment of three or more stars, such as ``a/***/b`` or ``***``, is one ``*`` here: it
  stays inside one path component. Git treats a bare ``***`` segment like ``**``.

Compiling is linear in the pattern: an unclosed ``[`` makes its segment, and so the
pattern, match nothing, and the rest of the segment is not scanned.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable, Sequence
from typing import Final

__all__ = ["Glob", "GlobSet", "compile_glob"]

_STAR: Final = object()  # one "*" in a segment, or a "**" segment
_ANY_ONE: Final = object()  # one "?"


class _Class:
    """A ``[...]`` bracket expression: single characters and inclusive ranges.

    The ranges are merged and sorted when the class is built, so a character is tested
    with one binary search however many ranges the class has.
    """

    __slots__ = ("his", "los", "negate", "singles")

    def __init__(self, negate: bool, singles: str, ranges: Iterable[tuple[str, str]]) -> None:
        self.negate = negate
        self.singles = frozenset(singles)
        merged: list[list[str]] = []
        for lo, hi in sorted(r for r in ranges if r[0] <= r[1]):  # a reversed range is empty
            if merged and ord(lo) <= ord(merged[-1][1]) + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self.los = [m[0] for m in merged]
        self.his = [m[1] for m in merged]

    def matches(self, ch: str) -> bool:
        i = bisect_right(self.los, ch) - 1
        hit = ch in self.singles or (i >= 0 and ch <= self.his[i])
        return hit != self.negate


_Token = str | _Class | object
_Segment = str | tuple[_Token, ...]  # a plain string is an all-literal segment
_NEVER: Final = object()  # a token no character matches
_NEVER_SEGMENT: Final[_Segment] = (_NEVER,)


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
            return _Class(negate, "".join(singles), ranges), i + 1
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
            singles.append(ch)  # as in git, the start also matches on its own: [c-a] matches c
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
        elif ch == "[":
            cls = _parse_class(text, i)
            if cls is None:
                # Like git's wildmatch, an unclosed "[" matches nothing, so the rest of the
                # segment is never read: one failed scan, then done. Compile stays linear.
                return _NEVER_SEGMENT
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


def _segment_matches(segment: _Segment, name: str, limit: int) -> int:
    """Match one component. Returns the steps taken (at least 1) if it matches, minus
    the steps if it does not; past ``limit`` steps it stops and does not match."""
    if isinstance(segment, str):
        return 1 if segment == name else -1
    t = n = 0
    star_t = star_n = -1
    steps = 1
    while n < len(name):
        if steps > limit:
            return -steps
        steps += 1
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
            return -steps
    while t < len(segment) and segment[t] is _STAR:
        t += 1
    return steps if t == len(segment) else -steps


_ONE_COMPONENT: Final[_Segment] = (_STAR,)
_NO_LIMIT: Final = 1 << 62  # more steps than any match can take
_PatternSegment = _Segment | None  # None is a "**" segment: zero or more whole components


class Glob:
    """One compiled pattern. Build it with :func:`compile_glob`."""

    __slots__ = ("_last", "_segments", "dir_only", "negated")

    def __init__(
        self, segments: tuple[_PatternSegment, ...], *, negated: bool, dir_only: bool
    ) -> None:
        self._segments = segments
        # "**/x" with one segment x (as for a pattern whose only "/" is a trailing one): only
        # the last component can match x, so it is the only one compared (#76 B2).
        self._last = segments[1] if len(segments) == 2 and segments[0] is None else None
        self.negated = negated
        self.dir_only = dir_only

    def match(self, path: str, is_dir: bool = False) -> bool:
        """True if the pattern matches exactly ``path`` (not a parent of it).

        ``is_dir`` says whether ``path`` is a folder; a folder-only pattern
        (trailing ``/``) never matches a file. The sign of ``negated`` is ignored here.
        """
        return self.match_counted(path, is_dir, _NO_LIMIT)[0]

    def match_counted(self, path: str, is_dir: bool, limit: int) -> tuple[bool, int]:
        """:meth:`match`, plus the work it took: one step per component compared and
        one per character step inside a component. Once the steps pass ``limit`` it
        stops and answers ``False``, so one call never does much more than ``limit``
        steps. The ``.gitignore`` match budget counts these steps (#76 B2, M-76-1).
        """
        if not path:
            return False, 1
        return self.match_parts(path.split("/"), is_dir, limit)

    def match_parts(self, parts: Sequence[str], is_dir: bool, limit: int) -> tuple[bool, int]:
        """:meth:`match_counted` on a path already split on ``/`` (one or more non-empty
        components). The steps don't depend on how long the path is, only on what is
        compared, so a caller that splits a path once can try many patterns on it.
        """
        if self.dir_only and not is_dir:
            return False, 1
        if self._last is not None:
            got = _segment_matches(self._last, parts[-1], limit - 1)
            return got > 0, 1 + abs(got)
        segs = self._segments
        s = p = 0
        star_s = star_p = -1
        steps = 1
        while p < len(parts):
            if steps > limit:
                return False, steps
            steps += 1
            at_end = s >= len(segs)
            seg = None if at_end else segs[s]
            if seg is None and not at_end:
                star_s, star_p = s, p
                s += 1
                continue
            got = 0 if seg is None else _segment_matches(seg, parts[p], limit - steps)
            steps += abs(got)
            if got > 0:
                s += 1
                p += 1
            elif star_s >= 0:
                star_p += 1
                p = star_p
                s = star_s + 1
            else:
                return False, steps
        while s < len(segs) and segs[s] is None:
            s += 1
        return s == len(segs), steps


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
        end = path.find("/")
        while end != -1:  # prefixes are sliced from the path, never rejoined
            if self._folder_excluded(path[:end]):
                return True
            end = path.find("/", end + 1)
        return self._verdict(path, is_dir)
