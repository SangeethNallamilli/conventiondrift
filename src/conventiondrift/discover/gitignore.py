"""C4 ``discover/gitignore.py``: ``.gitignore`` rules for the scan walk (T-010b, DESIGN §12 A-3).

Scan mode only: gated and compare runs read git trees, which hold no ignored files.
The patterns come from ``.git/info/exclude`` (lowest precedence), the root
``.gitignore`` and every nested ``.gitignore`` the walk enters, in that order. Each
file's patterns apply only to paths under its own folder, as in git. Global
excludes are never read (``GIT_CONFIG_GLOBAL=/dev/null``, A-3).

Line rules follow git's ``dir.c`` (``add_patterns_from_buffer`` and
``trim_trailing_spaces``), checked against ``git check-ignore``:

* a UTF-8 BOM at the start of the file is dropped;
* lines end at ``\\n``, and one ``\\r`` before it is dropped;
* blank lines and lines starting with ``#`` are not patterns (``\\#`` is a literal ``#``);
* trailing spaces are dropped unless the last one is escaped with ``\\``;
* a pattern that ends in an unescaped ``\\`` is counted but never matches (git's
  ``wildmatch`` rejects it; ``compile_glob`` alone would match a literal ``\\``).

Where :mod:`~conventiondrift.discover.globmatch` alone reads a pattern differently from
git, the pattern is rewritten first (D-TL-69 #3, checked against ``git check-ignore``):
patterns and paths are matched as UTF-8 bytes, so ``?`` and each class member stand for
one byte (``??`` matches ``é``); a ``/`` inside a ``[...]`` class stays in the class,
where it never matches, and anchors the pattern; ``\\/`` is a ``/``; a pattern with an
empty segment (``a//b``) is counted but never matches; and a segment of three or more
stars is ``**``. One difference is kept: git strips the literal text before a ``**``
from ``a**/*`` and so also matches the file ``a``; here ``a**/*`` needs a folder.

Matching is :mod:`conventiondrift.discover.globmatch` (linear time, no regular
expressions). Precedence is git's: the last matching pattern wins, a deeper
``.gitignore`` overrides a shallower one, and nothing under an ignored folder can
be re-included. The hard ``.git/`` and ``node_modules/`` exclusions are applied by
the walk before any of this, so a ``!`` pattern never reaches them (I-5).

Speed: a path is checked only against the patterns that can match it. The plain
text at the start or end of a pattern's last segment (``foo``, ``gen_*``,
``*.pyc``) must also be at the start or end of the path's last component, so those
patterns are looked up by that component; only the rest (``*``, ``**``, ``[ab]x``)
are tried on every path. The answer is the same as trying every pattern (``Glob.match`` decides).

Caps (A-3 condition 4): a ``.gitignore`` over :data:`GITIGNORE_MAX_BYTES` is not
read, and at most :data:`GITIGNORE_MAX_PATTERNS` patterns are used in total, in
load order. Both are counted for the I-12 ``gitignore_*`` counters and notes.

Match budget (A-3 condition 7, #76 B2 and M-76-1, D-TL-69): the pattern cap limits how
many patterns there are, not how long they take, and patterns the index can't narrow
are tried on every path. So all matching in one scan shares one budget:
:data:`GITIGNORE_MATCH_BUDGET` steps, plus :data:`GITIGNORE_MATCH_ALLOWANCE` more for
each path checked so far (D-TL-73) and :data:`GITIGNORE_MATCH_ALLOWANCE_PER_CHAR` for
each character of its last component (D-TL-76: a long name costs more to match), so a
stock ``.gitignore`` does not run out however many paths the walk has, at any depth
and with any name length, while 2,000 hostile patterns run it out within a few dozen
paths. Every path check, file or folder (a folder's
verdict is paid once, when it is first worked out and cached), pays four steps, one
per path component (the path is split once), two per index lookup, one per eight
patterns gathered as candidates, tried or not (L-76-1), two per pattern tried, one per
component each time the path is cut to a ``.gitignore``'s folder (once per folder per
check), plus the steps
:meth:`~conventiondrift.discover.globmatch.Glob.match_parts` reports. So a long path
costs its length once per check, not once per pattern (#76 CR B2). The folders above a
path are worked out once per check, and a pattern from a ``.gitignore`` in any other
folder is skipped without a try, so 20 copies of a ``.gitignore`` in sibling packages
cost about what one does (#76 CR S1). A match stops
as soon as it would pass the budget. Once the budget is spent, ``.gitignore`` is not
used for the rest of the walk: the path being checked and every later one are not
ignored, so the scan reads more, never less, as with the other caps.
:attr:`IgnoreRules.unchecked` counts those paths for the scan note.
"""

from __future__ import annotations

from typing import Final

from conventiondrift.discover.globmatch import Glob, compile_glob

__all__ = [
    "GITIGNORE_MATCH_ALLOWANCE",
    "GITIGNORE_MATCH_ALLOWANCE_PER_CHAR",
    "GITIGNORE_MATCH_BUDGET",
    "GITIGNORE_MAX_BYTES",
    "GITIGNORE_MAX_PATTERNS",
    "IgnoreRules",
    "gitignore_patterns",
]

GITIGNORE_MAX_BYTES: Final = 65_536  # A-3 condition 4: 64 KiB per file
GITIGNORE_MAX_PATTERNS: Final = 2_000  # A-3 condition 4: patterns in total, all files
# A-3 condition 7 (#76, D-TL-69, D-TL-73, D-TL-75, D-TL-76): match steps per scan, plus
# an allowance per path checked that grows with the length of the path's last component
# (its file or folder name). A step costs about 70-200 ns, so the base is about 0.5 s of
# matching, which is all 2,000 hostile patterns get (they run it out within a few dozen
# paths). A walk with GitHub's Python .gitignore spends about 85 steps per entry near
# the root and about 210 at depth 61 with short names, plus about one step per
# character of the name (about 1.5 for dotted names such as "a.b.a.b...", where each
# "." restarts "*.py[codz]"). The allowance is more than that at any depth up to the
# 64-folder cap and for any name length up to 255 (one check alone can cost more, up to
# about 650 steps; unused allowance carries over), so that file does not run out below
# the 500,000-entry walk cap. Before the allowance grew with the name, long or dotted
# names deep in the tree ran it out (100 characters at about 68,500 entries at depth
# 64; DESIGN A-3 #4a). Patterns that stay under the allowance never run it out and pay
# it on every path, so it also bounds their cost.
GITIGNORE_MATCH_BUDGET: Final = 3_000_000
GITIGNORE_MATCH_ALLOWANCE: Final = 256
GITIGNORE_MATCH_ALLOWANCE_PER_CHAR: Final = 2  # per character of the name checked
# L-76-1: candidates gathered (put in a set, then sorted) per match step, rounded down.
# Measured for the #76 follow-up: about 16 ns per candidate, whatever mix of index kinds
# they come from, against 128-140 ns per step for the hostile sets on the same machine.
_CANDIDATES_PER_STEP: Final = 8

_BOM: Final = "\ufeff"
_SPECIAL: Final = frozenset("*?[\\")  # anything in a segment that is not plain text


def _index_key(pattern: str) -> tuple[str, str] | None:
    """What the last component of a path must look like for ``pattern`` to match it,
    from the plain text of the pattern's last segment: ``("name", n)`` (equal to ``n``),
    ``("prefix", p)`` (starts with ``p``) or ``("suffix", s)`` (ends with ``s``).
    ``None`` if the segment says nothing usable, as for ``*`` or ``**``.
    """
    body = pattern[1:] if pattern.startswith("!") else pattern
    last = body.rstrip("/").rpartition("/")[2]
    if not _SPECIAL.intersection(last):
        return ("name", last)
    prefix = last[: next(i for i, char in enumerate(last) if char in _SPECIAL)]
    suffix = ""
    if "[" not in last and "\\" not in last:  # only * and ?: the text after the last one
        suffix = last[max(last.rfind("*"), last.rfind("?")) + 1 :]
    if prefix and len(prefix) >= len(suffix):
        return ("prefix", prefix)
    if suffix:
        return ("suffix", suffix)
    return None


def _bytes_view(text: str) -> str:
    """``text`` with one character per UTF-8 byte (``latin-1``), as git sees a name.

    Git matches bytes, so ``?`` and each class member stand for one byte and ``??``
    matches ``é``. Patterns and paths both go through this, so plain text still matches
    itself; names that are not UTF-8 keep their raw bytes (``surrogateescape``).
    """
    if text.isascii():
        return text
    return text.encode("utf-8", "surrogateescape").decode("latin-1")


def _class_items(text: str, start: int) -> tuple[list[tuple[str, str]], bool, int] | None:
    """The members of the class at ``text[start]`` (a ``[``), read as
    ``globmatch._parse_class`` reads them: ``(lo, hi)`` pairs (``lo == hi`` for a single
    character), whether it negates, and the index after its ``]``. ``None`` if not closed.
    """
    i = start + 1
    negate = i < len(text) and text[i] in "!^"
    i += negate
    items: list[tuple[str, str]] = []
    first = True
    while i < len(text):
        ch = text[i]
        if ch == "]" and not first:
            return items, negate, i + 1
        first = False
        if ch == "\\" and i + 1 < len(text):
            i += 1
            ch = text[i]
        hi = ch
        if i + 2 < len(text) and text[i + 1] == "-" and text[i + 2] != "]":
            hi = text[i + 2]
            i += 2
            if hi == "\\" and i + 1 < len(text):
                i += 1
                hi = text[i]
        items.append((ch, hi))
        i += 1
    return None


def _without_slash(items: list[tuple[str, str]], negate: bool) -> str:
    """A class with the same members as ``items`` except ``/``, which a path component
    never holds. A lone ``/`` becomes NUL, which no name holds either; a range that starts
    or ends at ``/`` starts at ``0`` or ends at ``.`` (the characters next to ``/``)."""
    out = ["[!" if negate else "["]
    for lo, hi in items:
        if lo == "/":
            lo, hi = ("0", hi) if hi > "/" else ("\0", "\0")
        elif hi == "/":
            hi = "."
        out.append("\\" + lo if lo == hi else f"\\{lo}-\\{hi}")
    out.append("]")
    return "".join(out)


def _git_glob(pattern: str) -> str | None:
    """``pattern`` rewritten so :func:`compile_glob` reads it as git does (#69 TE, D-TL-69
    #3), or ``None`` if git never matches it.

    * A ``/`` inside a class stays in the class (where it never matches) instead of
      splitting the pattern; ``\\/`` outside a class is a plain ``/``.
    * An empty segment (``a//b``, ``//a``, ``a//``) never matches in git.
    * A segment of three or more stars (``***``) is ``**``, as in git.
    """
    negate = pattern.startswith("!")
    body = pattern[negate:]
    segments: list[str] = []
    escaped: list[bool] = []  # per "/" split: was it written "\\/"
    current: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            if body[i + 1] == "/":
                segments.append("".join(current))
                escaped.append(True)
                current = []
            else:
                current.append(body[i : i + 2])
            i += 2
        elif ch == "/":
            segments.append("".join(current))
            escaped.append(False)
            current = []
            i += 1
        elif ch == "[":
            parsed = _class_items(body, i)
            if parsed is None:  # unclosed: compile_glob makes it match nothing, as git does
                current.append(body[i:])
                break
            items, class_negate, end = parsed
            if any("/" in item for item in items):
                current.append(_without_slash(items, class_negate))
            else:
                current.append(body[i:end])
            i = end
        else:
            current.append(ch)
            i += 1
    segments.append("".join(current))
    last = len(segments) - 1
    if any(not text and 0 < k < last for k, text in enumerate(segments)):
        return None
    if last and ((escaped[0] and not segments[0]) or (escaped[-1] and not segments[last])):
        return None  # "\\/a" is not anchored and "a\\/" not a folder pattern: no match
    rewritten = "/".join(
        "**" if len(text) > 2 and not text.strip("*") else text for text in segments
    )
    if "/" in body.removesuffix("/") and "/" not in rewritten.removesuffix("/"):
        rewritten = "/" + rewritten  # git anchors on any "/", even one inside a class
    return ("!" if negate else "") + rewritten


def _trim_trailing_spaces(line: str) -> str:
    """Git's ``trim_trailing_spaces``: drop the trailing run of spaces, except that a
    space escaped by an unescaped ``\\`` is kept, with nothing after it."""
    kept = line.rstrip(" ")
    if len(kept) == len(line):
        return line
    backslashes = len(kept) - len(kept.rstrip("\\"))
    if backslashes % 2:  # an odd run of backslashes escapes the first space
        return line[: len(kept) + 1]
    return kept


def gitignore_patterns(data: bytes) -> list[str]:
    """The pattern lines of one ``.gitignore`` file, in file order.

    Bytes that are not UTF-8 are kept with ``surrogateescape``, the same as the
    walk's file names, so a pattern matches the name it was written for. Decoding
    never fails.
    """
    text = data.decode("utf-8", "surrogateescape")
    if text.startswith(_BOM):
        text = text[1:]
    patterns: list[str] = []
    for raw in text.split("\n"):
        line = raw[:-1] if raw.endswith("\r") else raw
        if not line or line.startswith("#"):
            continue
        line = _trim_trailing_spaces(line)
        if line:
            patterns.append(line)
    return patterns


class IgnoreRules:
    """The ``.gitignore`` patterns loaded so far, with git's precedence.

    Call :meth:`add` for each file in load order: ``.git/info/exclude`` first, then
    each folder's ``.gitignore`` before anything below that folder is checked (the
    walk enters folders top-down). :meth:`ignored` answers for a repo-relative path.
    """

    def __init__(self) -> None:
        # (base folder, its components, pattern), in load order
        self._rules: list[tuple[str, tuple[str, ...], Glob]] = []
        # _index_key kind -> plain text -> rule positions; and the text lengths per kind
        self._lookup: dict[str, dict[str, list[int]]] = {"name": {}, "prefix": {}, "suffix": {}}
        self._lengths: dict[str, set[int]] = {"name": set(), "prefix": set(), "suffix": set()}
        self._anywhere: list[int] = []  # rules tried on every path
        self._folders: dict[str, bool] = {}
        self._work = 0  # match steps spent, against the budget
        self._checks = 0  # paths checked before the budget ran out, for the allowance
        self._names = 0  # and the characters in their last components
        self.loaded = 0
        self.skipped = 0
        self.unchecked = 0  # paths answered "not ignored" because the budget was spent

    def add(self, base: str, data: bytes) -> None:
        """Add the patterns of the ``.gitignore`` in folder ``base`` (``""`` is the root)."""
        for pattern in gitignore_patterns(data):
            if self.loaded >= GITIGNORE_MAX_PATTERNS:
                self.skipped += 1
                continue
            self.loaded += 1
            if (len(pattern) - len(pattern.rstrip("\\"))) % 2:
                continue  # ends in an unescaped "\\": git counts it but it never matches
            glob = _git_glob(_bytes_view(pattern))
            if glob is None:
                continue  # git never matches it
            folder = _bytes_view(base)
            self._index(len(self._rules), glob)
            self._rules.append(
                (folder, tuple(folder.split("/")) if folder else (), compile_glob(glob))
            )
        self._folders.clear()  # a cached folder verdict may change with new patterns

    def _index(self, position: int, pattern: str) -> None:
        key = _index_key(pattern)
        if key is None:
            self._anywhere.append(position)
            return
        kind, text = key
        self._lookup[kind].setdefault(text, []).append(position)
        self._lengths[kind].add(len(text))

    def _candidates(self, path: str) -> list[int]:
        """Positions of the rules that can match ``path``, last loaded first (none once
        the budget is spent)."""
        name = path.rpartition("/")[2]
        found = {*self._anywhere, *self._lookup["name"].get(name, ())}
        by_prefix, by_suffix = self._lookup["prefix"], self._lookup["suffix"]
        # A length longer than the name slices the whole name, which can find a shorter
        # key again; the set keeps each rule once.
        for length in self._lengths["prefix"]:
            found.update(by_prefix.get(name[:length], ()))
        for length in self._lengths["suffix"]:
            found.update(by_suffix.get(name[-length:], ()))
        # L-76-1: gathering and sorting are paid per candidate, so rules gathered but
        # never tried (a "!*" loaded last answers first) still cost. If that spends the
        # budget, nothing is sorted or tried.
        self._work += len(found) // _CANDIDATES_PER_STEP
        return [] if self.exhausted else sorted(found, reverse=True)

    @property
    def exhausted(self) -> bool:
        """True once the match budget is spent: nothing more is ignored."""
        return self._work > self._budget()

    def _budget(self) -> int:
        # Paths are counted only until the budget runs out, so once spent it stays spent.
        return (
            GITIGNORE_MATCH_BUDGET
            + GITIGNORE_MATCH_ALLOWANCE * self._checks
            + GITIGNORE_MATCH_ALLOWANCE_PER_CHAR * self._names
        )

    def _verdict(self, path: str, is_dir: bool, above: set[str]) -> bool:
        """The last matching pattern decides; a path no pattern matches is not ignored.
        Every step is paid from the match budget; if it runs out, ``False``.

        ``above`` holds the folders above ``path`` (``""`` for the root): a rule applies
        only if its ``.gitignore`` is in one of them. Any other rule is skipped without a
        try, paid only as a candidate gathered (#76 CR S1). The path is split once, and
        cut to each such folder once, so a try costs the same however long the path is;
        the split and the cuts are paid one step per component (#76 CR B2).
        """
        parts = path.split("/")
        # A check costs about four steps to start, one per component split and two per
        # index lookup (a slice and a dict lookup), measured against match steps for #76.
        self._work += 4 + len(parts) + 2 * sum(map(len, self._lengths.values()))
        below: dict[str, list[str]] = {}  # base folder -> path components under it
        for position in self._candidates(path):
            base, base_parts, glob = self._rules[position]
            if base not in above:
                continue
            self._work += 2  # a try costs about two match steps before matching starts
            rel = below.get(base)
            if rel is None:
                self._work += 1 + len(parts)
                rel = below[base] = parts[len(base_parts) :]
            matched, steps = glob.match_parts(rel, is_dir, self._budget() - self._work)
            self._work += steps
            if self.exhausted:
                return False
            if matched:
                return not glob.negated
        return False

    def _folder_ignored(self, folder: str, above: set[str]) -> bool:
        cached = self._folders.get(folder)
        if cached is None:
            cached = self._verdict(folder, True, above)
            self._folders[folder] = cached
        return cached

    def ignored(self, path: str, is_dir: bool = False) -> bool:
        """True if ``path``, or a folder above it, is ignored. ``False`` for every path
        once the match budget is spent (counted in :attr:`unchecked`)."""
        if not self._rules:
            return False
        path = _bytes_view(path)
        if not self.exhausted:
            self._checks += 1
            self._names += len(path) - path.rfind("/") - 1
            if self._check(path, is_dir):
                return True
        if self.exhausted:
            self.unchecked += 1
        return False

    def _check(self, path: str, is_dir: bool) -> bool:
        above = {""}  # the folders above the one being checked, worked out once per path
        end = path.find("/")
        while end != -1:  # prefixes are sliced from the path, never rejoined
            folder = path[:end]
            if self._folder_ignored(folder, above):
                return True
            if self.exhausted:
                return False
            above.add(folder)
            end = path.find("/", end + 1)
        return self._verdict(path, is_dir, above)
