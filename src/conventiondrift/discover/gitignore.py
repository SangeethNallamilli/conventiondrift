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
each path checked so far (D-TL-73), so a stock ``.gitignore`` does not run out on a
tree with short file names however many paths the walk has (long or dotted file names
deep in the tree can run it out: a known limit, DESIGN A-3 #4a), while 2,000 hostile
patterns run it out within a few dozen paths. Every path check, file or folder (a folder's
verdict is paid once, when it is first worked out and cached), pays four steps, one
per path component (the path is split once), two per index lookup, one per eight
patterns gathered as candidates, tried or not (L-76-1), two per pattern tried, one per
component each time the path is cut to a ``.gitignore``'s folder (once per folder per
check), plus the steps
:meth:`~conventiondrift.discover.globmatch.Glob.match_parts` reports. So a long path
costs its length once per check, not once per pattern (#76 CR B2). A match stops
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
    "GITIGNORE_MATCH_BUDGET",
    "GITIGNORE_MAX_BYTES",
    "GITIGNORE_MAX_PATTERNS",
    "IgnoreRules",
    "gitignore_patterns",
]

GITIGNORE_MAX_BYTES: Final = 65_536  # A-3 condition 4: 64 KiB per file
GITIGNORE_MAX_PATTERNS: Final = 2_000  # A-3 condition 4: patterns in total, all files
# A-3 condition 7 (#76, D-TL-69, D-TL-73, D-TL-75): match steps per scan, plus an
# allowance per path checked. A step costs about 70-200 ns, so the base is about 0.5 s
# of matching, which is all 2,000 hostile patterns get (they run it out within a few
# dozen paths). With short file names the allowance is more than a walk with GitHub's
# Python .gitignore spends per entry at any depth up to the 64-folder cap (about 85
# steps near the root, about 205 at depth 63; one check alone can cost up to about 350,
# and unused allowance carries over), so that file does not run out below the
# 500,000-entry walk cap. 192 ran out at about 240,000 entries at depth 63 (D-TL-75 says
# 256 then). A file name costs about one step per character, so long or dotted file
# names deep in the tree can still run it out (from about depth 20 to 40, or at any
# depth for 255-character names): a known limit until the allowance scales with the
# file name (DESIGN A-3 #4a, follow-up). Patterns that stay under the allowance never
# run it out and pay it on every path, so it also bounds their cost.
GITIGNORE_MATCH_BUDGET: Final = 3_000_000
GITIGNORE_MATCH_ALLOWANCE: Final = 256
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
            self._index(len(self._rules), pattern)
            self._rules.append(
                (base, tuple(base.split("/")) if base else (), compile_glob(pattern))
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
        return GITIGNORE_MATCH_BUDGET + GITIGNORE_MATCH_ALLOWANCE * self._checks

    def _verdict(self, path: str, is_dir: bool) -> bool:
        """The last matching pattern decides; a path no pattern matches is not ignored.
        Every step is paid from the match budget; if it runs out, ``False``.

        The path is split once, and cut to each ``.gitignore`` folder once, so a try
        costs the same however long the path is; the split and the cuts are paid one
        step per component (#76 CR B2).
        """
        parts = path.split("/")
        # A check costs about four steps to start, one per component split and two per
        # index lookup (a slice and a dict lookup), measured against match steps for #76.
        self._work += 4 + len(parts) + 2 * sum(map(len, self._lengths.values()))
        below: dict[str, list[str] | None] = {}  # base folder -> path components under it
        for position in self._candidates(path):
            self._work += 2  # a try costs about two match steps before matching starts
            base, base_parts, glob = self._rules[position]
            if base in below:
                rel = below[base]
            else:
                self._work += 1 + len(parts)
                depth = len(base_parts)
                inside = depth < len(parts) and tuple(parts[:depth]) == base_parts
                rel = below[base] = parts[depth:] if inside else None
            if rel is None:
                continue
            matched, steps = glob.match_parts(rel, is_dir, self._budget() - self._work)
            self._work += steps
            if self.exhausted:
                return False
            if matched:
                return not glob.negated
        return False

    def _folder_ignored(self, folder: str) -> bool:
        cached = self._folders.get(folder)
        if cached is None:
            cached = self._verdict(folder, True)
            self._folders[folder] = cached
        return cached

    def ignored(self, path: str, is_dir: bool = False) -> bool:
        """True if ``path``, or a folder above it, is ignored. ``False`` for every path
        once the match budget is spent (counted in :attr:`unchecked`)."""
        if not self._rules:
            return False
        if not self.exhausted:
            self._checks += 1
            if self._check(path, is_dir):
                return True
        if self.exhausted:
            self.unchecked += 1
        return False

    def _check(self, path: str, is_dir: bool) -> bool:
        end = path.find("/")
        while end != -1:  # prefixes are sliced from the path, never rejoined
            if self._folder_ignored(path[:end]):
                return True
            if self.exhausted:
                return False
            end = path.find("/", end + 1)
        return self._verdict(path, is_dir)
