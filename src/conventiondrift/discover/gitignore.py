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
* trailing spaces are dropped unless the last one is escaped with ``\\``.

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
"""

from __future__ import annotations

from typing import Final

from conventiondrift.discover.globmatch import Glob, compile_glob

__all__ = [
    "GITIGNORE_MAX_BYTES",
    "GITIGNORE_MAX_PATTERNS",
    "IgnoreRules",
    "gitignore_patterns",
]

GITIGNORE_MAX_BYTES: Final = 65_536  # A-3 condition 4: 64 KiB per file
GITIGNORE_MAX_PATTERNS: Final = 2_000  # A-3 condition 4: patterns in total, all files

_BOM: Final = "\ufeff"
_SPECIAL: Final = frozenset("*?[\\")  # anything in a segment that is not plain text
_STARS: Final = frozenset("*?")


def _index_key(pattern: str) -> tuple[str, str] | None:
    """What the last component of a path must look like for ``pattern`` to match it,
    from the plain text of the pattern's last segment: ``("name", n)`` (equal to ``n``),
    ``("prefix", p)`` (starts with ``p``) or ``("suffix", s)`` (ends with ``s``).
    ``None`` if the segment says nothing usable, as for ``*`` or ``**``.
    """
    body = pattern[1:] if pattern.startswith("!") else pattern
    last = body.rstrip("/").rpartition("/")[2]
    cut = next((i for i, char in enumerate(last) if char in _SPECIAL), -1)
    if cut < 0:
        return ("name", last)
    prefix = last[:cut]
    suffix = ""
    if not {"[", "\\"}.intersection(last):  # only * and ?: the text after the last one
        suffix = last[max(i for i, char in enumerate(last) if char in _STARS) + 1 :]
    if prefix and len(prefix) >= len(suffix):
        return ("prefix", prefix)
    if suffix:
        return ("suffix", suffix)
    return None


def _trim_trailing_spaces(line: str) -> str:
    """Git's ``trim_trailing_spaces``: drop the trailing run of unescaped spaces."""
    last_space = -1
    pos = 0
    while pos < len(line):
        char = line[pos]
        if char == " ":
            if last_space < 0:
                last_space = pos
        elif char == "\\":
            pos += 1  # the escaped character, if any, ends the run
            last_space = -1
        else:
            last_space = -1
        pos += 1
    return line if last_space < 0 else line[:last_space]


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
        self._rules: list[tuple[str, Glob]] = []  # (base folder, pattern), load order
        self._by_name: dict[str, list[int]] = {}  # last component -> rule positions
        self._by_prefix: dict[str, list[int]] = {}  # start of the last component -> ...
        self._by_suffix: dict[str, list[int]] = {}  # end of the last component -> ...
        self._prefix_lengths: set[int] = set()
        self._suffix_lengths: set[int] = set()
        self._anywhere: list[int] = []  # rules tried on every path
        self._folders: dict[str, bool] = {}
        self.loaded = 0
        self.skipped = 0

    def add(self, base: str, data: bytes) -> None:
        """Add the patterns of the ``.gitignore`` in folder ``base`` (``""`` is the root)."""
        for pattern in gitignore_patterns(data):
            if self.loaded >= GITIGNORE_MAX_PATTERNS:
                self.skipped += 1
                continue
            self.loaded += 1
            self._index(len(self._rules), pattern)
            self._rules.append((base, compile_glob(pattern)))
        self._folders.clear()  # a cached folder verdict may change with new patterns

    def _index(self, position: int, pattern: str) -> None:
        key = _index_key(pattern)
        if key is None:
            self._anywhere.append(position)
        elif key[0] == "name":
            self._by_name.setdefault(key[1], []).append(position)
        elif key[0] == "prefix":
            self._by_prefix.setdefault(key[1], []).append(position)
            self._prefix_lengths.add(len(key[1]))
        else:
            self._by_suffix.setdefault(key[1], []).append(position)
            self._suffix_lengths.add(len(key[1]))

    def _candidates(self, path: str) -> list[int]:
        """Positions of the rules that can match ``path``, last loaded first."""
        name = path.rpartition("/")[2]
        found = [*self._anywhere, *self._by_name.get(name, ())]
        for length in self._prefix_lengths:
            found.extend(self._by_prefix.get(name[:length], ()))
        for length in self._suffix_lengths:
            if length <= len(name):
                found.extend(self._by_suffix.get(name[len(name) - length :], ()))
        found.sort(reverse=True)
        return found

    def _verdict(self, path: str, is_dir: bool) -> bool:
        """The last matching pattern decides; a path no pattern matches is not ignored."""
        for position in self._candidates(path):
            base, glob = self._rules[position]
            if not base:
                rel = path
            elif path.startswith(base) and path[len(base) : len(base) + 1] == "/":
                rel = path[len(base) + 1 :]
            else:
                continue
            if glob.match(rel, is_dir):
                return not glob.negated
        return False

    def _folder_ignored(self, folder: str) -> bool:
        cached = self._folders.get(folder)
        if cached is None:
            cached = self._verdict(folder, True)
            self._folders[folder] = cached
        return cached

    def ignored(self, path: str, is_dir: bool = False) -> bool:
        """True if ``path``, or a folder above it, is ignored."""
        if not self._rules:
            return False
        end = path.find("/")
        while end != -1:  # prefixes are sliced from the path, never rejoined
            if self._folder_ignored(path[:end]):
                return True
            end = path.find("/", end + 1)
        return self._verdict(path, is_dir)
