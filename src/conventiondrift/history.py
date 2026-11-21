"""C8 history: dates each site line by the first-parent commit that last changed it.

DESIGN §10 S4 and §12 A-3 / A-5, INTERFACES I-11 C8, I-14 (``History`` and the C8 rulings),
FEASIBILITY F-1.
C8 asks the git reader (C3) for the first-parent chain of a tip commit and for
one newest-first patch stream, then maps each site line backward through the
hunks. A line inside a hunk's ``+`` side takes that commit's date and stops
moving; every other line shifts to its pre-image position. For a whole segment
this equals a forward replay, and it lets the patch-byte cap stop cleanly.

* **Selection by position, never by date.** The segment is the first-parent
  chain from the tip, up to the commit that ends 200 consecutive commits dated
  before the window start, or the commit cap (10,000), whichever comes first.
* **Dates only classify.** A line is recent iff the date of the commit that last
  changed it satisfies ``start <= date <= end``. Future-dated commits are never
  recent (AC-F4.15). Lines not touched in the segment are not recent. A merge is
  diffed against its first parent, so lines it brings in take the merge date.
* **Caps (R2.6).** At most ``COMMIT_CAP`` commits and ``PATCH_MAX_BYTES`` bytes of
  patch text are read, newest first. Lines not yet dated at a cap are not
  recent, and the result carries a note.
* **Scan mode (A-3).** Files in ``scan_files`` are compared with their ``HEAD``
  blob in Python. C4 passes each tracked file's blob id and unchanged flag in
  ``scan_tracked``; C8 never lists the tree or hashes. Untracked lines are
  recent, changed lines are recent, and unchanged lines are dated through
  ``HEAD``'s history. Past 5,000 lines on a side, a ``HEAD`` blob over C4's
  per-file ``.py`` size limit, or once the 200,000,000 diff budget is spent, a
  changed file counts as all recent. No git subcommand beyond the C3 methods is used.
* **Failure.** Any C3 failure, and any patch text that does not parse, raises
  ``ComponentError("history")``; the caller shows recent as unavailable.

The patch parser reads only ``@@ -a,b +c,d @@`` ranges from hunk headers and
ignores the function-name text after the second ``@@``, which comes from repo
config and attributes (SR, I-14 item 9). Hunk bodies are skipped by their line
counts, so a content line that looks like a header is never read as one.
"""

import difflib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final

from conventiondrift.components import GitReaderProtocol
from conventiondrift.discover.safefs import size_limit
from conventiondrift.errors import ComponentError, FileSkipped, GitUnavailable
from conventiondrift.model import HistoryResult, PyFile, Side, TrackedState, Window

__all__ = [
    "COMMIT_CAP",
    "PATCH_MAX_BYTES",
    "PRE_WINDOW_RUN",
    "SCAN_DIFF_BUDGET",
    "SCAN_LINE_LIMIT",
    "GitHistory",
    "compute_recent",
]

_COMPONENT: Final = "history"

COMMIT_CAP: Final = 10_000
"""R2.6: first-parent commits walked (equal to ``gitread.MAX_COUNT_CAP``)."""
PATCH_MAX_BYTES: Final = 256 * 1024 * 1024
"""R2.6: patch bytes read; C8 counts them and closes the stream at the cap (I-14 item 9)."""
PRE_WINDOW_RUN: Final = 200
"""S4: the walk stops after this many consecutive commits dated before the window start."""
SCAN_LINE_LIMIT: Final = 5_000
"""A-3 condition 5: a changed file with more lines than this on either side is all recent."""
SCAN_DIFF_BUDGET: Final = 200_000_000
"""A-3 condition 5: total of (HEAD lines x working-tree lines) over the files diffed."""

COMMIT_CAP_NOTE: Final = (
    f"History was limited to the newest {COMMIT_CAP:,} commits, "
    "so recent adherence may be incomplete."
)
PATCH_CAP_NOTE: Final = (
    f"History reading stopped at {PATCH_MAX_BYTES // 2**20} MiB of patch text, "
    "so recent adherence may be incomplete."
)
SCAN_LINE_LIMIT_NOTE: Final = (
    f"Changed files over {SCAN_LINE_LIMIT:,} lines were treated as entirely recent "
    "without a line diff, so recent adherence may be approximate."
)
SCAN_DIFF_BUDGET_NOTE: Final = (
    "The line-diff budget ran out, so the remaining changed files were treated as "
    "entirely recent and recent adherence may be approximate."
)


def bare_cr_note(count: int) -> str:
    """The note for ``count`` files whose lines git and Python number differently.

    Wording from the D-PM-45 amendment (note 5), singular and plural.
    """
    noun, pronoun = ("file has", "it") if count == 1 else ("files have", "them")
    return (
        f"{count} {noun} bare carriage-return line endings, which git does not count as "
        f"line breaks, so recent adherence may be approximate for {pronoun}."
    )


_FAILED: Final = "history could not be read"
_MALFORMED: Final = "unexpected patch text from git"

_HUNK: Final = re.compile(
    rb"@@ -([0-9]{1,12})(?:,([0-9]{1,12}))? \+([0-9]{1,12})(?:,([0-9]{1,12}))? @@"
)
_SHA_LINE: Final = re.compile(rb"\x00([0-9a-f]{40}|[0-9a-f]{64})")
_QUOTED_ESCAPE: Final = re.compile(rb'\\(?:([abtnvfr"\\])|([0-7]{3}))')
_SIMPLE_ESCAPES: Final = {
    b"a": b"\a",
    b"b": b"\b",
    b"t": b"\t",
    b"n": b"\n",
    b"v": b"\v",
    b"f": b"\f",
    b"r": b"\r",
    b'"': b'"',
    b"\\": b"\\",
}
_BARE_CR: Final = re.compile(rb"\r(?!\n)")
_SECTION_HEADERS: Final = (b"--- ", b"+++ ", b"rename from ", b"rename to ")
"""The file-name lines of a section, which git writes before its first hunk."""


def _unquote(token: bytes) -> bytes:
    """Undo git's C-style path quoting (``core.quotePath=true``)."""
    if len(token) < 2 or token[-1:] != b'"':
        raise ComponentError(_COMPONENT, _MALFORMED)
    body = token[1:-1]
    out = bytearray()
    pos = 0
    while pos < len(body):
        slash = body.find(b"\\", pos)
        if slash < 0:
            out += body[pos:]
            break
        out += body[pos:slash]
        match = _QUOTED_ESCAPE.match(body, slash)
        if match is None:
            raise ComponentError(_COMPONENT, _MALFORMED)
        if match[1] is not None:
            out += _SIMPLE_ESCAPES[match[1]]
        else:
            octal = int(match[2], 8)
            if octal > 0xFF:
                raise ComponentError(_COMPONENT, _MALFORMED)
            out.append(octal)
        pos = match.end()
    return bytes(out)


def _git_path(token: bytes, prefix: bytes) -> str | None:
    """A repo path from a ``---`` or ``+++`` value, or ``None`` for ``/dev/null``."""
    if token.startswith(b'"'):
        raw = _unquote(token)
    else:
        raw = token.split(b"\t", 1)[0]
        if raw == b"/dev/null":
            return None
    if not raw.startswith(prefix):
        raise ComponentError(_COMPONENT, _MALFORMED)
    return raw[len(prefix) :].decode("utf-8", "surrogateescape")


def _rename_path(token: bytes) -> str:
    raw = _unquote(token) if token.startswith(b'"') else token
    return raw.decode("utf-8", "surrogateescape")


@dataclass(slots=True)
class _Tracked:
    """The still-undated site lines of one tip file, in the current commit's coordinates."""

    file: str
    now: list[int]
    original: list[int]


class _Mapper:
    """Maps one tracked file's lines through one commit's hunks, which arrive in order.

    A line inside a hunk's ``+`` range takes the commit's date and leaves the walk. Every
    other line moves by the net size change (``new - old`` count) of the hunks before it,
    which is its position before the commit. Hunks are applied as they are read, so the
    memory used does not grow with the number of hunks.
    """

    __slots__ = ("_end", "_now", "_original", "_pos", "_shift", "_sink", "tracked")

    def __init__(self, tracked: _Tracked, sink: set[tuple[str, int]] | None) -> None:
        self.tracked = tracked
        self._sink = sink  # where dated lines go; None when the commit is outside the window
        self._pos = 0
        self._shift = 0
        self._end = 0
        self._now: list[int] = []
        self._original: list[int] = []

    def _keep(self) -> None:
        self._now.append(self.tracked.now[self._pos] - self._shift)
        self._original.append(self.tracked.original[self._pos])
        self._pos += 1

    def hunk(self, old_count: int, first: int, count: int) -> None:
        """Apply one ``@@ -a,old_count +first,count @@`` hunk."""
        if first < self._end:
            raise ComponentError(_COMPONENT, _MALFORMED)
        self._end = first + count - 1 if count else first
        lines = self.tracked.now
        while self._pos < len(lines) and lines[self._pos] < first + (0 if count else 1):
            self._keep()
        while self._pos < len(lines) and count and lines[self._pos] <= self._end:
            if self._sink is not None:
                self._sink.add((self.tracked.file, self.tracked.original[self._pos]))
            self._pos += 1
        self._shift += count - old_count

    def finish(self) -> _Tracked:
        """Carry the lines after the last hunk and return the updated tracked file."""
        while self._pos < len(self.tracked.now):
            self._keep()
        self.tracked.now = self._now
        self.tracked.original = self._original
        return self.tracked


@dataclass(slots=True)
class _Section:
    """One file's diff in one commit, collected until the next section starts."""

    old: str | None = None
    new: str | None = None
    rename_from: str | None = None
    rename_to: str | None = None
    hunks: bool = False
    mapper: _Mapper | None = None


class _Replay:
    """Maps tracked lines backward through a newest-first patch stream."""

    def __init__(
        self,
        chain: Sequence[tuple[str, datetime]],
        wanted: Mapping[str, Sequence[int]],
        start: datetime,
        end: datetime,
    ) -> None:
        self._index = {sha: pos for pos, (sha, _) in enumerate(chain)}
        self._dates = [when for _, when in chain]
        self._start = start
        self._end = end
        self._tracked: dict[str, _Tracked] = {
            path: _Tracked(path, list(lines), list(lines))
            for path, lines in wanted.items()
            if lines
        }
        self.recent: set[tuple[str, int]] = set()
        self._last = -1
        self._in_window = False
        self._section: _Section | None = None
        self._hunk_left = 0
        self._hunk_file: str | None = None  # the tracked file the open hunk belongs to
        self.bare_cr: set[str] = set()

    @property
    def done(self) -> bool:
        """True once every tracked line has been dated."""
        return not self._tracked

    @property
    def undated(self) -> bool:
        return bool(self._tracked)

    def feed(self, line: bytes) -> None:
        """Read one patch line (without its newline)."""
        if self._hunk_left:
            if not line.startswith(b"\\"):
                self._hunk_left -= 1
                if self._hunk_file is not None and b"\r" in line[:-1]:
                    self.bare_cr.add(self._hunk_file)
            return
        if line.startswith(b"\x00"):
            self._start_commit(line)
        elif line.startswith(b"diff --git "):
            if self._last < 0:  # every diff belongs to a commit, and its marker comes first
                raise ComponentError(_COMPONENT, _MALFORMED)
            self._finish_section()
            self._section = _Section()
        elif self._section is not None:
            self._header_line(line, self._section)

    def finish(self) -> None:
        """The stream ended on its own: apply the last complete section."""
        if self._hunk_left:
            raise ComponentError(_COMPONENT, _MALFORMED)
        self._finish_section()

    def _start_commit(self, line: bytes) -> None:
        self._finish_section()
        match = _SHA_LINE.fullmatch(line)
        position = self._index.get(match[1].decode("ascii")) if match else None
        if position is None or position <= self._last:
            raise ComponentError(_COMPONENT, _MALFORMED)
        self._last = position
        when = self._dates[position]
        self._in_window = self._start <= when <= self._end

    def _header_line(self, line: bytes, section: _Section) -> None:
        if line.startswith(b"@@ "):
            match = _HUNK.match(line)
            if match is None:
                raise ComponentError(_COMPONENT, _MALFORMED)
            old_count = 1 if match[2] is None else int(match[2])
            new_count = 1 if match[4] is None else int(match[4])
            self._hunk_left = old_count + new_count
            self._hunk_file = None
            section.hunks = True
            if section.mapper is None and section.new in self._tracked:
                sink = self.recent if self._in_window else None
                section.mapper = _Mapper(self._tracked[section.new], sink)
            if section.mapper is not None:
                section.mapper.hunk(old_count, int(match[3]), new_count)
                self._hunk_file = section.mapper.tracked.file
        elif section.hunks and line.startswith(_SECTION_HEADERS):
            # Git writes a section's file names before its first hunk. A name after a
            # hunk would re-point lines that were already mapped.
            raise ComponentError(_COMPONENT, _MALFORMED)
        elif line.startswith(b"--- "):
            section.old = _git_path(line[4:], b"a/")
        elif line.startswith(b"+++ "):
            section.new = _git_path(line[4:], b"b/")
        elif line.startswith(b"rename from "):
            section.rename_from = _rename_path(line[12:])
        elif line.startswith(b"rename to "):
            section.rename_to = _rename_path(line[10:])

    def _finish_section(self) -> None:
        section, self._section = self._section, None
        if section is None or not self._tracked:
            return
        tracked: _Tracked | None
        if section.hunks:
            if section.mapper is None or section.new is None:
                return  # a file nothing tracked lives in, or a deleted one
            del self._tracked[section.new]
            tracked, previous = section.mapper.finish(), section.old
        else:  # a pure rename moves lines without changing them; other changes have no hunks
            if section.rename_to is None or section.rename_from is None:
                return
            tracked = self._tracked.pop(section.rename_to, None)
            previous = section.rename_from
            if tracked is None:
                return
        if not tracked.now or previous is None:
            return  # every line is dated, or the file was created here
        if previous in self._tracked:
            raise ComponentError(_COMPONENT, _MALFORMED)
        self._tracked[previous] = tracked


def _since(end: datetime, days: int) -> datetime:
    """The window start; a date too early to subtract from is clamped, never an error."""
    try:
        return end - timedelta(days=days)
    except OverflowError:
        return datetime.min.replace(tzinfo=UTC)


def _segment(chain: Sequence[tuple[str, datetime]], start: datetime) -> tuple[int, bool]:
    """How many chain commits to keep (S4), and whether the chain may have been cut at the cap.

    The flag is only a candidate: a chain of exactly ``COMMIT_CAP`` commits is cut
    short only if its oldest commit has a parent (see ``_has_parent``).
    """
    run = 0
    for position, (_, when) in enumerate(chain):
        run = run + 1 if when < start else 0
        if run >= PRE_WINDOW_RUN:
            return position + 1, False
    return len(chain), len(chain) >= COMMIT_CAP


def _has_parent(git: GitReaderProtocol, sha: str) -> bool:
    """True if the first-parent chain goes past ``sha``.

    I-14 asks for ``limit + 1`` commits so a chain of exactly the cap is not a cap hit.
    The reader refuses a limit over ``COMMIT_CAP`` (``gitread.MAX_COUNT_CAP``), so the
    extra commit is asked for as a chain of two that starts at the oldest commit read.
    """
    return len(git.first_parent_chain(sha, 2)) > 1


def _walk(
    git: GitReaderProtocol,
    tip: str,
    wanted: Mapping[str, Sequence[int]],
    start: datetime,
    end: datetime,
) -> tuple[set[tuple[str, int]], list[str], set[str]]:
    """Date ``wanted`` (file -> tip lines) over the S4 segment ending at ``tip``.

    Returns the recent (file, line) pairs, the cap notes and the files in which a bare
    carriage return was read.
    """
    chain = git.first_parent_chain(tip, COMMIT_CAP)
    keep, commit_capped = _segment(chain, start)
    notes: list[str] = []
    if not chain:
        return set(), notes, set()
    from_sha = chain[keep][0] if keep < len(chain) else None
    replay = _Replay(chain[:keep], wanted, start, end)
    stream = git.patches(from_sha, tip)
    received = 0
    pending: list[bytes] = []
    cut = False
    try:
        for chunk in stream:
            received += len(chunk)
            *whole, tail = chunk.split(b"\n")
            if whole:
                if pending:
                    whole[0] = b"".join([*pending, whole[0]])
                pending = [tail] if tail else []
                for line in whole:
                    replay.feed(line)
            else:
                pending.append(tail)
            if replay.done:
                break
            if received >= PATCH_MAX_BYTES:
                cut = True
                break
        else:
            if pending:
                replay.feed(b"".join(pending))
            replay.finish()
    finally:
        stream.close()
    if cut and replay.undated:
        notes.append(PATCH_CAP_NOTE)
    if commit_capped and replay.undated and _has_parent(git, chain[-1][0]):
        notes.append(COMMIT_CAP_NOTE)
    return replay.recent, notes, replay.bare_cr


def _lines(data: bytes) -> list[bytes]:
    """Lines split on ``\\n`` like git's hunks; a final newline adds no empty line."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


@dataclass(slots=True)
class _ScanPlan:
    """Scan-mode handling of the head side, computed before the history walk."""

    wanted: dict[str, list[int]] = field(default_factory=dict)
    to_work: dict[str, dict[int, int]] = field(default_factory=dict)
    recent: set[tuple[str, int]] = field(default_factory=set)
    bare_cr: set[str] = field(default_factory=set)
    line_limit_files: int = 0
    budget_files: int = 0
    diff_work: int = 0


def _head_lines(git: GitReaderProtocol, blob: str, max_bytes: int) -> list[bytes] | None:
    """The ``HEAD`` blob's lines, or ``None`` if it is over ``max_bytes``.

    The reader checks the blob's size before it reads the body and raises
    ``FileSkipped`` for one over the limit, so a huge blob is never read.
    """
    try:
        return _lines(git.blob(blob, max_bytes))
    except FileSkipped:
        return None


def _scan_plan(
    git: GitReaderProtocol,
    head_sites: Mapping[str, frozenset[int]],
    scan_files: Sequence[PyFile],
    scan_tracked: Mapping[str, TrackedState],
    max_bytes: int,
) -> _ScanPlan:
    """A-3: split the head sites into dated-by-history, recent, and mapped-by-difflib.

    C4 supplies the ``HEAD`` blob id and the unchanged flag of every tracked file in
    ``scan_tracked``; a scan file without an entry is untracked. The tree is never
    listed and nothing is hashed here.
    """
    plan = _ScanPlan()
    working = {file.path: file.data for file in scan_files}
    exhausted = False
    for path in sorted(head_sites, key=lambda p: p.encode("utf-8", "surrogateescape")):
        lines = sorted(head_sites[path])
        data = working.get(path)
        if data is None:
            plan.wanted[path] = lines
            continue
        if _BARE_CR.search(data):
            plan.bare_cr.add(path)
        state = scan_tracked.get(path)
        if state is None:
            plan.recent.update((path, line) for line in lines)
            continue
        if state.unchanged:
            plan.wanted[path] = lines
            continue
        work_lines = _lines(data)
        if len(work_lines) > SCAN_LINE_LIMIT:
            plan.line_limit_files += 1
            plan.recent.update((path, line) for line in lines)
            continue
        if exhausted:
            plan.budget_files += 1
            plan.recent.update((path, line) for line in lines)
            continue
        head_lines = _head_lines(git, state.head_blob, max_bytes)
        if head_lines is None or len(head_lines) > SCAN_LINE_LIMIT:
            plan.line_limit_files += 1
            plan.recent.update((path, line) for line in lines)
            continue
        cost = len(head_lines) * len(work_lines)
        if plan.diff_work + cost > SCAN_DIFF_BUDGET:
            exhausted = True
            plan.budget_files += 1
            plan.recent.update((path, line) for line in lines)
            continue
        plan.diff_work += cost
        to_head = _map_unchanged(head_lines, work_lines)
        to_work = {head: work for work, head in to_head.items()}
        mapped = sorted(to_head[line] for line in lines if line in to_head)
        plan.recent.update((path, line) for line in lines if line not in to_head)
        if mapped:
            plan.wanted[path] = mapped
            plan.to_work[path] = to_work
    return plan


def _map_unchanged(head_lines: list[bytes], work_lines: list[bytes]) -> dict[int, int]:
    """Working-tree line number -> ``HEAD`` line number for every line difflib calls equal."""
    matcher = difflib.SequenceMatcher(None, head_lines, work_lines, autojunk=False)
    mapping: dict[int, int] = {}
    for tag, head_from, head_to, work_from, _ in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(head_to - head_from):
                mapping[work_from + offset + 1] = head_from + offset + 1
    return mapping


def _tips_for(
    sites: Mapping[Side, Mapping[str, frozenset[int]]],
    tips: Mapping[Side, str],
    scan_files: Sequence[PyFile],
) -> dict[Side, str | None]:
    """The commit each side with site lines analyzes; ``None`` is the reader's ``HEAD``.

    Only scan mode (no tips, scan files) may leave the head side without a tip, and
    tips together with scan files are a caller bug.
    """
    if tips and scan_files:
        raise ValueError("tips and scan files are for different modes; a call has one")
    scan_mode = bool(scan_files)
    found: dict[Side, str | None] = {}
    for side in ("base", "head"):
        if not any(sites.get(side, {}).values()):
            continue
        if side in tips:
            found[side] = tips[side]
        elif side == "head" and scan_mode:
            found[side] = None
        else:
            raise ValueError(f"no tip commit was given for the {side} sites")
    return found


def _compute(
    git: GitReaderProtocol,
    end: datetime,
    window: Window,
    sites: Mapping[Side, Mapping[str, frozenset[int]]],
    needed: Mapping[Side, str | None],
    scan_files: Sequence[PyFile],
    scan_tracked: Mapping[str, TrackedState],
    max_bytes: int,
) -> HistoryResult:
    start = _since(end, window.days)
    recent: set[tuple[Side, str, int]] = set()
    notes: list[str] = []
    bare_cr: set[str] = set()
    plan = _ScanPlan()
    for side, given in needed.items():
        side_sites = sites[side]
        tip = given if given is not None else git.resolve("HEAD")
        wanted: Mapping[str, Sequence[int]] = {p: sorted(v) for p, v in side_sites.items()}
        if side == "head" and scan_files:
            plan = _scan_plan(git, side_sites, scan_files, scan_tracked, max_bytes)
            wanted = plan.wanted
        if any(wanted.values()):
            dated, side_notes, side_cr = _walk(git, tip, wanted, start, end)
        else:
            dated, side_notes, side_cr = set(), [], set()
        bare_cr |= side_cr
        notes.extend(n for n in side_notes if n not in notes)
        translate = plan.to_work if side == "head" else {}
        for path, line in dated:
            mapped = translate[path][line] if path in translate else line
            recent.add((side, path, mapped))
    recent.update(("head", path, line) for path, line in plan.recent)
    bare_cr |= plan.bare_cr
    if plan.line_limit_files:
        notes.append(SCAN_LINE_LIMIT_NOTE)
    if plan.budget_files:
        notes.append(SCAN_DIFF_BUDGET_NOTE)
    if bare_cr:
        notes.append(bare_cr_note(len(bare_cr)))
    stats = {
        "scan_all_recent_line_limit": plan.line_limit_files,
        "scan_all_recent_diff_budget": plan.budget_files,
        "scan_diff_work": plan.diff_work,
    }
    return HistoryResult(frozenset(recent), True, tuple(notes), stats)


def compute_recent(
    git: GitReaderProtocol | None,
    window: Window,
    sites: Mapping[Side, Mapping[str, frozenset[int]]],
    *,
    tips: Mapping[Side, str] = {},
    scan_files: Sequence[PyFile] = (),
    scan_tracked: Mapping[str, TrackedState] = {},
    max_file_bytes: int | None = None,
) -> HistoryResult:
    """The recent site lines per side, with the notes and ``scan_*`` counters (I-14 ``History``).

    PR mode: ``tips`` has the commit each side's site lines were read from (base: the
    merge base, head: the PR head). Scan mode: ``tips`` is empty, ``scan_files`` is the
    working tree and the head side is dated from the reader's ``HEAD``. A side with
    site lines and no tip, and ``tips`` together with ``scan_files``, are caller bugs
    and raise ``ValueError`` (checked first).

    ``max_file_bytes`` is the size limit for a ``HEAD`` blob read in scan mode: the
    value passed, or C4's per-file ``.py`` limit when it is ``None``.

    If ``git`` is ``None``, or the window is not available (or has no end), nothing
    is read and the result is ``available=False`` with an empty set. Any git failure,
    and any patch text that cannot be read, raises ``ComponentError("history")``.
    """
    needed = _tips_for(sites, tips, scan_files)
    max_bytes = size_limit("python") if max_file_bytes is None else max_file_bytes
    if git is None or not window.available or window.end is None:
        return HistoryResult(frozenset(), False, (), _no_stats())
    try:
        return _compute(git, window.end, window, sites, needed, scan_files, scan_tracked, max_bytes)
    except ComponentError as exc:
        if exc.component == _COMPONENT:
            raise
        raise ComponentError(_COMPONENT, _FAILED) from exc
    except (GitUnavailable, FileSkipped, MemoryError) as exc:
        raise ComponentError(_COMPONENT, _FAILED) from exc


def _no_stats() -> dict[str, int]:
    return {
        "scan_all_recent_line_limit": 0,
        "scan_all_recent_diff_budget": 0,
        "scan_diff_work": 0,
    }


class GitHistory:
    """The production C8 (``Components.history``): the I-14 ``History`` Protocol, no state."""

    def recent(
        self,
        git: GitReaderProtocol | None,
        window: Window,
        sites: Mapping[Side, Mapping[str, frozenset[int]]],
        *,
        tips: Mapping[Side, str] = {},
        scan_files: Sequence[PyFile] = (),
        scan_tracked: Mapping[str, TrackedState] = {},
        max_file_bytes: int | None = None,
    ) -> HistoryResult:
        return compute_recent(
            git,
            window,
            sites,
            tips=tips,
            scan_files=scan_files,
            scan_tracked=scan_tracked,
            max_file_bytes=max_file_bytes,
        )
