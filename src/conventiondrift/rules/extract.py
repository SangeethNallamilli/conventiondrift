"""C6 rule extraction, DESIGN §7 steps 1-3 (T-013, critical module).

Instruction-file Markdown goes through three steps, all deterministic, with no
model and no network (AC-F2.1, AC-F2.2):

1. **Segmenting** (``segment``): the text is split into bullets and paragraph
   sentences. ``.mdc`` front matter is skipped and code fences are ignored.
   Every candidate sentence carries the line it starts on (AC-F2.8).
2. **Normalizing** (``normalize``): lowercase, whitespace collapsed, Markdown
   emphasis and backticks stripped, the I-7 marker dropped.
3. **Recognizing** (``recognize``): a sentence is a rule only if it has one of
   the imperative shapes in ``SHAPES``, the fixed table from DESIGN §7. The
   table is plain data, so tests can enumerate it.

The R2.6 caps (DESIGN §10 S4) are applied per file: at most
``MAX_CANDIDATES_PER_FILE`` candidate sentences and at most
``MAX_RULES_PER_FILE`` rules. DESIGN §12 A-5 fixes the order: the first N in
file order (line, then column) are kept and the rest are counted as dropped,
so the caller can list them.

I-7 inline ignore markers attach to a rule when they are on the rule's start
line or alone on the line directly above it (``attach_markers``). Every other
marker is returned as unattached.

Every regex applied to repo text here is in ``REGEXES`` (SECURITY-RULES R2.5),
uses no nested or overlapping quantifiers, and runs on text whose whitespace
is already collapsed where that matters.

Checker mapping (``match_rule``, specificity, the I-10 RuleMatch subset check),
duplicates and conflicts are T-015, not this module.
"""

import re
from bisect import bisect_right
from collections.abc import Collection, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Final, NamedTuple

from conventiondrift.model import ExtractedRule, FileRules

__all__ = [
    "MARKER",
    "MAX_CANDIDATES_PER_FILE",
    "MAX_RULES_PER_FILE",
    "REGEXES",
    "SHAPES",
    "Candidate",
    "Marker",
    "Shape",
    "attach_markers",
    "extract_file",
    "find_markers",
    "normalize",
    "recognize",
    "segment",
]

MARKER: Final = "<!-- conventiondrift: ignore -->"
"""The I-7 inline ignore marker: exact, case-sensitive, single spaces."""

MAX_CANDIDATES_PER_FILE: Final = 5_000
"""R2.6 (DESIGN §10 S4): candidate sentences kept per instruction file."""

MAX_RULES_PER_FILE: Final = 500
"""R2.6 (DESIGN §10 S4): rules kept per instruction file."""


@dataclass(frozen=True, slots=True)
class Shape:
    """One imperative rule shape from DESIGN §7 step 3.

    ``pattern`` starts with ``\\A`` and is applied to normalized text, so it
    is anchored at the start of the sentence.
    """

    name: str
    pattern: re.Pattern[str]


# DESIGN §7 step 3, in table order; the first shape that matches names the rule.
# Each pattern starts with \A, so even re.search tries one start position.
# Normalized text has single spaces only, so a literal " " never meets a run of
# whitespace, and each ".*" is followed by a fixed literal: matching is linear.
SHAPES: Final[tuple[Shape, ...]] = (
    Shape("use X", re.compile(r"\Ause \S")),
    Shape("prefer X over Y", re.compile(r"\Aprefer \S.* over \S")),
    Shape("always X", re.compile(r"\Aalways \S")),
    Shape("never X", re.compile(r"\Anever \S")),
    Shape("do not / don't X", re.compile(r"\A(?:do not|don't|don\u2019t) \S")),
    Shape("X, not Y", re.compile(r"\A[^,]+, not \S")),
    Shape("avoid X", re.compile(r"\Aavoid \S")),
    Shape("store / keep / represent X as Y", re.compile(r"\A(?:store|keep|represent) \S.* as \S")),
)

# A list item: optional indent, a bullet or an ordered-list number, then
# whitespace or the end of the line (used with re.match).
_BULLET: Final = re.compile(r"\A[ \t]*(?:[-*+]|[0-9]{1,9}[.)])(?:[ \t]+|$)")
# An ATX heading (used with re.match).
_HEADING: Final = re.compile(r"\A {0,3}#{1,6}(?:[ \t]|$)")
# A maximal run of underscores; whether it is emphasis is decided in Python.
_UNDERSCORE_RUN: Final = re.compile(r"_+")

REGEXES: Final[tuple[re.Pattern[str], ...]] = (
    _BULLET,
    _HEADING,
    _UNDERSCORE_RUN,
    *(shape.pattern for shape in SHAPES),
)
"""The R2.5 ReDoS registry for this module: every regex applied to repo text."""

_TERMINATORS: Final = frozenset(".!?")
_BREAK_CHARS: Final = frozenset("-*_=")


@dataclass(frozen=True, slots=True)
class Candidate:
    """A candidate sentence: the line it starts on and its text.

    ``text`` has the I-7 marker removed and its whitespace collapsed to single
    spaces; Markdown is otherwise kept as written.
    """

    line: int
    text: str
    column: int = field(default=0, compare=False)
    """1-based column (in characters of the line as written) of the first character; 0 = unknown."""


class Marker(NamedTuple):
    """An I-7 marker found on ``line``; ``alone`` when nothing else is on that line.

    A ``(line, alone_on_line)`` pair, the element type of I-13 ``Policy.markers``.
    """

    line: int
    alone: bool


def _split_lines(text: str) -> list[str]:
    # Only LF (and CRLF) end a line, as in git and GitHub line numbers;
    # str.splitlines() would also split on VT, FF, U+2028 and others.
    return [line.removesuffix("\r") for line in text.split("\n")]


def _front_matter_end(path: str, lines: Sequence[str]) -> int:
    """Number of leading lines that are ``.mdc`` front matter (0 when there is none)."""
    if not path.endswith(".mdc") or not lines or lines[0].strip() != "---":
        return 0
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            return index + 1
    # I-13 C6 ruling (T-013-1): an unclosed "---" block is read as no front matter,
    # as CommonMark renders it (a thematic break), so the file's rules are kept.
    return 0


def _fence_open(line: str) -> tuple[str, int] | None:
    """The fence character and length when ``line`` opens a code fence."""
    # Any indentation is accepted (CommonMark allows 0-3 spaces): ignoring more
    # code is the conservative reading for fences nested in list items.
    stripped = line.lstrip(" \t")
    if stripped[:3] not in ("```", "~~~"):
        return None
    char = stripped[0]
    length = len(stripped) - len(stripped.lstrip(char))
    if char == "`" and "`" in stripped[length:]:
        return None  # CommonMark: a backtick fence's info string has no backtick
    return char, length


def _fence_closes(line: str, char: str, length: int) -> bool:
    stripped = line.strip(" \t")
    return len(stripped) >= length and stripped == char * len(stripped)


def _is_break(content: str) -> bool:
    """A thematic break or setext underline such as ``---``, ``***`` or ``===``."""
    marks = content.replace(" ", "").replace("\t", "")
    return len(marks) >= 3 and set(marks) <= _BREAK_CHARS and len(set(marks)) == 1


class _Line(NamedTuple):
    """One line of a bullet or paragraph: ``content`` is what is split into sentences.

    It is ``raw`` with each marker replaced by one space, minus its first ``skip``
    characters (the bullet).
    """

    number: int
    content: str
    raw: str
    skip: int


def _raw_index(raw: str, index: int) -> int:
    """Where ``index`` in ``raw`` with each marker replaced by one space is in ``raw`` itself."""
    shift = 0
    position = raw.find(MARKER)
    while position >= 0 and position - shift < index:
        shift += len(MARKER) - 1
        position = raw.find(MARKER, position + len(MARKER))
    return index + shift


def _is_vs(text: str, period: int) -> bool:
    """Whether ``text[period]`` is the period of a whole-word "vs." or "v." (any case).

    INTERFACES I-10 item 6(c): a sentence never ends there, unless the text ends there. Only
    the two or three characters before the period are read, so the split stays linear.
    """
    if text[period] != ".":
        return False
    for word in ("vs", "v"):
        start = period - len(word)
        if start >= 0 and text[start:period].lower() == word:
            before = text[start - 1] if start else " "
            return not (before.isalnum() or before == "_")
    return False


def _sentences(block: Sequence[_Line]) -> Iterator[Candidate]:
    """Split one bullet or paragraph into sentences with their start lines and columns."""
    offsets: list[int] = []
    position = 0
    for entry in block:
        offsets.append(position)
        position += len(entry.content) + 1
    text = "\n".join(entry.content for entry in block)
    size = len(text)
    index = 0
    while index < size:
        while index < size and text[index].isspace():
            index += 1
        if index >= size:
            return
        start = index
        while index < size:
            char = text[index]
            index += 1
            if char in _TERMINATORS and (index >= size or text[index].isspace()):
                if index < size and _is_vs(text, index - 1):
                    continue
                break
        which = bisect_right(offsets, start) - 1
        entry = block[which]
        within = entry.skip + start - offsets[which]
        yield Candidate(
            line=entry.number,
            text=" ".join(text[start:index].split()),
            column=_raw_index(entry.raw, within) + 1,
        )


def segment(path: str, text: str) -> Iterator[Candidate]:
    """Yield every candidate sentence of ``text`` in file order (DESIGN §7 step 1).

    ``path`` is used only to tell whether the file is ``.mdc`` (front matter).
    Line numbers are 1-based. Blank lines, a line holding only the I-7 marker,
    headings, thematic breaks and code fences end a bullet or paragraph;
    a new bullet starts a new one. Fenced lines and front matter yield nothing.
    """
    lines = _split_lines(text)
    first = _front_matter_end(path, lines)
    block: list[_Line] = []
    fence: tuple[str, int] | None = None
    for number in range(first + 1, len(lines) + 1):
        raw = lines[number - 1]
        if fence is not None:
            if _fence_closes(raw, *fence):
                fence = None
            continue
        opened = _fence_open(raw)
        if opened is not None:
            yield from _sentences(block)
            block = []
            fence = opened
            continue
        content = raw.replace(MARKER, " ")
        if not content.strip() or _is_break(content) or _HEADING.match(content):
            yield from _sentences(block)
            block = []
            continue
        bullet = _BULLET.match(content)
        if bullet is not None:
            yield from _sentences(block)
            block = [_Line(number, content[bullet.end() :], raw, bullet.end())]
            continue
        block.append(_Line(number, content, raw, 0))
    yield from _sentences(block)


def _strip_underscore_emphasis(text: str) -> str:
    """Drop ``_`` runs used as emphasis; keep those inside a word (``integer_cents``)."""
    parts: list[str] = []
    last = 0
    for run in _UNDERSCORE_RUN.finditer(text):
        start, end = run.span()
        inside_word = start > 0 and end < len(text) and text[start - 1].isalnum()
        inside_word = inside_word and text[end].isalnum()
        if not inside_word:
            parts.append(text[last:start])
            last = end
    parts.append(text[last:])
    return "".join(parts)


def normalize(text: str) -> str:
    """DESIGN §7 step 2: the I-7 marker dropped, emphasis and backticks stripped,
    lowercased, whitespace collapsed to single spaces."""
    text = text.replace(MARKER, " ").replace("`", "").replace("*", "")
    text = _strip_underscore_emphasis(text)
    return " ".join(text.lower().split())


def recognize(normalized_text: str) -> str | None:
    """The name of the first ``SHAPES`` entry that ``normalized_text`` has, else None.

    Shapes are matched at the start of the sentence, where an imperative is.
    """
    # I-13 C6 ruling (T-013-2): shapes match only at the start of a sentence,
    # so prose such as "We use Django" is not a rule; AC-F2.3-F2.5 hold.
    for shape in SHAPES:
        if shape.pattern.match(normalized_text):
            return shape.name
    return None


def find_markers(text: str) -> tuple[Marker, ...]:
    """Every line holding the I-7 marker, in line order (one entry per line)."""
    return tuple(
        Marker(line=number, alone=line.strip() == MARKER)
        for number, line in enumerate(_split_lines(text), start=1)
        if MARKER in line
    )


def attach_markers(
    rule_lines: Collection[int], markers: Sequence[tuple[int, bool]]
) -> tuple[frozenset[int], tuple[int, ...]]:
    """I-7 attachment: ``(ignored rule start lines, unattached marker lines)``.

    A marker applies to a rule starting on its own line, or, when it is alone
    on its line, to a rule starting on the line directly below. A marker that
    applies to no rule is unattached.
    """
    ignored: set[int] = set()
    unattached: list[int] = []
    for line, alone in markers:
        target = line + 1 if alone else line
        if target in rule_lines:
            ignored.add(target)
        else:
            unattached.append(line)
    return frozenset(ignored), tuple(unattached)


def extract_file(
    path: str, data: bytes, *, markers: Sequence[tuple[int, bool]] | None = None
) -> FileRules:
    """Extract the rules of one instruction file (DESIGN §7 steps 1-3, R2.6, I-7).

    ``markers`` defaults to the markers in ``data`` itself. A caller whose
    policy side differs from the analyzed side passes the policy side's markers
    (I-7, D-PM-12).
    """
    # C4 has already refused binary and undecodable files (I-13); "replace"
    # keeps this function total on any bytes. A UTF-8 BOM is stripped (I-13).
    text = data.decode("utf-8-sig", errors="replace")
    kept: list[Candidate] = []
    candidates_dropped = 0
    for candidate in segment(path, text):
        if len(kept) < MAX_CANDIDATES_PER_FILE:
            kept.append(candidate)
        else:
            candidates_dropped += 1
    found: list[tuple[Candidate, str, str]] = []
    rules_dropped = 0
    for candidate in kept:
        normalized = normalize(candidate.text)
        shape = recognize(normalized)
        if shape is None:
            continue
        if len(found) < MAX_RULES_PER_FILE:
            found.append((candidate, normalized, shape))
        else:
            rules_dropped += 1
    if markers is None:
        markers = find_markers(text)
    # A marker is matched against the kept rules only; one whose rule was cut
    # by a cap is listed as unattached.
    ignored, unattached = attach_markers({c.line for c, _, _ in found}, markers)
    rules = tuple(
        ExtractedRule(
            line=candidate.line,
            column=candidate.column,
            text=candidate.text,
            normalized_text=normalized,
            shape=shape,
            ignored=candidate.line in ignored,
        )
        for candidate, normalized, shape in found
    )
    return FileRules(
        path=path,
        rules=rules,
        unattached_markers=unattached,
        candidates_dropped=candidates_dropped,
        rules_dropped=rules_dropped,
    )
