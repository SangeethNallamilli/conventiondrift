"""Property test: backward mapping (C8) equals a forward replay on random edit histories.

(T-020; DESIGN §10 S4: "gives the same result as a forward replay".) Each example builds a random
file history (insertions, deletions, replacements, renames, shuffled and forged dates), renders it
as ``-U0`` patch text, and checks that C8, reading the patches newest first, finds exactly the
lines a forward replay says were last changed inside the window. Names deliberately avoid the
``test_ac_`` prefix: the AC-named tests belong to the Test Engineer.
"""

import random
from dataclasses import dataclass, field
from datetime import datetime

from history_support import END, FakeGit, file_diff, hunk, marker, sha, when, window
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conventiondrift.history import compute_recent

# Days before the window end: inside the window, before it, and after it (forged).
DAYS = (0.0, 1.0, 45.0, 89.5, 90.0, 91.0, 200.0, 5000.0, -1.0, -3000.0)


@dataclass
class Step:
    """One commit of the history, oldest first."""

    when: datetime
    path: bytes
    renamed_from: bytes | None
    hunks: list[tuple[int, int, int, int]] = field(default_factory=list)


def edit(
    rnd: random.Random, lines: list[int], next_id: int
) -> tuple[list[int], list[tuple[int, int, int, int]], int]:
    """Random ``-U0`` edits: hunks are separated by at least one kept line, like git's."""
    new: list[int] = []
    hunks: list[tuple[int, int, int, int]] = []
    i = 0
    last_was_change = False
    while True:
        room = len(lines) - i
        if last_was_change and room == 0:
            break
        low = 1 if last_was_change else 0
        keep = min(rnd.randint(low, max(min(4, room), low)), room)
        new += lines[i : i + keep]
        i += keep
        room = len(lines) - i
        removed = rnd.randint(0, min(3, room))
        added = rnd.randint(0, 3)
        if removed == 0 and added == 0:
            if room == 0 or rnd.random() < 0.3:
                break
            continue
        old_start = i + 1 if removed else i
        new_start = len(new) + 1 if added else len(new)
        hunks.append((old_start, removed, new_start, added))
        new += range(next_id, next_id + added)
        next_id += added
        i += removed
        last_was_change = True
    return new, hunks, next_id


def build(rnd: random.Random, commits: int) -> tuple[list[Step], list[int], dict[int, datetime]]:
    """A random history: its steps, the final line ids and the date of each line's last change."""
    steps: list[Step] = []
    dates: dict[int, datetime] = {}
    count = rnd.randint(1, 6)
    lines = list(range(count))
    path = b"p0.py"
    steps.append(Step(when(rnd.choice(DAYS)), path, None, [(0, 0, 1, count)]))
    for line in lines:
        dates[line] = steps[0].when
    next_id = count
    for index in range(1, commits):
        stamp = when(rnd.choice(DAYS))
        previous = path
        if rnd.random() < 0.25:
            path = b"p%d.py" % index
        lines, hunks, next_id = edit(rnd, lines, next_id)
        for line in lines:
            dates.setdefault(line, stamp)
        steps.append(Step(stamp, path, previous if path != previous else None, hunks))
    return steps, lines, dates


def render(steps: list[Step]) -> tuple[list[tuple[str, datetime]], list[bytes]]:
    chain: list[tuple[str, datetime]] = []
    patches: list[bytes] = []
    for position in range(len(steps) - 1, -1, -1):
        step = steps[position]
        commit = sha(len(steps) - position)
        chain.append((commit, step.when))
        bodies = [hunk(*h) for h in step.hunks]
        if position == 0:
            section = file_diff(
                step.path, *bodies, old=b"/dev/null", header=b"new file mode 100644\n"
            )
        elif step.renamed_from is not None:
            section = file_diff(
                step.path, *bodies, old=step.renamed_from, rename_from=step.renamed_from
            )
        elif bodies:
            section = file_diff(step.path, *bodies)
        else:
            section = b""
        patches.append(marker(commit) + section)
    return chain, patches


@settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(seed=st.randoms(use_true_random=False), commits=st.integers(min_value=1, max_value=9))
def test_backward_mapping_equals_forward_replay(seed: random.Random, commits: int) -> None:
    steps, final, dates = build(seed, commits)
    chain, patches = render(steps)
    path = steps[-1].path.decode()
    sites = frozenset(range(1, len(final) + 1))
    start, end = when(90), END
    expected = {
        ("head", path, number)
        for number, line in enumerate(final, 1)
        if start <= dates[line] <= end
    }
    git = FakeGit(chain, patches)
    result = compute_recent(git, window(90), {"head": {path: sites}}, tips={"head": chain[0][0]})
    assert result.recent == expected
