"""D-TL-59b: every wall-clock time-budget test carries ``@pytest.mark.timing``.

CI runs ``-m timing`` without coverage and ``-m "not timing"`` under coverage, because
coverage tracing slows CPU-bound code several times and pushed budgets over on Windows
(PR #65 at cc0bc5a: ``test_the_registry_maps_a_1_mib_rule_sentence_in_linear_time``,
5.22 s against 5.0 s). This guard walks every ``test_*.py`` under ``tests/`` with ``ast``
and fails, naming the node, when a test function uses ``assert_linear``, ``best_time``,
``_best_time``, ``time.perf_counter`` or ``time.monotonic`` (directly, or through a
function, class or fixture defined in the same module) and is neither marked ``timing``
nor listed in ``EXEMPT``. It fails closed: a new timing test, a stale exemption, or a
``timing`` mark on a test that times nothing all fail. This guard is not a timing test.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
ROOT = TESTS.parent
TIMING_HELPERS = frozenset({"assert_linear", "best_time", "_best_time"})
CLOCKS = frozenset({"perf_counter", "monotonic"})

# Process-behaviour tests: they time how a child process, socket or reader thread is
# killed, closed or timed out, not how fast our code runs, so they stay under coverage.
_EXEMPT_BY_FILE: dict[str, dict[str, str]] = {
    "tests/unit/test_github_transport.py": {
        "test_real_stalled_server_ends_at_the_overall_deadline": (
            "real socket stall must end at the overall request deadline"
        ),
        "test_real_slow_drip_server_ends_at_the_overall_deadline": (
            "real slow-drip socket must end at the overall request deadline"
        ),
        "test_deadline_socket_passes_size_and_flags_through": (
            "passes time.monotonic as the socket clock; no budget is asserted"
        ),
    },
    "tests/unit/test_gitread.py": {
        "test_bounded_stdout_over_cap_kills_with_fixed_text": (
            "child is killed at the stdout cap, not after its sleep"
        ),
        "test_bounded_timeout_kills_with_fixed_text": "child is killed at the run timeout",
        "test_hanging_git_is_killed_after_the_timeout": (
            "hanging git is killed at the run timeout"
        ),
    },
    "tests/unit/test_gitread_close.py": {
        "test_windows_close_returns_while_the_raw_close_is_still_blocked": (
            "close returns while a raw close is blocked (fake clock)"
        ),
        "test_a_real_blocked_reader_is_closed_promptly": (
            "blocked reader thread is joined within the join limit"
        ),
    },
    "tests/unit/test_gitread_deadline.py": {
        "test_real_slow_chunks_time_out_on_the_overall_deadline": (
            "slow child output ends at the overall read deadline"
        ),
        "test_running_out_kills_the_whole_tree": (
            "polls (via _gone/_polls) until the killed grandchild is gone"
        ),
    },
    "tests/unit/test_gitread_job.py": {
        "test_a_real_kill_after_git_exits_takes_the_in_group_tree": (
            "job/group kill reaches the grandchildren after git exits"
        ),
        "test_a_real_kill_after_git_exits_spares_the_escaped": (
            "job/group kill spares an escaped grandchild"
        ),
    },
    "tests/unit/test_gitread_kill.py": {
        "test_timeout_kills_the_grandchild_too": "timeout kill takes the grandchild too",
    },
    "tests/unit/test_gitread_listing.py": {
        "test_blob_request_timeout_kills_both_processes": (
            "blob request timeout kills both git processes"
        ),
        "test_batch_send_to_an_exited_process_is_a_component_error": (
            "monotonic is the wait deadline for an exited batch process"
        ),
        "test_batch_process_reports_eof_and_reads_lines": (
            "polls a real batch process up to a deadline"
        ),
        "test_batch_pump_stops_when_killed_with_a_full_queue": (
            "polls the pump queue up to a deadline, then kills"
        ),
        "test_batch_wait_timeout_is_a_component_error": (
            "a short wait deadline on a live batch process"
        ),
    },
    "tests/unit/test_gitread_pipe_holders.py": {
        "test_alive_tells_running_zombie_and_reaped_apart": (
            "polls a real child until it is a zombie"
        ),
        "test_a_pipe_holding_grandchild_never_stretches_a_kill": (
            "a pipe-holding grandchild must not stretch a kill"
        ),
    },
}
EXEMPT: dict[str, str] = {
    f"{path}::{name}": reason
    for path, tests in _EXEMPT_BY_FILE.items()
    for name, reason in tests.items()
}


def _is_timing_mark(node: ast.expr) -> bool:
    if isinstance(node, ast.Call):
        node = node.func
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "timing"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "mark"
    )


def _marks(value: ast.expr) -> list[ast.expr]:
    return list(value.elts) if isinstance(value, (ast.List, ast.Tuple)) else [value]


class _Module:
    def __init__(self, path: Path) -> None:
        self.tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        self.time_modules = set()
        self.clock_names = set()
        self.module_marked = False
        self.helpers: dict[str, ast.AST] = {}
        for node in self.tree.body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "time":
                        self.time_modules.add(a.asname or "time")
            elif isinstance(node, ast.ImportFrom) and node.module == "time":
                for a in node.names:
                    if a.name in CLOCKS:
                        self.clock_names.add(a.asname or a.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith(("test_", "Test")):
                    self.helpers[node.name] = node
            elif isinstance(node, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets):
                    self.module_marked = any(_is_timing_mark(m) for m in _marks(node.value))
        self.timed_helpers = self._close_over_helpers()

    def _body_nodes(self, node: ast.AST) -> list[ast.AST]:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            roots: list[ast.AST] = [node.args, *node.body]
        elif isinstance(node, ast.ClassDef):
            roots = list(node.body)
        else:
            roots = [node]
        return [n for r in roots for n in ast.walk(r)]

    def _direct(self, node: ast.AST) -> bool:
        for n in self._body_nodes(node):
            if isinstance(n, ast.Name) and (n.id in TIMING_HELPERS or n.id in self.clock_names):
                return True
            if isinstance(n, ast.Attribute):
                if n.attr in TIMING_HELPERS:
                    return True
                if (
                    n.attr in CLOCKS
                    and isinstance(n.value, ast.Name)
                    and n.value.id in self.time_modules
                ):
                    return True
        return False

    def _names(self, node: ast.AST) -> set[str]:
        names = {n.id for n in self._body_nodes(node) if isinstance(n, ast.Name)}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Fixtures defined in this module arrive as parameters.
            names |= {
                a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            }
        return names

    def _close_over_helpers(self) -> set[str]:
        timed = {name for name, node in self.helpers.items() if self._direct(node)}
        changed = True
        while changed:
            changed = False
            for name, node in self.helpers.items():
                if name not in timed and self._names(node) & timed:
                    timed.add(name)
                    changed = True
        return timed

    def uses_timing(self, node: ast.AST) -> bool:
        return self._direct(node) or bool(self._names(node) & self.timed_helpers)

    def tests(self) -> list[tuple[str, ast.AST, bool]]:
        """(name, node, marked) for each test function, including methods of Test* classes."""
        out: list[tuple[str, ast.AST, bool]] = []
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test"
            ):
                marked = self.module_marked or any(_is_timing_mark(d) for d in node.decorator_list)
                out.append((node.name, node, marked))
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                cls_marked = self.module_marked or any(
                    _is_timing_mark(d) for d in node.decorator_list
                )
                for item in node.body:
                    if isinstance(
                        item, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ) and item.name.startswith("test"):
                        marked = cls_marked or any(_is_timing_mark(d) for d in item.decorator_list)
                        out.append((f"{node.name}::{item.name}", item, marked))
        return out


def _scan() -> tuple[set[str], set[str], set[str]]:
    """Node ids of (timing tests, marked tests, all tests) under tests/."""
    timing: set[str] = set()
    marked: set[str] = set()
    every: set[str] = set()
    for path in sorted(TESTS.rglob("test_*.py")):
        module = _Module(path)
        rel = path.relative_to(ROOT).as_posix()
        for name, node, is_marked in module.tests():
            nodeid = f"{rel}::{name}"
            every.add(nodeid)
            if module.uses_timing(node):
                timing.add(nodeid)
            if is_marked:
                marked.add(nodeid)
    return timing, marked, every


def test_every_time_budget_test_is_marked_timing_or_exempt() -> None:
    timing, marked, _ = _scan()
    missing = sorted(timing - marked - EXEMPT.keys())
    assert not missing, f"time-budget tests without @pytest.mark.timing (D-TL-59b): {missing}"


def test_only_time_budget_tests_are_marked_timing() -> None:
    timing, marked, _ = _scan()
    stray = sorted(marked - timing)
    assert not stray, f"@pytest.mark.timing on tests that time nothing: {stray}"


def test_every_exemption_names_an_unmarked_timing_test_with_a_reason() -> None:
    timing, marked, every = _scan()
    stale = sorted(k for k in EXEMPT if k not in every or k not in timing)
    assert not stale, f"stale timing exemptions (test gone or no longer timed): {stale}"
    both = sorted(EXEMPT.keys() & marked)
    assert not both, f"exempt tests must not also be marked timing: {both}"
    assert all(reason.strip() for reason in EXEMPT.values())


def test_the_guard_sees_the_known_timing_helpers_and_is_not_itself_marked() -> None:
    timing, marked, every = _scan()
    here = Path(__file__).relative_to(ROOT).as_posix()
    mine = {nodeid for nodeid in every if nodeid.startswith(f"{here}::")}
    assert mine and not mine & marked and not mine & timing
    assert {
        "tests/security/test_extract_linear.py::test_sec_t09_single_line_extraction_is_linear",
        "tests/unit/test_rules_extract.py::test_extract_file_at_size_cap_is_fast",
        "tests/unit/test_globmatch.py::test_hostile_patterns_are_fast",
    } <= timing
