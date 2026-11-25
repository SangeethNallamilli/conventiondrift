"""D-TL-59b: every wall-clock time-budget test carries ``@pytest.mark.timing``.

CI runs ``-m "timing and not network"`` without coverage and ``-m "not network and not
timing"`` under coverage, because coverage tracing slows CPU-bound code several times and
pushed budgets over on Windows (PR #65 at cc0bc5a:
``test_the_registry_maps_a_1_mib_rule_sentence_in_linear_time``, 5.22 s against 5.0 s).

This guard parses every ``.py`` file under ``tests/`` with ``ast``. A function or class is
*timed* when it reads a clock (``time.perf_counter``/``perf_counter_ns``/``monotonic``/
``monotonic_ns``/``time``/``time_ns``/``process_time``/``thread_time`` and their ``_ns``
forms, the ``timeit`` module or anything imported from it, ``from time import ...``
aliases) or names ``assert_linear``, ``best_time`` or ``_best_time``, or when it uses a
timed function, class, module-level name (``CLOCK = time.perf_counter``) or fixture,
wherever under ``tests/`` that is defined: in the same module, imported (transitively)
from another test module such as ``checker_support.py``, a ``conftest.py`` fixture taken
by parameter name (``@pytest.fixture(name=...)`` included), or a method reached through
``self.``/``cls.``/``super()`` on the class or a base class under ``tests/`` (D-TL-62).
A timed test must carry the mark (decorator, class or module ``pytestmark``, or
``marks=`` on every ``pytest.param``) or be listed in ``EXEMPT`` with a reason. It fails
closed: a new timed test, a stale or marked exemption, a ``timing`` mark on a test that
times nothing, a partly marked parametrization, or a marker or fixture-name form the guard
cannot read all fail, naming the node.
This guard is not a timing test.
"""

from __future__ import annotations

import ast
import functools
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
ROOT = TESTS.parent
TIMING_HELPERS = frozenset({"assert_linear", "best_time", "_best_time"})
CLOCKS = frozenset(
    {
        "perf_counter",
        "perf_counter_ns",
        "monotonic",
        "monotonic_ns",
        "time",
        "time_ns",
        "process_time",
        "process_time_ns",
        "thread_time",
        "thread_time_ns",
    }
)
FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

# Tests that read a clock but check no budget on how fast our code runs, so they stay
# under coverage: process behaviour (how a child process, socket or reader thread is
# killed, closed or timed out), or a helper's timing that the test never asserts on.
_EXEMPT_BY_FILE: dict[str, dict[str, str]] = {
    "tests/bench/test_benchlib.py": {
        "test_probe_cli_init_without_dash_b_for_old_git": (
            "probe_cli times one CLI run via run_check; only the git init fallback is asserted"
        ),
    },
    "tests/spec/test_edge_cases.py": {
        "test_ac_e_12_large_pr_expected_findings": (
            "run_check times the CLI run; only the AC-E.12 findings are asserted, not wall time"
        ),
    },
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
            "polls (via gone_within) until the killed grandchild is gone"
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
    "tests/unit/test_liveness_probe.py": {
        "test_a_live_process_reads_running_and_the_probe_leaves_it_running": (
            "polls a live child for a moment; asserts the probe's answers, not wall time"
        ),
        "test_an_ended_process_reads_gone": "one poll of a reaped child (wait=0)",
        "test_a_zombie_reads_gone": "polls a killed child until it is a zombie",
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
        "test_triggers_cover_every_kill_path_in_the_code": (
            "compares the names in TRIGGERS (whose triggers use _Gate's clock); runs nothing"
        ),
        "test_the_gate_dumps_every_thread_when_a_kill_overruns": (
            "checks the stack dump _Gate writes when a kill overruns; asserts no budget"
        ),
        "test_the_gate_dumps_nothing_for_a_prompt_kill": (
            "checks _Gate writes no stack dump when stopped in time; asserts no budget"
        ),
    },
}
EXEMPT: dict[str, str] = {
    f"{path}::{name}": reason
    for path, tests in _EXEMPT_BY_FILE.items()
    for name, reason in tests.items()
}


Key = tuple[Path, str]  # (file, top-level name)


@dataclass
class _Module:
    """One parsed file: its imports, top-level definitions and marker spellings."""

    path: Path
    tree: ast.Module
    time_modules: set[str] = field(default_factory=set)
    timeit_modules: set[str] = field(default_factory=set)
    clock_names: set[str] = field(default_factory=set)
    pytest_names: set[str] = field(default_factory=set)
    mark_names: set[str] = field(default_factory=set)
    param_names: set[str] = field(default_factory=set)
    timing_names: set[str] = field(default_factory=set)
    imported: dict[str, Key] = field(default_factory=dict)
    module_aliases: dict[str, Path] = field(default_factory=dict)
    defs: dict[str, ast.AST] = field(default_factory=dict)
    fixtures: dict[str, str] = field(default_factory=dict)  # fixture name -> function
    owner: dict[str, ast.ClassDef] = field(default_factory=dict)  # "Cls.meth" -> Cls


class _Tree:
    """Every ``.py`` file under ``tests`` and which top-level definitions are timed."""

    def __init__(self, tests: Path, root: Path) -> None:
        self.tests, self.root = tests, root
        self.modules: dict[Path, _Module] = {}
        self.problems: list[str] = []
        for path in sorted(tests.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except SyntaxError as exc:
                if path.name.startswith("test_") or path.name == "conftest.py":
                    self.problems.append(f"{self._rel(path)}: cannot parse ({exc.msg})")
                continue
            self.modules[path] = _Module(path, tree)
        for module in self.modules.values():
            self._index(module)
        self.timed = self._close_over()

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    # --- imports -----------------------------------------------------------------

    def _resolve(self, here: Path, dotted: str, level: int) -> Path | None:
        """The file under tests/ that ``dotted`` names, as pytest's sys.path would find it."""
        parts = dotted.split(".") if dotted else []
        if level:
            base = here.parent
            for _ in range(level - 1):
                base = base.parent
            bases = [base]
        else:
            bases = [here.parent, self.tests, self.root]
        for base in bases:
            target = base.joinpath(*parts)
            for candidate in (target.with_suffix(".py"), target / "__init__.py"):
                if candidate in self.modules:
                    return candidate
        return None

    def _index(self, m: _Module) -> None:
        for node in ast.walk(m.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    bound = a.asname or a.name.split(".")[0]
                    if a.name == "time":
                        m.time_modules.add(bound)
                    elif a.name == "timeit":
                        m.timeit_modules.add(bound)
                    elif a.name == "pytest":
                        m.pytest_names.add(bound)
                    elif a.asname and (found := self._resolve(m.path, a.name, 0)):
                        m.module_aliases[a.asname] = found
                    elif found := self._resolve(m.path, a.name, 0):
                        m.module_aliases[bound] = found
            elif isinstance(node, ast.ImportFrom):
                source = node.module or ""
                for a in node.names:
                    bound = a.asname or a.name
                    if node.level == 0 and source == "time" and a.name in CLOCKS:
                        m.clock_names.add(bound)
                    elif node.level == 0 and source == "timeit":
                        m.clock_names.add(bound)
                    elif node.level == 0 and source == "pytest" and a.name == "mark":
                        m.mark_names.add(bound)
                    elif node.level == 0 and source == "pytest" and a.name == "param":
                        m.param_names.add(bound)
                    elif sub := self._resolve(m.path, f"{source}.{a.name}".strip("."), node.level):
                        m.module_aliases[bound] = sub
                    elif found := self._resolve(m.path, source, node.level):
                        m.imported[bound] = (found, a.name)
        for node in m.tree.body:
            if isinstance(node, DEFS):
                m.defs[node.name] = node
                if isinstance(node, FUNCS):
                    for d in node.decorator_list:
                        if self._is_fixture(m, d):
                            m.fixtures[self._fixture_name(m, node, d)] = node.name
                if isinstance(node, ast.ClassDef):
                    # Methods, so ``self.<name>`` / ``super().<name>`` can be followed.
                    for item in node.body:
                        if isinstance(item, FUNCS):
                            m.defs[f"{node.name}.{item.name}"] = item
                            m.owner[f"{node.name}.{item.name}"] = node
            elif isinstance(node, ast.Assign) and self.is_timing_mark(m, node.value):
                m.timing_names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                # Module-level names (``CLOCK = time.perf_counter``) are followed like
                # functions: a name bound to a clock is timed wherever it is used.
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    names = t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]
                    for n in names:
                        if isinstance(n, ast.Name) and n.id not in m.defs:
                            m.defs[n.id] = node

    def _fixture_name(self, m: _Module, node: ast.AST, decorator: ast.expr) -> str:
        """The name a test asks for: ``@pytest.fixture(name="...")`` or the function name."""
        assert isinstance(node, FUNCS)
        if isinstance(decorator, ast.Call):
            for kw in decorator.keywords:
                if kw.arg == "name":
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        return kw.value.value
                    self.problems.append(
                        f"{self._rel(m.path)}::{node.name}: cannot read fixture "
                        f"name={ast.unparse(kw.value)}; use a string literal"
                    )
        return node.name

    def _is_fixture(self, m: _Module, node: ast.expr) -> bool:
        target = node.func if isinstance(node, ast.Call) else node
        if isinstance(target, ast.Attribute):
            return target.attr == "fixture"
        return isinstance(target, ast.Name) and target.id == "fixture"

    # --- marks -------------------------------------------------------------------

    def _is_mark_object(self, m: _Module, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in m.mark_names
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "mark"
            and isinstance(node.value, ast.Name)
            and node.value.id in m.pytest_names
        )

    def is_timing_mark(self, m: _Module, node: ast.expr) -> bool:
        if isinstance(node, ast.Name) and node.id in m.timing_names:
            return True
        if isinstance(node, ast.Call):
            node = node.func
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "timing"
            and self._is_mark_object(m, node.value)
        )

    def _mentions_timing(self, node: ast.AST) -> bool:
        return "timing" in ast.unparse(node)

    def marks_in(self, m: _Module, value: ast.expr, where: str) -> bool:
        """True if ``value`` (a mark, or a list/tuple of marks) holds ``timing``."""
        items = list(value.elts) if isinstance(value, (ast.List, ast.Tuple)) else [value]
        found = False
        for item in items:
            if self.is_timing_mark(m, item):
                found = True
            elif self._mentions_timing(item):
                self.problems.append(
                    f"{where}: cannot read marker form {ast.unparse(item)!r}; "
                    "use @pytest.mark.timing"
                )
        return found

    def _is_param(self, m: _Module, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        if isinstance(f, ast.Name):
            return f.id in m.param_names
        return (
            isinstance(f, ast.Attribute)
            and f.attr == "param"
            and isinstance(f.value, ast.Name)
            and f.value.id in m.pytest_names
        )

    def _param_marked(self, m: _Module, call: ast.Call, where: str) -> bool:
        return any(kw.arg == "marks" and self.marks_in(m, kw.value, where) for kw in call.keywords)

    def decorators_mark(self, m: _Module, decorators: Iterable[ast.expr], where: str) -> bool:
        """Whether the decorators mark every case ``timing``; report partial marking."""
        marked = False
        for d in decorators:
            if self.is_timing_mark(m, d):
                marked = True
                continue
            target = d.func if isinstance(d, ast.Call) else d
            if (
                isinstance(d, ast.Call)
                and isinstance(target, ast.Attribute)
                and target.attr == "parametrize"
                and self._is_mark_object(m, target.value)
            ):
                values = d.args[1] if len(d.args) > 1 else None
                for kw in d.keywords:
                    if kw.arg == "argvalues":
                        values = kw.value
                if isinstance(values, (ast.List, ast.Tuple)):
                    flags = [
                        self._is_param(m, v) and self._param_marked(m, v, where)  # type: ignore[arg-type]
                        for v in values.elts
                    ]
                    if flags and all(flags):
                        marked = True
                    elif any(flags):
                        self.problems.append(
                            f"{where}: only {sum(flags)} of {len(flags)} pytest.param cases "
                            "carry marks=pytest.mark.timing; mark every case or the function"
                        )
                elif values is not None and self._mentions_timing(values):
                    self.problems.append(
                        f"{where}: cannot read the parametrize values for a timing mark"
                    )
            elif self._mentions_timing(d):
                self.problems.append(
                    f"{where}: cannot read marker form {ast.unparse(d)!r}; use @pytest.mark.timing"
                )
        return marked

    # --- timing ------------------------------------------------------------------

    def _body(self, node: ast.AST) -> list[ast.AST]:
        if isinstance(node, FUNCS):
            roots: list[ast.AST] = [node.args, *node.body]
        elif isinstance(node, ast.ClassDef):
            roots = list(node.body)
        else:
            roots = [node]
        return [n for r in roots for n in ast.walk(r)]

    def _direct(self, m: _Module, node: ast.AST) -> bool:
        for n in self._body(node):
            if isinstance(n, ast.Name) and (n.id in TIMING_HELPERS or n.id in m.clock_names):
                return True
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
                if n.attr in TIMING_HELPERS:
                    return True
                if n.value.id in m.time_modules and n.attr in CLOCKS:
                    return True
                if n.value.id in m.timeit_modules:
                    return True
            elif isinstance(n, ast.Attribute) and n.attr in TIMING_HELPERS:
                return True
        return False

    def _fixture_owner(self, m: _Module, name: str) -> Key | None:
        """Where pytest would find fixture ``name`` for a test in ``m``: module, then conftests."""
        if name in m.fixtures:
            return (m.path, m.fixtures[name])
        folder = m.path.parent
        while True:
            conftest = self.modules.get(folder / "conftest.py")
            if conftest is not None and name in conftest.fixtures:
                return (conftest.path, conftest.fixtures[name])
            if folder == self.tests or folder == folder.parent:
                return None
            folder = folder.parent

    def _class_of(self, m: _Module, base: ast.expr) -> tuple[_Module, ast.ClassDef] | None:
        """The class under tests/ that a base-class expression names, if any."""
        key: Key | None = None
        if isinstance(base, ast.Name):
            if isinstance(m.defs.get(base.id), ast.ClassDef):
                key = (m.path, base.id)
            elif base.id in m.imported:
                key = self._target(m.imported[base.id])
        elif (
            isinstance(base, ast.Attribute)
            and isinstance(base.value, ast.Name)
            and base.value.id in m.module_aliases
        ):
            key = self._target((m.module_aliases[base.value.id], base.attr))
        if key is None:
            return None
        owner = self.modules[key[0]]
        found = owner.defs.get(key[1])
        return (owner, found) if isinstance(found, ast.ClassDef) else None

    def _method(
        self, m: _Module, cls: ast.ClassDef, name: str, skip_own: bool = False
    ) -> Key | None:
        """Where ``name`` is defined for ``cls``: the class itself, then its bases."""
        seen: set[tuple[Path, str]] = set()
        todo: list[tuple[_Module, ast.ClassDef, bool]] = [(m, cls, skip_own)]
        while todo:
            mod, c, skip = todo.pop(0)
            if (mod.path, c.name) in seen:
                continue
            seen.add((mod.path, c.name))
            if not skip and f"{c.name}.{name}" in mod.defs:
                return (mod.path, f"{c.name}.{name}")
            for base in c.bases:
                found = self._class_of(mod, base)
                if found is not None:
                    todo.append((found[0], found[1], False))
        return None

    def uses(self, m: _Module, node: ast.AST, cls: ast.ClassDef | None = None) -> set[Key]:
        """The definitions (anywhere under tests/) that ``node`` refers to.

        ``cls`` is the class a method belongs to, so ``self.x``/``cls.x`` and
        ``super().x`` resolve through it and its bases under tests/.
        """
        out: set[Key] = set()
        for n in self._body(node):
            if cls is not None and isinstance(n, ast.Attribute):
                v = n.value
                if isinstance(v, ast.Name) and v.id in {"self", "cls"}:
                    if (key := self._method(m, cls, n.attr)) is not None:
                        out.add(key)
                elif (
                    isinstance(v, ast.Call)
                    and isinstance(v.func, ast.Name)
                    and v.func.id == "super"
                    and (key := self._method(m, cls, n.attr, skip_own=True)) is not None
                ):
                    out.add(key)
            if isinstance(n, ast.Name):
                if n.id in m.defs:
                    out.add((m.path, n.id))
                elif n.id in m.imported:
                    out.add(m.imported[n.id])
            elif (
                isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name)
                and n.value.id in m.module_aliases
            ):
                out.add((m.module_aliases[n.value.id], n.attr))
        if isinstance(node, FUNCS):
            a = node.args
            for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
                owner = self._fixture_owner(m, arg.arg)
                if owner is not None:
                    out.add(owner)
        return out

    def _target(self, key: Key) -> Key | None:
        """Follow re-exports: ``key`` names a definition, or an import of one."""
        seen: set[Key] = set()
        while key not in seen:
            seen.add(key)
            m = self.modules.get(key[0])
            if m is None:
                return None
            if key[1] in m.defs:
                return key
            if key[1] in m.imported:
                key = m.imported[key[1]]
                continue
            return None
        return None

    def _close_over(self) -> set[Key]:
        nodes = {
            (m.path, name): (m, node)
            for m in self.modules.values()
            for name, node in m.defs.items()
        }
        timed = {key for key, (m, node) in nodes.items() if self._direct(m, node)}
        edges = {key: self.uses(m, node, m.owner.get(key[1])) for key, (m, node) in nodes.items()}
        changed = True
        while changed:
            changed = False
            for key, refs in edges.items():
                if key not in timed and any(self._target(r) in timed for r in refs):
                    timed.add(key)
                    changed = True
        return timed

    def is_timed(self, m: _Module, node: ast.AST, cls: ast.ClassDef | None = None) -> bool:
        return self._direct(m, node) or any(
            self._target(r) in self.timed for r in self.uses(m, node, cls)
        )

    # --- tests -------------------------------------------------------------------

    def _pytestmark(self, m: _Module, body: list[ast.stmt], where: str) -> bool:
        marked = False
        for node in body:
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
            ):
                marked = self.marks_in(m, node.value, where) or marked
        return marked

    def scan(self) -> tuple[set[str], set[str], set[str]]:
        """Node ids of (timed tests, marked tests, all tests)."""
        timed: set[str] = set()
        marked: set[str] = set()
        every: set[str] = set()
        for path, m in self.modules.items():
            if not path.name.startswith("test_"):
                continue
            rel = self._rel(path)
            module_marked = self._pytestmark(m, m.tree.body, f"{rel}::pytestmark")
            cases: list[tuple[str, ast.AST, bool, ast.ClassDef | None]] = []
            for node in m.tree.body:
                if isinstance(node, FUNCS) and node.name.startswith("test"):
                    where = f"{rel}::{node.name}"
                    marks = self.decorators_mark(m, node.decorator_list, where)
                    cases.append((where, node, marks, None))
                elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                    where = f"{rel}::{node.name}"
                    cls_marked = self.decorators_mark(m, node.decorator_list, where)
                    cls_marked = self._pytestmark(m, node.body, where) or cls_marked
                    for item in node.body:
                        if isinstance(item, FUNCS) and item.name.startswith("test"):
                            inner = f"{where}::{item.name}"
                            own = self.decorators_mark(m, item.decorator_list, inner)
                            cases.append((inner, item, cls_marked or own, node))
            for nodeid, case, is_marked, owner in cases:
                every.add(nodeid)
                if self.is_timed(m, case, owner):
                    timed.add(nodeid)
                if module_marked or is_marked:
                    marked.add(nodeid)
            # A timing mark the walk above never reached (e.g. on a pytest.param built
            # outside a parametrize literal) cannot be checked: fail closed.
            for n in ast.walk(m.tree):
                if self._is_param(m, n) and any(
                    kw.arg == "marks" and self._mentions_timing(kw.value)
                    for kw in n.keywords  # type: ignore[attr-defined]
                ):
                    if not self._in_parametrize_literal(m, n):
                        self.problems.append(
                            f"{rel}:{n.lineno}: pytest.param(..., marks=...timing...) outside "  # type: ignore[attr-defined]
                            "a literal @pytest.mark.parametrize list; the guard cannot read it"
                        )
        return timed, marked, every

    def _in_parametrize_literal(self, m: _Module, param: ast.AST) -> bool:
        for node in ast.walk(m.tree):
            if isinstance(node, FUNCS):
                for d in node.decorator_list:
                    if isinstance(d, ast.Call) and any(
                        isinstance(v, (ast.List, ast.Tuple)) and param in v.elts
                        for v in [*d.args, *(kw.value for kw in d.keywords)]
                    ):
                        return True
        return False


@functools.cache
def _scan(tests: Path = TESTS, root: Path = ROOT) -> tuple[set[str], set[str], set[str], list[str]]:
    tree = _Tree(tests, root)
    timed, marked, every = tree.scan()
    return timed, marked, every, tree.problems


def test_every_time_budget_test_is_marked_timing_or_exempt() -> None:
    timing, marked, _, _ = _scan()
    missing = sorted(timing - marked - EXEMPT.keys())
    assert not missing, f"time-budget tests without @pytest.mark.timing (D-TL-59b): {missing}"


def test_only_time_budget_tests_are_marked_timing() -> None:
    timing, marked, _, _ = _scan()
    stray = sorted(marked - timing)
    assert not stray, f"@pytest.mark.timing on tests that time nothing: {stray}"


def test_every_exemption_names_an_unmarked_timing_test_with_a_reason() -> None:
    timing, marked, every, _ = _scan()
    stale = sorted(k for k in EXEMPT if k not in every or k not in timing)
    assert not stale, f"stale timing exemptions (test gone or no longer timed): {stale}"
    both = sorted(EXEMPT.keys() & marked)
    assert not both, f"exempt tests must not also be marked timing: {both}"
    assert all(reason.strip() for reason in EXEMPT.values())


def test_every_timing_marker_form_is_understood() -> None:
    _, _, _, problems = _scan()
    assert not problems, f"timing marks the guard cannot read: {problems}"


def test_the_guard_sees_the_known_timing_helpers_and_is_not_itself_marked() -> None:
    timing, marked, every, _ = _scan()
    here = Path(__file__).relative_to(ROOT).as_posix()
    mine = {nodeid for nodeid in every if nodeid.startswith(f"{here}::")}
    assert mine and not mine & marked and not mine & timing
    assert {
        "tests/security/test_extract_linear.py::test_sec_t09_single_line_extraction_is_linear",
        "tests/unit/test_rules_extract.py::test_extract_file_at_size_cap_is_fast",
        "tests/unit/test_globmatch.py::test_hostile_patterns_are_fast",
    } <= timing


# --- self-tests: each detection on a small tree ----------------------------------


def _tree(tmp_path: Path, files: dict[str, str]) -> tuple[set[str], set[str], set[str], list[str]]:
    tests = tmp_path / "tests"
    for name, source in files.items():
        target = tests / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    return _scan(tests, tmp_path)


T = "tests/unit/test_x.py::test_it"


@pytest.mark.parametrize(
    "call",
    [
        "time.perf_counter()",
        "time.perf_counter_ns()",
        "time.monotonic()",
        "time.monotonic_ns()",
        "time.time()",
        "time.time_ns()",
        "time.process_time()",
        "time.thread_time()",
        "time.process_time_ns()",
        "time.thread_time_ns()",
    ],
)
def test_self_every_time_clock_is_timed(tmp_path: Path, call: str) -> None:
    src = f"import time\n\ndef test_it():\n    {call}\n"
    timed, *_ = _tree(tmp_path, {"unit/test_x.py": src})
    assert timed == {T}


@pytest.mark.parametrize(
    "src",
    [
        "import time as t\n\ndef test_it():\n    t.monotonic()\n",
        "from time import perf_counter_ns as clock\n\ndef test_it():\n    clock()\n",
        "from time import process_time\n\ndef test_it():\n    process_time()\n",
        "import timeit\n\ndef test_it():\n    timeit.timeit('1')\n",
        "import timeit as ti\n\ndef test_it():\n    ti.default_timer()\n",
        "from timeit import Timer\n\ndef test_it():\n    Timer('1').timeit(1)\n",
        "from timeit import repeat as r\n\ndef test_it():\n    r('1')\n",
        "from timeit import default_timer\n\ndef test_it():\n    default_timer()\n",
    ],
    ids=[
        "time-alias",
        "from-time-alias",
        "from-time",
        "timeit",
        "timeit-alias",
        "Timer",
        "repeat-alias",
        "default_timer",
    ],
)
def test_self_aliases_and_timeit_are_timed(tmp_path: Path, src: str) -> None:
    timed, *_ = _tree(tmp_path, {"unit/test_x.py": src})
    assert timed == {T}


def test_self_sleep_alone_is_not_timed(tmp_path: Path) -> None:
    src = "import time\n\ndef test_it():\n    time.sleep(0)\n"
    timed, *_ = _tree(tmp_path, {"unit/test_x.py": src})
    assert timed == set()


def test_self_a_local_helper_is_followed(tmp_path: Path) -> None:
    src = (
        "import time\n\ndef _clock():\n    return time.monotonic()\n\n"
        "def _twice():\n    return _clock() + _clock()\n\ndef test_it():\n    _twice()\n"
    )
    timed, *_ = _tree(tmp_path, {"unit/test_x.py": src})
    assert timed == {T}


@pytest.mark.parametrize(
    "importer",
    [
        "from support import helper\n\ndef test_it():\n    helper()\n",
        "from support import helper as h\n\ndef test_it():\n    h()\n",
        "import support\n\ndef test_it():\n    support.helper()\n",
        "import support as s\n\ndef test_it():\n    s.helper()\n",
        "from unit.support import helper\n\ndef test_it():\n    helper()\n",
        "from tests.unit import support\n\ndef test_it():\n    support.helper()\n",
        "from .support import helper\n\ndef test_it():\n    helper()\n",
        "from again import helper\n\ndef test_it():\n    helper()\n",
        "from wrap import outer\n\ndef test_it():\n    outer()\n",
    ],
    ids=[
        "from",
        "from-alias",
        "import",
        "import-alias",
        "pythonpath",
        "package",
        "relative",
        "re-export",
        "transitive",
    ],
)
def test_self_helpers_imported_from_other_test_modules_are_followed(
    tmp_path: Path, importer: str
) -> None:
    files = {
        "unit/support.py": "import time\n\ndef helper():\n    return time.perf_counter()\n",
        "unit/again.py": "from support import helper\n",
        "unit/wrap.py": "from support import helper\n\ndef outer():\n    return helper()\n",
        "unit/test_x.py": importer,
    }
    timed, *_ = _tree(tmp_path, files)
    assert timed == {T}


def test_self_an_imported_helper_without_a_clock_is_not_timed(tmp_path: Path) -> None:
    files = {
        "unit/support.py": "def helper():\n    return 1\n",
        "unit/test_x.py": "from support import helper\n\ndef test_it():\n    helper()\n",
    }
    timed, *_ = _tree(tmp_path, files)
    assert timed == set()


@pytest.mark.parametrize("where", ["conftest.py", "unit/conftest.py", "unit/test_x.py"])
def test_self_a_timed_fixture_taken_by_parameter_is_followed(tmp_path: Path, where: str) -> None:
    fixture = (
        "import time\nimport pytest\n\n@pytest.fixture\n"
        "def stopwatch():\n    return time.monotonic()\n\n"
        "@pytest.fixture\ndef wrapped(stopwatch):\n    return stopwatch\n"
    )
    test = "def test_it(wrapped):\n    pass\n"
    files = {where: fixture + ("\n" + test if where == "unit/test_x.py" else "")}
    if where != "unit/test_x.py":
        files["unit/test_x.py"] = test
    timed, *_ = _tree(tmp_path, files)
    assert timed == {T}


@pytest.mark.parametrize(
    ("header", "decorator"),
    [
        ("import pytest", "@pytest.mark.timing"),
        ("import pytest as pt", "@pt.mark.timing"),
        ("from pytest import mark", "@mark.timing"),
        ("from pytest import mark as m", "@m.timing"),
        ("import pytest\ntiming = pytest.mark.timing", "@timing"),
    ],
)
def test_self_marker_spellings_count_as_marked(tmp_path: Path, header: str, decorator: str) -> None:
    src = f"{header}\nimport time\n\n{decorator}\ndef test_it():\n    time.monotonic()\n"
    timed, marked, _, problems = _tree(tmp_path, {"unit/test_x.py": src})
    assert (timed, marked, problems) == ({T}, {T}, [])


def test_self_module_and_class_pytestmark_count_as_marked(tmp_path: Path) -> None:
    src = (
        "import time\nimport pytest\n\npytestmark = [pytest.mark.timing]\n\n"
        "class TestA:\n    pytestmark = pytest.mark.timing\n\n"
        "    def test_it(self):\n        time.monotonic()\n\n"
        "def test_it():\n    time.monotonic()\n"
    )
    timed, marked, _, problems = _tree(tmp_path, {"unit/test_x.py": src})
    both = {T, "tests/unit/test_x.py::TestA::test_it"}
    assert (timed, marked, problems) == (both, both, [])


def test_self_every_param_marked_counts_as_marked(tmp_path: Path) -> None:
    src = (
        "import time\nimport pytest\nfrom pytest import param\n\n"
        "@pytest.mark.parametrize('n', [pytest.param(1, marks=pytest.mark.timing),\n"
        "                               param(2, marks=[pytest.mark.timing])])\n"
        "def test_it(n):\n    time.monotonic()\n"
    )
    timed, marked, _, problems = _tree(tmp_path, {"unit/test_x.py": src})
    assert (timed, marked, problems) == ({T}, {T}, [])


def test_self_a_partly_marked_parametrize_is_reported(tmp_path: Path) -> None:
    src = (
        "import time\nimport pytest\n\n"
        "@pytest.mark.parametrize('n', [pytest.param(1, marks=pytest.mark.timing), 2])\n"
        "def test_it(n):\n    time.monotonic()\n"
    )
    timed, marked, _, problems = _tree(tmp_path, {"unit/test_x.py": src})
    assert (timed, marked) == ({T}, set())
    assert len(problems) == 1 and "only 1 of 2 pytest.param cases" in problems[0]
    assert problems[0].startswith(T)


@pytest.mark.parametrize(
    "decorator",
    [
        "@getattr(pytest.mark, 'timing')",
        "@pytest.mark.__getattr__('timing')",
        "@MARKS['timing']",
    ],
)
def test_self_an_unreadable_marker_form_is_reported(tmp_path: Path, decorator: str) -> None:
    src = (
        f"import time\nimport pytest\nMARKS = {{}}\n\n{decorator}\n"
        "def test_it():\n    time.monotonic()\n"
    )
    timed, marked, _, problems = _tree(tmp_path, {"unit/test_x.py": src})
    assert (timed, marked) == ({T}, set())
    assert len(problems) == 1 and "cannot read marker form" in problems[0]


def test_self_a_marked_param_outside_a_parametrize_literal_is_reported(tmp_path: Path) -> None:
    src = (
        "import time\nimport pytest\n\nCASES = [pytest.param(1, marks=pytest.mark.timing)]\n\n"
        "@pytest.mark.parametrize('n', CASES)\ndef test_it(n):\n    time.monotonic()\n"
    )
    _, marked, _, problems = _tree(tmp_path, {"unit/test_x.py": src})
    assert marked == set()
    assert any("outside a literal @pytest.mark.parametrize" in p for p in problems)


# --- D-TL-62: self./super() methods, module-level clock aliases, named fixtures ------

TA = "tests/unit/test_x.py::TestA::test_it"


@pytest.mark.parametrize(
    "src",
    [
        # a helper method on the test class itself
        "import time\n\nclass TestA:\n    def _measure(self):\n"
        "        return time.perf_counter()\n\n    def test_it(self):\n        self._measure()\n",
        # a helper method two hops away through another method
        "import time\n\nclass TestA:\n    def _clock(self):\n        return time.monotonic()\n\n"
        "    def _measure(self):\n        return self._clock()\n\n"
        "    def test_it(self):\n        self._measure()\n",
        # inherited from a base class in the same module
        "import time\n\nclass _Base:\n    def _measure(self):\n        return time.monotonic()\n\n"
        "class TestA(_Base):\n    def test_it(self):\n        self._measure()\n",
        # inherited from a base class imported from another test module
        "from support import Base\n\nclass TestA(Base):\n    def test_it(self):\n"
        "        self._measure()\n",
        # through a module alias and a grandparent class
        "import support\n\nclass _Mid(support.Base):\n    pass\n\n"
        "class TestA(_Mid):\n    def test_it(self):\n        self._measure()\n",
        # super() from an override
        "from support import Base\n\nclass TestA(Base):\n    def _measure(self):\n"
        "        return super()._measure()\n\n    def test_it(self):\n        self._measure()\n",
    ],
    ids=["own", "two-hops", "base", "imported-base", "alias-grandparent", "super"],
)
def test_self_timed_methods_through_self_are_followed(tmp_path: Path, src: str) -> None:
    files = {
        "unit/support.py": "import time\n\nclass Base:\n    def _measure(self):\n"
        "        return time.perf_counter()\n",
        "unit/test_x.py": src,
    }
    timed, *_ = _tree(tmp_path, files)
    assert timed == {TA}


def test_self_an_untimed_method_or_an_unrelated_class_is_not_followed(tmp_path: Path) -> None:
    src = (
        "import time\n\nclass Other:\n    def _measure(self):\n        return time.monotonic()\n\n"
        "class TestA:\n    def _measure(self):\n        return 1\n\n"
        "    def test_it(self):\n        self._measure()\n"
    )
    timed, *_ = _tree(tmp_path, {"unit/test_x.py": src})
    assert timed == set()


@pytest.mark.parametrize(
    ("support", "test"),
    [
        ("", "import time\nCLOCK = time.perf_counter\n\ndef test_it():\n    CLOCK()\n"),
        ("", "from time import monotonic\nnow = monotonic\n\ndef test_it():\n    now()\n"),
        ("", "import time\nnow: object = time.monotonic_ns\n\ndef test_it():\n    now\n"),
        (
            "",
            "import time\nCLOCK = time.perf_counter\n\ndef _elapsed():\n    return CLOCK()\n\n"
            "def test_it():\n    _elapsed()\n",
        ),
        (
            "import time\nCLOCK = time.perf_counter\n",
            "from support import CLOCK\n\ndef test_it():\n    CLOCK()\n",
        ),
        (
            "import time\nCLOCK = time.perf_counter\n",
            "import support\n\ndef test_it():\n    support.CLOCK()\n",
        ),
        (
            "import time\n_C = time.perf_counter\nCLOCK = _C\n",
            "from support import CLOCK as c\n\ndef test_it():\n    c()\n",
        ),
    ],
    ids=["module", "from-time", "annotated", "via-helper", "imported", "module-attr", "chained"],
)
def test_self_module_level_clock_aliases_are_followed(
    tmp_path: Path, support: str, test: str
) -> None:
    files = {"unit/test_x.py": test}
    if support:
        files["unit/support.py"] = support
    timed, *_ = _tree(tmp_path, files)
    assert timed == {T}


def test_self_a_module_level_constant_without_a_clock_is_not_timed(tmp_path: Path) -> None:
    src = "import time\nPAUSE = time.sleep\nLIMIT = 5\n\ndef test_it():\n    PAUSE(0)\n    LIMIT\n"
    timed, *_ = _tree(tmp_path, {"unit/test_x.py": src})
    assert timed == set()


@pytest.mark.parametrize("where", ["conftest.py", "unit/conftest.py", "unit/test_x.py"])
def test_self_a_fixture_registered_under_name_is_followed(tmp_path: Path, where: str) -> None:
    fixture = (
        "import time\nimport pytest\n\n@pytest.fixture(name='stopwatch')\n"
        "def _stopwatch_fixture():\n    return time.monotonic()\n"
    )
    test = "def test_it(stopwatch):\n    pass\n"
    files = {where: fixture + ("\n" + test if where == "unit/test_x.py" else "")}
    if where != "unit/test_x.py":
        files["unit/test_x.py"] = test
    timed, *_ = _tree(tmp_path, files)
    assert timed == {T}


def test_self_a_renamed_fixture_is_not_found_under_its_function_name(tmp_path: Path) -> None:
    files = {
        "conftest.py": "import time\nimport pytest\n\n@pytest.fixture(name='stopwatch')\n"
        "def clock():\n    return time.monotonic()\n",
        "unit/test_x.py": "def test_it(clock):\n    pass\n",
    }
    timed, _, _, problems = _tree(tmp_path, files)
    assert (timed, problems) == (set(), [])


def test_self_an_unreadable_fixture_name_is_reported(tmp_path: Path) -> None:
    src = (
        "import pytest\nNAME = 'stopwatch'\n\n@pytest.fixture(name=NAME)\n"
        "def clock():\n    return 1\n"
    )
    *_, problems = _tree(tmp_path, {"conftest.py": src})
    assert len(problems) == 1 and "cannot read fixture name=NAME" in problems[0]
