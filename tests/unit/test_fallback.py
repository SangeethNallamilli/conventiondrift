"""Unit tests for the minimal fallback writer in conventiondrift.fallback (T-006b).

DESIGN §4 and §12 A-8, INTERFACES I-2 and I-14 Q6. Names avoid the ``test_ac_`` prefix; the
spec text each test exercises is quoted in a comment. Negative inputs are built from the code's
own constants (``WITHHELD``, ``GIT_TOO_OLD_TEXT``, ``CheckerId``), never from literals the code
doesn't define.
"""

import ast
import io
import os
import stat
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Literal, get_args

import pytest

from conventiondrift import core, fallback
from conventiondrift.components import Components
from conventiondrift.core import RunContext, internal_error, run
from conventiondrift.errors import ComponentError, GitTooOld
from conventiondrift.fallback import (
    GIT_TOO_OLD_TEXT,
    SECTION_HEADING,
    SUMMARY_ENV,
    SUMMARY_OPEN_FLAGS,
    SUMMARY_REFUSED,
    WITHHELD,
    action_section,
    cli_lines,
    write_internal_errors,
)
from conventiondrift.model import CheckerId, InternalError

SRC = Path(__file__).resolve().parents[2] / "src" / "conventiondrift"
CHECKER_IDS: tuple[CheckerId, ...] = get_args(CheckerId)
PLANTED = "ghp_FAKE0000planted /home/x/secret.py contents"
GENERIC = f"Exception: {WITHHELD}"


def _error(component: str = "render", cls: str = "ComponentError") -> InternalError:
    return InternalError(component, f"{cls}: {WITHHELD}")


# --- the texts (I-14 Q6, A-8) ---------------------------------------------------------------


def test_the_constants_match_what_core_builds() -> None:
    # The fallback re-checks messages against its own copy of the fixed texts; this ties the
    # copy to the code that builds them, so the two cannot drift apart.
    assert internal_error(ValueError(PLANTED)) == _error("core", "ValueError")
    assert internal_error(GitTooOld()) == InternalError("gitread", GIT_TOO_OLD_TEXT)
    for error in (internal_error(ComponentError("render", PLANTED)), internal_error(GitTooOld())):
        assert fallback._safe(error) == (error.component, error.message)


def test_the_action_section_has_a_heading_and_one_line_per_error() -> None:
    # I-14: "the summary section is headed `Internal error`, with one line per error:
    # Internal error in `<component>`: <message>".
    errors = [_error("checker:logging"), InternalError("gitread", GIT_TOO_OLD_TEXT)]
    section = action_section(errors)
    assert section == (
        "\n"
        f"{SECTION_HEADING}\n"
        "\n"
        f"Internal error in `checker:logging`: ComponentError: {WITHHELD}\n"
        "\n"
        "Internal error in `gitread`: git 2.30 or newer is required\n"
    )
    assert SECTION_HEADING.endswith("Internal error")


def test_the_cli_has_one_line_per_error() -> None:
    # I-14: "stderr gets one line per error: conventiondrift: internal error in <component>:
    # <message>".
    errors = [_error("checker:logging"), InternalError("gitread", GIT_TOO_OLD_TEXT)]
    assert cli_lines(errors) == [
        f"conventiondrift: internal error in checker:logging: ComponentError: {WITHHELD}",
        "conventiondrift: internal error in gitread: git 2.30 or newer is required",
    ]


@pytest.mark.parametrize("checker", CHECKER_IDS)
def test_every_checker_component_is_named(checker: CheckerId) -> None:
    error = _error(f"checker:{checker}")
    assert f"`checker:{checker}`" in action_section([error])
    assert f"in checker:{checker}:" in cli_lines([error])[0]


def _bad_components() -> list[str]:
    ok = f"checker:{CHECKER_IDS[0]}"
    return [
        ok.upper(),
        ok + "\n## injected",
        ok + "`",
        ok + " ",
        ":" + ok,
        PLANTED,
        "",
        "é" + ok,
    ]


@pytest.mark.parametrize("component", _bad_components())
def test_a_component_outside_the_i14_pattern_is_written_as_core(component: str) -> None:
    error = _error(component)
    assert fallback._safe(error)[0] == "core"
    assert "Internal error in `core`:" in action_section([error])
    assert cli_lines([error])[0].startswith("conventiondrift: internal error in core: ")
    for text in (action_section([error]), *cli_lines([error])):
        assert component not in text or component == ""


def _bad_messages() -> list[str]:
    cls = "ComponentError"
    return [
        PLANTED,
        WITHHELD,  # no class name
        f"{cls}: {WITHHELD}\n## injected",
        f"{cls}: {WITHHELD}\n",
        f"\n{cls}: {WITHHELD}",
        f"{cls}: {WITHHELD}!",
        f"{cls}:{WITHHELD}",
        f"{cls} : {WITHHELD}",
        f"é{cls}: {WITHHELD}",
        f"{cls}: {WITHHELD} `x`",
        f"1{cls}: {WITHHELD}",
        GIT_TOO_OLD_TEXT + ", found 2.29.0",
        "",
    ]


@pytest.mark.parametrize("message", _bad_messages())
def test_a_message_that_is_not_one_of_the_fixed_forms_is_replaced(message: str) -> None:
    error = InternalError("render", message)
    assert fallback._safe(error) == ("render", GENERIC)
    for text in (action_section([error]), *cli_lines([error])):
        assert text.rstrip("\n").endswith(GENERIC)
        assert message in GENERIC or message not in text  # the bare text is part of GENERIC


def test_planted_values_never_reach_either_output() -> None:
    errors = [
        InternalError(PLANTED, PLANTED),
        internal_error(ComponentError(f"checker:{CHECKER_IDS[0]}", PLANTED)),
    ]
    for text in (action_section(errors), *cli_lines(errors)):
        assert PLANTED not in text
        for part in PLANTED.split():
            assert part not in text


def test_the_component_pattern_is_the_one_core_uses() -> None:
    assert fallback._COMPONENT.pattern == core._COMPONENT.pattern


HOSTILE = ["a\nb", "a`b", "@x", "::warning::boom", "x\n::warning::y", "`@x`\n", "\n## owned"]


@pytest.mark.parametrize("hostile", HOSTILE)
def test_hostile_text_is_replaced_in_the_summary_and_on_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], hostile: str
) -> None:
    # I-14 "Fallback writer details" 3 and 4, for both writers and for both fields.
    errors = [
        InternalError(hostile, hostile),
        InternalError(hostile, _error().message),
        InternalError("render", hostile),
        InternalError(hostile + "x", f"{hostile}: {WITHHELD}"),
    ]
    summary = tmp_path / "s.md"
    write_internal_errors(errors, entry="action", env={SUMMARY_ENV: str(summary)})
    cli = io.StringIO()
    write_internal_errors(errors, entry="cli", env={}, stderr=cli)

    replaced = [
        InternalError("core", GENERIC),
        InternalError("core", _error().message),
        InternalError("render", GENERIC),
        InternalError("core", GENERIC),
    ]
    assert summary.read_text(encoding="utf-8") == action_section(replaced)
    assert cli.getvalue().splitlines() == cli_lines(replaced)
    # Exactly the expected lines: nothing the hostile text added is a line of its own.
    assert len(summary.read_text(encoding="utf-8").splitlines()) == 2 + 2 * len(errors)
    assert len(cli.getvalue().splitlines()) == len(errors)
    for text in (summary.read_text(encoding="utf-8"), cli.getvalue()):
        for part in (hostile.strip(), *hostile.split("\n")):
            assert not part or part not in text or part in GENERIC
    assert capsys.readouterr() == ("", "")


def test_a_valid_component_is_the_only_thing_wrapped_in_md() -> None:
    line = f"Internal error in `checker:{CHECKER_IDS[0]}`: ComponentError: {WITHHELD}"
    assert action_section([_error(f"checker:{CHECKER_IDS[0]}")]).splitlines()[-1] == line
    assert action_section([_error()]).splitlines()[-1].endswith(f": ComponentError: {WITHHELD}")


# --- where it writes (A-8) ------------------------------------------------------------------


def test_action_appends_one_section_to_the_summary_and_writes_nothing_else(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "summary.md"
    summary.write_text("earlier step\n", encoding="utf-8")
    write_internal_errors([_error()], entry="action", env={SUMMARY_ENV: str(summary)})
    assert summary.read_text(encoding="utf-8") == "earlier step\n" + action_section([_error()])
    assert capsys.readouterr() == ("", "")
    assert [p.name for p in tmp_path.iterdir()] == ["summary.md"]


@pytest.mark.parametrize("env", [{}, {SUMMARY_ENV: ""}], ids=["unset", "empty"])
def test_action_without_a_summary_file_writes_the_stderr_lines_instead(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    env: dict[str, str],
) -> None:
    # I-14 "Fallback writer details" 2: never silent.
    monkeypatch.chdir(tmp_path)
    write_internal_errors([_error()], entry="action", env=env)
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "".join(line + "\n" for line in cli_lines([_error()]))
    assert list(tmp_path.iterdir()) == []


def test_action_creates_no_file_for_no_errors(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    write_internal_errors([], entry="action", env={SUMMARY_ENV: str(summary)})
    assert not summary.exists()


def test_cli_writes_to_stderr_only_and_leaves_the_summary_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # GITHUB_STEP_SUMMARY can be set when the CLI runs in CI (I-2 `entry`): it is not used.
    summary = tmp_path / "summary.md"
    write_internal_errors([_error()], entry="cli", env={SUMMARY_ENV: str(summary)})
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "".join(line + "\n" for line in cli_lines([_error()]))
    assert not summary.exists()


def test_cli_writes_to_a_given_stream_and_nothing_for_no_errors() -> None:
    stream = io.StringIO()
    write_internal_errors(
        [_error(), _error("core", "KeyError")], entry="cli", env={}, stderr=stream
    )
    assert stream.getvalue().splitlines() == cli_lines([_error(), _error("core", "KeyError")])
    empty = io.StringIO()
    write_internal_errors([], entry="cli", env={}, stderr=empty)
    assert empty.getvalue() == ""


# --- it never raises (I-14) -----------------------------------------------------------------


def test_an_unwritable_summary_writes_the_stderr_lines_instead(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The append raises OSError: a directory, and a path whose parent doesn't exist.
    expected = SUMMARY_REFUSED + "\n" + "".join(line + "\n" for line in cli_lines([_error()]))
    for bad in (tmp_path, tmp_path / "missing" / "s.md"):
        write_internal_errors([_error()], entry="action", env={SUMMARY_ENV: str(bad)})
        assert capsys.readouterr() == ("", expected)
    assert list(tmp_path.iterdir()) == []


def test_a_summary_that_works_leaves_stderr_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "s.md"
    stream = io.StringIO()
    write_internal_errors(
        [_error()], entry="action", env={SUMMARY_ENV: str(summary)}, stderr=stream
    )
    assert stream.getvalue() == ""
    assert capsys.readouterr() == ("", "")


def test_the_action_fallback_goes_to_a_given_stream() -> None:
    stream = io.StringIO()
    write_internal_errors([_error()], entry="action", env={}, stderr=stream)
    assert stream.getvalue().splitlines() == cli_lines([_error()])


def test_a_broken_stderr_is_swallowed() -> None:
    class Broken(io.StringIO):
        def write(self, s: str) -> int:
            raise OSError("closed")

    write_internal_errors([_error()], entry="cli", env={}, stderr=Broken())
    write_internal_errors([_error()], entry="action", env={}, stderr=Broken())


@pytest.mark.parametrize("entry", ["action", "cli"])
def test_keyboard_interrupt_propagates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entry: Literal["action", "cli"]
) -> None:
    def interrupted(_errors: object) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(fallback, "action_section", interrupted)
    monkeypatch.setattr(fallback, "cli_lines", interrupted)
    with pytest.raises(KeyboardInterrupt):
        write_internal_errors(
            [_error()], entry=entry, env={SUMMARY_ENV: str(tmp_path / "s.md")}, stderr=io.StringIO()
        )


# --- through run() (AC-F7.4 and AC-N4.2, the part that needs no pipeline) --------------------


class _Raises:
    """A stand-in pipeline that records ``fail-on`` and raises, like a failing component."""

    def __init__(self, exc: BaseException, fail_on: str) -> None:
        self.exc = exc
        self.fail_on = fail_on

    def __call__(
        self, argv: list[str], env: object, entry: str, components: Components, context: RunContext
    ) -> core.RunOutcome:
        context.explicit_fail_on = self.fail_on
        raise self.exc


def _run_action(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exc: BaseException,
    fail_on: str,
) -> tuple[int, str]:
    summary = tmp_path / "summary.md"
    monkeypatch.setattr(core, "_pipeline", _Raises(exc, fail_on))
    code = run([], {SUMMARY_ENV: str(summary)}, entry="action")
    return code, summary.read_text(encoding="utf-8") if summary.exists() else ""


@pytest.mark.parametrize(("fail_on", "expected"), [("none", 0), ("new-stale", 3), ("any-stale", 3)])
@pytest.mark.parametrize("checker", CHECKER_IDS)
def test_a_failing_checker_is_named_in_the_summary_under_every_fail_on(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    checker: CheckerId,
    fail_on: str,
    expected: int,
) -> None:
    # AC-F7.4: exit 0 under none, non-zero otherwise, and the section names the checker.
    code, text = _run_action(
        monkeypatch, tmp_path, ComponentError(f"checker:{checker}", PLANTED), fail_on
    )
    assert code == expected
    assert text == action_section(
        [InternalError(f"checker:{checker}", "ComponentError: " + WITHHELD)]
    )
    assert "Internal error" in text
    assert f"`checker:{checker}`" in text
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(("fail_on", "expected"), [("none", 0), ("new-stale", 3)])
def test_a_failure_during_reporting_gives_a_clean_section(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fail_on: str, expected: int
) -> None:
    # AC-N4.2: an error description, no stack trace, no file content, no token value.
    exc: Exception
    try:
        raise OSError(PLANTED)
    except OSError as cause:
        exc = ComponentError("render", PLANTED)
        exc.__cause__ = cause
        exc.add_note(PLANTED)
    code, text = _run_action(monkeypatch, tmp_path, exc, fail_on)
    assert code == expected
    assert f"Internal error in `render`: ComponentError: {WITHHELD}" in text
    assert "Traceback" not in text
    assert 'File "' not in text
    for part in PLANTED.split():
        assert part not in text


def test_errors_recorded_before_the_failure_are_written_with_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    earlier = _error(f"checker:{CHECKER_IDS[0]}")

    def pipeline(
        argv: list[str], env: object, entry: str, components: Components, context: RunContext
    ) -> core.RunOutcome:
        context.internal_errors = (earlier,)
        raise ComponentError("render", PLANTED)

    monkeypatch.setattr(core, "_pipeline", pipeline)
    summary = tmp_path / "s.md"
    assert run([], {SUMMARY_ENV: str(summary)}, entry="action") == 0
    assert summary.read_text(encoding="utf-8") == action_section(
        [earlier, _error("render", "ComponentError")]
    )


def test_cli_run_writes_stderr_lines_and_not_the_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(core, "_pipeline", _Raises(GitTooOld(), "none"))
    summary = tmp_path / "s.md"
    assert run([], {SUMMARY_ENV: str(summary)}, entry="cli") == 0
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "conventiondrift: internal error in gitread: git 2.30 or newer is required\n"
    assert not summary.exists()


@pytest.mark.parametrize("summary", [None, "", "dir"], ids=["unset", "empty", "unwritable"])
def test_a_missing_or_unwritable_summary_uses_stderr_and_keeps_the_exit_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    summary: str | None,
) -> None:
    env = {} if summary is None else {SUMMARY_ENV: str(tmp_path) if summary else ""}
    for fail_on, expected in (("none", 0), ("new-stale", 3), ("any-stale", 3)):
        monkeypatch.setattr(core, "_pipeline", _Raises(RuntimeError(PLANTED), fail_on))
        assert run([], env, entry="action") == expected
        out, err = capsys.readouterr()
        assert out == ""
        warning = SUMMARY_REFUSED + "\n" if summary else ""
        line = f"conventiondrift: internal error in core: RuntimeError: {WITHHELD}\n"
        assert err == warning + line
    assert list(tmp_path.iterdir()) == []


def test_a_run_without_an_error_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outcome = core.AnalysisOutcome(
        fail_on="none",
        head_only=False,
        new_stale_met=False,
        any_stale_met=False,
        internal_error=False,
    )
    summary = tmp_path / "s.md"
    called: list[object] = []
    monkeypatch.setattr(core, "write_internal_errors", lambda *a, **k: called.append(a))
    monkeypatch.setattr(core, "_pipeline", lambda *a: outcome)
    assert run([], {SUMMARY_ENV: str(summary)}, entry="action") == 0
    assert called == []
    assert not summary.exists()
    assert capsys.readouterr() == ("", "")


# --- static checks (A-8, AC-N3.15) -----------------------------------------------------------


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
    return found


def test_fallback_imports_nothing_from_render_except_escape() -> None:
    # A-8: "It imports nothing from `render` except `render/escape.py`."
    imports = _imports(SRC / "fallback.py")
    render = {name for name in imports if name.startswith("conventiondrift.render")}
    assert render == {"conventiondrift.render.escape"}
    assert not any(
        name in ("conventiondrift.core", "conventiondrift.components") for name in imports
    )


def test_the_scanner_sees_a_planted_render_import(tmp_path: Path) -> None:
    planted = tmp_path / "x.py"
    planted.write_text("from conventiondrift.render.comment import x\nimport os\n")
    assert _imports(planted) == {"conventiondrift.render.comment", "os"}


def test_no_fault_injection_identifiers_are_shipped() -> None:
    # I-2: the test-only fault code is `conventiondrift_testkit` with `InjectedFault` and
    # `FaultyComponent`; none may appear in src (AC-N3.15, the part that is in this repo).
    names: Callable[[Path], bool] = lambda p: any(  # noqa: E731
        word in p.read_text(encoding="utf-8")
        for word in ("conventiondrift_testkit", "InjectedFault", "FaultyComponent")
    )
    assert not [p for p in SRC.rglob("*.py") if "_vendor" not in p.parts and names(p)]
    # The scan is not vacuous: this very test file names them.
    assert names(Path(__file__))


# --- the summary file check (SR ruling on T-006b) --------------------------------------------


def _fallback_output(errors: list[InternalError] | None = None) -> str:
    errors = [_error()] if errors is None else errors
    return SUMMARY_REFUSED + "\n" + "".join(line + "\n" for line in cli_lines(errors))


def _refused(path: Path | str) -> str:
    stream = io.StringIO()
    write_internal_errors([_error()], entry="action", env={SUMMARY_ENV: str(path)}, stderr=stream)
    return stream.getvalue()


def test_the_open_flags_append_create_and_refuse_links_where_possible() -> None:
    required = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    assert SUMMARY_OPEN_FLAGS & required == required
    for name in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_BINARY"):
        flag = getattr(os, name, 0)
        assert SUMMARY_OPEN_FLAGS & flag == flag, name
    for name in ("O_TRUNC", "O_EXCL", "O_RDWR"):
        assert not SUMMARY_OPEN_FLAGS & getattr(os, name, 0), name


def test_a_missing_summary_file_is_still_created_as_a_regular_file(tmp_path: Path) -> None:
    summary = tmp_path / "new.md"
    stream = io.StringIO()
    write_internal_errors(
        [_error()], entry="action", env={SUMMARY_ENV: str(summary)}, stderr=stream
    )
    assert stream.getvalue() == ""
    assert stat.S_ISREG(summary.lstat().st_mode)
    assert summary.read_text(encoding="utf-8") == action_section([_error()])


@pytest.mark.skipif(not getattr(os, "O_NOFOLLOW", 0), reason="no O_NOFOLLOW on this platform")
def test_a_symlink_to_a_regular_file_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text("kept\n", encoding="utf-8")
    link = tmp_path / "summary.md"
    try:
        link.symlink_to(target)
    except OSError:  # pragma: no cover - symlinks not allowed here
        pytest.skip("symlinks are not available")
    assert _refused(link) == _fallback_output()
    assert target.read_text(encoding="utf-8") == "kept\n"


FIFO_OPEN_LIMIT = 30.0
"""Seconds the no-reader FIFO open may take before the test calls it a hang (no clock read)."""


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_a_fifo_is_refused_with_or_without_a_reader(tmp_path: Path) -> None:
    fifo = tmp_path / "summary.md"
    os.mkfifo(fifo)
    # No reader: the non-blocking open fails, so nothing waits on the pipe. It runs in a daemon
    # thread joined with a timeout, so a lost O_NONBLOCK fails here instead of hanging CI.
    outputs: list[str] = []
    worker = threading.Thread(target=lambda: outputs.append(_refused(fifo)), daemon=True)
    worker.start()
    worker.join(timeout=FIFO_OPEN_LIMIT)
    if worker.is_alive():
        pytest.fail(
            f"opening a FIFO with no reader blocked for {FIFO_OPEN_LIMIT} s: "
            "SUMMARY_OPEN_FLAGS must keep O_NONBLOCK"
        )
    assert outputs == [_fallback_output()]
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    try:
        # A reader: the open works and the regular-file check refuses it.
        assert _refused(fifo) == _fallback_output()
        assert os.read(reader, 1) == b""  # nothing was written, and the writer is closed
    finally:
        os.close(reader)


def test_a_directory_is_refused(tmp_path: Path) -> None:
    assert _refused(tmp_path) == _fallback_output()


class _Spy:
    """Records the fds ``os.open`` returns and ``os.close`` closes, as ``fallback`` sees them."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.opened: list[int] = []
        self.closed: list[int] = []
        real_open, real_close = os.open, os.close

        def opening(path: str, flags: int, mode: int = 0o777) -> int:
            fd = real_open(path, flags, mode)
            self.opened.append(fd)
            return fd

        def closing(fd: int) -> None:
            self.closed.append(fd)
            real_close(fd)

        monkeypatch.setattr(os, "open", opening)
        monkeypatch.setattr(os, "close", closing)


def _not_regular_modes() -> Iterator[int]:
    for name in ("S_IFDIR", "S_IFIFO", "S_IFCHR", "S_IFBLK", "S_IFSOCK", "S_IFLNK"):
        mode = getattr(stat, name, 0)
        if mode and not stat.S_ISREG(mode):
            yield mode | 0o644


@pytest.mark.parametrize("mode", list(_not_regular_modes()))
def test_a_file_that_fstat_says_is_not_regular_is_refused_and_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: int
) -> None:
    summary = tmp_path / "summary.md"
    summary.write_bytes(b"")
    spy = _Spy(monkeypatch)
    real_fstat = os.fstat

    def faked(fd: int) -> os.stat_result:
        real = real_fstat(fd)
        # Only the summary's fd is faked; pytest's own capture also calls fstat.
        return os.stat_result((mode, *real[1:])) if fd in spy.opened else real

    monkeypatch.setattr(os, "fstat", faked)
    assert _refused(summary) == _fallback_output()
    assert spy.opened and spy.closed == spy.opened
    assert summary.read_bytes() == b""


def test_an_fstat_error_is_refused_and_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    summary = tmp_path / "summary.md"
    spy = _Spy(monkeypatch)

    real_fstat = os.fstat

    def failing(fd: int) -> os.stat_result:
        # Only the summary's fd fails; pytest's own capture also calls fstat.
        if fd in spy.opened:
            raise OSError(f"fstat failed for {summary}")
        return real_fstat(fd)

    monkeypatch.setattr(os, "fstat", failing)
    out = _refused(summary)
    assert out == _fallback_output()
    assert str(summary) not in out
    assert spy.opened and spy.closed == spy.opened


@pytest.mark.parametrize("errno_name", ["ELOOP", "EACCES", "ENXIO", "EISDIR"])
def test_an_open_error_gives_a_warning_without_the_path_or_the_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, errno_name: str
) -> None:
    import errno as errno_module

    summary = tmp_path / f"{PLANTED.split()[0]}.md"
    text = f"{errno_name}: {os.strerror(getattr(errno_module, errno_name))} {summary}"

    def failing(path: str, flags: int, mode: int = 0o777) -> int:
        assert flags == SUMMARY_OPEN_FLAGS
        raise OSError(getattr(errno_module, errno_name), text, str(summary))

    monkeypatch.setattr(os, "open", failing)
    out = _refused(summary)
    assert out == _fallback_output()
    for part in (str(summary), summary.name, text, os.strerror(getattr(errno_module, errno_name))):
        assert part not in out
    assert not summary.exists()


@pytest.mark.parametrize("error", [OSError, ValueError])
def test_a_write_error_after_the_checks_falls_back_and_closes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: type[Exception]
) -> None:
    summary = tmp_path / "summary.md"
    closed: list[bool] = []
    real_fdopen = os.fdopen

    class Failing:
        def __init__(self, fd: int, mode: str) -> None:
            self.file = real_fdopen(fd, mode)

        def __enter__(self) -> "Failing":
            return self

        def __exit__(self, *exc: object) -> None:
            self.file.close()
            closed.append(self.file.closed)

        def write(self, data: bytes) -> int:
            raise error(f"no space left for {summary}")

    monkeypatch.setattr(os, "fdopen", Failing)
    out = _refused(summary)
    assert out == _fallback_output()
    assert str(summary) not in out
    assert closed == [True]


def test_the_warning_names_no_path_and_comes_once_before_the_lines(tmp_path: Path) -> None:
    errors = [_error(), _error(f"checker:{CHECKER_IDS[0]}")]
    stream = io.StringIO()
    write_internal_errors(errors, entry="action", env={SUMMARY_ENV: str(tmp_path)}, stderr=stream)
    lines = stream.getvalue().splitlines()
    assert lines == [SUMMARY_REFUSED, *cli_lines(errors)]
    assert str(tmp_path) not in SUMMARY_REFUSED
    assert SUMMARY_ENV not in SUMMARY_REFUSED


def test_the_cli_never_warns_about_the_summary(tmp_path: Path) -> None:
    stream = io.StringIO()
    write_internal_errors([_error()], entry="cli", env={SUMMARY_ENV: str(tmp_path)}, stderr=stream)
    assert SUMMARY_REFUSED not in stream.getvalue()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_created_summary_file_gets_the_same_mode_as_before(tmp_path: Path) -> None:
    # open(path, "ab") created files with mode 0o666 less the umask; so does os.open here.
    summary = tmp_path / "new.md"
    old = os.umask(0)
    try:
        write_internal_errors([_error()], entry="action", env={SUMMARY_ENV: str(summary)})
    finally:
        os.umask(old)
    assert stat.S_IMODE(summary.stat().st_mode) == 0o666


# --- without O_NOFOLLOW: the lstat check before the open (SR ruling for Windows) ------------


@pytest.fixture
def no_nofollow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take the platform's ``O_NOFOLLOW`` out of the open flags, as on Windows."""
    monkeypatch.setattr(fallback, "SUMMARY_OPEN_FLAGS", SUMMARY_OPEN_FLAGS & ~fallback._NOFOLLOW)
    monkeypatch.setattr(fallback, "_NOFOLLOW", 0)


class _LstatSpy:
    """Records ``os.lstat`` calls on one path and can fake their result; other paths are real."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        path: Path,
        result: object = None,
        error: OSError | None = None,
    ) -> None:
        self.calls: list[str] = []
        real_lstat = os.lstat

        def lstat(target: str) -> object:
            if str(target) != str(path):
                return real_lstat(target)
            self.calls.append(str(target))
            if error is not None:
                raise error
            return real_lstat(target) if result is None else result

        monkeypatch.setattr(os, "lstat", lstat)


def _fake_lstat(attributes: int) -> object:
    class Result:
        st_mode = stat.S_IFREG | 0o644
        st_file_attributes = attributes

    return Result()


def test_the_reparse_point_bit_is_the_windows_one() -> None:
    assert fallback._REPARSE_POINT == stat.FILE_ATTRIBUTE_REPARSE_POINT == 0x400
    assert fallback._NOFOLLOW == getattr(os, "O_NOFOLLOW", 0)


@pytest.mark.skipif(not getattr(os, "O_NOFOLLOW", 0), reason="no O_NOFOLLOW on this platform")
def test_with_o_nofollow_there_is_no_lstat_before_the_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    summary = tmp_path / "summary.md"
    spy = _LstatSpy(monkeypatch, summary)
    assert _refused(summary) == ""
    assert spy.calls == []


@pytest.mark.usefixtures("no_nofollow")
@pytest.mark.parametrize("target_exists", [True, False], ids=["target", "dangling"])
def test_without_o_nofollow_a_symlink_is_refused_before_the_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, target_exists: bool
) -> None:
    target = tmp_path / "target.md"
    if target_exists:
        target.write_text("kept\n", encoding="utf-8")
    link = tmp_path / "summary.md"
    try:
        link.symlink_to(target)
    except OSError:  # pragma: no cover - symlinks not allowed here
        pytest.skip("symlinks are not available")
    lstat_spy = _LstatSpy(monkeypatch, link)
    spy = _Spy(monkeypatch)
    assert _refused(link) == _fallback_output()
    assert lstat_spy.calls == [str(link)]
    assert spy.opened == []
    if target_exists:
        assert target.read_text(encoding="utf-8") == "kept\n"
    else:
        assert not target.exists()


@pytest.mark.usefixtures("no_nofollow")
def test_without_o_nofollow_a_reparse_point_is_refused_before_the_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    summary = tmp_path / "summary.md"
    summary.write_bytes(b"")
    _LstatSpy(monkeypatch, summary, result=_fake_lstat(fallback._REPARSE_POINT))
    spy = _Spy(monkeypatch)
    assert _refused(summary) == _fallback_output()
    assert spy.opened == []
    assert summary.read_bytes() == b""


@pytest.mark.usefixtures("no_nofollow")
def test_without_o_nofollow_other_file_attributes_still_append(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    summary = tmp_path / "summary.md"
    summary.write_text("before\n", encoding="utf-8")
    others = ~fallback._REPARSE_POINT & 0xFFFF
    spy = _LstatSpy(monkeypatch, summary, result=_fake_lstat(others))
    assert _refused(summary) == ""
    assert spy.calls == [str(summary)]
    assert summary.read_text(encoding="utf-8") == "before\n" + action_section([_error()])


@pytest.mark.usefixtures("no_nofollow")
def test_without_o_nofollow_a_regular_file_is_still_appended(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    summary = tmp_path / "summary.md"
    summary.write_text("before\n", encoding="utf-8")
    spy = _LstatSpy(monkeypatch, summary)
    assert _refused(summary) == ""
    assert spy.calls == [str(summary)]
    assert summary.read_text(encoding="utf-8") == "before\n" + action_section([_error()])


@pytest.mark.usefixtures("no_nofollow")
def test_without_o_nofollow_a_missing_file_is_still_created(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    summary = tmp_path / "new.md"
    spy = _LstatSpy(monkeypatch, summary)
    assert _refused(summary) == ""
    assert spy.calls == [str(summary)]
    assert stat.S_ISREG(summary.lstat().st_mode)
    assert summary.read_text(encoding="utf-8") == action_section([_error()])


@pytest.mark.usefixtures("no_nofollow")
@pytest.mark.parametrize("errno_name", ["EACCES", "ELOOP", "ENAMETOOLONG", "ENOTDIR"])
def test_without_o_nofollow_an_lstat_error_refuses_without_the_path_or_the_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, errno_name: str
) -> None:
    import errno as errno_module

    code = getattr(errno_module, errno_name)
    summary = tmp_path / f"{PLANTED.split()[0]}.md"
    text = f"{errno_name}: {os.strerror(code)} {summary}"
    _LstatSpy(monkeypatch, summary, error=OSError(code, text, str(summary)))
    spy = _Spy(monkeypatch)
    out = _refused(summary)
    assert out == _fallback_output()
    for part in (str(summary), summary.name, text, os.strerror(code)):
        assert part not in out
    assert spy.opened == []
    assert not summary.exists()


@pytest.mark.usefixtures("no_nofollow")
@pytest.mark.parametrize("mode", [stat.S_IFDIR | 0o755, stat.S_IFIFO | 0o644])
def test_without_o_nofollow_fstat_still_refuses_a_non_regular_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: int
) -> None:
    summary = tmp_path / "summary.md"
    summary.write_bytes(b"")
    lstat_spy = _LstatSpy(monkeypatch, summary)
    spy = _Spy(monkeypatch)
    real_fstat = os.fstat

    def faked(fd: int) -> os.stat_result:
        real = real_fstat(fd)
        return os.stat_result((mode, *real[1:])) if fd in spy.opened else real

    monkeypatch.setattr(os, "fstat", faked)
    assert _refused(summary) == _fallback_output()
    assert lstat_spy.calls == [str(summary)]
    assert spy.opened and spy.closed == spy.opened
    assert summary.read_bytes() == b""


@pytest.mark.usefixtures("no_nofollow")
def test_without_o_nofollow_a_real_directory_is_refused(tmp_path: Path) -> None:
    assert _refused(tmp_path) == _fallback_output()


# --- review follow-ups: NUL in the path, a read-only file, symlinks on Windows CI -------------


def _nul_path(tmp_path: Path) -> str:
    return str(tmp_path / f"{PLANTED.split()[0]}\x00.md")


def _assert_refused_quietly(out: str, path: str, error: Exception) -> None:
    assert out == _fallback_output()
    for part in (path, path.replace("\x00", ""), Path(path).name, str(error)):
        assert part not in out


def _nul_error(path: str) -> ValueError:
    """The error ``os`` raises for this path, read from ``os`` itself rather than written here."""
    with pytest.raises(ValueError) as caught:
        os.lstat(path)
    return caught.value


def test_a_nul_byte_in_the_path_refuses_with_the_warning(tmp_path: Path) -> None:
    path = _nul_path(tmp_path)
    _assert_refused_quietly(_refused(path), path, _nul_error(path))
    assert list(tmp_path.iterdir()) == []


@pytest.mark.usefixtures("no_nofollow")
def test_without_o_nofollow_a_nul_byte_in_the_path_refuses_before_the_open(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _nul_path(tmp_path)
    error = _nul_error(path)
    spy = _Spy(monkeypatch)
    _assert_refused_quietly(_refused(path), path, error)
    assert spy.opened == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("nofollow", [True, False], ids=["o_nofollow", "lstat"])
def test_a_value_error_from_open_refuses_with_the_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, nofollow: bool
) -> None:
    if not nofollow:
        monkeypatch.setattr(
            fallback, "SUMMARY_OPEN_FLAGS", SUMMARY_OPEN_FLAGS & ~fallback._NOFOLLOW
        )
        monkeypatch.setattr(fallback, "_NOFOLLOW", 0)
    summary = tmp_path / "summary.md"
    error = ValueError(f"bad path {summary}")

    def failing(path: str, flags: int, mode: int = 0o777) -> int:
        assert flags == fallback.SUMMARY_OPEN_FLAGS
        raise error

    monkeypatch.setattr(os, "open", failing)
    _assert_refused_quietly(_refused(summary), str(summary), error)
    assert not summary.exists()


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="POSIX permission bits; root can write a read-only file",
)
def test_a_read_only_summary_file_is_refused_and_left_unchanged(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    summary.write_bytes(b"before\n")
    summary.chmod(0o444)
    try:
        out = _refused(summary)
    finally:
        summary.chmod(0o644)
    assert out == _fallback_output()
    assert str(summary) not in out
    assert summary.read_bytes() == b"before\n"


@pytest.mark.skipif(
    not (os.environ.get("CI") and sys.platform == "win32"),
    reason="Windows CI only: the real-symlink tests must not skip there",
)
def test_symlinks_can_be_created_on_windows_ci(tmp_path: Path) -> None:
    # The real-symlink tests skip when symlinks can't be made; on Windows CI that would hide
    # the lstat check, so there it must work.
    target = tmp_path / "target.md"
    target.write_text("kept\n", encoding="utf-8")
    link = tmp_path / "summary.md"
    link.symlink_to(target)
    assert link.is_symlink()
