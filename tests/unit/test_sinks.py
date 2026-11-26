"""Unit tests for the production output sinks in conventiondrift.sinks (CON-73, I-2).

The file rules come from SR's ruling on T-006b (the summary writer): no symlink, regular files
only, append, never inherit the descriptor. The tests exercise both platform shapes — with
``O_NOFOLLOW`` and the ``lstat`` fallback Windows takes — by injecting the flags through
``EnvSinks`` exactly as ``fallback`` does.
"""

from __future__ import annotations

import io
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, get_args, get_type_hints

import pytest

from conventiondrift import sinks
from conventiondrift.components import Outputs, SinkStatus
from conventiondrift.sinks import (
    ARTIFACT_DIR,
    NOFOLLOW,
    OUTPUT_ENV,
    OUTPUT_NAMES,
    SUMMARY_ENV,
    SUMMARY_OPEN_FLAGS,
    TEMP_ENV,
    ActionSinks,
    EnvSinks,
)

POSIX = os.name != "nt"
OUTPUTS = Outputs(
    stale_count=3,
    new_stale_count=1,
    report_path="/runner-temp/conventiondrift/report.json",
    sarif_path="",
)


def _parse_output_file(text: str) -> dict[str, str]:
    """GitHub's heredoc output format, enough to prove exactly four entries survive injection."""
    lines = text.splitlines()
    parsed: dict[str, str] = {}
    index = 0
    while index < len(lines):
        header = lines[index]
        index += 1
        if "<<" not in header:
            continue
        name, delimiter = header.split("<<", 1)
        block: list[str] = []
        while index < len(lines) and lines[index] != delimiter:
            block.append(lines[index])
            index += 1
        parsed[name] = "\n".join(block)
    return parsed


def _summary(env: dict[str, str], path: Path) -> EnvSinks:
    env[SUMMARY_ENV] = str(path)
    return EnvSinks(env)


# --- constants ------------------------------------------------------------------------


def test_the_four_output_names_are_the_pinned_ones() -> None:
    assert OUTPUT_NAMES == ("stale-count", "new-stale-count", "report-path", "sarif-path")
    assert isinstance(OUTPUT_NAMES, tuple)


def test_the_summary_flags_keep_their_security_properties() -> None:
    required = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    assert SUMMARY_OPEN_FLAGS & required == required
    assert SUMMARY_OPEN_FLAGS & NOFOLLOW == NOFOLLOW


def test_environment_names_are_the_github_ones() -> None:
    assert (SUMMARY_ENV, OUTPUT_ENV, TEMP_ENV) == (
        "GITHUB_STEP_SUMMARY",
        "GITHUB_OUTPUT",
        "RUNNER_TEMP",
    )
    assert ARTIFACT_DIR == "conventiondrift"


# --- outputs --------------------------------------------------------------------------


def test_outputs_write_exactly_four_entries(tmp_path: Path) -> None:
    path = tmp_path / "outputs"
    sink = EnvSinks({OUTPUT_ENV: str(path)})
    assert sink.outputs(OUTPUTS) == "written"
    entries = _parse_output_file(path.read_text(encoding="utf-8"))
    assert tuple(entries) == OUTPUT_NAMES
    assert entries == {
        "stale-count": "3",
        "new-stale-count": "1",
        "report-path": "/runner-temp/conventiondrift/report.json",
        "sarif-path": "",
    }


def test_outputs_append_across_calls(tmp_path: Path) -> None:
    path = tmp_path / "outputs"
    sink = EnvSinks({OUTPUT_ENV: str(path)})
    assert sink.outputs(OUTPUTS) == "written"
    assert sink.outputs(OUTPUTS) == "written"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert sum(1 for line in lines if line.startswith("stale-count<<")) == 2


def test_a_hostile_path_cannot_add_an_output_entry(tmp_path: Path) -> None:
    path = tmp_path / "outputs"
    hostile = "1\nghadelimiter_x\nsarif-path<<EOF\nevil\nEOF\n"
    sink = EnvSinks({OUTPUT_ENV: str(path)})
    outputs = Outputs(stale_count=0, new_stale_count=0, report_path=hostile, sarif_path="")
    assert sink.outputs(outputs) == "written"
    entries = _parse_output_file(path.read_text(encoding="utf-8"))
    assert tuple(entries) == OUTPUT_NAMES
    assert "evil" not in entries


def test_outputs_refuse_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.out"
    target.write_text("kept\n", encoding="utf-8")
    link = tmp_path / "outputs"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert EnvSinks({OUTPUT_ENV: str(link)}).outputs(OUTPUTS) == "refused"
    assert target.read_text(encoding="utf-8") == "kept\n"


def test_outputs_are_unavailable_without_the_variable() -> None:
    assert EnvSinks({}).outputs(OUTPUTS) == "unavailable"
    assert EnvSinks({OUTPUT_ENV: ""}).outputs(OUTPUTS) == "unavailable"


def test_outputs_are_refused_when_the_escape_cannot_make_a_delimiter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_delimiter(name: str, value: str) -> str:
        raise ValueError("no heredoc delimiter absent from the value")

    monkeypatch.setattr(sinks, "output_heredoc", no_delimiter)
    path = tmp_path / "outputs"
    assert EnvSinks({OUTPUT_ENV: str(path)}).outputs(OUTPUTS) == "refused"
    assert not path.exists()


# --- summary_section ------------------------------------------------------------------


def test_summary_sections_are_appended_as_utf8(tmp_path: Path) -> None:
    path = tmp_path / "summary.md"
    sink = _summary({}, path)
    assert sink.summary_section("## one\n") == "written"
    assert sink.summary_section("## two — ünïcode\n") == "written"
    assert path.read_text(encoding="utf-8") == "## one\n## two — ünïcode\n"


def test_a_new_summary_file_gets_the_same_mode_as_before(tmp_path: Path) -> None:
    if not POSIX:
        pytest.skip("POSIX permission bits")
    path = tmp_path / "new.md"
    old = os.umask(0)
    try:
        assert _summary({}, path).summary_section("x\n") == "written"
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o666


def test_summary_is_unavailable_without_the_variable() -> None:
    assert EnvSinks({}).summary_section("x\n") == "unavailable"
    assert EnvSinks({SUMMARY_ENV: ""}).summary_section("x\n") == "unavailable"


def test_summary_refuses_a_symlink_and_leaves_the_target_alone(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text("kept\n", encoding="utf-8")
    link = tmp_path / "summary.md"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert _summary({}, link).summary_section("x\n") == "refused"
    assert target.read_text(encoding="utf-8") == "kept\n"


def test_summary_refuses_a_directory(tmp_path: Path) -> None:
    directory = tmp_path / "summary.md"
    directory.mkdir()
    assert _summary({}, directory).summary_section("x\n") == "refused"


def test_summary_refuses_a_path_with_a_nul_byte(tmp_path: Path) -> None:
    path = str(tmp_path / "summary.md") + "\0x"
    assert EnvSinks({SUMMARY_ENV: path}).summary_section("x\n") == "refused"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
def test_summary_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "summary.md"
    os.mkfifo(fifo)
    assert _summary({}, fifo).summary_section("x\n") == "refused"


def test_summary_refuses_when_the_open_raises_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_open(path: str, flags: int, mode: int = 0o777) -> int:
        raise ValueError("bad path")

    monkeypatch.setattr(os, "open", failing_open)
    assert _summary({}, tmp_path / "summary.md").summary_section("x\n") == "refused"


def test_summary_refuses_when_fstat_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[int] = []
    real_open = os.open
    real_fstat = os.fstat

    def opening(path: str, flags: int, mode: int = 0o777) -> int:
        fd = real_open(path, flags, mode)
        opened.append(fd)
        return fd

    def failing_fstat(fd: int) -> os.stat_result:
        # Only the sink's own fd fails; pytest's capture also calls fstat.
        if fd in opened:
            raise OSError("gone")
        return real_fstat(fd)

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "fstat", failing_fstat)
    assert _summary({}, tmp_path / "summary.md").summary_section("x\n") == "refused"


def test_summary_refuses_when_the_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_fdopen(fd: int, mode: str) -> object:
        os.close(fd)
        raise OSError("disk full")

    monkeypatch.setattr(os, "fdopen", failing_fdopen)
    assert _summary({}, tmp_path / "summary.md").summary_section("x\n") == "refused"


# --- the lstat branch (a platform without O_NOFOLLOW, as on Windows) --------------------


def test_without_o_nofollow_the_flags_still_open_a_regular_file(tmp_path: Path) -> None:
    path = tmp_path / "summary.md"
    env = {SUMMARY_ENV: str(path)}
    sink = EnvSinks(env, open_flags=SUMMARY_OPEN_FLAGS & ~NOFOLLOW, nofollow=0)
    assert sink.summary_section("x\n") == "written"
    assert path.read_text(encoding="utf-8") == "x\n"


def test_without_o_nofollow_a_missing_file_is_still_created(tmp_path: Path) -> None:
    path = tmp_path / "missing" / "summary.md"
    path.parent.mkdir()
    sink = EnvSinks({SUMMARY_ENV: str(path)}, open_flags=SUMMARY_OPEN_FLAGS & ~NOFOLLOW, nofollow=0)
    assert sink.summary_section("x\n") == "written"
    assert path.exists()


def test_without_o_nofollow_a_symlink_is_refused_before_the_open(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text("kept\n", encoding="utf-8")
    link = tmp_path / "summary.md"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    sink = EnvSinks({SUMMARY_ENV: str(link)}, open_flags=SUMMARY_OPEN_FLAGS & ~NOFOLLOW, nofollow=0)
    assert sink.summary_section("x\n") == "refused"
    assert target.read_text(encoding="utf-8") == "kept\n"


class _FakeStat:
    """The only two attributes ``_no_link_before_open`` reads, with a Windows reparse point."""

    def __init__(self, mode: int, attributes: int) -> None:
        self.st_mode = mode
        self.st_file_attributes = attributes


def test_without_o_nofollow_a_reparse_point_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "summary.md"
    path.write_text("kept\n", encoding="utf-8")

    def fake_lstat(target: str) -> _FakeStat:
        return _FakeStat(stat.S_IFREG, sinks.REPARSE_POINT)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    sink = EnvSinks({SUMMARY_ENV: str(path)}, open_flags=SUMMARY_OPEN_FLAGS & ~NOFOLLOW, nofollow=0)
    assert sink.summary_section("x\n") == "refused"
    assert path.read_text(encoding="utf-8") == "kept\n"


def test_without_o_nofollow_a_plain_file_is_not_a_reparse_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "summary.md"

    def fake_lstat(target: str) -> _FakeStat:
        return _FakeStat(stat.S_IFREG, 0)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    sink = EnvSinks({SUMMARY_ENV: str(path)}, open_flags=SUMMARY_OPEN_FLAGS & ~NOFOLLOW, nofollow=0)
    assert sink.summary_section("x\n") == "written"


def test_without_o_nofollow_an_lstat_error_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_lstat(target: str) -> os.stat_result:
        raise OSError("denied")

    monkeypatch.setattr(os, "lstat", failing_lstat)
    sink = EnvSinks(
        {SUMMARY_ENV: str(tmp_path / "s.md")},
        open_flags=SUMMARY_OPEN_FLAGS & ~NOFOLLOW,
        nofollow=0,
    )
    assert sink.summary_section("x\n") == "refused"


# --- annotations ----------------------------------------------------------------------


class _FailingStream:
    """A binary stream whose write fails."""

    def write(self, data: bytes) -> int:
        raise OSError("closed")

    def flush(self) -> None:
        raise OSError("closed")


class _TextOnlyStdout:
    """A stdout without a ``buffer`` (some capture plugins), recording the text it gets."""

    def __init__(self, fail: bool = False) -> None:
        self.written: list[str] = []
        self._fail = fail

    def write(self, text: str) -> int:
        if self._fail:
            raise OSError("closed")
        self.written.append(text)
        return len(text)

    def flush(self) -> None:
        if self._fail:
            raise OSError("closed")


def test_annotations_write_each_line_as_utf8_bytes() -> None:
    stream = io.BytesIO()
    sink = EnvSinks({}, stdout=stream)
    assert sink.annotations(("::warning file=a.py,line=1::stale — ünïcode", "::error::x")) == (
        "written"
    )
    assert stream.getvalue().decode("utf-8") == (
        "::warning file=a.py,line=1::stale — ünïcode\n::error::x\n"
    )


def test_no_annotations_writes_nothing() -> None:
    stream = io.BytesIO()
    assert EnvSinks({}, stdout=stream).annotations(()) == "written"
    assert stream.getvalue() == b""


def test_annotations_are_refused_when_the_stream_fails() -> None:
    assert EnvSinks({}, stdout=_FailingStream()).annotations(("::error::x",)) == "refused"  # type: ignore[arg-type]


def test_annotations_fall_back_to_a_text_only_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    stdout = _TextOnlyStdout()
    monkeypatch.setattr(sys, "stdout", stdout)
    assert EnvSinks({}).annotations(("::error::x",)) == "written"
    assert stdout.written == ["::error::x\n"]


def test_annotations_are_refused_when_the_text_stdout_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdout", _TextOnlyStdout(fail=True))
    assert EnvSinks({}).annotations(("::error::x",)) == "refused"


def test_the_injected_stream_is_a_binary_stream() -> None:
    """CON-73: the annotations stream is pinned to BinaryIO, so encoding can never raise."""
    hints = get_type_hints(EnvSinks.__init__)
    assert hints["stdout"] == BinaryIO | None
    assert hints["open_flags"] == int | None and hints["nofollow"] == int | None


def test_the_default_stream_is_stdouts_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = io.BytesIO()

    class WithBuffer(io.StringIO):
        buffer = stream

    monkeypatch.setattr(sys, "stdout", WithBuffer())
    assert EnvSinks({}).annotations(("::error::x",)) == "written"
    assert stream.getvalue() == b"::error::x\n"


# --- artifact -------------------------------------------------------------------------


def _temp(tmp_path: Path) -> Path:
    root = tmp_path / "runner-temp"
    root.mkdir()
    return root


def test_artifact_writes_under_runner_temp(tmp_path: Path) -> None:
    root = _temp(tmp_path)
    sink = EnvSinks({TEMP_ENV: str(root)})
    path = sink.artifact(name="report.json", data=b"{}")
    assert path == root / ARTIFACT_DIR / "report.json"
    assert path is not None and path.read_bytes() == b"{}"


def test_artifact_directory_and_file_modes(tmp_path: Path) -> None:
    if not POSIX:
        pytest.skip("POSIX permission bits")
    root = _temp(tmp_path)
    path = EnvSinks({TEMP_ENV: str(root)}).artifact(name="results.sarif", data=b"x")
    assert path is not None
    assert stat.S_IMODE((root / ARTIFACT_DIR).stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_artifact_overwrites_an_existing_file(tmp_path: Path) -> None:
    root = _temp(tmp_path)
    sink = EnvSinks({TEMP_ENV: str(root)})
    assert sink.artifact(name="report.json", data=b"one") is not None
    path = sink.artifact(name="report.json", data=b"two")
    assert path is not None and path.read_bytes() == b"two"


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b", "/abs", "Upper", "-x", "a" * 65])
def test_an_unsafe_artifact_name_is_refused(tmp_path: Path, name: str) -> None:
    root = _temp(tmp_path)
    assert EnvSinks({TEMP_ENV: str(root)}).artifact(name=name, data=b"x") is None
    assert not (root / ARTIFACT_DIR).exists()


def test_artifacts_are_unavailable_without_runner_temp() -> None:
    assert EnvSinks({}).artifact(name="report.json", data=b"x") is None
    assert EnvSinks({TEMP_ENV: ""}).artifact(name="report.json", data=b"x") is None


def test_artifact_refuses_a_missing_temp_directory(tmp_path: Path) -> None:
    sink = EnvSinks({TEMP_ENV: str(tmp_path / "missing")})
    assert sink.artifact(name="report.json", data=b"x") is None


def test_artifact_refuses_a_temp_path_with_a_nul_byte(tmp_path: Path) -> None:
    sink = EnvSinks({TEMP_ENV: str(tmp_path) + "\0x"})
    assert sink.artifact(name="report.json", data=b"x") is None


def test_artifact_refuses_when_the_directory_name_is_a_file(tmp_path: Path) -> None:
    root = _temp(tmp_path)
    (root / ARTIFACT_DIR).write_bytes(b"not a directory")
    assert EnvSinks({TEMP_ENV: str(root)}).artifact(name="report.json", data=b"x") is None


def test_artifact_refuses_a_symlinked_directory(tmp_path: Path) -> None:
    root = _temp(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    try:
        (root / ARTIFACT_DIR).symlink_to(elsewhere)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert EnvSinks({TEMP_ENV: str(root)}).artifact(name="report.json", data=b"x") is None
    assert list(elsewhere.iterdir()) == []


def test_artifact_refuses_a_symlinked_file(tmp_path: Path) -> None:
    root = _temp(tmp_path)
    directory = root / ARTIFACT_DIR
    directory.mkdir()
    target = tmp_path / "target.json"
    target.write_bytes(b"kept")
    try:
        (directory / "report.json").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert EnvSinks({TEMP_ENV: str(root)}).artifact(name="report.json", data=b"x") is None
    assert target.read_bytes() == b"kept"


def test_artifact_refuses_when_the_open_or_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _temp(tmp_path)

    def failing_open(path: str, flags: int, mode: int = 0o777) -> int:
        raise OSError("denied")

    monkeypatch.setattr(os, "open", failing_open)
    assert EnvSinks({TEMP_ENV: str(root)}).artifact(name="report.json", data=b"x") is None

    monkeypatch.undo()

    def failing_fdopen(fd: int, mode: str) -> object:
        os.close(fd)
        raise ValueError("bad handle")

    monkeypatch.setattr(os, "fdopen", failing_fdopen)
    assert EnvSinks({TEMP_ENV: str(root)}).artifact(name="report.json", data=b"x") is None


# --- ActionSinks ----------------------------------------------------------------------


class _Client:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.result: tuple[str, str | None] = ("updated", None)

    def publish(
        self,
        *,
        repo: str,
        pr_number: int,
        run_head_sha: str,
        comment: str | None,
        sarif: str | None,
        sarif_commit_sha: str,
        sarif_ref: str,
    ) -> tuple[str, str | None]:
        self.calls.append(
            {
                "repo": repo,
                "pr_number": pr_number,
                "run_head_sha": run_head_sha,
                "comment": comment,
                "sarif": sarif,
                "sarif_commit_sha": sarif_commit_sha,
                "sarif_ref": sarif_ref,
            }
        )
        return self.result


def _publish(sink: ActionSinks) -> tuple[object, object]:
    return sink.publish(
        repo="o/r",
        pr_number=7,
        run_head_sha="a" * 40,
        comment="body",
        sarif="{ }",
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )


def test_publish_delegates_to_c12_unchanged() -> None:
    client = _Client()
    sink = ActionSinks({}, client)  # type: ignore[arg-type]
    assert _publish(sink) == ("updated", None)
    assert client.calls == [
        {
            "repo": "o/r",
            "pr_number": 7,
            "run_head_sha": "a" * 40,
            "comment": "body",
            "sarif": "{ }",
            "sarif_commit_sha": "c" * 40,
            "sarif_ref": "refs/pull/7/merge",
        }
    ]


def test_action_sinks_also_write_the_runner_outputs(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    outputs = tmp_path / "outputs"
    sink = ActionSinks(
        {SUMMARY_ENV: str(summary), OUTPUT_ENV: str(outputs)},
        _Client(),  # type: ignore[arg-type]
    )
    assert sink.summary_section("s\n") == "written"
    assert sink.outputs(OUTPUTS) == "written"
    assert summary.read_text(encoding="utf-8") == "s\n"
    assert outputs.read_text(encoding="utf-8").count("<<") == 4


def test_env_sinks_has_no_publish_so_a_run_cannot_post_twice() -> None:
    """CON-73: publishing goes only through ``Sinks.publish`` (``ActionSinks``)."""
    assert not hasattr(EnvSinks, "publish")


def test_status_values_are_the_spec_tri_state() -> None:
    """The tri-state is what the fallback branches on; a fourth value would be a ContractError."""
    statuses: tuple[SinkStatus, ...] = ("written", "refused", "unavailable")
    assert get_args(SinkStatus) == statuses


def test_the_sink_methods_never_raise_for_a_bad_destination(tmp_path: Path) -> None:
    """CON-73: every runner-side method reports through SinkStatus instead of raising."""
    broken = {"\0": "x"}
    calls: tuple[Callable[[], object], ...] = (
        lambda: EnvSinks(broken).summary_section("x"),
        lambda: EnvSinks(broken).outputs(OUTPUTS),
        lambda: EnvSinks({TEMP_ENV: str(tmp_path) + "\0"}).artifact(name="r.json", data=b"x"),
    )
    for call in calls:  # each one reports, none raises
        assert call() in ("written", "refused", "unavailable", None)
