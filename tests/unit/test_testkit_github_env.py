"""Unit tests for the runner-environment emulation in the testkit (CON-29).

The emitter is the real one (``conventiondrift.sinks.EnvSinks`` over ``gh.env``), so these tests
prove the emulation and the reader agree with production, including the Control-Pictures inverse
for output values.
"""

from __future__ import annotations

import io
import json
import os
from typing import Any

import pytest

from conventiondrift.model import Outputs
from conventiondrift.sinks import EnvSinks
from conventiondrift_testkit.github_env import (
    ARTIFACT_DIR,
    GitHubEnv,
    control_pictures_inverse,
    github_env,
    parse_outputs,
)


def test_the_emulated_environment_has_the_runner_variables() -> None:
    with github_env(inputs={"fail-on": "new-stale", "sarif": "true"}) as gh:
        env = gh.env
        assert env["GITHUB_ACTIONS"] == "true"
        assert env["GITHUB_EVENT_NAME"] == "pull_request"
        assert env["GITHUB_REPOSITORY"] == "octo/demo"
        assert env["INPUT_FAIL_ON"] == "new-stale"
        assert env["INPUT_SARIF"] == "true"
        assert env["RUNNER_TEMP"] == str(gh.temp)
        assert gh.path("output").exists() and gh.path("summary").exists()
        assert gh.path("event") == gh.event_file
        assert json.loads(gh.event_file.read_text(encoding="utf-8")) == {}


def test_an_event_payload_is_written_and_read_back() -> None:
    event = {"pull_request": {"number": 7, "base": {"sha": "a" * 40}}}
    with github_env(event=event, event_name="pull_request_target") as gh:
        assert gh.event() == event
        assert gh.env["GITHUB_EVENT_NAME"] == "pull_request_target"


def test_the_environment_is_restored_exactly_and_new_keys_are_removed() -> None:
    before = dict(os.environ)
    with github_env() as gh:
        assert os.environ["GITHUB_OUTPUT"] == str(gh.path("output"))
        os.environ["CD_TEST_LEAK"] = "1"
        os.environ.pop("PATH", None) if "PATH" in os.environ else None
    assert dict(os.environ) == before
    assert "CD_TEST_LEAK" not in os.environ
    assert os.environ.get("GITHUB_OUTPUT") == before.get("GITHUB_OUTPUT")


def test_the_scope_is_not_re_entrant() -> None:
    with github_env(), pytest.raises(RuntimeError, match="not re-entrant"):
        with github_env():
            pass


def test_an_invalid_input_name_is_refused_before_anything_is_changed() -> None:
    before = dict(os.environ)
    with pytest.raises(ValueError, match="invalid input name"):
        with github_env(inputs={"bad name!": "x"}):
            pass
    assert dict(os.environ) == before


def test_an_unknown_path_kind_is_a_programming_error() -> None:
    with github_env() as gh:
        with pytest.raises(ValueError, match="unknown path kind"):
            gh.path("sarif")


def test_outputs_match_the_real_writer_including_the_control_picture_inverse() -> None:
    with github_env() as gh:
        sink = EnvSinks(gh.env, stdout=io.BytesIO())
        outputs = Outputs(
            stale_count=3,
            new_stale_count=1,
            report_path="line1\nline2",
            sarif_path="",
        )
        assert sink.outputs(outputs) == "written"
        parsed = gh.outputs()
    assert parsed == {
        "stale-count": "3",
        "new-stale-count": "1",
        "report-path": "line1\nline2",
        "sarif-path": "",
    }


def test_the_summary_and_the_artifacts_are_readable_through_the_emulation() -> None:
    with github_env() as gh:
        sink = EnvSinks(gh.env, stdout=io.BytesIO())
        assert sink.summary_section("## Internal error\n") == "written"
        assert gh.artifacts() == {}
        written = sink.artifact(name="report.json", data=b'{"a":1}')
        assert written is not None
        assert gh.summary() == "## Internal error\n"
        assert gh.artifacts() == {"report.json": b'{"a":1}'}
        assert written.parent.name == ARTIFACT_DIR


def test_a_truncated_heredoc_keeps_the_rest_as_the_value() -> None:
    parsed = parse_outputs("stale-count<<ghadelimiter_x\n3\n")
    assert parsed == {"stale-count": "3"}


def test_the_control_pictures_inverse_is_exact_and_leaves_labels_alone() -> None:
    assert control_pictures_inverse("a\u240ab") == "a\nb"
    assert control_pictures_inverse("\u2400") == "\x00"
    assert control_pictures_inverse("\u240d") == "\r"
    assert control_pictures_inverse("\u2421") == "\x7f"
    assert control_pictures_inverse("U+200B stays a label") == "U+200B stays a label"
    assert control_pictures_inverse("plain") == "plain"


def test_a_custom_workspace_is_honoured(tmp_path: Any) -> None:
    custom = str(tmp_path / "ws")
    with github_env(workspace=custom) as gh:
        assert gh.workspace.as_posix() == custom
        assert gh.env["GITHUB_WORKSPACE"] == custom


def test_the_default_workspace_is_inside_the_scope() -> None:
    with github_env() as gh:
        assert gh.workspace.is_dir()
        assert gh.root in gh.workspace.parents


def test_the_root_property_requires_an_entered_scope() -> None:
    with pytest.raises(RuntimeError, match="not entered"):
        _ = GitHubEnv().root


def test_entering_twice_on_the_same_object_is_refused() -> None:
    env = GitHubEnv()
    with env:
        with pytest.raises(RuntimeError):
            env.__enter__()
