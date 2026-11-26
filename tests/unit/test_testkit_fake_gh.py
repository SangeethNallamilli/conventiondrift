"""Unit tests for the ``fake_gh`` transport in the testkit (CON-29).

Expected results are written from I-3/DESIGN §4 and from ``github.py``'s own notes, and every
case runs the real ``GitHubApiClient`` over the fake - the fake is a ``Transport``, so no
production code is bypassed and no socket is opened.
"""

from __future__ import annotations

import io

import pytest

from conventiondrift.github import (
    MARKER,
    NOTE_API_ERROR,
    NOTE_BAD_REQUEST,
    NOTE_DEADLINE,
    NOTE_HEAD_MOVED,
    NOTE_LOOKUP_ERROR,
    HttpResponse,
)
from conventiondrift.sinks import ActionSinks
from conventiondrift_testkit import MemorySinks
from conventiondrift_testkit.fake_gh import (
    BASE_URL,
    REPO,
    TOKEN,
    FakeGitHub,
    Req,
    UnexpectedWrite,
)
from conventiondrift_testkit.github_env import github_env

BODY = f"{MARKER}\n## conventiondrift\nnew body"
OLD_BODY = f"{MARKER}\nold body"
OTHER_HEAD = "b" * 40


def _send(fake: FakeGitHub, method: str, path: str, body: bytes | None = None) -> HttpResponse:
    return fake.request(method, BASE_URL + path, {}, body, 1.0)


# -- read paths and the zero-write posture ----------------------------------------


def test_lookup_with_no_comment_makes_no_write_and_needs_no_declaration() -> None:
    fake = FakeGitHub()
    assert fake.client().lookup(repo=REPO, pr_number=7) == (False, None)
    fake.assert_no_writes()
    assert [r.method for r in fake.requests] == ["GET"]


def test_lookup_finds_our_comment_and_ignores_other_peoples() -> None:
    fake = FakeGitHub()
    fake.seed_comment(OLD_BODY)
    fake.seed_comment("human comment", ours=False)
    assert fake.client().lookup(repo=REPO, pr_number=7) == (True, None)
    assert len(fake.ours()) == 1


def test_an_undeclared_write_raises_and_is_not_applied() -> None:
    fake = FakeGitHub()
    with pytest.raises(UnexpectedWrite, match="POST"):
        fake.client().publish(
            repo=REPO,
            pr_number=7,
            run_head_sha="a" * 40,
            comment=BODY,
            sarif=None,
            sarif_commit_sha="c" * 40,
            sarif_ref="refs/pull/7/merge",
        )
    assert fake.unexpected_writes and fake.comments == []


def test_allow_all_writes_opts_out_of_default_deny() -> None:
    fake = FakeGitHub()
    fake.allow_all_writes()
    outcome, note = fake.client().publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=BODY,
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )
    assert (outcome, note) == ("posted", None)
    assert fake.comment_bodies() == [BODY]


def test_expect_write_matches_method_and_suffix_and_is_consumed() -> None:
    fake = FakeGitHub()
    fake.expect_write("POST", "/comments")
    fake.client().publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=BODY,
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )
    # The allowance was used once; a second write needs a new declaration.
    with pytest.raises(UnexpectedWrite):
        _send(fake, "POST", f"/repos/{REPO}/issues/7/comments", b'{"body":"x"}')
    with pytest.raises(ValueError, match="times must be at least 1"):
        fake.expect_write("POST", times=0)


# -- the comment lifecycle --------------------------------------------------------


def test_publish_creates_updates_and_uploads_sarif() -> None:
    fake = FakeGitHub()
    fake.expect_write("POST", "/comments")
    fake.expect_write("POST", "/sarifs")
    client = fake.client()
    assert client.publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=BODY,
        sarif='{"version":"2.1.0"}',
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    ) == ("posted", None)
    assert fake.comment_bodies() == [BODY]
    assert fake.sarif_payloads()[0]["commit_sha"] == "c" * 40
    assert fake.sarif_payloads()[0]["ref"] == "refs/pull/7/merge"
    assert fake.sarif_texts() == ['{"version":"2.1.0"}']

    fake.expect_write("PATCH")
    assert client.publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=f"{MARKER}\nsecond",
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    ) == ("updated", None)
    assert fake.comment_bodies() == [f"{MARKER}\nsecond"]


def test_a_moved_head_is_a_note_and_no_write() -> None:
    fake = FakeGitHub(head_sha=OTHER_HEAD)
    outcome, note = fake.client().publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=BODY,
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )
    assert (outcome, note) == ("skipped", NOTE_HEAD_MOVED)
    fake.assert_no_writes()


def test_nothing_to_write_is_a_skip_with_no_request_at_all() -> None:
    fake = FakeGitHub()
    outcome, note = fake.client().publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=None,
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )
    assert (outcome, note) == ("skipped", None)
    assert fake.requests == []


def test_converge_deletes_the_duplicate_after_a_create() -> None:
    fake = FakeGitHub()

    def add_duplicate(req: Req) -> HttpResponse | None:
        if req.method == "POST" and req.path.endswith("/comments"):
            fake.seed_comment(f"{MARKER}\nolder", cid=900)
        return None

    fake.hooks.append(add_duplicate)
    fake.expect_write("POST", "/comments")
    fake.expect_write("PATCH")
    fake.expect_write("DELETE")
    outcome, note = fake.client().publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=BODY,
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )
    assert (outcome, note) == ("updated", None)
    # The lower id survives, the created duplicate is deleted, and the survivor gets the body.
    assert [c["id"] for c in fake.comments] == [900]
    assert fake.comment_bodies() == [BODY]
    assert len(fake.deletes()) == 1


# -- faults -----------------------------------------------------------------------


def test_a_retryable_status_is_retried_without_real_sleep() -> None:
    fake = FakeGitHub()
    fake.fail_next(429)
    delays: list[float] = []
    assert fake.client(sleep=delays.append).lookup(repo=REPO, pr_number=7) == (False, None)
    assert len(fake.requests) == 2
    assert delays == [0.5]


def test_exhausted_retries_end_in_a_note_not_an_exception() -> None:
    fake = FakeGitHub()
    for _ in range(3):
        fake.fail_next(500)
    assert fake.client(sleep=lambda _s: None).lookup(repo=REPO, pr_number=7) == (
        False,
        NOTE_LOOKUP_ERROR,
    )
    assert len(fake.requests) == 3


def test_a_non_retryable_status_is_one_request() -> None:
    fake = FakeGitHub()
    fake.fail_next(401)
    assert fake.client().lookup(repo=REPO, pr_number=7) == (False, NOTE_LOOKUP_ERROR)
    assert len(fake.requests) == 1


def test_a_transport_timeout_is_the_deadline_note() -> None:
    fake = FakeGitHub()
    fake.timeout_next()
    assert fake.client().lookup(repo=REPO, pr_number=7) == (False, NOTE_DEADLINE)


def test_malformed_json_is_an_api_error_not_a_crash() -> None:
    fake = FakeGitHub()
    fake.malformed_next()
    assert fake.client().lookup(repo=REPO, pr_number=7) == (False, NOTE_LOOKUP_ERROR)


def test_a_cross_host_redirect_is_never_followed() -> None:
    # A blocked redirect surfaces as "no response", which C12 retries at most MAX_RETRIES times;
    # the retry goes to the original base URL, never to the redirect target.
    fake = FakeGitHub()
    fake.redirect_next("https://evil.test/steal")
    assert fake.client(sleep=lambda _s: None).lookup(repo=REPO, pr_number=7) == (False, None)
    assert len(fake.requests) == 2
    assert all("evil.test" not in r.url for r in fake.requests)
    assert fake.comments == []


def test_a_redirect_without_a_location_is_returned_as_is() -> None:
    fake = FakeGitHub()
    fake.redirect_next("")
    assert _send(fake, "GET", f"/repos/{REPO}/pulls/7").status == 302


# -- routes and replies -----------------------------------------------------------


def test_unknown_paths_and_repositories_are_404() -> None:
    fake = FakeGitHub()
    assert _send(fake, "GET", "/repos/other/repo/pulls/7").status == 404
    assert _send(fake, "GET", "/nope").status == 404
    assert _send(fake, "GET", f"/repos/{REPO}/pulls/not-a-number").status == 404
    assert _send(fake, "GET", f"/repos/{REPO}/pulls/7/files").status == 404
    assert _send(fake, "GET", f"/repos/{REPO}/issues/7/labels").status == 404


def test_method_and_body_errors_are_explicit() -> None:
    fake = FakeGitHub()
    fake.allow_all_writes()
    assert _send(fake, "POST", f"/repos/{REPO}/pulls/7").status == 405
    assert _send(fake, "GET", f"/repos/{REPO}/issues/comments/123").status == 404
    assert _send(fake, "PATCH", f"/repos/{REPO}/issues/comments/123").status == 404
    assert _send(fake, "PUT", f"/repos/{REPO}/issues/7/comments").status == 405
    assert _send(fake, "POST", f"/repos/{REPO}/issues/7/comments", b"[]").status == 400
    assert _send(fake, "POST", f"/repos/{REPO}/code-scanning/sarifs", b"[]").status == 400
    assert _send(fake, "GET", f"/repos/{REPO}/code-scanning/sarifs").status == 404
    fake.seed_comment(OLD_BODY, cid=5)
    assert _send(fake, "PATCH", f"/repos/{REPO}/issues/comments/5", b"[]").status == 400
    assert _send(fake, "GET", f"/repos/{REPO}/issues/comments/5").status == 405


def test_pagination_honours_per_page_and_page() -> None:
    fake = FakeGitHub()
    for cid in range(1, 4):
        fake.seed_comment(OLD_BODY, cid=cid)
    first = _send(fake, "GET", f"/repos/{REPO}/issues/7/comments?per_page=2&page=1")
    second = _send(fake, "GET", f"/repos/{REPO}/issues/7/comments?per_page=2&page=2")
    import json

    assert [c["id"] for c in json.loads(first.body)] == [1, 2]
    assert [c["id"] for c in json.loads(second.body)] == [3]


def test_the_reply_helper_and_the_recorded_request_helpers() -> None:
    fake = FakeGitHub()
    reply = FakeGitHub.reply(201, {"ok": True})
    assert reply.status == 201 and reply.body == b'{"ok": true}'
    assert FakeGitHub.reply(204).body == b""
    fake.expect_write("POST", "/comments")
    _send(fake, "POST", f"/repos/{REPO}/issues/7/comments", b'{"body":"x"}')
    _send(fake, "GET", f"/repos/{REPO}/pulls/7")
    assert fake.methods() == ["POST", "GET"]
    assert fake.requests_to("/pulls/7")[0].method == "GET"
    assert fake.comment_requests()[0].method == "POST"
    assert fake.deletes() == []


def test_the_client_request_carries_the_production_headers_and_is_repr_safe() -> None:
    fake = FakeGitHub()
    assert fake.client().lookup(repo=REPO, pr_number=7) == (False, None)
    headers = fake.headers_of()
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in repr(fake.requests[0])


def test_writes_and_deletes_are_listed() -> None:
    fake = FakeGitHub()
    fake.allow_all_writes()
    _send(fake, "POST", f"/repos/{REPO}/issues/7/comments", b'{"body":"x"}')
    _send(fake, "DELETE", f"/repos/{REPO}/issues/comments/1000")
    assert [r.method for r in fake.writes()] == ["POST", "DELETE"]
    assert [r.method for r in fake.deletes()] == ["DELETE"]
    with pytest.raises(AssertionError, match="expected no writes"):
        fake.assert_no_writes()


def test_a_request_repr_redacts_the_token_header() -> None:
    req = Req("GET", BASE_URL + "/x", {"Authorization": "Bearer hunter2"}, None)
    assert "hunter2" not in repr(req)
    assert "<redacted>" in repr(req)
    assert req.query == {} and req.json is None
    assert FakeGitHub().__repr__().startswith("FakeGitHub(")


# -- Components wiring ------------------------------------------------------------


def test_components_with_an_env_wires_the_real_sinks_over_the_fake() -> None:
    fake = FakeGitHub()
    with github_env() as gh:
        components = fake.components(env=gh.env, stdout=io.BytesIO())
        assert isinstance(components.sinks, ActionSinks)
        fake.expect_write("POST", "/comments")
        outcome, note = components.sinks.publish(
            repo=REPO,
            pr_number=7,
            run_head_sha="a" * 40,
            comment=BODY,
            sarif=None,
            sarif_commit_sha="c" * 40,
            sarif_ref="refs/pull/7/merge",
        )
        assert (outcome, note) == ("posted", None)
        assert components.github_client is not None
        client = components.github_client(BASE_URL, TOKEN)
        assert client.lookup(repo=REPO, pr_number=7) == (True, None)


def test_components_can_use_memory_sinks_and_stay_off_the_network() -> None:
    fake = FakeGitHub()
    sinks = MemorySinks()
    components = fake.components(sinks=sinks)
    assert components.sinks is sinks
    assert fake.requests == []


def test_components_without_env_writes_nothing_but_still_publishes() -> None:
    fake = FakeGitHub()
    components = fake.components()
    assert isinstance(components.sinks, ActionSinks)
    fake.expect_write("POST", "/comments")
    assert (
        components.sinks.publish(
            repo=REPO,
            pr_number=7,
            run_head_sha="a" * 40,
            comment=BODY,
            sarif=None,
            sarif_commit_sha="c" * 40,
            sarif_ref="refs/pull/7/merge",
        )[0]
        == "posted"
    )


def test_the_client_helper_wires_the_fake_as_the_transport() -> None:
    fake = FakeGitHub()
    client = fake.client()
    assert client.lookup(repo=REPO, pr_number=7) == (False, None)
    assert fake.requests[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert f"{REPO}" in fake.requests[0].url


def test_bad_inputs_from_the_client_never_reach_the_transport() -> None:
    fake = FakeGitHub()
    assert fake.client().publish(
        repo="bad repo",
        pr_number=0,
        run_head_sha="nope",
        comment=BODY,
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    ) == ("skipped", NOTE_BAD_REQUEST)
    assert fake.requests == []


def test_a_server_side_bad_body_is_an_api_error() -> None:
    fake = FakeGitHub()
    fake.expect_write("POST", "/comments")

    def hook(_req: Req) -> HttpResponse | None:
        return FakeGitHub.reply(200, {"id": "x"})

    fake.hooks.append(hook)
    assert fake.client().publish(
        repo=REPO,
        pr_number=7,
        run_head_sha="a" * 40,
        comment=BODY,
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    ) == ("skipped", NOTE_API_ERROR)


def test_the_fake_satisfies_the_transport_protocol() -> None:
    from conventiondrift.github import Transport

    github_transport: Transport = FakeGitHub()
    assert callable(github_transport.request)
