"""Unit tests for C12, the GitHub API client (T-027; I-3, I-11 C12, DESIGN §3a, §4).

Nothing here touches the network: every client gets a ``FakeGitHub`` transport
(an in-memory API) or a patched ``http.client`` connection. Tokens are obvious
fakes. Expected results are written by hand from I-3, DESIGN §4 and PLAN T-027.
"""

import base64
import gzip
import http.client
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlsplit

import pytest

from conventiondrift import github
from conventiondrift.components import Components, GitHubClient
from conventiondrift.github import (
    ALL_NOTES,
    BOT_LOGIN,
    BOT_TYPE,
    MARKER,
    MAX_CONVERGE_DELETES,
    OURS_CONDITIONS,
    RETRY_STATUSES,
    GitHubApiClient,
    HttpClientTransport,
    HttpResponse,
    client_from_env,
    failed_conditions,
    is_marked,
    is_ours,
    normalize_base_url,
)

TOKEN = "fake-token-for-tests-0000"  # noqa: S105 -- an obvious fake, never a real secret
BASE = "https://api.github.test"
REPO = "octo/demo"
PR = 7
HEAD = "a" * 40
OTHER_HEAD = "b" * 40
GITHUB_SHA = "c" * 40
GITHUB_REF = "refs/pull/7/merge"
BODY = f"{MARKER}\n## conventiondrift\nnew body"
OLD_BODY = f"{MARKER}\nold body"


# -- the fake API -----------------------------------------------------------------


@dataclass
class Req:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    timeout: float = 0.0

    @property
    def path(self) -> str:
        return urlsplit(self.url).path

    @property
    def json(self) -> Any:
        assert self.body is not None
        return json.loads(self.body)


def bot_comment(
    cid: int, body: str = OLD_BODY, *, issue: int = PR, repo: str = REPO
) -> dict[str, Any]:
    return {
        "id": cid,
        "user": {"login": BOT_LOGIN, "type": BOT_TYPE},
        "body": body,
        "issue_url": f"{BASE}/repos/{repo}/issues/{issue}",
    }


@dataclass
class FakeGitHub:
    """An in-memory GitHub API. ``hooks`` can replace the reply for a request."""

    comments: list[dict[str, Any]] = field(default_factory=list)
    head_sha: str = HEAD
    next_id: int = 1000
    requests: list[Req] = field(default_factory=list)
    hooks: list[Callable[[Req], HttpResponse | None]] = field(default_factory=list)
    on_create: Callable[["FakeGitHub"], None] | None = None
    sarifs: list[dict[str, Any]] = field(default_factory=list)

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        req = Req(method, url, dict(headers), body, timeout)
        self.requests.append(req)
        for hook in self.hooks:
            reply = hook(req)
            if reply is not None:
                return reply
        return self._route(req)

    @staticmethod
    def reply(
        status: int, data: object = None, headers: Mapping[str, str] | None = None
    ) -> HttpResponse:
        body = b"" if data is None else json.dumps(data).encode()
        return HttpResponse(status, dict(headers or {}), body)

    def _route(self, req: Req) -> HttpResponse:
        parts = req.path.split("/")
        if req.method == "GET" and req.path == f"/repos/{REPO}/pulls/{PR}":
            return self.reply(200, {"number": PR, "head": {"sha": self.head_sha}})
        if req.path == f"/repos/{REPO}/issues/{PR}/comments":
            if req.method == "GET":
                q = parse_qs(urlsplit(req.url).query)
                per, page = int(q["per_page"][0]), int(q["page"][0])
                ordered = sorted(self.comments, key=lambda c: int(c.get("id", 0)))
                return self.reply(200, ordered[(page - 1) * per : page * per])
            if req.method == "POST":
                cid = self.next_id
                self.next_id += 1
                self.comments.append(bot_comment(cid, req.json["body"]))
                if self.on_create is not None:
                    self.on_create(self)
                return self.reply(201, {"id": cid})
        if (
            parts[:5] == ["", "repos", *REPO.split("/"), "issues"]
            and len(parts) == 7
            and parts[5] == "comments"
        ):
            cid = int(parts[6])
            found = [c for c in self.comments if c["id"] == cid]
            if not found:
                return self.reply(404, {"message": "Not Found"})
            if req.method == "PATCH":
                found[0]["body"] = req.json["body"]
                return self.reply(200, found[0])
            if req.method == "DELETE":
                self.comments.remove(found[0])
                return self.reply(204)
        if req.method == "POST" and req.path == f"/repos/{REPO}/code-scanning/sarifs":
            self.sarifs.append(req.json)
            return self.reply(202, {"id": "sarif-1"})
        return self.reply(404, {"message": "Not Found"})

    def writes(self) -> list[Req]:
        return [r for r in self.requests if r.method != "GET"]

    def deletes(self) -> list[Req]:
        return [r for r in self.requests if r.method == "DELETE"]

    def comment_requests(self) -> list[Req]:
        return [r for r in self.requests if "/comments" in r.path or "/pulls/" in r.path]


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make(api: FakeGitHub, clock: Clock | None = None) -> GitHubApiClient:
    c = clock or Clock()
    return GitHubApiClient(BASE, TOKEN, transport=api, sleep=c.sleep, clock=c)


def publish(
    client: GitHubApiClient,
    *,
    comment: str | None = BODY,
    sarif: str | None = None,
    pr: int = PR,
    head: str = HEAD,
) -> tuple[str, str | None]:
    return client.publish(repo=REPO, pr_number=pr, run_head_sha=head, comment=comment, sarif=sarif)


# -- identity (I-3, ADR-0005) ------------------------------------------------------

# One decoy per identity check; each breaks exactly one check (D-TL-25).
DECOYS: dict[str, Callable[[dict[str, Any]], None]] = {
    "user_with_marker": lambda c: c["user"].update(login="mallory", type="User"),
    "spoofed_login_non_bot": lambda c: c["user"].update(type="User"),
    "bot_type_other_login": lambda c: c["user"].update(login="renovate[bot]"),
    "bot_without_marker": lambda c: c.update(body="## conventiondrift\nno marker"),
    "marker_not_on_line_1": lambda c: c.update(body=f"hello\n{MARKER}"),
    "other_issue_url": lambda c: c.update(issue_url=f"{BASE}/repos/{REPO}/issues/{PR + 1}"),
    "other_repo_issue_url": lambda c: c.update(issue_url=f"{BASE}/repos/octo/other/issues/{PR}"),
    "longer_pr_in_issue_url": lambda c: c.update(issue_url=f"{BASE}/repos/{REPO}/issues/{PR}0"),
    "missing_issue_url": lambda c: c.pop("issue_url"),
    "non_string_issue_url": lambda c: c.update(issue_url=PR),
    "string_id": lambda c: c.update(id=str(c["id"])),
    "bool_id": lambda c: c.update(id=True),
    "missing_user": lambda c: c.pop("user"),
}


def decoy(kind: str, cid: int) -> dict[str, Any]:
    c = bot_comment(cid)
    DECOYS[kind](c)
    return c


def test_ours_requires_every_check() -> None:
    assert is_ours(bot_comment(5), repo=REPO, pr_number=PR)
    assert failed_conditions(bot_comment(5), repo=REPO, pr_number=PR) == frozenset()
    assert failed_conditions("x", repo=REPO, pr_number=PR) == frozenset(OURS_CONDITIONS)


@pytest.mark.parametrize("kind", sorted(DECOYS))
def test_each_decoy_breaks_exactly_one_condition(kind: str) -> None:
    # Ruling 5 / D-TL-25: each decoy fails one ours-condition on its own and passes the rest.
    assert len(failed_conditions(decoy(kind, 5), repo=REPO, pr_number=PR)) == 1


def test_decoys_cover_every_ours_condition() -> None:
    # D-TL-25: the decoy classes are checked against the code's own condition set.
    broken = {
        name
        for kind in DECOYS
        for name in failed_conditions(decoy(kind, 5), repo=REPO, pr_number=PR)
    }
    assert broken == set(OURS_CONDITIONS)
    assert set(OURS_CONDITIONS) == {"id", "bot_identity", "marker", "issue_url"}


@pytest.mark.parametrize("kind", sorted(DECOYS))
def test_each_decoy_is_not_ours(kind: str) -> None:
    assert not is_ours(decoy(kind, 5), repo=REPO, pr_number=PR)


def test_ours_ignores_non_dict_and_repo_case() -> None:
    assert not is_ours([1], repo=REPO, pr_number=PR)
    assert not is_ours(bot_comment(0), repo=REPO, pr_number=PR)
    c = bot_comment(3)
    c["body"] = 5
    assert not is_ours(c, repo=REPO, pr_number=PR)
    c = bot_comment(3)
    c["user"] = "github-actions[bot]"
    assert not is_ours(c, repo=REPO, pr_number=PR)
    c = bot_comment(3)
    c["issue_url"] = "http://[::1"
    assert not is_ours(c, repo=REPO, pr_number=PR)
    assert is_ours(bot_comment(3, repo="Octo/Demo"), repo=REPO, pr_number=PR)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (MARKER, True),
        (f"{MARKER}\nx", True),
        (f"{MARKER}\r\nx", True),
        (f" {MARKER}\nx", False),
        (f"{MARKER} \nx", False),
        ("<!-- conventiondrift:sticky v2 -->\nx", False),
        ("", False),
    ],
)
def test_marker_must_be_exact_line_1(body: str, expected: bool) -> None:
    assert is_marked(body) is expected


# -- base URL and token -------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "allow_http", "expected"),
    [
        ("https://api.github.com", False, "https://api.github.com"),
        ("https://ghe.example/api/v3/", False, "https://ghe.example/api/v3"),
        ("http://127.0.0.1:8080", True, "http://127.0.0.1:8080"),
        ("http://api.github.com", False, None),
        ("ftp://api.github.com", True, None),
        ("https://user:pw@api.github.com", False, None),
        ("https://user@api.github.com", False, None),
        ("https://api.github.com?x=1", False, None),
        ("https://api.github.com#frag", False, None),
        ("https://api.github.com:99999", False, None),
        ("https://api.github.com/a b", False, None),
        ("https:///nohost", False, None),
        ("", False, None),
    ],
)
def test_normalize_base_url(url: str, allow_http: bool, expected: str | None) -> None:
    assert normalize_base_url(url, allow_http=allow_http) == expected


def test_env_http_base_url_is_refused_and_never_connects() -> None:
    api = FakeGitHub()
    env = {"GITHUB_API_URL": "http://api.github.test", "GITHUB_TOKEN": TOKEN}
    client = client_from_env(env, transport=api)
    assert publish(client) == ("skipped", github.NOTE_NO_BASE_URL)  # type: ignore[arg-type]
    assert api.requests == []


def test_missing_env_base_url_is_refused() -> None:
    client = client_from_env({"GITHUB_TOKEN": TOKEN})
    outcome = client.publish(repo=REPO, pr_number=PR, run_head_sha=HEAD, comment=BODY, sarif=None)
    assert outcome == ("skipped", github.NOTE_NO_BASE_URL)
    assert github._SkippingClient(github.NOTE_NO_BASE_URL).lookup(repo=REPO, pr_number=PR) == (
        False,
        github.NOTE_NO_BASE_URL,
    )


def test_seam_base_url_allows_http() -> None:
    api = FakeGitHub()
    env = {"GITHUB_API_URL": "https://ignored.test", "GITHUB_TOKEN": TOKEN}
    client = client_from_env(env, base_url_override="http://127.0.0.1:9", transport=api)
    client.publish(repo=REPO, pr_number=PR, run_head_sha=HEAD, comment=BODY, sarif=None)
    assert api.requests
    assert all(r.url.startswith("http://127.0.0.1:9/") for r in api.requests)


def test_factory_gets_env_base_and_token() -> None:
    seen: list[tuple[str, str]] = []

    class Stub:
        def publish(self, **kw: Any) -> tuple[str, None]:
            return "skipped", None

        def lookup(self, **kw: Any) -> tuple[bool, None]:
            return False, None

    def factory(base: str, token: str) -> GitHubClient:
        seen.append((base, token))
        return Stub()  # type: ignore[return-value]

    env = {"GITHUB_API_URL": "https://api.github.test/", "GITHUB_TOKEN": TOKEN}
    client_from_env(env, factory=factory)
    assert seen == [("https://api.github.test", TOKEN)]
    # The Components seam types line up with the factory.
    Components(github_client=factory, github_base_url="http://127.0.0.1:1")


@pytest.mark.parametrize("token", ["", "has space", "line\nbreak", "tab\tx", "é"])
def test_unusable_token_makes_no_request(token: str) -> None:
    api = FakeGitHub()
    client = GitHubApiClient(BASE, token, transport=api)
    assert publish(client) == ("skipped", github.NOTE_NO_AUTH)
    assert client.lookup(repo=REPO, pr_number=PR) == (False, github.NOTE_NO_AUTH)
    assert api.requests == []


def test_token_only_in_authorization_header() -> None:
    api = FakeGitHub(comments=[bot_comment(3)])
    publish(make(api), sarif='{"version": "2.1.0"}')
    assert api.requests
    for r in api.requests:
        assert r.headers["Authorization"] == f"Bearer {TOKEN}"
        assert TOKEN not in r.url
        assert r.body is None or TOKEN.encode() not in r.body
        others = {k: v for k, v in r.headers.items() if k != "Authorization"}
        assert TOKEN not in repr(others)


def test_repr_and_pickle_never_show_token() -> None:
    client = make(FakeGitHub())
    assert TOKEN not in repr(client)
    assert TOKEN not in str(client)
    assert "<redacted>" in repr(client)
    with pytest.raises(TypeError) as info:
        client.__reduce__()
    assert TOKEN not in str(info.value)


def test_notes_never_contain_token_or_response_text() -> None:
    def leak(req: Req) -> HttpResponse:
        return HttpResponse(500, {"x-echo": TOKEN}, f"error {TOKEN} secret-body".encode())

    api = FakeGitHub(hooks=[leak])
    outcome, note = publish(make(api), sarif="{}")
    assert outcome == "skipped"
    assert note is not None
    assert TOKEN not in note
    assert "secret-body" not in note
    for n in ALL_NOTES:
        assert TOKEN not in n


def test_transport_exception_text_never_leaks() -> None:
    def boom(req: Req) -> HttpResponse:
        raise ValueError(f"Invalid header value {TOKEN!r}")

    api = FakeGitHub(hooks=[boom])
    outcome, note = publish(make(api))
    assert (outcome, note) == ("skipped", github.NOTE_API_ERROR)


# -- redirects ------------------------------------------------------------------------


def _redirect_to(
    location: str, *, status: int = 302, once: bool = True
) -> Callable[[Req], HttpResponse | None]:
    done: list[bool] = []

    def hook(req: Req) -> HttpResponse | None:
        if req.method == "GET" and req.path.endswith(f"/pulls/{PR}") and not (once and done):
            done.append(True)
            return HttpResponse(status, {"location": location}, b"")
        return None

    return hook


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.test/repos/octo/demo/pulls/7",
        "http://api.github.test/repos/octo/demo/pulls/7",
        "https://api.github.test:8443/repos/octo/demo/pulls/7",
        "//evil.test/x",
    ],
)
def test_no_token_and_no_request_on_cross_origin_redirect(location: str) -> None:
    api = FakeGitHub(hooks=[_redirect_to(location, once=False)])
    outcome, note = publish(make(api))
    assert (outcome, note) == ("skipped", github.NOTE_API_ERROR)
    for r in api.requests:
        assert urlsplit(r.url).netloc == "api.github.test"
        assert urlsplit(r.url).scheme == "https"


@pytest.mark.parametrize("status", sorted(github.REDIRECT_STATUSES))
def test_same_origin_redirect_is_followed_with_token(status: int) -> None:
    api = FakeGitHub(hooks=[_redirect_to(f"{BASE}/repos/{REPO}/pulls/{PR}", status=status)])
    assert publish(make(api))[0] == "posted"
    assert api.requests[1].path == f"/repos/{REPO}/pulls/{PR}"
    assert api.requests[1].headers["Authorization"] == f"Bearer {TOKEN}"


def test_redirect_loop_is_bounded() -> None:
    api = FakeGitHub(hooks=[_redirect_to(f"{BASE}/repos/{REPO}/pulls/{PR}", once=False)])
    clock = Clock()
    assert publish(make(api, clock)) == ("skipped", github.NOTE_API_ERROR)
    # (1 + MAX_REDIRECTS) hops per attempt, 1 + MAX_RETRIES attempts.
    assert len(api.requests) == (1 + github.MAX_REDIRECTS) * (1 + github.MAX_RETRIES)


def test_redirect_without_location_is_a_failure() -> None:
    api = FakeGitHub(hooks=[lambda r: HttpResponse(302, {}, b"") if r.method == "GET" else None])
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)


def test_redirect_on_a_write_is_not_followed() -> None:
    def hook(req: Req) -> HttpResponse | None:
        if req.method == "POST":
            return HttpResponse(307, {"location": f"{BASE}/elsewhere"}, b"")
        return None

    api = FakeGitHub(hooks=[hook])
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)
    assert [r.method for r in api.requests].count("POST") == 1


def test_auth_header_only_for_base_origin() -> None:
    client = make(FakeGitHub())
    assert "Authorization" in client._headers(f"{BASE}/x", has_body=False)
    assert "Authorization" not in client._headers("https://evil.test/x", has_body=False)
    assert "Authorization" not in client._headers("not a url", has_body=True)


# -- retries (DESIGN §4) --------------------------------------------------------------


def _fail_first(n: int, status: int | None) -> Callable[[Req], HttpResponse | None]:
    count = [0]

    def hook(req: Req) -> HttpResponse | None:
        if count[0] < n:
            count[0] += 1
            if status is None:
                raise TimeoutError("timed out")
            return HttpResponse(status, {}, b"{}")
        return None

    return hook


@pytest.mark.parametrize("status", [*sorted(RETRY_STATUSES), None])
def test_two_retries_then_success(status: int | None) -> None:
    clock = Clock()
    api = FakeGitHub(hooks=[_fail_first(2, status)])
    assert publish(make(api, clock)) == ("posted", None)
    assert clock.sleeps == [0.5, 1.0]


@pytest.mark.parametrize("status", [*sorted(RETRY_STATUSES), None])
def test_third_failure_gives_a_note_not_an_error(status: int | None) -> None:
    clock = Clock()
    api = FakeGitHub(hooks=[_fail_first(99, status)])
    assert publish(make(api, clock)) == ("skipped", github.NOTE_API_ERROR)
    assert len(api.requests) == 3
    assert sum(clock.sleeps) <= github.DEADLINE_SECONDS


@pytest.mark.parametrize("status", [400, 401, 404, 410, 422])
def test_non_retryable_status_fails_at_once(status: int) -> None:
    clock = Clock()
    api = FakeGitHub(hooks=[_fail_first(99, status)])
    assert publish(make(api, clock)) == ("skipped", github.NOTE_API_ERROR)
    assert len(api.requests) == 1
    assert clock.sleeps == []


def test_retries_stop_when_budget_would_be_exceeded() -> None:
    clock = Clock()

    def slow(req: Req) -> HttpResponse:
        clock.now += 1.8  # each attempt takes 1.8 s
        return HttpResponse(503, {}, b"")

    api = FakeGitHub(hooks=[slow])
    assert publish(make(api, clock)) == ("skipped", github.NOTE_DEADLINE)
    # attempt 1 ends at 1.8 s; its 0.5 s backoff ends at 2.3 s < 3 s, so retry with
    # 0.7 s left; attempt 2 ends at 4.1 s; no time is left for another one.
    assert len(api.requests) == 2
    assert [r.timeout for r in api.requests] == [3.0, pytest.approx(0.7)]
    assert clock.sleeps == [0.5]


# -- the overall deadline (I-13 C12 ruling 3) ---------------------------------------------


def _ticking(clock: Clock, seconds: float) -> Callable[[Req], HttpResponse | None]:
    def hook(req: Req) -> HttpResponse | None:
        clock.now += seconds
        return None

    return hook


def test_socket_timeout_is_the_time_left_under_the_deadline() -> None:
    clock = Clock()
    api = FakeGitHub(hooks=[_ticking(clock, 0.25)])
    assert publish(make(api, clock)) == ("posted", None)
    expected = [github.DEADLINE_SECONDS - 0.25 * i for i in range(len(api.requests))]
    assert [r.timeout for r in api.requests] == pytest.approx(expected)


def test_socket_timeout_never_exceeds_the_request_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(github, "DEADLINE_SECONDS", 30.0)
    clock = Clock()
    api = FakeGitHub(hooks=[_ticking(clock, 15.0)])
    make(api, clock).lookup(repo=REPO, pr_number=PR)
    assert [r.timeout for r in api.requests] == [github.REQUEST_TIMEOUT_SECONDS]


def test_publish_out_of_time_is_skipped_with_a_note() -> None:
    clock = Clock()
    api = FakeGitHub(hooks=[_ticking(clock, 1.0)])
    assert publish(make(api, clock)) == ("skipped", github.NOTE_DEADLINE)
    # PR head at 0 s, listing at 1 s, create at 2 s; nothing starts at or after 3 s.
    assert [r.method for r in api.requests] == ["GET", "GET", "POST"]
    assert api.deletes() == []


def test_publish_out_of_time_before_any_write_writes_nothing() -> None:
    clock = Clock()
    api = FakeGitHub(comments=[bot_comment(5)], hooks=[_ticking(clock, 1.5)])
    assert publish(make(api, clock)) == ("skipped", github.NOTE_DEADLINE)
    assert api.writes() == []


def test_lookup_out_of_time_returns_not_found_with_a_note() -> None:
    clock = Clock()
    comments = [decoy("user_with_marker", i) for i in range(1, 501)] + [bot_comment(501)]
    api = FakeGitHub(comments=comments, hooks=[_ticking(clock, 1.0)])
    assert make(api, clock).lookup(repo=REPO, pr_number=PR) == (False, github.NOTE_DEADLINE)
    assert len(api.requests) == 3
    assert api.writes() == []


def test_deadline_is_per_call() -> None:
    clock = Clock()
    api = FakeGitHub(hooks=[_ticking(clock, 0.6)])
    client = make(api, clock)
    assert client.lookup(repo=REPO, pr_number=PR) == (False, None)  # 0 s to 0.6 s
    # publish starts a fresh 3 s at 0.6 s, so its 5th request still starts at 3.0 s.
    assert publish(client) == ("posted", None)
    assert len(api.requests) == 6
    assert api.requests[1].timeout == pytest.approx(github.DEADLINE_SECONDS)
    assert api.requests[5].timeout == pytest.approx(0.6)


def test_lookup_never_raises() -> None:
    def broken_clock() -> float:
        raise RuntimeError("clock failed")

    api = FakeGitHub(comments=[bot_comment(5)])
    client = GitHubApiClient(BASE, TOKEN, transport=api, clock=broken_clock)
    assert client.lookup(repo=REPO, pr_number=PR) == (False, github.NOTE_LOOKUP_ERROR)
    assert api.requests == []


@pytest.mark.parametrize(
    "payload", [b"not json", b"\xff\xfe", b"[" * 100000, b'{"head": 3}', b"[]"]
)
def test_malformed_pr_json_is_a_note(payload: bytes) -> None:
    api = FakeGitHub(
        hooks=[lambda r: HttpResponse(200, {}, payload) if "/pulls/" in r.path else None]
    )
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)
    assert api.writes() == []


def test_malformed_comment_listing_is_a_note() -> None:
    api = FakeGitHub(
        hooks=[
            lambda r: (
                HttpResponse(200, {}, b'{"a": 1}')
                if "/comments" in r.path and r.method == "GET"
                else None
            )
        ]
    )
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)
    assert api.writes() == []


def test_bad_pr_head_sha_is_a_note() -> None:
    api = FakeGitHub(head_sha="not-a-sha")
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)


# -- input checks -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("repo", "pr", "head"),
    [
        ("octo", PR, HEAD),
        ("octo/demo/x", PR, HEAD),
        ("../demo", PR, HEAD),
        ("octo/..", PR, HEAD),
        ("octo/de mo", PR, HEAD),
        (REPO, 0, HEAD),
        (REPO, -1, HEAD),
        (REPO, True, HEAD),
        (REPO, PR, "a" * 39),
        (REPO, PR, "g" * 40),
        (REPO, PR, "main"),
    ],
)
def test_invalid_publish_arguments_make_no_request(repo: str, pr: int, head: str) -> None:
    api = FakeGitHub()
    out = make(api).publish(repo=repo, pr_number=pr, run_head_sha=head, comment=BODY, sarif="{}")
    assert out == ("skipped", github.NOTE_BAD_REQUEST)
    assert api.requests == []


def test_body_without_marker_is_not_posted() -> None:
    api = FakeGitHub()
    assert publish(make(api), comment="no marker") == ("skipped", github.NOTE_BAD_BODY)
    assert api.requests == []


def test_uppercase_run_head_matches() -> None:
    api = FakeGitHub()
    assert publish(make(api), head=HEAD.upper())[0] == "posted"


# -- lookup (§2 step 8, S7) ------------------------------------------------------------


def test_lookup_finds_ours_and_is_read_only() -> None:
    api = FakeGitHub(comments=[decoy("user_with_marker", 1), bot_comment(2)])
    assert make(api).lookup(repo=REPO, pr_number=PR) == (True, None)
    assert api.writes() == []


@pytest.mark.parametrize("kind", sorted(DECOYS))
def test_lookup_ignores_each_decoy(kind: str) -> None:
    api = FakeGitHub(comments=[decoy(kind, 1)])
    assert make(api).lookup(repo=REPO, pr_number=PR) == (False, None)


def test_lookup_works_with_read_only_token_and_writes_nothing() -> None:
    # lookup has no read-only switch to honour: it only ever GETs.
    api = FakeGitHub(comments=[bot_comment(2)])
    assert make(api).lookup(repo=REPO, pr_number=PR) == (True, None)
    assert api.requests
    assert api.writes() == []


def test_lookup_error_is_a_note() -> None:
    api = FakeGitHub(hooks=[_fail_first(99, 500)])
    assert make(api).lookup(repo=REPO, pr_number=PR) == (False, github.NOTE_LOOKUP_ERROR)


def test_lookup_rejects_bad_pr_and_bad_repo() -> None:
    api = FakeGitHub()
    client = make(api)
    assert client.lookup(repo=REPO, pr_number=0) == (False, github.NOTE_BAD_REQUEST)
    assert client.lookup(repo="bad", pr_number=PR) == (False, github.NOTE_BAD_REQUEST)
    assert api.requests == []


def test_lookup_paginates() -> None:
    comments = [decoy("user_with_marker", i) for i in range(1, 251)] + [bot_comment(251)]
    api = FakeGitHub(comments=comments)
    assert make(api).lookup(repo=REPO, pr_number=PR) == (True, None)
    pages = [parse_qs(urlsplit(r.url).query)["page"][0] for r in api.requests]
    assert pages == ["1", "2", "3"]


def test_listing_stops_at_page_cap() -> None:
    comments = [decoy("user_with_marker", i) for i in range(1, 100 * github.MAX_COMMENT_PAGES + 50)]
    api = FakeGitHub(comments=comments)
    assert make(api).lookup(repo=REPO, pr_number=PR) == (False, None)
    assert len(api.requests) == github.MAX_COMMENT_PAGES


# -- create / update (AC-F6.1, AC-F6.2, AC-E.22, SEC-T12) ---------------------------------


def test_creates_when_none_exists() -> None:
    api = FakeGitHub()
    assert publish(make(api)) == ("posted", None)
    assert [c["body"] for c in api.comments] == [BODY]
    posts = [r for r in api.requests if r.method == "POST"]
    assert posts[0].path == f"/repos/{REPO}/issues/{PR}/comments"
    assert posts[0].json == {"body": BODY}


def test_updates_lowest_id_match_and_leaves_others() -> None:
    decoy_c = decoy("user_with_marker", 1)
    api = FakeGitHub(comments=[decoy_c, bot_comment(10), bot_comment(9), bot_comment(30)])
    assert publish(make(api)) == ("updated", None)
    bodies = {c["id"]: c["body"] for c in api.comments}
    assert bodies == {1: OLD_BODY, 9: BODY, 10: OLD_BODY, 30: OLD_BODY}
    assert [(r.method, r.path) for r in api.writes()] == [
        ("PATCH", f"/repos/{REPO}/issues/comments/9")
    ]


def test_rerun_same_commit_keeps_one_comment_and_id() -> None:
    api = FakeGitHub()
    client = make(api)
    assert publish(client)[0] == "posted"
    first_id = api.comments[0]["id"]
    assert publish(client) == ("updated", None)
    assert publish(client) == ("updated", None)
    assert [c["id"] for c in api.comments] == [first_id]
    assert api.comments[0]["body"] == BODY


def test_second_push_updates_same_comment() -> None:
    api = FakeGitHub()
    assert publish(make(api))[0] == "posted"
    cid = api.comments[0]["id"]
    api.head_sha = OTHER_HEAD
    second = f"{MARKER}\nsecond push"
    assert publish(make(api), comment=second, head=OTHER_HEAD) == ("updated", None)
    assert [(c["id"], c["body"]) for c in api.comments] == [(cid, second)]


@pytest.mark.parametrize("kind", sorted(DECOYS))
def test_decoy_is_never_edited_and_ours_is_created(kind: str) -> None:
    d = decoy(kind, 1)
    api = FakeGitHub(comments=[d])
    assert publish(make(api)) == ("posted", None)
    assert d["body"] in (OLD_BODY, "## conventiondrift\nno marker", f"hello\n{MARKER}")
    assert all(not r.path.endswith("/comments/1") for r in api.writes())


def test_head_moved_writes_nothing() -> None:
    api = FakeGitHub(head_sha=OTHER_HEAD, comments=[bot_comment(5)])
    assert publish(make(api)) == ("skipped", github.NOTE_HEAD_MOVED)
    assert api.writes() == []


def test_update_failure_is_a_note() -> None:
    api = FakeGitHub(
        comments=[bot_comment(5)],
        hooks=[lambda r: HttpResponse(422, {}, b"") if r.method == "PATCH" else None],
    )
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)


@pytest.mark.parametrize("reply", [b'{"id": "x"}', b'{"id": 0}', b"[]", b"bad"])
def test_create_without_valid_id_is_a_note(reply: bytes) -> None:
    api = FakeGitHub(hooks=[lambda r: HttpResponse(201, {}, reply) if r.method == "POST" else None])
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)


# -- converge after create (I-3) ----------------------------------------------------------


def race(*ids: int, issue: int = PR) -> Callable[[FakeGitHub], None]:
    """Simulate racing runs that created comments while this one created its own."""

    def on_create(api: FakeGitHub) -> None:
        for cid in ids:
            api.comments.append(bot_comment(cid, f"{MARKER}\nracer {cid}", issue=issue))
        api.on_create = None

    return on_create


def test_converge_keeps_lowest_and_reapplies_body() -> None:
    api = FakeGitHub(next_id=50, on_create=race(40))
    assert publish(make(api)) == ("updated", None)
    assert [(c["id"], c["body"]) for c in api.comments] == [(40, BODY)]
    assert [r.path for r in api.deletes()] == [f"/repos/{REPO}/issues/comments/50"]


def test_converge_when_ours_is_lowest_deletes_racers() -> None:
    api = FakeGitHub(next_id=50, on_create=race(60, 70))
    assert publish(make(api)) == ("posted", None)
    assert [c["id"] for c in api.comments] == [50]
    assert sorted(r.path for r in api.deletes()) == [
        f"/repos/{REPO}/issues/comments/60",
        f"/repos/{REPO}/issues/comments/70",
    ]
    assert not any(r.method == "PATCH" for r in api.requests)


def test_two_racing_runs_converge_on_one_comment() -> None:
    # Both runs listed no comment and both created one: A got 100, B got 101.
    api = FakeGitHub(next_id=100)
    api.on_create = race(101)
    run_a, run_b = make(api), make(api)
    assert publish(run_a) == ("posted", None)
    # B now runs its own converge step for the comment it created.
    run_b._start_deadline()
    assert run_b._converge(REPO, PR, HEAD, f"{MARKER}\nB", 101) == ("posted", None)
    assert [c["id"] for c in api.comments] == [100]
    assert api.comments[0]["body"] == BODY


def test_delete_404_counts_as_success() -> None:
    def gone(req: Req) -> HttpResponse | None:
        if req.method == "DELETE":
            return HttpResponse(404, {}, b'{"message": "Not Found"}')
        return None

    api = FakeGitHub(next_id=50, on_create=race(40), hooks=[gone])
    assert publish(make(api)) == ("updated", None)


def test_delete_failure_is_a_note_never_an_error() -> None:
    api = FakeGitHub(
        next_id=50,
        on_create=race(40),
        hooks=[lambda r: HttpResponse(500, {}, b"") if r.method == "DELETE" else None],
    )
    outcome, note = publish(make(api))
    assert outcome == "updated"
    assert note == github.NOTE_CONVERGE_ERROR


def test_reapply_only_if_head_still_matches() -> None:
    def on_create(api: FakeGitHub) -> None:
        race(40)(api)
        api.head_sha = OTHER_HEAD  # a newer push landed during this run

    api = FakeGitHub(next_id=50, on_create=on_create)
    assert publish(make(api)) == ("skipped", github.NOTE_HEAD_MOVED)
    assert [(c["id"], c["body"]) for c in api.comments] == [(40, f"{MARKER}\nracer 40")]
    assert not any(r.method == "PATCH" for r in api.requests)


def test_reapply_failure_is_a_note() -> None:
    api = FakeGitHub(
        next_id=50,
        on_create=race(40),
        hooks=[lambda r: HttpResponse(500, {}, b"") if r.method == "PATCH" else None],
    )
    assert publish(make(api)) == ("posted", github.NOTE_API_ERROR)


def test_converge_relist_failure_is_a_note() -> None:
    calls = [0]

    def hook(req: Req) -> HttpResponse | None:
        if req.method == "GET" and "/comments" in req.path:
            calls[0] += 1
            if calls[0] > 1:
                return HttpResponse(500, {}, b"")
        return None

    api = FakeGitHub(hooks=[hook])
    assert publish(make(api)) == ("posted", github.NOTE_CONVERGE_ERROR)
    assert api.deletes() == []


# SR condition (1): deletes only on the current PR's issue number from the event payload.


# T-028 reads the event payload and passes its PR number as ``pr_number`` (ruling 2).


def test_converge_delete_only_on_event_payload_pr_number() -> None:
    api = FakeGitHub(next_id=50, on_create=race(60))
    publish(make(api), pr=PR)
    assert api.deletes()
    lists = [r.path for r in api.requests if r.method == "GET" and "/comments" in r.path]
    assert set(lists) == {f"/repos/{REPO}/issues/{PR}/comments"}
    assert [r.path for r in api.deletes()] == [f"/repos/{REPO}/issues/comments/60"]


def test_converge_delete_refused_when_pr_number_differs_from_event_payload() -> None:
    # Duplicates of ours sit on PR 7; the run's event payload names PR 8. Even when the
    # API (wrongly) hands PR 7's comments to PR 8's listing, none of them is touched.
    other = PR + 1
    ours_on_pr = [bot_comment(5), bot_comment(6), bot_comment(7)]

    def route(req: Req) -> HttpResponse | None:
        if req.method == "GET" and req.path == f"/repos/{REPO}/pulls/{other}":
            return FakeGitHub.reply(200, {"number": other, "head": {"sha": HEAD}})
        if req.method == "GET" and req.path == f"/repos/{REPO}/issues/{other}/comments":
            return FakeGitHub.reply(200, ours_on_pr)
        if req.method == "POST" and req.path == f"/repos/{REPO}/issues/{other}/comments":
            return FakeGitHub.reply(201, {"id": 50})
        return None

    api = FakeGitHub(comments=list(ours_on_pr), hooks=[route])
    assert publish(make(api), pr=other) == ("posted", None)
    assert api.deletes() == []
    assert not any(r.method == "PATCH" for r in api.requests)
    assert {r.path for r in api.writes()} == {f"/repos/{REPO}/issues/{other}/comments"}


@pytest.mark.parametrize("event_pr", [None, 0])
def test_converge_delete_refused_without_event_payload_pr_number(event_pr: int | None) -> None:
    api = FakeGitHub(next_id=50, on_create=race(60))
    pr: Any = event_pr
    assert publish(make(api), pr=pr) == ("skipped", github.NOTE_BAD_REQUEST)
    assert api.requests == []


def test_converge_never_deletes_comment_of_another_issue_in_listing() -> None:
    # A listing that (wrongly) includes another issue's comment must not delete it.
    api = FakeGitHub(next_id=50, on_create=race(60, issue=PR + 1))
    assert publish(make(api)) == ("posted", None)
    assert api.deletes() == []
    assert sorted(c["id"] for c in api.comments) == [50, 60]


# SR condition (2): every deleted comment passes both identity checks.


@pytest.mark.parametrize("kind", sorted(DECOYS))
def test_converge_never_deletes_decoys(kind: str) -> None:
    def on_create(api: FakeGitHub) -> None:
        api.comments.append(decoy(kind, 60))
        api.comments.append(decoy(kind, 10))
        api.on_create = None

    api = FakeGitHub(next_id=50, on_create=on_create)
    assert publish(make(api)) == ("posted", None)
    assert api.deletes() == []
    assert len(api.comments) == 3


def test_converge_deletes_only_identity_passing_comments() -> None:
    def on_create(api: FakeGitHub) -> None:
        api.comments.extend(
            [
                decoy("user_with_marker", 55),
                bot_comment(56, f"{MARKER}\nr"),
                decoy("bot_without_marker", 57),
            ]
        )
        api.on_create = None

    api = FakeGitHub(next_id=50, on_create=on_create)
    publish(make(api))
    assert [r.path for r in api.deletes()] == [f"/repos/{REPO}/issues/comments/56"]


def test_delete_guard_rechecks_identity() -> None:
    client = make(FakeGitHub())
    bad = github._Comment(60, decoy("user_with_marker", 60))
    assert client._delete_duplicate(REPO, PR, bad, kept_id=50) is False
    assert client._transport.requests == []  # type: ignore[attr-defined]


# SR condition (3): the kept comment (lowest id, compared as an integer) is never deleted.


def test_converge_kept_lowest_id_never_deleted_numeric_ids() -> None:
    # As strings "9" > "10"; as integers 9 < 10. 9 must be kept.
    api = FakeGitHub(next_id=10, on_create=race(9, 100))
    assert publish(make(api)) == ("updated", None)
    assert [c["id"] for c in api.comments] == [9]
    deleted = sorted(r.path.rsplit("/", 1)[1] for r in api.deletes())
    assert deleted == ["10", "100"]
    assert all(not r.path.endswith("/comments/9") for r in api.deletes())


def test_delete_guard_refuses_kept_or_lower_id() -> None:
    client = make(FakeGitHub())
    assert (
        client._delete_duplicate(REPO, PR, github._Comment(50, bot_comment(50)), kept_id=50)
        is False
    )
    assert (
        client._delete_duplicate(REPO, PR, github._Comment(49, bot_comment(49)), kept_id=50)
        is False
    )
    assert client._transport.requests == []  # type: ignore[attr-defined]


# SR condition (4): at most 5 deletes per run.


def test_converge_max_5_deletes_per_run() -> None:
    assert MAX_CONVERGE_DELETES == 5
    api = FakeGitHub(next_id=10, on_create=race(*range(11, 19)))  # 8 duplicates above ours
    outcome, note = publish(make(api))
    assert outcome == "posted"
    assert note == github.NOTE_DELETE_CAP
    assert len(api.deletes()) == 5
    assert sorted(c["id"] for c in api.comments) == [10, 16, 17, 18]


def test_converge_exactly_5_duplicates_all_deleted_no_note() -> None:
    api = FakeGitHub(next_id=10, on_create=race(*range(11, 16)))
    assert publish(make(api)) == ("posted", None)
    assert len(api.deletes()) == 5


# SR condition (5): fork and Dependabot runs make no writes, deletes included.
# Ruling 2: C1 computes B6 read_only for both, and T-028 then passes comment=None and
# sarif=None, so that is exactly what reaches publish.

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


@pytest.mark.parametrize("who", ["fork", "dependabot"])
def test_converge_fork_and_dependabot_make_no_writes_deletes_included(who: str) -> None:
    comments = [bot_comment(5), bot_comment(6), bot_comment(7)]  # duplicates a write run would fix
    api = FakeGitHub(comments=comments, next_id=50, on_create=race(60))
    client = make(api)
    outcome, note = client.publish(
        repo=REPO, pr_number=PR, run_head_sha=HEAD, comment=None, sarif=None
    )
    assert (outcome, note) == ("skipped", None)
    assert [r for r in api.requests if r.method in WRITE_METHODS] == []
    assert api.requests == []
    assert [c["id"] for c in api.comments] == [5, 6, 7]
    # The read-only lookup T-028 still runs on such a run makes no write either.
    assert client.lookup(repo=REPO, pr_number=PR) == (True, None)
    assert [r for r in api.requests if r.method in WRITE_METHODS] == []


# -- comment=None, SARIF and skipped (AC-F6.11, I-5; rulings 2, 4, 6) ----------------------


def test_comment_false_makes_no_comment_writes() -> None:
    # comment: false reaches publish as comment=None (ruling 2).
    api = FakeGitHub(comments=[bot_comment(5), bot_comment(6)])
    assert publish(make(api), comment=None, sarif=None) == ("skipped", None)
    assert api.requests == []


def test_comment_none_is_skipped_even_with_sarif() -> None:
    # Ruling 6: the outcome is about the comment, and comment=None is skipped.
    api = FakeGitHub(comments=[bot_comment(5)])
    out = publish(make(api), comment=None, sarif='{"version": "2.1.0"}')
    assert out == ("skipped", github.NOTE_SARIF_NO_REF)
    assert api.comment_requests() == []
    assert api.writes() == []


def test_api_failure_is_skipped_with_a_note() -> None:
    # Ruling 6: an API failure is skipped with a note, never an exception.
    api = FakeGitHub(hooks=[lambda r: HttpResponse(500, {}, b"")])
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)
    assert api.writes() == []


def test_comment_false_still_uploads_sarif() -> None:
    # Ruling 4: SARIF follows its own input, so comment=None does not stop the SARIF
    # step. Until publish has a GITHUB_SHA source (open Architect question) that step
    # is a fixed note and no request.
    api = FakeGitHub()
    assert publish(make(api), comment=None, sarif="{}") == ("skipped", github.NOTE_SARIF_NO_REF)
    assert api.requests == []


def _sarif_client(api: FakeGitHub) -> GitHubApiClient:
    client = make(api)
    client._start_deadline()
    return client


def test_sarif_upload_payload() -> None:
    api = FakeGitHub()
    sarif = '{"version": "2.1.0", "runs": []}'
    client = _sarif_client(api)
    assert client._upload_sarif(REPO, sarif, commit_sha=GITHUB_SHA, ref=GITHUB_REF) is None
    assert len(api.sarifs) == 1
    up = api.sarifs[0]
    assert up["commit_sha"] == GITHUB_SHA
    assert up["ref"] == GITHUB_REF
    assert gzip.decompress(base64.b64decode(up["sarif"])).decode() == sarif


def test_sarif_disabled_is_not_uploaded() -> None:
    # sarif: false reaches publish as sarif=None (ruling 2).
    api = FakeGitHub()
    assert publish(make(api), sarif=None) == ("posted", None)
    assert all("code-scanning" not in r.path for r in api.requests)


@pytest.mark.parametrize(
    ("sha", "ref"),
    [
        (None, GITHUB_REF),
        (GITHUB_SHA, None),
        ("main", GITHUB_REF),
        (GITHUB_SHA, "pull/7/merge"),
        (GITHUB_SHA, "refs/x y"),
    ],
)
def test_sarif_without_valid_sha_or_ref_is_skipped(sha: str | None, ref: str | None) -> None:
    api = FakeGitHub()
    client = _sarif_client(api)
    assert client._upload_sarif(REPO, "{}", commit_sha=sha, ref=ref) == github.NOTE_SARIF_NO_REF
    assert api.requests == []


def test_sarif_failure_adds_note_and_keeps_comment_outcome() -> None:
    api = FakeGitHub(
        hooks=[lambda r: HttpResponse(403, {}, b"") if "code-scanning" in r.path else None]
    )
    client = _sarif_client(api)
    note = client._upload_sarif(REPO, "{}", commit_sha=GITHUB_SHA, ref=GITHUB_REF)
    assert note == github.NOTE_SARIF_ERROR
    assert publish(make(FakeGitHub()), sarif="{}") == ("posted", github.NOTE_SARIF_NO_REF)


def test_comment_and_sarif_notes_are_joined() -> None:
    api = FakeGitHub(head_sha=OTHER_HEAD)
    out = publish(make(api), sarif="{}")
    assert out == ("skipped", f"{github.NOTE_HEAD_MOVED} {github.NOTE_SARIF_NO_REF}")


def test_client_satisfies_protocol() -> None:
    client: GitHubClient = make(FakeGitHub())
    assert client.publish(repo=REPO, pr_number=PR, run_head_sha=HEAD, comment=None, sarif=None) == (
        "skipped",
        None,
    )
    assert client.lookup(repo=REPO, pr_number=PR) == (False, None)
    # The production class itself fits the Components factory type, (base_url, token).
    factory: Callable[[str, str], GitHubClient] = GitHubApiClient
    assert Components(github_client=factory).github_client is GitHubApiClient


# -- the stdlib transport (no network: http.client is patched) ------------------------------


class _FakeResp:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, n: int) -> bytes:
        return self._body[:n]

    def getheaders(self) -> list[tuple[str, str]]:
        return [("Content-Type", "application/json"), ("Location", "x")]


class _FakeConn:
    made: ClassVar[list["_FakeConn"]] = []
    body = b"{}"

    def __init__(
        self, host: str, port: int | None, *, timeout: float, context: object = None
    ) -> None:
        self.args = (host, port, timeout, context)
        self.sent: tuple[str, str, bytes | None, dict[str, str]] | None = None
        self.closed = False
        _FakeConn.made.append(self)

    def request(
        self,
        method: str,
        target: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.sent = (method, target, body, headers or {})

    def getresponse(self) -> _FakeResp:
        return _FakeResp(200, _FakeConn.body)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_conn(monkeypatch: pytest.MonkeyPatch) -> type[_FakeConn]:
    _FakeConn.made = []
    _FakeConn.body = b"{}"
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeConn)
    monkeypatch.setattr(http.client, "HTTPConnection", _FakeConn)
    return _FakeConn


def test_transport_https_request(fake_conn: type[_FakeConn]) -> None:
    resp = HttpClientTransport().request(
        "GET", "https://api.github.test/a/b?x=1", {"H": "v"}, None, 4.0
    )
    assert resp == HttpResponse(200, {"content-type": "application/json", "location": "x"}, b"{}")
    conn = fake_conn.made[0]
    assert conn.args[0:3] == ("api.github.test", None, 4.0)
    assert conn.args[3] is not None  # an ssl context
    assert conn.sent == ("GET", "/a/b?x=1", None, {"H": "v"})
    assert conn.closed


def test_transport_http_for_seam(fake_conn: type[_FakeConn]) -> None:
    HttpClientTransport().request("POST", "http://127.0.0.1:9", {}, b"x", 1.0)
    conn = fake_conn.made[0]
    assert conn.args == ("127.0.0.1", 9, 1.0, None)
    assert conn.sent == ("POST", "/", b"x", {})


def test_transport_caps_response_size(fake_conn: type[_FakeConn]) -> None:
    fake_conn.body = b"x" * (github.MAX_RESPONSE_BYTES + 1)
    with pytest.raises(github.ResponseTooLarge):
        HttpClientTransport().request("GET", "https://api.github.test/", {}, None, 1.0)
    assert fake_conn.made[0].closed


def test_default_transport_is_stdlib() -> None:
    client = GitHubApiClient(BASE, TOKEN)
    assert isinstance(client._transport, HttpClientTransport)


def test_constructor_with_bad_base_url_never_connects() -> None:
    api = FakeGitHub()
    client = GitHubApiClient("http://api.github.test", TOKEN, transport=api)
    assert publish(client) == ("skipped", github.NOTE_NO_BASE_URL)
    assert api.requests == []


@pytest.mark.parametrize("location", ["https://api.github.test:bad/x", "http://[::1"])
def test_unparsable_redirect_location_is_a_failure(location: str) -> None:
    api = FakeGitHub(hooks=[_redirect_to(location, once=False)])
    assert publish(make(api)) == ("skipped", github.NOTE_API_ERROR)
    assert all(urlsplit(r.url).netloc == "api.github.test" for r in api.requests)


def test_decoys_cover_every_identity_field() -> None:
    # D-TL-25: the decoy classes must break each field the I-3 identity reads.
    def fields(c: dict[str, Any]) -> dict[str, object]:
        user = c.get("user")
        flat: dict[str, object] = {k: v for k, v in c.items() if k != "user"}
        flat["user"] = user if not isinstance(user, dict) else None
        if isinstance(user, dict):
            flat.update({f"user.{k}": v for k, v in user.items()})
        return flat

    good = fields(bot_comment(5))
    touched: set[str] = set()
    for kind in DECOYS:
        bad = fields(decoy(kind, 5))
        touched |= {k for k in good.keys() | bad.keys() if good.get(k, ...) != bad.get(k, ...)}
    assert {"id", "body", "issue_url", "user.login", "user.type"} <= touched
