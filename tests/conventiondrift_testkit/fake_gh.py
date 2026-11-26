"""A stateful, in-process GitHub API for tests: a real ``github.Transport`` (CON-29).

No sockets and no HTTP server: :class:`FakeGitHub` implements the existing production seam
``github.Transport`` (``request(method, url, headers, body, timeout) -> HttpResponse``), so
``GitHubApiClient`` runs completely unchanged over it. That keeps every C12 hardening path under
test (token header, redirect refusal, retry, deadline, notes) on every platform, Windows
included, and it composes with ``net_monitor`` because nothing here opens a connection.

**Writes are default-deny.** Recording ``requests`` alone means a test that forgets to assert
still passes while writing, which is exactly what CON-29 ("asserts zero write calls") is meant to
stop. A ``POST``/``PATCH``/``DELETE`` therefore raises :class:`UnexpectedWrite` unless the test
asked for it first with :meth:`FakeGitHub.expect_write` (finally giving that write a legitimate
reason to exist) or opted out for the whole fake with :meth:`FakeGitHub.allow_all_writes`.
Read-only paths - ``lookup``, a head-only run, a skipped comment - need no declaration and get
the zero-write assertion for free.

A ``hook`` reply is served before the default-deny check, so a hook is the explicit escape
hatch: a test that answers a write itself has taken responsibility for that write.

Failure injection is one-shot and applies to the next request, before routing:
:meth:`FakeGitHub.fail_next` (401/403/404/429/5xx), :meth:`FakeGitHub.timeout_next` (raises
``github.DeadlineExceeded``), :meth:`FakeGitHub.malformed_next` (200 with a body that is not
JSON) and :meth:`FakeGitHub.redirect_next` (a redirect reply; C12 must never contact the new
origin).
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, BinaryIO, Final
from urllib.parse import parse_qs, urlsplit

from conventiondrift.github import BOT_LOGIN, BOT_TYPE, DeadlineExceeded, HttpResponse

__all__ = [
    "BASE_URL",
    "PR_NUMBER",
    "REPO",
    "FakeGitHub",
    "Req",
    "UnexpectedWrite",
]

REPO: Final = "octo/demo"
PR_NUMBER: Final = 7
BASE_URL: Final = "https://api.github.test"
TOKEN: Final = "fake-token-for-tests-0000"  # noqa: S105 -- an obvious fake, never a real secret
_HEAD: Final = "a" * 40

_ROUTE: Final = re.compile(r"^/repos/([^/]+/[^/]+)/(pulls|issues|code-scanning)/(.+)$")


@dataclass(frozen=True, slots=True)
class Req:
    """One request the fake received. ``repr`` redacts the token header."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    timeout: float = 0.0

    def __repr__(self) -> str:
        safe = {
            k: ("<redacted>" if k.lower() in ("authorization", "proxy-authorization") else v)
            for k, v in self.headers.items()
        }
        return f"Req({self.method} {self.url!r}, headers={safe!r}, body={self.body!r})"

    @property
    def path(self) -> str:
        return urlsplit(self.url).path

    @property
    def query(self) -> dict[str, list[str]]:
        return parse_qs(urlsplit(self.url).query)

    @property
    def json(self) -> Any:
        if self.body is None:
            return None
        return json.loads(self.body)


class UnexpectedWrite(BaseException):
    """A write request no test declared: the fake refuses it instead of quietly recording it.

    It derives from ``BaseException``, not ``Exception``, on purpose. C12's whole contract is that
    a transport failure becomes a note (``_once`` catches ``Exception``), so an ``Exception`` here
    would be swallowed and the test would pass with a quietly refused write. A test bug must not
    look like a handled API failure.
    """


@dataclass(slots=True)
class _Allow:
    method: str | None
    suffix: str | None
    remaining: int


@dataclass(slots=True)
class _Fault:
    status: int | None = None
    body: bytes | None = None
    headers: Mapping[str, str] | None = None
    timeout: bool = False


class FakeGitHub:
    """In-memory GitHub API over the ``github.Transport`` seam; writes are default-deny."""

    def __init__(
        self,
        *,
        head_sha: str = _HEAD,
        login: str = BOT_LOGIN,
        login_type: str = BOT_TYPE,
        base_url: str = BASE_URL,
        repo: str = REPO,
        pr_number: int = PR_NUMBER,
    ) -> None:
        self.head_sha = head_sha
        self.login = login
        self.login_type = login_type
        self.base_url = base_url
        self.repo = repo
        self.pr_number = pr_number
        self.requests: list[Req] = []
        self.comments: list[dict[str, Any]] = []
        self.sarifs: list[dict[str, Any]] = []
        self.hooks: list[Callable[[Req], HttpResponse | None]] = []
        self.unexpected_writes: list[Req] = []
        self.faults: list[_Fault] = []
        self._allow: list[_Allow] = []
        self._allow_all = False
        self._next_id = 1000

    def __repr__(self) -> str:
        return f"FakeGitHub(repo={self.repo!r}, pr={self.pr_number}, requests={len(self.requests)})"

    # -- the Transport ---------------------------------------------------------

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
        if self.faults:
            fault = self.faults.pop(0)
            if fault.timeout:
                raise DeadlineExceeded
            return HttpResponse(fault.status or 500, dict(fault.headers or {}), fault.body or b"")
        for hook in self.hooks:
            reply = hook(req)
            if reply is not None:
                return reply
        if req.method != "GET":
            self._check_write(req)
        return self._route(req)

    # -- write posture --------------------------------------------------------

    def expect_write(self, method: str = "*", path: str | None = None, *, times: int = 1) -> None:
        """Allow up to ``times`` writes that match ``method`` (or any) and ``path`` suffix."""
        if times < 1:
            raise ValueError("times must be at least 1")
        self._allow.append(_Allow(None if method == "*" else method.upper(), path, times))

    def allow_all_writes(self) -> None:
        """Opt this fake out of default-deny (for a test that asserts on the recorded writes)."""
        self._allow_all = True

    def _check_write(self, req: Req) -> None:
        if self._allow_all:
            return
        for allow in self._allow:
            if allow.method is not None and allow.method != req.method:
                continue
            if allow.suffix is not None and not req.path.endswith(allow.suffix):
                continue
            allow.remaining -= 1
            if allow.remaining == 0:
                self._allow.remove(allow)
            return
        self.unexpected_writes.append(req)
        raise UnexpectedWrite(f"undeclared write: {req.method} {req.path}")

    def writes(self) -> list[Req]:
        return [r for r in self.requests if r.method != "GET"]

    def deletes(self) -> list[Req]:
        return [r for r in self.requests if r.method == "DELETE"]

    def comment_requests(self) -> list[Req]:
        """Only the comment endpoints; the pull-request head read is not a comment request."""
        return [r for r in self.requests if "/comments" in r.path]

    def requests_to(self, suffix: str) -> list[Req]:
        return [r for r in self.requests if r.path.endswith(suffix)]

    def assert_no_writes(self) -> None:
        """Fail with the offending calls unless the run made no write request at all."""
        writes = self.writes()
        if writes:
            calls = [f"{r.method} {r.path}" for r in writes]
            raise AssertionError(f"expected no writes, got: {calls}")

    # -- state ----------------------------------------------------------------

    def seed_comment(self, body: str, *, cid: int | None = None, ours: bool = True) -> int:
        """Place a comment as if a previous run (or a human) had left it. Returns its id."""
        cid = self._next_id if cid is None else cid
        self._next_id = max(self._next_id, cid) + 1
        login, login_type = (self.login, self.login_type) if ours else ("someone", "User")
        self.comments.append(self._comment(cid, body, login, login_type, self.pr_number))
        return cid

    def comment_bodies(self) -> list[str]:
        return [str(c.get("body", "")) for c in self.comments]

    def sarif_payloads(self) -> list[dict[str, Any]]:
        return list(self.sarifs)

    def sarif_texts(self) -> list[str]:
        """The uploaded SARIF documents, ungzipped and base64-decoded."""
        out: list[str] = []
        for payload in self.sarifs:
            packed = payload.get("sarif")
            if isinstance(packed, str):
                out.append(gzip.decompress(base64.b64decode(packed)).decode("utf-8"))
        return out

    def _comment(
        self, cid: int, body: str, login: str, login_type: str, pr_number: int
    ) -> dict[str, Any]:
        return {
            "id": cid,
            "user": {"login": login, "type": login_type},
            "body": body,
            "issue_url": f"{self.base_url}/repos/{self.repo}/issues/{pr_number}",
        }

    # -- fault injection ------------------------------------------------------

    def fail_next(self, status: int = 500, *, body: bytes | None = None) -> None:
        """The next request replies with ``status`` (401/403/404/429/5xx)."""
        self.faults.append(_Fault(status=status, body=body))

    def timeout_next(self) -> None:
        """The next request raises ``github.DeadlineExceeded``, as the real transport does."""
        self.faults.append(_Fault(timeout=True))

    def malformed_next(self) -> None:
        """The next request returns 200 with a body that is not JSON."""
        self.faults.append(_Fault(status=200, body=b"{not json"))

    def redirect_next(self, location: str, *, status: int = 302) -> None:
        """The next request redirects to ``location``; C12 must not contact that origin."""
        self.faults.append(_Fault(status=status, headers={"location": location}, body=b""))

    # -- replies --------------------------------------------------------------

    @staticmethod
    def reply(
        status: int, data: object = None, headers: Mapping[str, str] | None = None
    ) -> HttpResponse:
        body = b"" if data is None else json.dumps(data).encode("utf-8")
        return HttpResponse(status, dict(headers or {}), body)

    def _route(self, req: Req) -> HttpResponse:
        match = _ROUTE.match(req.path)
        if match is None:
            return self.reply(404, {"message": "Not Found"})
        repo, kind, rest = match.group(1), match.group(2), match.group(3)
        if repo != self.repo:
            return self.reply(404, {"message": "Not Found"})
        if kind == "pulls":
            return self._pull(req, rest)
        if kind == "issues":
            return self._issue(req, rest)
        if kind == "code-scanning":
            return self._code_scanning(req, rest)
        return self.reply(404, {"message": "Not Found"})  # pragma: no cover - regex guard

    def _pull(self, req: Req, rest: str) -> HttpResponse:
        number, _, tail = rest.partition("/")
        if tail or not number.isdigit():
            return self.reply(404, {"message": "Not Found"})
        if req.method != "GET":
            return self.reply(405, {"message": "Method Not Allowed"})
        return self.reply(200, {"number": int(number), "head": {"sha": self.head_sha}})

    def _issue(self, req: Req, rest: str) -> HttpResponse:
        number, _, tail = rest.partition("/")
        if tail == "comments" and number.isdigit():
            return self._comments(req, int(number))
        if number == "comments" and tail.isdigit():
            return self._comment_item(req, int(tail))
        return self.reply(404, {"message": "Not Found"})

    def _comments(self, req: Req, number: int) -> HttpResponse:
        if req.method == "GET":
            per = int(req.query.get("per_page", ["30"])[0])
            page = int(req.query.get("page", ["1"])[0])
            ordered = sorted(self.comments, key=lambda c: int(c.get("id", 0)))
            return self.reply(200, ordered[(page - 1) * per : page * per])
        if req.method == "POST":
            payload = req.json if req.body is not None else None
            body = payload.get("body") if isinstance(payload, dict) else None
            if not isinstance(body, str):
                return self.reply(400, {"message": "Bad Request"})
            cid = self._next_id
            self._next_id += 1
            self.comments.append(self._comment(cid, body, self.login, self.login_type, number))
            return self.reply(201, {"id": cid})
        return self.reply(405, {"message": "Method Not Allowed"})

    def _comment_item(self, req: Req, cid: int) -> HttpResponse:
        found = [c for c in self.comments if c.get("id") == cid]
        if not found:
            return self.reply(404, {"message": "Not Found"})
        if req.method == "PATCH":
            payload = req.json if req.body is not None else None
            body = payload.get("body") if isinstance(payload, dict) else None
            if not isinstance(body, str):
                return self.reply(400, {"message": "Bad Request"})
            found[0]["body"] = body
            return self.reply(200, found[0])
        if req.method == "DELETE":
            self.comments.remove(found[0])
            return self.reply(204)
        return self.reply(405, {"message": "Method Not Allowed"})

    def _code_scanning(self, req: Req, rest: str) -> HttpResponse:
        if rest != "sarifs" or req.method != "POST":
            return self.reply(404, {"message": "Not Found"})
        payload = req.json if req.body is not None else None
        if not isinstance(payload, dict):
            return self.reply(400, {"message": "Bad Request"})
        self.sarifs.append(payload)
        return self.reply(202, {"id": "sarif-1"})

    # -- wiring ---------------------------------------------------------------

    def client(
        self,
        *,
        token: str = TOKEN,
        base_url: str | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> Any:
        """A real ``GitHubApiClient`` over this fake (production code, no sockets)."""
        from conventiondrift.github import GitHubApiClient

        if sleep is None:
            return GitHubApiClient(base_url or self.base_url, token, transport=self)
        return GitHubApiClient(base_url or self.base_url, token, transport=self, sleep=sleep)

    def components(
        self,
        *,
        sinks: Any = None,
        env: Mapping[str, str] | None = None,
        token: str = TOKEN,
        base_url: str | None = None,
        stdout: BinaryIO | None = None,
    ) -> Any:
        """``Components`` wired to this fake.

        With ``env=gh.env`` the sink is the production ``ActionSinks`` over this fake, so one
        test asserts both the HTTP side (comment, SARIF, lookup) and the runner side (outputs,
        summary, annotations, artifacts). With ``sinks=MemorySinks()`` every runner write stays
        in memory. With neither, ``ActionSinks`` over an empty env writes nothing.
        """
        from conventiondrift.components import Components
        from conventiondrift.sinks import ActionSinks

        client = self.client(token=token, base_url=base_url)
        sink = sinks
        if sink is None:
            sink = ActionSinks(env or {}, client, stdout=stdout or io.BytesIO())
        return Components(
            github_client=lambda _base, _token: client,
            github_base_url=base_url or self.base_url,
            sinks=sink,
        )

    # -- introspection helpers -------------------------------------------------

    def ours(self) -> list[dict[str, Any]]:
        """Comments that satisfy C12's "is this our sticky comment" conditions."""
        from conventiondrift.github import is_ours

        return [c for c in self.comments if is_ours(c, repo=self.repo, pr_number=self.pr_number)]

    def headers_of(self, index: int = -1) -> Mapping[str, str]:
        return self.requests[index].headers

    def methods(self) -> Sequence[str]:
        return [r.method for r in self.requests]
