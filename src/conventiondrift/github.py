"""C12, the GitHub API client (DESIGN §1, §3a, §4; INTERFACES I-3, I-11 C12, I-14).

This is the only module that reads the token and the only one that opens a
network connection. The rules it follows:

- **Base URL** comes only from ``GITHUB_API_URL`` and must be ``https://``.
  Plain ``http://`` is accepted only when the URL comes through the
  ``Components.github_base_url`` test seam.
- **Token** comes only from ``GITHUB_TOKEN`` in the environment. It is sent
  only in the ``Authorization`` header, only to the base URL's own origin, and
  never appears in a URL, argv, exception, note or ``repr``. A redirect to any
  other origin is never followed, so no other host is contacted at all
  (SECURITY-RULES R4, R6).
- **Errors** never propagate. Every HTTP or transport failure becomes
  ``("skipped", note)`` with a fixed note; the run's result never depends on
  the API (§4, §8.3). Notes never quote a response, header or exception.
- **Deadline (I-13 C12 ruling 3):** each ``lookup`` and each ``publish`` has
  one overall deadline of ``DEADLINE_SECONDS`` covering every request, redirect
  and retry. Each request's socket timeout is ``min(REQUEST_TIMEOUT_SECONDS,
  time left)``. Running out gives ``("skipped", NOTE_DEADLINE)`` from
  ``publish`` and ``(False, NOTE_DEADLINE)`` from ``lookup``; neither raises.
- **Retries:** a retryable failure (transport error, 403, 429, 5xx) is retried
  at most ``MAX_RETRIES`` times with backoff, and only while the backoff ends
  before the deadline.
- **Sticky comment (I-3, ADR-0005, ruling 5):** ours means ``user.login ==
  "github-actions[bot]"``, ``user.type == "Bot"``, an integer id, body line 1
  equal to the marker, **and** an ``issue_url`` naming this repo (ignoring
  case) and this PR. Before writing, the PR's head SHA must equal the run's
  head SHA. It updates the lowest-id match or creates one, and after a create
  it runs the converge step under the Security Reviewer's five conditions.
- **Run facts (ruling 2):** ``publish`` acts only on its arguments. T-028
  passes the event payload's PR number as ``pr_number``, and ``comment=None``
  / ``sarif=None`` when the input is off or the token is read-only (B6), so a
  fork or Dependabot run reaches ``publish`` with nothing to write.
"""

import base64
import gzip
import http.client
import json
import re
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol
from urllib.parse import urljoin, urlsplit

from conventiondrift.components import GitHubClient, PublishOutcome

MARKER: Final = "<!-- conventiondrift:sticky v1 -->"
"""Line 1 of every sticky comment body (I-3)."""
BOT_LOGIN: Final = "github-actions[bot]"
BOT_TYPE: Final = "Bot"

MAX_RETRIES: Final = 2
"""Retries after the first attempt (DESIGN §4)."""
BACKOFF_SECONDS: Final = (0.5, 1.0)
"""Sleep before retry 1 and retry 2."""
DEADLINE_SECONDS: Final = 3.0
"""One overall deadline per ``lookup`` / ``publish`` call, retries included (ruling 3)."""
REQUEST_TIMEOUT_SECONDS: Final = 10.0
"""Upper bound on one request's socket timeout; the deadline usually caps it lower."""
RETRY_STATUSES: Final = frozenset({403, 429, 500, 502, 503, 504})
"""HTTP statuses that are retried: rate limit, 403 and 5xx (DESIGN §4)."""
REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS: Final = 3
MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
COMMENTS_PER_PAGE: Final = 100
MAX_COMMENT_PAGES: Final = 50
MAX_CONVERGE_DELETES: Final = 5
"""SR condition 4: a run deletes at most this many duplicate comments (I-3)."""
API_VERSION: Final = "2022-11-28"
USER_AGENT: Final = "conventiondrift"

NOTE_NO_BASE_URL: Final = (
    "GitHub API access was skipped because GITHUB_API_URL is not a valid https URL."
)
NOTE_NO_AUTH: Final = "GitHub API access was skipped because no usable token was provided."
NOTE_BAD_REQUEST: Final = (
    "GitHub API access was skipped because the repository, PR number or head SHA is invalid."
)
NOTE_BAD_BODY: Final = "The PR comment was skipped because its body has no sticky marker."
NOTE_API_ERROR: Final = (
    "The PR comment could not be written because the GitHub API returned an error."
)
NOTE_LOOKUP_ERROR: Final = (
    "The existing PR comment could not be looked up because the GitHub API returned an error."
)
NOTE_HEAD_MOVED: Final = "The PR comment was left unchanged because the PR has a newer head commit."
NOTE_CONVERGE_ERROR: Final = (
    "Duplicate conventiondrift comments could not all be removed; a later run will retry."
)
NOTE_DELETE_CAP: Final = (
    "More than 5 duplicate conventiondrift comments were found; the rest are left for a later run."
)
NOTE_SARIF_ERROR: Final = "The SARIF upload to code scanning failed."
NOTE_SARIF_NO_REF: Final = (
    "The SARIF upload was skipped because GITHUB_SHA or GITHUB_REF is missing or invalid."
)
NOTE_DEADLINE: Final = (
    "GitHub API access stopped because it did not finish within its 3 second limit."
)

_SHA = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")
_REF = re.compile(r"refs/[\x21-\x7e]{1,250}")


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """One HTTP response. ``headers`` keys are lower-case."""

    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    """Sends one HTTP request and never follows redirects. Tests inject fakes."""

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse: ...


class ResponseTooLarge(Exception):
    """A response body was over ``MAX_RESPONSE_BYTES``."""


class HttpClientTransport:
    """The production transport on stdlib ``http.client``; it never follows redirects."""

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        parts = urlsplit(url)
        host = parts.hostname or ""
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                host, parts.port, timeout=timeout, context=ssl.create_default_context()
            )
        else:
            conn = http.client.HTTPConnection(host, parts.port, timeout=timeout)
        try:
            conn.request(method, target, body=body, headers=dict(headers))
            resp = conn.getresponse()
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ResponseTooLarge
            return HttpResponse(resp.status, {k.lower(): v for k, v in resp.getheaders()}, data)
        finally:
            conn.close()


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host or parts.scheme not in ("http", "https"):
        return None
    return parts.scheme, host, port or (443 if parts.scheme == "https" else 80)


def normalize_base_url(url: str, *, allow_http: bool) -> str | None:
    """Return the base URL without a trailing ``/``, or ``None`` when it is not allowed."""
    if not url or any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url):
        return None
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 -- raises ValueError for a bad port
    except ValueError:
        return None
    allowed = ("https", "http") if allow_http else ("https",)
    if parts.scheme not in allowed or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.query or parts.fragment or "?" in url or "#" in url:
        return None
    return url.rstrip("/")


def is_marked(body: str) -> bool:
    """True when line 1 of ``body`` is exactly the sticky marker (I-3)."""
    first = body.split("\n", 1)[0]
    if first.endswith("\r"):
        first = first[:-1]
    return first == MARKER


def _has_id(comment: Mapping[str, object], repo: str, pr_number: int) -> bool:
    cid = comment.get("id")
    return type(cid) is int and cid >= 1


def _has_bot_identity(comment: Mapping[str, object], repo: str, pr_number: int) -> bool:
    user = comment.get("user")
    return (
        isinstance(user, dict) and user.get("login") == BOT_LOGIN and user.get("type") == BOT_TYPE
    )


def _has_marker(comment: Mapping[str, object], repo: str, pr_number: int) -> bool:
    body = comment.get("body")
    return isinstance(body, str) and is_marked(body)


def _names_this_pr(comment: Mapping[str, object], repo: str, pr_number: int) -> bool:
    issue_url = comment.get("issue_url")
    if not isinstance(issue_url, str):
        return False  # a comment without issue_url is never edited or deleted (ruling 5)
    try:
        path = urlsplit(issue_url).path
    except ValueError:
        return False
    return path.casefold().endswith(f"/repos/{repo}/issues/{pr_number}".casefold())


OURS_CONDITIONS: Final[Mapping[str, Callable[[Mapping[str, object], str, int], bool]]] = {
    "id": _has_id,
    "bot_identity": _has_bot_identity,
    "marker": _has_marker,
    "issue_url": _names_this_pr,
}
"""Every condition a comment must pass to count as ours (I-3; I-13 C12 ruling 5)."""


def failed_conditions(comment: object, *, repo: str, pr_number: int) -> frozenset[str]:
    """The names in ``OURS_CONDITIONS`` that ``comment`` fails (all of them for a non-dict)."""
    if not isinstance(comment, dict):
        return frozenset(OURS_CONDITIONS)
    return frozenset(
        name for name, check in OURS_CONDITIONS.items() if not check(comment, repo, pr_number)
    )


def is_ours(comment: object, *, repo: str, pr_number: int) -> bool:
    """Both I-3 identity checks, the marker, a valid integer id and ``issue_url`` naming this PR."""
    return not failed_conditions(comment, repo=repo, pr_number=pr_number)


@dataclass(frozen=True, slots=True)
class _Comment:
    id: int
    raw: Mapping[str, object]


Method = Literal["GET", "POST", "PATCH", "DELETE"]


class GitHubApiClient:
    """The production C12 client. It satisfies ``components.GitHubClient``.

    The constructor never raises and never validates by raising: an unusable
    base URL or token makes every call return ``skipped`` with a fixed note.
    """

    __slots__ = (
        "_base",
        "_clock",
        "_deadline",
        "_expired",
        "_sleep",
        "_token",
        "_transport",
        "_unusable",
    )

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        allow_http: bool = False,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        base = normalize_base_url(base_url, allow_http=allow_http)
        self._base = base or ""
        self._token = token if _TOKEN.fullmatch(token or "") else ""
        self._transport: Transport = transport or HttpClientTransport()
        self._sleep = sleep
        self._clock = clock
        self._deadline = 0.0
        self._expired = False
        self._unusable: str | None = None
        if base is None:
            self._unusable = NOTE_NO_BASE_URL
        elif not self._token:
            self._unusable = NOTE_NO_AUTH

    def __repr__(self) -> str:
        return f"GitHubApiClient(base_url={self._base!r}, token=<redacted>)"

    __str__ = __repr__

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("GitHubApiClient holds a token and cannot be pickled")

    # -- HTTP -----------------------------------------------------------------

    def _headers(self, url: str, *, has_body: bool) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if has_body:
            headers["Content-Type"] = "application/json"
        if _origin(url) is not None and _origin(url) == _origin(self._base):
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _start_deadline(self) -> None:
        self._deadline = self._clock() + DEADLINE_SECONDS
        self._expired = False

    def _time_left(self) -> float:
        return self._deadline - self._clock()

    def _once(self, method: Method, url: str, body: bytes | None) -> HttpResponse | None:
        for _ in range(MAX_REDIRECTS + 1):
            if _origin(url) != _origin(self._base):
                return None  # never contact, let alone send the token to, another origin
            left = self._time_left()
            if left <= 0:
                self._expired = True
                return None
            try:
                resp = self._transport.request(
                    method,
                    url,
                    self._headers(url, has_body=body is not None),
                    body,
                    min(REQUEST_TIMEOUT_SECONDS, left),
                )
            except Exception:  # noqa: BLE001 -- §4: any transport failure is a note, never a crash
                return None
            if resp.status not in REDIRECT_STATUSES or method != "GET":
                return resp
            location = resp.headers.get("location")
            if not location:
                return resp
            try:
                url = urljoin(url, location)
            except ValueError:
                return None
        return None

    def _call(self, method: Method, path: str, payload: object = None) -> HttpResponse | None:
        url = self._base + path
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        attempt = 0
        while True:
            resp = self._once(method, url, body)
            if resp is not None and resp.status not in RETRY_STATUSES:
                return resp
            if self._expired or attempt >= MAX_RETRIES:
                return resp
            delay = BACKOFF_SECONDS[attempt]
            if self._time_left() - delay <= 0:
                self._expired = True  # the retry could not start before the deadline
                return resp
            self._sleep(delay)
            attempt += 1

    @staticmethod
    def _json(resp: HttpResponse | None, *, ok: frozenset[int]) -> object:
        if resp is None or resp.status not in ok:
            return None
        try:
            return json.loads(resp.body.decode("utf-8"))
        except (ValueError, RecursionError):
            return None

    # -- reads ----------------------------------------------------------------

    def _pr_head(self, repo: str, pr_number: int) -> str | None:
        data = self._json(self._call("GET", f"/repos/{repo}/pulls/{pr_number}"), ok=_OK)
        if not isinstance(data, dict):
            return None
        head = data.get("head")
        sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(sha, str) or not _SHA.fullmatch(sha):
            return None
        return sha.lower()

    def _list_ours(self, repo: str, pr_number: int) -> list[_Comment] | None:
        ours: list[_Comment] = []
        for page in range(1, MAX_COMMENT_PAGES + 1):
            path = (
                f"/repos/{repo}/issues/{pr_number}/comments"
                f"?per_page={COMMENTS_PER_PAGE}&page={page}"
            )
            data = self._json(self._call("GET", path), ok=_OK)
            if not isinstance(data, list):
                return None
            for item in data:
                if is_ours(item, repo=repo, pr_number=pr_number):
                    ours.append(_Comment(item["id"], item))
            if len(data) < COMMENTS_PER_PAGE:
                break
        return ours

    def _check(self, repo: str, pr_number: int, run_head_sha: str | None) -> str | None:
        if self._unusable is not None:
            return self._unusable
        if not isinstance(repo, str) or not _REPO.fullmatch(repo):
            return NOTE_BAD_REQUEST
        if any(part in (".", "..") for part in repo.split("/")):
            return NOTE_BAD_REQUEST
        if type(pr_number) is not int or pr_number < 1:
            return NOTE_BAD_REQUEST
        if run_head_sha is not None and (
            not isinstance(run_head_sha, str) or not _SHA.fullmatch(run_head_sha)
        ):
            return NOTE_BAD_REQUEST
        return None

    def lookup(self, *, repo: str, pr_number: int) -> tuple[bool, str | None]:
        """Read-only: does our sticky comment already exist on this PR? (§2 step 8, S7).

        It only GETs and never raises (I-13 C12 ruling 1).
        """
        try:
            note = self._check(repo, pr_number, None)
            if note is not None:
                return False, note
            self._start_deadline()
            ours = self._list_ours(repo, pr_number)
            if self._expired:
                return False, NOTE_DEADLINE
            if ours is None:
                return False, NOTE_LOOKUP_ERROR
            return bool(ours), None
        except Exception:  # noqa: BLE001 -- the Protocol promises lookup never raises
            return False, NOTE_LOOKUP_ERROR

    # -- writes ---------------------------------------------------------------

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
    ) -> tuple[PublishOutcome, str | None]:
        """Write the sticky comment and upload SARIF; never raises for HTTP errors.

        It acts only on its arguments (ruling 2): ``comment=None`` makes no
        comment request of any kind (no list, create, update or delete), and
        ``sarif=None`` makes no SARIF request. ``sarif_commit_sha`` and
        ``sarif_ref`` are ``GITHUB_SHA`` / ``GITHUB_REF`` from T-028 and go to
        the upload verbatim; C12 never derives them (ruling 7). The outcome
        describes the
        comment, so ``comment=None`` is ``skipped`` (ruling 6); T-028 writes the
        summary note saying why the comment was off.
        """
        note = self._check(repo, pr_number, run_head_sha)
        if note is not None:
            return "skipped", note
        if comment is None and sarif is None:
            return "skipped", None
        self._start_deadline()
        notes: list[str] = []
        outcome: PublishOutcome = "skipped"
        if comment is not None:
            outcome, cnote = self._publish_comment(repo, pr_number, run_head_sha.lower(), comment)
            if cnote:
                notes.append(cnote)
        if sarif is not None:
            snote = self._upload_sarif(repo, sarif, commit_sha=sarif_commit_sha, ref=sarif_ref)
            if snote:
                notes.append(snote)
        if self._expired:
            return "skipped", NOTE_DEADLINE
        return outcome, " ".join(notes) or None

    def _publish_comment(
        self, repo: str, pr_number: int, run_head_sha: str, body: str
    ) -> tuple[PublishOutcome, str | None]:
        if not is_marked(body):
            return "skipped", NOTE_BAD_BODY
        head = self._pr_head(repo, pr_number)
        if head is None:
            return "skipped", NOTE_API_ERROR
        if head != run_head_sha:
            return "skipped", NOTE_HEAD_MOVED
        ours = self._list_ours(repo, pr_number)
        if ours is None:
            return "skipped", NOTE_API_ERROR
        if ours:
            kept = min(ours, key=lambda c: c.id)
            if self._update(repo, kept.id, body):
                return "updated", None
            return "skipped", NOTE_API_ERROR
        created = self._json(
            self._call("POST", f"/repos/{repo}/issues/{pr_number}/comments", {"body": body}),
            ok=frozenset({201}),
        )
        cid = created.get("id") if isinstance(created, dict) else None
        if type(cid) is not int or cid < 1:
            return "skipped", NOTE_API_ERROR
        return self._converge(repo, pr_number, run_head_sha, body, cid)

    def _update(self, repo: str, comment_id: int, body: str) -> bool:
        resp = self._call("PATCH", f"/repos/{repo}/issues/comments/{comment_id}", {"body": body})
        return resp is not None and resp.status in _OK

    def _converge(
        self, repo: str, pr_number: int, run_head_sha: str, body: str, created_id: int
    ) -> tuple[PublishOutcome, str | None]:
        """I-3 converge-after-create, under the Security Reviewer's five conditions."""
        ours = self._list_ours(repo, pr_number)
        head = self._pr_head(repo, pr_number)
        if ours is None:
            return "posted", NOTE_CONVERGE_ERROR
        if len(ours) <= 1:
            return "posted", None
        kept_id = min(c.id for c in ours)
        duplicates = sorted((c for c in ours if c.id > kept_id), key=lambda c: c.id)
        notes: list[str] = []
        failed = False
        for dup in duplicates[:MAX_CONVERGE_DELETES]:
            if not self._delete_duplicate(repo, pr_number, dup, kept_id):
                failed = True
        if failed:
            notes.append(NOTE_CONVERGE_ERROR)
        if len(duplicates) > MAX_CONVERGE_DELETES:
            notes.append(NOTE_DELETE_CAP)
        outcome: PublishOutcome
        if kept_id == created_id:
            outcome = "posted"
        elif head == run_head_sha:
            if self._update(repo, kept_id, body):
                outcome = "updated"
            else:
                outcome = "posted"
                notes.append(NOTE_API_ERROR)
        else:
            outcome = "skipped"
            notes.append(NOTE_HEAD_MOVED)
        return outcome, " ".join(notes) or None

    def _delete_duplicate(self, repo: str, pr_number: int, dup: _Comment, kept_id: int) -> bool:
        # Conditions 1-3 are re-checked here, right before the DELETE.
        if type(dup.id) is not int or dup.id <= kept_id:
            return False
        if not is_ours(dup.raw, repo=repo, pr_number=pr_number):
            return False
        resp = self._call("DELETE", f"/repos/{repo}/issues/comments/{dup.id}")
        # A 404 means another run already removed it: success, never an error (I-3).
        return resp is not None and resp.status in (200, 204, 404)

    def _upload_sarif(self, repo: str, sarif: str, *, commit_sha: str, ref: str) -> str | None:
        # I-5: commit_sha = GITHUB_SHA and ref = GITHUB_REF, sent exactly as given
        # (ruling 7). A missing or malformed value skips the upload with a note.
        if not commit_sha or not _SHA.fullmatch(commit_sha) or not ref or not _REF.fullmatch(ref):
            return NOTE_SARIF_NO_REF
        packed = base64.b64encode(gzip.compress(sarif.encode("utf-8"), mtime=0)).decode("ascii")
        payload = {"commit_sha": commit_sha, "ref": ref, "sarif": packed}
        resp = self._call("POST", f"/repos/{repo}/code-scanning/sarifs", payload)
        if resp is None or resp.status not in _OK:
            return NOTE_SARIF_ERROR
        return None


_OK: Final = frozenset({200, 201, 202, 204})


class _SkippingClient:
    """Returned when the base URL from the environment is not allowed; it never connects."""

    __slots__ = ("_note",)

    def __init__(self, note: str) -> None:
        self._note = note

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
    ) -> tuple[PublishOutcome, str | None]:
        return "skipped", self._note

    def lookup(self, *, repo: str, pr_number: int) -> tuple[bool, str | None]:
        return False, self._note


def client_from_env(
    env: Mapping[str, str],
    *,
    base_url_override: str | None = None,
    factory: Callable[[str, str], GitHubClient] | None = None,
    transport: Transport | None = None,
) -> GitHubClient:
    """Build C12 from the environment, for the CLI only (I-13 C12 ruling 2).

    The Action path (T-028) reads the token itself and calls the
    ``Components.github_client`` factory, ``(base_url, token)``, or
    ``GitHubApiClient`` directly. Here the base URL is ``GITHUB_API_URL``
    (https only), or ``base_url_override`` from ``Components.github_base_url``
    (http allowed, tests only). ``factory`` is ``Components.github_client``;
    ``None`` means ``GitHubApiClient``.
    """
    allow_http = base_url_override is not None
    raw = base_url_override if base_url_override is not None else env.get("GITHUB_API_URL", "")
    base = normalize_base_url(raw, allow_http=allow_http)
    if base is None:
        return _SkippingClient(NOTE_NO_BASE_URL)
    token = env.get("GITHUB_TOKEN", "")
    if factory is not None:
        return factory(base, token)
    return GitHubApiClient(base, token, allow_http=allow_http, transport=transport)


ALL_NOTES: Final = frozenset(
    {
        NOTE_NO_BASE_URL,
        NOTE_NO_AUTH,
        NOTE_BAD_REQUEST,
        NOTE_BAD_BODY,
        NOTE_API_ERROR,
        NOTE_LOOKUP_ERROR,
        NOTE_HEAD_MOVED,
        NOTE_CONVERGE_ERROR,
        NOTE_DELETE_CAP,
        NOTE_SARIF_ERROR,
        NOTE_SARIF_NO_REF,
        NOTE_DEADLINE,
    }
)
"""Every fixed note C12 can return. Notes never quote a response, header or exception."""
