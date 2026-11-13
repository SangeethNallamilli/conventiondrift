"""Tests for C12's transport deadline (I-13 C12 ruling 3).

Timing is deterministic. The deadline tests drive the real ``HttpClientTransport``
and ``http.client`` over a scripted fake socket on a fake clock: each socket
operation spends its scripted delay on the fake clock, and a delay longer than
the timeout the transport set costs exactly that timeout and raises
``TimeoutError``, as a real socket would. Nothing sleeps. The watchdog timer is
a fake that the tests fire by hand.

A second group runs the transport over real local sockets (127.0.0.1 only) to
check the plumbing: request and response bytes, chunked bodies, the size cap,
refused connections, address fallback, DNS and the TLS path. Those tests assert
outcomes, not durations, except one generous upper bound on a stalled server.
"""

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Any

import pytest

from conventiondrift import github
from conventiondrift.github import (
    DEADLINE_SECONDS,
    MARKER,
    REQUEST_TIMEOUT_SECONDS,
    DeadlineExceeded,
    GitHubApiClient,
    HttpClientTransport,
    ResponseTooLarge,
    _read_body,
    _shutdown,
    _Watchdog,
)

TOKEN = "fake-token-for-tests-0000"  # noqa: S105 -- an obvious fake, never a real secret
REPO = "octo/demo"
PR = 7
HEAD = "a" * 40
SLACK = 0.5  # allowed overrun past the deadline (the fake clock never uses it)
START = 1000.0


# -- fakes: clock, timer, scripted socket, TLS ---------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> float:
        return self.now


class FakeTimer:
    """Stands in for ``threading.Timer``: never runs on its own; ``fire`` runs it."""

    def __init__(self, seconds: float, function: Callable[[], None]) -> None:
        self.seconds = seconds
        self.function = function
        self.daemon = False
        self.started = self.cancelled = self.joined = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True

    def join(self, timeout: float | None = None) -> None:
        self.joined = True

    def fire(self) -> None:
        self.function()


Step = tuple[float, bytes]
"""One scripted server reply: (delay in seconds, bytes)."""


class FakeSocket:
    """A scripted peer on a fake clock.

    Every operation costs its delay. If the delay is longer than the timeout
    currently set, the operation costs exactly the timeout and raises
    ``TimeoutError`` (the rest of the delay stays for the next call), like a
    real blocking socket with a timeout.
    """

    def __init__(
        self,
        clock: FakeClock,
        replies: Sequence[Step] = (),
        *,
        connect_delay: float = 0.0,
        handshake_delay: float = 0.0,
        send_delay: float = 0.0,
        send_max: int | None = None,
        on_recv: Callable[[], None] | None = None,
    ) -> None:
        self.clock = clock
        self.replies = list(replies)
        self.connect_delay = connect_delay
        self.handshake_delay = handshake_delay
        self.send_delay = send_delay
        self.send_max = send_max
        self.on_recv = on_recv
        self.timeout: float | None = None
        self.timeouts: list[float] = []
        self.sent = b""
        self.recvs = 0
        self.closed = False
        self.shut = False
        self.shut_how: int | None = None

    def _spend(self, delay: float) -> float:
        """Spend ``delay`` (or the timeout, raising); return what is left of it."""
        if self.timeout is not None and delay > self.timeout:
            self.clock.now += self.timeout
            raise TimeoutError("timed out")
        self.clock.now += delay
        return 0.0

    def settimeout(self, value: float | None) -> None:
        self.timeout = value
        if value is not None:
            self.timeouts.append(value)

    def connect(self, address: object) -> None:
        self._spend(self.connect_delay)

    def do_handshake(self) -> None:
        self._spend(self.handshake_delay)

    def send(self, data: memoryview) -> int:
        self._spend(self.send_delay)
        n = len(data) if self.send_max is None else min(self.send_max, len(data))
        self.sent += bytes(data[:n])
        return n

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        self.recvs += 1
        if self.on_recv is not None:
            self.on_recv()
        if self.shut:
            raise OSError("socket shut down")
        if not self.replies:
            return 0
        delay, data = self.replies[0]
        if self.timeout is not None and delay > self.timeout:
            self.clock.now += self.timeout
            self.replies[0] = (delay - self.timeout, data)
            raise TimeoutError("timed out")
        self.clock.now += delay
        n = min(len(buffer), nbytes or len(buffer), len(data))
        buffer[:n] = data[:n]
        if n < len(data):
            self.replies[0] = (0.0, data[n:])
        else:
            self.replies.pop(0)
        return n

    def shutdown(self, how: int) -> None:
        self.shut = True
        self.shut_how = how

    def close(self) -> None:
        self.closed = True

    def fileno(self) -> int:
        return -1


class FakeTls:
    def __init__(self) -> None:
        self.server_hostname: str | None = None

    def wrap_socket(
        self, sock: FakeSocket, *, server_hostname: str, do_handshake_on_connect: bool
    ) -> FakeSocket:
        assert do_handshake_on_connect is False
        self.server_hostname = server_hostname
        return sock


def numeric(*args: object) -> list[github.AddrInfo]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))]


class Rig:
    """A transport wired to fakes; each new connection takes the next scripted socket."""

    def __init__(
        self,
        clock: FakeClock,
        sockets: Sequence[FakeSocket],
        resolver: github.Resolver = numeric,
    ) -> None:
        self.clock = clock
        self.sockets = list(sockets)
        self.used: list[FakeSocket] = []
        self.timers: list[FakeTimer] = []
        self.tls = FakeTls()
        self.transport = HttpClientTransport(
            clock=clock,
            resolver=resolver,
            ssl_context=lambda: self.tls,  # type: ignore[arg-type,return-value]
            socket_factory=self._socket,  # type: ignore[arg-type]
            timer=self._timer,
        )

    def _socket(self, family: object, kind: object, proto: object) -> FakeSocket:
        sock = self.sockets.pop(0)
        self.used.append(sock)
        return sock

    def _timer(self, seconds: float, function: Callable[[], None]) -> FakeTimer:
        timer = FakeTimer(seconds, function)
        self.timers.append(timer)
        return timer

    def get(self, url: str = "https://api.github.test/x", timeout: float = DEADLINE_SECONDS) -> Any:
        return self.transport.request("GET", url, {}, None, timeout)


def ok(body: bytes = b"[]", delay: float = 0.0) -> Step:
    head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    return delay, head.encode() + body


def slow_steps(data: bytes, every: float) -> list[Step]:
    return [(every, bytes([b])) for b in data]


HEADERS = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Pad: " + b"p" * 60 + b"\r\n\r\n[]"
BODY_HEAD = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
CHUNK_HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
SLOW: dict[str, list[Step]] = {
    "status and headers": slow_steps(HEADERS, 1.5),
    "body": [(0.0, BODY_HEAD), *slow_steps(b"[" + b" " * 98 + b"]", 1.5)],
    "chunked body": [(0.0, CHUNK_HEAD), *slow_steps(b"1\r\n[\r\n" + b"1\r\n \r\n" * 40, 1.5)],
    "nothing after accept": [(10_000.0, b"never")],
    "byte every 0.9 s": slow_steps(HEADERS, 0.9),
}


# -- the absolute deadline in the transport (fake socket, fake clock) -----------------------------


@pytest.mark.parametrize("kind", sorted(SLOW))
def test_a_slow_response_stops_at_the_deadline(kind: str) -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, SLOW[kind])
    rig = Rig(clock, [sock])
    with pytest.raises(DeadlineExceeded):
        rig.get()
    assert clock.now - START <= DEADLINE_SECONDS
    assert all(t <= REQUEST_TIMEOUT_SECONDS for t in sock.timeouts)
    assert sock.closed


def test_each_socket_timeout_is_the_time_left_and_never_grows() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, slow_steps(HEADERS, 0.7))
    with pytest.raises(DeadlineExceeded):
        Rig(clock, [sock]).get()
    reads = sock.timeouts[1:]  # after the connect timeout
    assert reads == sorted(reads, reverse=True)
    assert reads[0] == pytest.approx(DEADLINE_SECONDS)
    assert reads[-1] == pytest.approx(0.2)  # four bytes at 0.7 s each, then 0.2 s left


def test_the_socket_timeout_is_capped_per_operation() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok()])
    resp = Rig(clock, [sock]).get(timeout=25.0)
    assert resp.status == 200
    assert max(sock.timeouts) == REQUEST_TIMEOUT_SECONDS


def test_a_stalled_connect_stops_at_the_deadline() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok()], connect_delay=10_000.0)
    with pytest.raises(DeadlineExceeded):
        Rig(clock, [sock]).get()
    assert clock.now - START == pytest.approx(DEADLINE_SECONDS)
    assert sock.closed


def test_a_stalled_tls_handshake_stops_at_the_deadline() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok()], connect_delay=1.0, handshake_delay=10_000.0)
    with pytest.raises(DeadlineExceeded):
        Rig(clock, [sock]).get()
    assert clock.now - START == pytest.approx(DEADLINE_SECONDS)
    assert sock.closed


def test_a_slow_upload_stops_at_the_deadline() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok()], send_delay=0.5, send_max=8)
    rig = Rig(clock, [sock])
    with pytest.raises(DeadlineExceeded):
        rig.transport.request("POST", "https://api.github.test/x", {}, b"x" * 4096, 3.0)
    assert clock.now - START <= DEADLINE_SECONDS
    assert 0 < len(sock.sent) < 4096


def test_sends_go_out_in_bounded_pieces() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok()])
    body = b"y" * (github.IO_CHUNK_BYTES * 2 + 5)
    Rig(clock, [sock]).transport.request("POST", "https://api.github.test/x", {}, body, 3.0)
    assert sock.sent.endswith(body)


def test_a_response_completing_exactly_at_the_deadline_is_late() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok(delay=DEADLINE_SECONDS)])
    with pytest.raises(DeadlineExceeded):
        Rig(clock, [sock]).get()


def test_a_response_completing_just_before_the_deadline_is_a_result() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok(b'{"a": 1}', delay=DEADLINE_SECONDS - 0.01)])
    rig = Rig(clock, [sock])
    resp = rig.get()
    assert (resp.status, resp.body) == (200, b'{"a": 1}')
    assert rig.tls.server_hostname == "api.github.test"
    assert sock.sent.startswith(b"GET /x HTTP/1.1\r\nHost: api.github.test\r\n")


def test_plain_http_skips_tls() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok()])
    rig = Rig(clock, [sock])
    assert rig.get("http://127.0.0.1:8080/x").status == 200
    assert rig.tls.server_hostname is None
    assert b"Host: 127.0.0.1:8080\r\n" in sock.sent


def test_a_connection_error_before_the_deadline_is_an_os_error() -> None:
    clock = FakeClock()

    def refused() -> None:
        raise ConnectionResetError

    sock = FakeSocket(clock, [ok()], on_recv=refused)
    with pytest.raises(OSError) as info:
        Rig(clock, [sock]).get()
    assert not isinstance(info.value, DeadlineExceeded)


def test_the_size_cap_still_applies() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok(b"x" * (github.MAX_RESPONSE_BYTES + 1))])
    with pytest.raises(ResponseTooLarge):
        Rig(clock, [sock]).get()


# -- the watchdog inside the transport ------------------------------------------------------------


def test_the_watchdog_is_armed_for_the_time_left_and_stopped_on_success() -> None:
    clock = FakeClock()
    rig = Rig(clock, [FakeSocket(clock, [ok()])])
    rig.get()
    (timer,) = rig.timers
    assert timer.seconds == pytest.approx(DEADLINE_SECONDS)
    assert (timer.daemon, timer.started, timer.cancelled, timer.joined) == (True, True, True, True)


def test_the_watchdog_is_stopped_on_failure() -> None:
    clock = FakeClock()
    rig = Rig(clock, [FakeSocket(clock, [(10_000.0, b"x")])])
    with pytest.raises(DeadlineExceeded):
        rig.get()
    assert rig.timers[0].cancelled and rig.timers[0].joined


def test_a_watchdog_firing_mid_request_is_the_deadline() -> None:
    # A blocking call that ignores its timeout: the watchdog shuts the socket.
    clock = FakeClock()
    box: list[Rig] = []

    def fire() -> None:
        box[0].timers[0].fire()

    sock = FakeSocket(clock, [ok()], on_recv=fire)
    box.append(Rig(clock, [sock]))
    with pytest.raises(DeadlineExceeded):
        box[0].get()
    assert sock.shut


# -- DNS -----------------------------------------------------------------------------------------


def test_a_late_name_resolution_is_the_deadline() -> None:
    clock = FakeClock()

    def resolver(*args: object) -> list[github.AddrInfo]:
        if len(args) == 6:
            raise socket.gaierror  # not an IP literal
        clock.now += DEADLINE_SECONDS  # resolved, but only at the deadline
        return numeric()

    transport = HttpClientTransport(clock=clock, resolver=resolver)
    with pytest.raises(DeadlineExceeded):
        transport.request("GET", "http://slow.test/", {}, None, DEADLINE_SECONDS)


def test_a_hung_name_resolution_is_the_deadline() -> None:
    # stdlib can't cancel getaddrinfo: the helper is waited on only until the
    # deadline (0.05 s, real), then left to finish once released.
    release = threading.Event()

    def resolver(*args: object) -> list[github.AddrInfo]:
        if len(args) == 6:
            raise socket.gaierror
        release.wait(30)
        raise socket.gaierror

    with pytest.raises(DeadlineExceeded):
        HttpClientTransport(resolver=resolver).request("GET", "http://hung.test/", {}, None, 0.05)
    release.set()
    for t in threading.enumerate():
        if t.name == "conventiondrift-dns":
            t.join(30)
    assert not any(t.name == "conventiondrift-dns" for t in threading.enumerate())


def test_a_failed_name_resolution_is_an_os_error() -> None:
    def resolver(*args: object) -> list[github.AddrInfo]:
        raise socket.gaierror

    with pytest.raises(OSError) as info:
        HttpClientTransport(resolver=resolver).request("GET", "http://nx.test/", {}, None, 2.0)
    assert not isinstance(info.value, DeadlineExceeded)


# -- the client over the transport: the run's outcome -------------------------------------------


def _client(rig: Rig) -> GitHubApiClient:
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        rig.clock.now += seconds

    return GitHubApiClient(
        "https://api.github.test", TOKEN, transport=rig.transport, clock=rig.clock, sleep=sleep
    )


@pytest.mark.parametrize("kind", sorted(SLOW))
def test_lookup_against_a_slow_server_reports_the_deadline(kind: str) -> None:
    clock = FakeClock()
    rig = Rig(clock, [FakeSocket(clock, list(SLOW[kind])) for _ in range(4)])
    assert _client(rig).lookup(repo=REPO, pr_number=PR) == (False, github.NOTE_DEADLINE)
    assert clock.now - START <= DEADLINE_SECONDS + SLACK
    assert len(rig.used) == 1  # never retried past the deadline


@pytest.mark.parametrize("kind", sorted(SLOW))
def test_publish_against_a_slow_server_reports_the_deadline(kind: str) -> None:
    clock = FakeClock()
    rig = Rig(clock, [FakeSocket(clock, list(SLOW[kind])) for _ in range(4)])
    out = _client(rig).publish(
        repo=REPO,
        pr_number=PR,
        run_head_sha=HEAD,
        comment=f"{MARKER}\nbody",
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )
    assert out == ("skipped", github.NOTE_DEADLINE)
    assert clock.now - START <= DEADLINE_SECONDS + SLACK
    assert not any(s.sent.startswith((b"POST", b"PATCH", b"DELETE")) for s in rig.used)


def test_lookup_against_a_prompt_server_succeeds() -> None:
    clock = FakeClock()
    pages = [FakeSocket(clock, [ok(b"[]", delay=0.1)])]
    assert _client(Rig(clock, pages)).lookup(repo=REPO, pr_number=PR) == (False, None)


# -- _read_body on its own -------------------------------------------------------------------------


class _Resp:
    def __init__(self, pieces: list[bytes], clock: FakeClock, step: float) -> None:
        self.pieces = pieces
        self.clock = clock
        self.step = step
        self.reads: list[int] = []

    def read(self, amt: int) -> bytes:
        self.reads.append(amt)
        self.clock.now += self.step
        return self.pieces.pop(0) if self.pieces else b""


def _read(pieces: list[bytes], step: float) -> tuple[_Resp, Callable[[], bytes]]:
    clock = FakeClock()
    resp = _Resp(pieces, clock, step)
    return resp, lambda: _read_body(resp, START + 1.0, clock)  # type: ignore[arg-type]


def test_body_is_read_in_bounded_chunks() -> None:
    resp, run = _read([b"ab", b"cd"], 0.1)
    assert run() == b"abcd"
    assert all(n <= github.READ_CHUNK_BYTES for n in resp.reads)


def test_body_deadline_is_checked_before_each_chunk() -> None:
    resp, run = _read([b"a", b"b", b"c", b"d"], 0.4)
    with pytest.raises(DeadlineExceeded):
        run()
    assert len(resp.reads) == 3  # reads start at 0.0, 0.4 and 0.8; none at 1.2


def test_body_completing_after_the_deadline_is_late() -> None:
    resp, run = _read([b"a"], 0.6)  # the chunk ends at 0.6, the EOF read at 1.2
    with pytest.raises(DeadlineExceeded):
        run()
    assert len(resp.reads) == 2


# -- the watchdog on its own -------------------------------------------------------------------


def test_watchdog_fire_shuts_the_watched_socket() -> None:
    a, b = socket.socketpair()
    with a, b:
        dog = _Watchdog(5.0, FakeTimer)
        dog.watch(a)
        dog.start()
        dog._timer.fire()  # type: ignore[attr-defined]
        try:
            got = a.recv(1)
        except OSError:
            got = b""
        dog.stop()
    assert got == b""
    assert dog.fired is True


def test_watchdog_that_already_fired_shuts_a_new_socket_at_once() -> None:
    a, b = socket.socketpair()
    with a, b:
        dog = _Watchdog(0.0, FakeTimer)
        dog._timer.fire()  # type: ignore[attr-defined]
        dog.watch(a)
        try:
            got = a.recv(1)
        except OSError:
            got = b""
    assert got == b""


def test_watchdog_stop_cancels_and_joins_a_started_timer_only() -> None:
    unstarted = _Watchdog(1.0, FakeTimer)
    unstarted.stop()
    assert unstarted._timer.cancelled and not unstarted._timer.joined  # type: ignore[attr-defined]
    started = _Watchdog(1.0, FakeTimer)
    started.start()
    started.stop()
    assert started._timer.joined  # type: ignore[attr-defined]


def test_watchdog_negative_time_is_zero() -> None:
    assert _Watchdog(-1.0, FakeTimer)._timer.seconds == 0.0  # type: ignore[attr-defined]


def test_watchdog_real_timer_stops_without_firing() -> None:
    dog = _Watchdog(60.0)
    dog.start()
    dog.stop()
    assert dog.fired is False
    assert not dog._timer.is_alive()  # type: ignore[attr-defined]


def test_shutdown_works_on_a_socket_and_on_a_socket_like_object() -> None:
    a, b = socket.socketpair()
    with a, b:
        _shutdown(a)
        try:
            got = a.recv(1)
        except OSError:
            got = b""
        assert got == b""
    fake = FakeSocket(FakeClock())
    _shutdown(fake)
    assert fake.shut
    closed = socket.socket()
    closed.close()
    _shutdown(closed)  # an OSError is swallowed


# -- real local sockets: plumbing only -------------------------------------------------------------

Handler = Callable[[socket.socket, threading.Event], None]


class Server:
    """Accepts on 127.0.0.1 and runs ``handler`` per connection in a ``srv-`` thread."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port: int = self.listener.getsockname()[1]
        self.conns: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.accept_thread = threading.Thread(target=self._accept, name="srv-accept", daemon=True)
        self.accept_thread.start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            if self.stop.is_set():
                conn.close()
                return
            self.conns.append(conn)
            t = threading.Thread(target=self._run, args=(conn,), name="srv-conn", daemon=True)
            self.threads.append(t)
            t.start()

    def _run(self, conn: socket.socket) -> None:
        try:
            self.handler(conn, self.stop)
        except OSError:
            pass

    def close(self) -> None:
        self.stop.set()
        try:  # wake accept()
            socket.create_connection(("127.0.0.1", self.port), timeout=5).close()
        except OSError:
            pass
        self.accept_thread.join(5)
        for conn in self.conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        for t in self.threads:
            t.join(5)
        self.listener.close()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def serve() -> Iterator[Callable[[Handler], Server]]:
    made: list[Server] = []

    def start(handler: Handler) -> Server:
        server = Server(handler)
        made.append(server)
        return server

    yield start
    for server in made:
        server.close()


def read_request(conn: socket.socket) -> bytes:
    conn.settimeout(10)
    data = b""
    while b"\r\n\r\n" not in data:
        piece = conn.recv(65536)
        if not piece:
            return data
        data += piece
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(rest) < length:
        piece = conn.recv(65536)
        if not piece:
            break
        rest += piece
    return head + b"\r\n\r\n" + rest


def respond(status: int, payload: bytes, *, extra: str = "") -> bytes:
    return (
        f"HTTP/1.1 {status} X\r\nContent-Length: {len(payload)}\r\n{extra}Connection: close\r\n\r\n"
    ).encode() + payload


def api(conn: socket.socket, stop: threading.Event) -> None:
    request = read_request(conn)
    method, target = request.split(b"\r\n", 1)[0].decode().split(" ")[:2]
    if method == "GET" and target.startswith(f"/repos/{REPO}/pulls/{PR}"):
        conn.sendall(respond(200, json.dumps({"head": {"sha": HEAD}}).encode()))
    elif method == "GET" and "/comments" in target:
        conn.sendall(respond(200, b"[]"))
    elif method == "POST" and target.endswith("/comments"):
        conn.sendall(respond(201, b'{"id": 5}'))
    else:
        conn.sendall(respond(404, b"{}"))


def stall(conn: socket.socket, stop: threading.Event) -> None:
    stop.wait()  # accept, then say nothing until the test ends


def test_real_transport_sends_the_request_and_reads_the_response(
    serve: Callable[[Handler], Server],
) -> None:
    seen: list[bytes] = []

    def echo(conn: socket.socket, stop: threading.Event) -> None:
        seen.append(read_request(conn))
        conn.sendall(respond(201, b'{"ok": 1}', extra="X-Thing: Yes\r\n"))

    server = serve(echo)
    resp = HttpClientTransport().request(
        "POST", f"{server.base}/a/b?x=1", {"H": "v"}, b'{"k": 1}', 5.0
    )
    assert (resp.status, resp.body, resp.headers["x-thing"]) == (201, b'{"ok": 1}', "Yes")
    head, _, body = seen[0].partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    assert lines[0] == b"POST /a/b?x=1 HTTP/1.1"
    assert f"Host: 127.0.0.1:{server.port}".encode() in lines
    assert b"H: v" in lines
    assert body == b'{"k": 1}'


def test_real_transport_reads_a_chunked_body(serve: Callable[[Handler], Server]) -> None:
    def chunked(conn: socket.socket, stop: threading.Event) -> None:
        read_request(conn)
        conn.sendall(CHUNK_HEAD + b"1\r\n[\r\n1\r\n]\r\n0\r\n\r\n")

    server = serve(chunked)
    assert HttpClientTransport().request("GET", f"{server.base}/", {}, None, 5.0).body == b"[]"


def test_real_transport_caps_the_response_size(
    serve: Callable[[Handler], Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    def big(conn: socket.socket, stop: threading.Event) -> None:
        read_request(conn)
        conn.sendall(respond(200, b"x" * 20))

    monkeypatch.setattr(github, "MAX_RESPONSE_BYTES", 10)
    server = serve(big)
    with pytest.raises(ResponseTooLarge):
        HttpClientTransport().request("GET", f"{server.base}/", {}, None, 5.0)


def test_real_stalled_server_ends_at_the_deadline_not_the_per_read_timeout(
    serve: Callable[[Handler], Server],
) -> None:
    # Outcome plus a generous bound: the per-read cap alone would take 10 s.
    server = serve(stall)
    start = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        HttpClientTransport().request("GET", f"{server.base}/", {}, None, 0.3)
    assert time.monotonic() - start < REQUEST_TIMEOUT_SECONDS / 2


def _dead_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port: int = probe.getsockname()[1]
    probe.close()
    return port


def test_real_connection_refused_is_an_os_error() -> None:
    with pytest.raises(OSError) as info:
        HttpClientTransport().request("GET", f"http://127.0.0.1:{_dead_port()}/", {}, None, 5.0)
    assert not isinstance(info.value, DeadlineExceeded)


def test_real_transport_tries_the_next_address(serve: Callable[[Handler], Server]) -> None:
    server = serve(api)
    dead = _dead_port()

    def resolver(*args: object) -> Sequence[github.AddrInfo]:
        if len(args) == 6:
            raise socket.gaierror
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", dead)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", server.port)),
        ]

    resp = HttpClientTransport(resolver=resolver).request(
        "GET", f"http://api.example.test/repos/{REPO}/issues/{PR}/comments", {}, None, 5.0
    )
    assert resp.status == 200


def test_real_dns_name_is_resolved(serve: Callable[[Handler], Server]) -> None:
    server = serve(api)
    resp = HttpClientTransport().request(
        "GET", f"http://localhost:{server.port}/repos/{REPO}/issues/{PR}/comments", {}, None, 5.0
    )
    assert resp.status == 200


class _PlainTls:
    """A stand-in TLS context: records the SNI name and hands back the plain socket."""

    def __init__(self, fail: bool = False) -> None:
        self.server_hostname: str | None = None
        self.fail = fail

    def wrap_socket(
        self, sock: socket.socket, *, server_hostname: str, do_handshake_on_connect: bool
    ) -> socket.socket:
        if self.fail:
            raise OSError("tls setup failed")
        self.server_hostname = server_hostname
        return _NoTlsSocket(fileno=sock.detach())


class _NoTlsSocket(socket.socket):
    def do_handshake(self) -> None:
        pass


def test_real_https_path_uses_sni(serve: Callable[[Handler], Server]) -> None:
    server = serve(api)
    tls = _PlainTls()
    transport = HttpClientTransport(ssl_context=lambda: tls)  # type: ignore[arg-type,return-value]
    url = f"https://127.0.0.1:{server.port}/repos/{REPO}/issues/{PR}/comments"
    assert transport.request("GET", url, {}, None, 5.0).status == 200
    assert tls.server_hostname == "127.0.0.1"


def test_real_tls_setup_failure_is_an_os_error(serve: Callable[[Handler], Server]) -> None:
    server = serve(stall)
    transport = HttpClientTransport(
        ssl_context=lambda: _PlainTls(fail=True)  # type: ignore[arg-type,return-value]
    )
    with pytest.raises(OSError, match="tls setup failed"):
        transport.request("GET", f"https://127.0.0.1:{server.port}/", {}, None, 5.0)


def test_real_client_round_trip(serve: Callable[[Handler], Server]) -> None:
    server = serve(api)
    client = GitHubApiClient(server.base, TOKEN, allow_http=True)
    assert client.lookup(repo=REPO, pr_number=PR) == (False, None)
    out = client.publish(
        repo=REPO,
        pr_number=PR,
        run_head_sha=HEAD,
        comment=f"{MARKER}\nbody",
        sarif=None,
        sarif_commit_sha="c" * 40,
        sarif_ref="refs/pull/7/merge",
    )
    assert out[0] in {"posted", "skipped"}


# -- remaining edges -------------------------------------------------------------------------------


def test_a_watchdog_firing_as_the_headers_arrive_is_the_deadline() -> None:
    # The response parsed, but the watchdog had fired: the result is not used.
    clock = FakeClock()
    box: list[Rig] = []

    def fire_late() -> None:
        box[0].timers[0].fire()
        sock.shut = False  # the cut lands after the bytes were already read

    sock = FakeSocket(clock, [ok()], on_recv=fire_late)
    box.append(Rig(clock, [sock]))
    with pytest.raises(DeadlineExceeded):
        box[0].get()


class _Interrupt(BaseException):
    pass


def test_an_interrupt_during_connect_closes_the_socket_and_propagates() -> None:
    clock = FakeClock()
    sock = FakeSocket(clock, [ok()])

    def connect(address: object) -> None:
        raise _Interrupt

    sock.connect = connect  # type: ignore[method-assign]
    with pytest.raises(_Interrupt):
        Rig(clock, [sock]).get()
    assert sock.closed


def test_the_deadline_socket_reports_the_real_fileno() -> None:
    a, b = socket.socketpair()
    with a, b:
        wrapped = github._DeadlineSocket(a, START + 1.0, FakeClock())
        assert wrapped.fileno() == a.fileno()


def test_a_call_that_starts_after_the_deadline_never_reaches_the_transport() -> None:
    times = iter([START, START + DEADLINE_SECONDS])
    calls: list[str] = []

    class Never:
        def request(self, *args: object) -> None:
            calls.append("request")

    client = GitHubApiClient(
        "https://api.github.test",
        TOKEN,
        transport=Never(),  # type: ignore[arg-type]
        clock=lambda: next(times),
    )
    assert client.lookup(repo=REPO, pr_number=PR) == (False, github.NOTE_DEADLINE)
    assert calls == []


def test_the_request_line_host_and_port_reach_the_resolver_and_the_wire() -> None:
    clock = FakeClock()
    calls: list[tuple[object, ...]] = []

    def resolver(*args: object) -> list[github.AddrInfo]:
        calls.append(args)
        return numeric()

    for url, port, line in [
        ("https://api.github.test", 443, b"GET / HTTP/1.1\r\nHost: api.github.test\r\n"),
        ("http://api.github.test", 80, b"GET / HTTP/1.1\r\nHost: api.github.test\r\n"),
        ("http://api.github.test:81/p?q=1", 81, b"GET /p?q=1 HTTP/1.1\r\n"),
    ]:
        calls.clear()
        rig = Rig(clock, [FakeSocket(clock, [ok()])], resolver)
        assert rig.get(url).status == 200
        assert calls == [("api.github.test", port, 0, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)]
        assert rig.used[0].sent.startswith(line)


def test_a_name_is_resolved_in_a_named_daemon_helper() -> None:
    seen: list[tuple[object, ...]] = []

    def resolver(*args: object) -> list[github.AddrInfo]:
        if len(args) == 6:
            raise socket.gaierror
        me = threading.current_thread()
        seen.append((me.name, me.daemon, *args))
        return []

    with pytest.raises(OSError, match=r"^no address$"):
        HttpClientTransport(resolver=resolver).request("GET", "http://a.test/", {}, None, 5.0)
    assert seen == [("conventiondrift-dns", True, "a.test", 80, 0, socket.SOCK_STREAM)]


def test_a_failed_name_resolution_has_a_fixed_message() -> None:
    def resolver(*args: object) -> list[github.AddrInfo]:
        raise socket.gaierror("detail that must not leak")

    with pytest.raises(OSError, match=r"^name resolution failed$"):
        HttpClientTransport(resolver=resolver).request("GET", "http://nx.test/", {}, None, 5.0)


def test_a_watchdog_firing_during_connect_shuts_that_socket() -> None:
    clock = FakeClock()
    box: list[Rig] = []
    sock = FakeSocket(clock, [ok()])

    def connect(address: object) -> None:
        box[0].timers[0].fire()

    sock.connect = connect  # type: ignore[method-assign]
    box.append(Rig(clock, [sock]))
    with pytest.raises(DeadlineExceeded):
        box[0].get()
    assert sock.shut_how == socket.SHUT_RDWR


def test_deadline_socket_passes_size_and_flags_through() -> None:
    a, b = socket.socketpair()
    with a, b:
        b.sendall(b"abcdef")
        wrapped = github._DeadlineSocket(a, time.monotonic() + 60.0, time.monotonic)
        buf = bytearray(8)
        assert wrapped.recv_into(buf, 2, socket.MSG_PEEK) == 2
        assert wrapped.recv_into(buf, 3) == 3
        assert bytes(buf[:3]) == b"abc"


def test_body_of_exactly_the_cap_is_accepted_and_reads_ask_for_one_more(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(github, "MAX_RESPONSE_BYTES", 10)
    resp, run = _read([b"abcd", b"efghij"], 0.0)
    assert run() == b"abcdefghij"
    assert resp.reads == [11, 7, 1]


class Scripted:
    """A transport stub on the fake clock: each request takes its scripted time."""

    def __init__(self, clock: FakeClock, script: list[tuple[float, object]]) -> None:
        self.clock = clock
        self.script = script

    def request(self, *args: object) -> github.HttpResponse:
        took, outcome = self.script.pop(0)
        self.clock.now += took
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, github.HttpResponse)
        return outcome


BUSY = github.HttpResponse(500, {}, b"")
EMPTY = github.HttpResponse(200, {}, b"[]")


@pytest.mark.parametrize(
    ("took", "last", "expected"),
    [
        (1.5, OSError("x"), (False, github.NOTE_DEADLINE)),  # fails exactly at the deadline
        (1.5, EMPTY, (False, github.NOTE_DEADLINE)),  # completes exactly at the deadline
        (1.0, OSError("x"), (False, github.NOTE_LOOKUP_ERROR)),  # fails with 0.5 s left
        (1.0, EMPTY, (False, None)),  # completes with 0.5 s left
    ],
)
def test_the_last_retry_ending_at_or_before_the_deadline(
    took: float, last: object, expected: tuple[bool, str | None]
) -> None:
    # Two quick 500s and both backoffs leave 1.5 s for the last attempt.
    clock = FakeClock()
    transport = Scripted(clock, [(0.0, BUSY), (0.0, BUSY), (took, last)])

    def sleep(seconds: float) -> None:
        clock.now += seconds

    client = GitHubApiClient(
        "https://api.github.test",
        TOKEN,
        transport=transport,
        clock=clock,
        sleep=sleep,
    )
    assert client.lookup(repo=REPO, pr_number=PR) == expected
    assert transport.script == []
