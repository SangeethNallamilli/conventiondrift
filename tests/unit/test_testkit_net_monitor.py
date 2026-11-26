"""Unit tests for the egress guard in the testkit (CON-29).

The guard is a Python-level socket wrapper, so these tests drive it directly: a loopback
connection is allowed (a real local server, as ``test_github_transport.py`` uses), a non-local
one raises, and an attempt is recorded even when the raised error is swallowed.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from conventiondrift_testkit.net_monitor import (
    NetworkEscape,
    NetworkGuard,
    is_loopback,
    network_guard,
)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.9.9.9", True),
        ("::1", True),
        ("localhost", True),
        ("localhost.localdomain", True),
        ("0.0.0.0", True),  # noqa: S104 - unspecified: only meaningful as a local bind
        ("::", True),
        ("8.8.8.8", False),
        ("2001:4860:4860::8888", False),
        ("example.com", False),
        ("", True),  # no host at all: a bind, not egress
    ],
)
def test_loopback_classification(host: str, expected: bool) -> None:
    assert is_loopback(host) is expected


def test_a_non_local_connect_raises_and_is_recorded() -> None:
    with NetworkGuard("tests/unit/x.py::t") as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(NetworkEscape, match="blocked outbound network access"):
                sock.connect(("203.0.113.9", 443))
        finally:
            sock.close()
    assert guard.attempts == ["203.0.113.9"]


def test_the_escape_error_carries_the_target_and_test_id() -> None:
    error = NetworkEscape("203.0.113.9", "t.py::case")
    assert error.target == "203.0.113.9"
    assert error.node_id == "t.py::case"
    assert "203.0.113.9" in str(error)


def test_a_swallowed_escape_is_still_recorded() -> None:
    with NetworkGuard("t") as guard:
        try:
            socket.create_connection(("example.com", 443), timeout=0.01)
        except NetworkEscape:
            pass
    assert guard.attempts == ["example.com"]


requires_af_unix = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="this platform has no AF_UNIX sockets"
)


def test_a_bytes_host_is_checked_too() -> None:
    # CR minor (a): a bytes host must not slip past the fail-closed check.
    with NetworkGuard("t") as guard:
        with pytest.raises(NetworkEscape):
            socket.getaddrinfo(b"example.com", 80)
        with pytest.raises(NetworkEscape):
            socket.create_connection((b"example.com", 443), timeout=0.01)  # type: ignore[arg-type]
    assert guard.attempts == ["example.com", "example.com"]


def test_a_bytes_loopback_host_is_allowed() -> None:
    with NetworkGuard("t") as guard:
        assert socket.getaddrinfo(b"127.0.0.1", 0)
    assert guard.attempts == []


def test_a_non_ascii_bytes_host_is_blocked_without_raising() -> None:
    with NetworkGuard("t") as guard:
        with pytest.raises(NetworkEscape):
            socket.getaddrinfo(b"\xff\xfe", 80)
    assert guard.attempts and "\\xff" in guard.attempts[0]


def test_datagram_egress_is_guarded() -> None:
    # CR minor (b): sendto is intercepted, not merely documented.
    with NetworkGuard("t") as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(NetworkEscape):
                sock.sendto(b"x", ("203.0.113.9", 53))
            assert sock.sendto(b"x", ("127.0.0.1", 9)) == 1
        finally:
            sock.close()
    assert guard.attempts == ["203.0.113.9"]


def test_create_connection_and_getaddrinfo_are_guarded() -> None:
    with NetworkGuard("t") as guard:
        with pytest.raises(NetworkEscape):
            socket.getaddrinfo("example.com", 443)
        with pytest.raises(NetworkEscape):
            socket.create_connection(("example.com", 443), timeout=0.01)
    assert sorted(guard.attempts) == ["example.com", "example.com"]


def test_the_guard_works_on_a_platform_without_af_unix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression for the Windows CI crash: no wrapper may read ``socket.AF_UNIX`` at call time."""
    monkeypatch.delattr(socket, "AF_UNIX", raising=False)
    with NetworkGuard("t") as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(NetworkEscape):  # not AttributeError
                sock.connect(("example.com", 443))
            with pytest.raises(NetworkEscape):
                sock.connect_ex(("example.com", 443))
        finally:
            sock.close()
        with pytest.raises(NetworkEscape):
            socket.getaddrinfo("example.com", 80)
        assert socket.getaddrinfo("127.0.0.1", 80)  # loopback still allowed
    assert guard.attempts.count("example.com") == 3


def test_without_af_unix_the_guard_still_checks_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Windows shape, from the narrow fix: a None family constant must still block egress."""
    import conventiondrift_testkit.net_monitor as module

    monkeypatch.setattr(module, "_UNIX", None)
    with NetworkGuard("t") as guard:
        with pytest.raises(NetworkEscape):
            socket.getaddrinfo("10.9.9.9", 0)
    assert guard.attempts == ["10.9.9.9"]


def test_getaddrinfo_for_a_local_bind_is_allowed() -> None:
    with NetworkGuard("t") as guard:
        assert socket.getaddrinfo(None, 0)
        assert socket.getaddrinfo("127.0.0.1", 0)
        assert socket.getaddrinfo("::1", 0, socket.AF_INET6)
    assert guard.attempts == []


def test_a_loopback_connection_is_allowed_against_a_real_local_server() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted: list[bool] = []

    def accept() -> None:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        with conn:
            accepted.append(True)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        with NetworkGuard("t") as guard:
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            client.close()
        thread.join(timeout=2)
    finally:
        server.close()
    assert guard.attempts == []
    assert accepted == [True]


@requires_af_unix
def test_an_af_unix_path_is_not_egress(tmp_path: Any) -> None:
    path = str(tmp_path / "s.sock")
    unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with NetworkGuard("t") as guard:
            with pytest.raises(OSError):
                unix.connect(path)  # nothing is listening: the real connect error, not the guard
        assert guard.attempts == []
    finally:
        unix.close()


def test_connect_ex_is_guarded_too() -> None:
    with NetworkGuard("t") as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(NetworkEscape):
                sock.connect_ex(("example.com", 443))
        finally:
            sock.close()
    assert guard.attempts == ["example.com"]


def test_connect_ex_on_a_closed_loopback_port_is_allowed() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with NetworkGuard("t") as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            code = sock.connect_ex(("127.0.0.1", port))
        finally:
            sock.close()
    assert guard.attempts == []
    assert code != 0  # refused: the real connect_ex ran


def test_a_non_tuple_address_has_no_host_to_check() -> None:
    with NetworkGuard("t") as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(TypeError):
                sock.connect(None)  # type: ignore[arg-type]
        finally:
            sock.close()
    assert guard.attempts == []


@requires_af_unix
def test_getaddrinfo_with_the_unix_family_skips_the_host_check() -> None:
    with NetworkGuard("t") as guard:
        try:
            socket.getaddrinfo("example.com", 0, socket.AF_UNIX)
        except OSError:
            pass
    assert guard.attempts == []


def test_the_originals_are_restored_after_the_scope() -> None:
    original_connect = socket.socket.connect
    original_getaddrinfo = socket.getaddrinfo
    with NetworkGuard("t"):
        assert socket.socket.connect is not original_connect
    assert socket.socket.connect is original_connect
    assert socket.getaddrinfo is original_getaddrinfo


def test_the_fixture_skips_the_guard_for_a_network_marked_test() -> None:
    request = SimpleNamespace(
        node=SimpleNamespace(
            nodeid="t",
            get_closest_marker=lambda name: object() if name == "network" else None,
        )
    )
    generated: Iterator[NetworkGuard | None] = network_guard.__wrapped__(request)  # type: ignore[attr-defined]
    assert next(generated) is None
    with pytest.raises(StopIteration):
        next(generated)


def test_the_fixture_installs_and_removes_its_guard_for_an_offline_test() -> None:
    request = SimpleNamespace(
        node=SimpleNamespace(nodeid="t", get_closest_marker=lambda name: None),
    )
    original = socket.socket.connect
    generated: Iterator[NetworkGuard | None] = network_guard.__wrapped__(request)  # type: ignore[attr-defined]
    guard = next(generated)
    assert isinstance(guard, NetworkGuard)
    assert socket.socket.connect is not original
    with pytest.raises(StopIteration):
        next(generated)
    assert socket.socket.connect is original


def test_the_fixture_fails_the_test_when_an_escape_was_swallowed() -> None:
    request = SimpleNamespace(
        node=SimpleNamespace(nodeid="t", get_closest_marker=lambda name: None),
    )
    generated: Iterator[NetworkGuard | None] = network_guard.__wrapped__(request)  # type: ignore[attr-defined]
    guard = next(generated)
    assert guard is not None
    try:
        socket.getaddrinfo("example.com", 443)
    except NetworkEscape:
        pass
    with pytest.raises(pytest.fail.Exception, match="network escape attempt"):
        next(generated)


@pytest.mark.timing  # a wall-clock budget: D-TL-59b, run without coverage
def test_thousands_of_guarded_no_ops_stay_cheap() -> None:
    """The per-test cost is four attribute sets; this pins that it is not doing work per call."""
    import time

    with NetworkGuard("t"):
        start = time.perf_counter()
        for _ in range(2000):
            socket.getaddrinfo("127.0.0.1", 0)
        elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"loopback getaddrinfo is too expensive under the guard: {elapsed:.3f}s"
