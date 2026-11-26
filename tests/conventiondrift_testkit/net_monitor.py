"""In-process egress guard for the offline suite (CON-29).

Autouse, fails closed. For every test that is not marked ``network`` it patches four Python socket
entry points - ``socket.socket.connect``, ``socket.socket.connect_ex``,
``socket.create_connection`` and ``socket.getaddrinfo`` - and raises :class:`NetworkEscape` on any
destination that is not local. An attempt is recorded before it is raised, so a test that catches
the error still fails at teardown: swallowing an escape is not a way to pass.

Exempt, narrowly:

* ``AF_UNIX`` sockets (path addresses) - a local socket, not egress;
* loopback addresses - ``127.0.0.0/8``, ``::1`` and the names ``localhost``/
  ``localhost.localdomain`` - so a local test server (``tests/unit/test_github_transport.py``)
  and ``socketpair`` keep working;
* the unspecified addresses ``0.0.0.0``/``::``, which only make sense for a local bind;
* tests marked ``network`` (the existing marker), which skip the guard entirely. That is the one
  exemption, it is per test, and it is what keeps ``pytest -m network`` able to reach the pinned
  download. ``--strict-markers`` is already on, so no unknown marker can open it.

**Boundary.** This is a Python-level guard over socket entry points, not a sandbox. It does not
see egress from a subprocess, from ``ctypes``, or through a connection that was already open when
the test started, and it cannot police a library that talks to a socket obtained some other way.
The reason the C12 path is safe is the transport seam, not this monitor: ``fake_gh`` is a
``github.Transport``, so ``GitHubApiClient`` runs with no socket at all. Do not treat the monitor
as a guarantee about code it cannot intercept.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Final

import pytest

__all__ = ["NetworkEscape", "NetworkGuard", "is_loopback", "network_guard"]

_LOCAL_NAMES: Final = frozenset({"localhost", "localhost.localdomain"})


class NetworkEscape(RuntimeError):
    """An outbound connection attempt to a non-local destination was blocked."""

    def __init__(self, target: str, node_id: str) -> None:
        super().__init__(f"blocked outbound network access to {target!r} in {node_id}")
        self.target = target
        self.node_id = node_id


def is_loopback(host: str) -> bool:
    """True for a loopback address or a local name; ``False`` for anything unresolved."""
    if host in _LOCAL_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _host_of(address: object) -> str | None:
    """The host part of a connect/create_connection address, or ``None`` for a path address."""
    if isinstance(address, tuple) and address:
        first = address[0]
        return first if isinstance(first, str) else None
    return None


@dataclass
class NetworkGuard:
    """Installs the socket wrappers for one test and restores them afterwards."""

    node_id: str = ""
    attempts: list[str] = field(default_factory=list)
    _saved: dict[str, Any] = field(default_factory=dict, repr=False)

    def __enter__(self) -> NetworkGuard:
        self._saved = {
            "connect": socket.socket.connect,
            "connect_ex": socket.socket.connect_ex,
            "create_connection": socket.create_connection,
            "getaddrinfo": socket.getaddrinfo,
        }
        guard = self

        def connect(sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
            return guard._connect(sock, address, *args, **kwargs)

        def connect_ex(sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
            return guard._connect_ex(sock, address, *args, **kwargs)

        # Plain functions, so the descriptor protocol still binds the socket instance; assigning
        # the guard's bound methods would make ``sock.connect(addr)`` pass only ``addr``.
        setattr(socket.socket, "connect", connect)  # noqa: B010 - a class patch
        setattr(socket.socket, "connect_ex", connect_ex)  # noqa: B010 - a class patch
        setattr(socket, "create_connection", self._create_connection)  # noqa: B010
        setattr(socket, "getaddrinfo", self._getaddrinfo)  # noqa: B010
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        setattr(socket.socket, "connect", self._saved["connect"])  # noqa: B010
        setattr(socket.socket, "connect_ex", self._saved["connect_ex"])  # noqa: B010
        setattr(socket, "create_connection", self._saved["create_connection"])  # noqa: B010
        setattr(socket, "getaddrinfo", self._saved["getaddrinfo"])  # noqa: B010
        self._saved.clear()

    # -- checks ---------------------------------------------------------------

    def check(self, host: str | None) -> None:
        """Record and raise for a non-local host; ``None`` means "no host to check"."""
        if host is None or is_loopback(host):
            return
        self.attempts.append(host)
        raise NetworkEscape(host, self.node_id)

    # -- the wrappers ---------------------------------------------------------

    def _connect(self, sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
        if getattr(sock, "family", None) != socket.AF_UNIX:
            self.check(_host_of(address))
        return self._saved["connect"](sock, address, *args, **kwargs)

    def _connect_ex(self, sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
        if getattr(sock, "family", None) != socket.AF_UNIX:
            self.check(_host_of(address))
        return self._saved["connect_ex"](sock, address, *args, **kwargs)

    def _create_connection(self, address: object, *args: Any, **kwargs: Any) -> Any:
        self.check(_host_of(address))
        return self._saved["create_connection"](address, *args, **kwargs)

    def _getaddrinfo(self, host: object, port: object, *args: Any, **kwargs: Any) -> Any:
        family = kwargs.get("family", args[0] if args else 0)
        if family != socket.AF_UNIX:
            self.check(host if isinstance(host, str) else None)
        return self._saved["getaddrinfo"](host, port, *args, **kwargs)


@pytest.fixture(autouse=True)
def network_guard(request: pytest.FixtureRequest) -> Iterator[NetworkGuard | None]:
    """Block non-local egress for this test unless it is marked ``network`` (CON-29)."""
    if request.node.get_closest_marker("network") is not None:
        yield None
        return
    guard = NetworkGuard(request.node.nodeid)
    with guard:
        yield guard
    if guard.attempts:
        # The raise may have been swallowed; the teardown still fails the test.
        pytest.fail(
            "network escape attempt(s) during an offline test: "
            + ", ".join(sorted(set(guard.attempts)))
            + " (mark the test `network` only if the egress is the point of the test)"
        )
