"""In-process egress guard for the offline suite (CON-29).

Autouse, fails closed. For every test that is not marked ``network`` it patches four Python socket
entry points - ``socket.socket.connect``, ``socket.socket.connect_ex``,
``socket.create_connection`` and ``socket.getaddrinfo`` - and raises :class:`NetworkEscape` on any
destination that is not local. An attempt is recorded before it is raised, so a test that catches
the error still fails at teardown: swallowing an escape is not a way to pass.

Exempt, narrowly:

* ``AF_UNIX`` sockets (path addresses) - a local socket, not egress (skipped where the platform
  has no ``AF_UNIX``, as on Windows);
* loopback addresses - ``127.0.0.0/8``, ``::1`` and the names ``localhost``/
  ``localhost.localdomain`` - so a local test server (``tests/unit/test_github_transport.py``)
  and ``socketpair`` keep working;
* the unspecified addresses ``0.0.0.0``/``::``, which only make sense for a local bind;
* tests marked ``network`` (the existing marker), which skip the guard entirely. That is the one
  exemption, it is per test, and it is what keeps ``pytest -m network`` able to reach the pinned
  download. ``--strict-markers`` is already on, so no unknown marker can open it.

**Boundary.** This is a Python-level guard over socket entry points, not a sandbox. It does not
see egress from a subprocess, from ``ctypes``, through an already-open connection, or via
``sendmmsg`` (which is not wrapped); it cannot police a library that talks to a socket obtained
some other way. Datagrams *are* covered through ``sendto``.
The reason the C12 path is safe is the transport seam, not this monitor: ``fake_gh`` is a
``github.Transport``, so ``GitHubApiClient`` runs with no socket at all. Do not treat the monitor
as a guarantee about code it cannot intercept.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import FrameType, TracebackType
from typing import Any, Final

import pytest

__all__ = ["NetworkEscape", "NetworkGuard", "is_loopback", "network_guard"]

_LOCAL_NAMES: Final = frozenset({"localhost", "localhost.localdomain"})
_UNIX: Final = getattr(socket, "AF_UNIX", None)
"""Absent on Windows: resolved once, because comparing to ``socket.AF_UNIX`` raised there."""


_LAYER_SKIP: Final = ("conventiondrift_testkit.net_monitor", "_pytest.", "pluggy.", "pytest.")
"""Frames that are the guard itself or the runner, never the layer worth naming."""

CLIENT_LIBRARIES: Final = (
    "urllib.request",
    "http.client",
    "socket",
    "requests",
    "urllib3",
    "conventiondrift.github",
)
"""The explicit, small set of client libraries whose frame names the layer (outermost wins)."""


def _library_layer() -> str | None:
    """The **outermost known client-library frame** that led to the blocked call (TE finding 2).

    Walked only on the failure path, from the raise site outwards. Only the explicit small
    ``CLIENT_LIBRARIES`` set counts: ``urllib.request.urlopen``, ``http.client``'s own call,
    ``requests``/``urllib3`` and our C12 client are all named by the library, and the outermost
    such frame wins. A raw call that never enters a library frame (a patched
    ``socket.create_connection`` or a bare ``sock.connect``) has no frame to name here; the
    wrapper then uses its own ``socket.*`` entry-point name.
    """
    frame: FrameType | None = sys._getframe(1)
    outer: str | None = None
    while frame is not None:
        module = str(frame.f_globals.get("__name__", ""))
        if any(module == lib or module.startswith(f"{lib}.") for lib in CLIENT_LIBRARIES):
            outer = f"{module}.{frame.f_code.co_name}"
        frame = frame.f_back
    return outer


def _calling_layer() -> str:
    """The innermost test frame, else the outermost non-runner frame, else ``"unknown"``."""
    frame: FrameType | None = sys._getframe(1)
    test_fallback: str | None = None
    outermost: str | None = None
    while frame is not None:
        module = str(frame.f_globals.get("__name__", ""))
        if not any(module == skip or module.startswith(skip) for skip in _LAYER_SKIP):
            name = f"{module}.{frame.f_code.co_name}"
            if module == "__main__" or module.startswith("tests.") or module.startswith("unit."):
                test_fallback = test_fallback or name
            else:
                outermost = name
        frame = frame.f_back
    return test_fallback or outermost or "unknown"


class NetworkEscape(RuntimeError):
    """An outbound connection attempt to a non-local destination was blocked.

    ``layer`` names the outermost client-library frame that attempted it, so the same failure
    from ``socket``, ``http.client`` and ``urllib.request`` is distinguishable in one message.
    """

    def __init__(self, target: str, node_id: str, layer: str | None = None) -> None:
        self.layer = (_library_layer() or _calling_layer()) if layer is None else layer
        super().__init__(
            f"blocked outbound network access to {target!r} in {node_id} (layer: {self.layer})"
        )
        self.target = target
        self.node_id = node_id


def _is_unix_family(family: object) -> bool:
    return _UNIX is not None and family == _UNIX


def _text(host: bytes) -> str:
    """A bytes host, as text: ASCII when possible, a backslash-escaped label otherwise."""
    return host.decode("ascii", "backslashreplace")


def is_loopback(host: str) -> bool:
    """True for a loopback address, an empty host, or a local name; else ``False``."""
    if host == "" or host in _LOCAL_NAMES:
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
        if isinstance(first, str):
            return first
        if isinstance(first, bytes):
            return _text(first)
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
            "sendto": socket.socket.sendto,
        }
        guard = self

        def connect(sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
            return guard._connect(sock, address, *args, **kwargs)

        def connect_ex(sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
            return guard._connect_ex(sock, address, *args, **kwargs)

        def sendto(sock: socket.socket, data: object, *args: Any, **kwargs: Any) -> Any:
            return guard._sendto(sock, data, *args, **kwargs)

        # Plain functions, so the descriptor protocol still binds the socket instance; assigning
        # the guard's bound methods would make ``sock.connect(addr)`` pass only ``addr``.
        setattr(socket.socket, "connect", connect)  # noqa: B010 - a class patch
        setattr(socket.socket, "connect_ex", connect_ex)  # noqa: B010 - a class patch
        setattr(socket, "create_connection", self._create_connection)  # noqa: B010
        setattr(socket, "getaddrinfo", self._getaddrinfo)  # noqa: B010
        setattr(socket.socket, "sendto", sendto)  # noqa: B010
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
        setattr(socket.socket, "sendto", self._saved["sendto"])  # noqa: B010
        self._saved.clear()

    # -- checks ---------------------------------------------------------------

    def check(self, host: str | None, *, via: str | None = None) -> None:
        """Record and raise for a non-local host; ``None`` means "no host to check".

        ``via`` is the socket entry point the call came through. It is used only when the stack
        walk finds no known client-library frame (a raw ``socket.*`` call from test code), so the
        three planted escapes stay distinguishable either way.
        """
        if host is None or is_loopback(host):
            return
        self.attempts.append(host)
        layer = _library_layer() or via or _calling_layer()
        raise NetworkEscape(host, self.node_id, layer)

    # -- the wrappers ---------------------------------------------------------

    def _connect(self, sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
        if not _is_unix_family(getattr(sock, "family", None)):
            self.check(_host_of(address), via="socket.connect")
        return self._saved["connect"](sock, address, *args, **kwargs)

    def _connect_ex(self, sock: socket.socket, address: object, *args: Any, **kwargs: Any) -> Any:
        if not _is_unix_family(getattr(sock, "family", None)):
            self.check(_host_of(address), via="socket.connect_ex")
        return self._saved["connect_ex"](sock, address, *args, **kwargs)

    def _create_connection(self, address: object, *args: Any, **kwargs: Any) -> Any:
        self.check(_host_of(address), via="socket.create_connection")
        return self._saved["create_connection"](address, *args, **kwargs)

    def _getaddrinfo(self, host: object, port: object, *args: Any, **kwargs: Any) -> Any:
        family = kwargs.get("family", args[0] if args else 0)
        if not _is_unix_family(family):
            if isinstance(host, bytes):
                self.check(_text(host), via="socket.getaddrinfo")
            else:
                self.check(host if isinstance(host, str) else None, via="socket.getaddrinfo")
        return self._saved["getaddrinfo"](host, port, *args, **kwargs)

    def _sendto(self, sock: socket.socket, data: object, *args: Any, **kwargs: Any) -> Any:
        """Datagram egress: ``sendto(data, address)`` and ``sendto(data, flags, address)``."""
        address = kwargs.get("address", args[-1] if args else None)
        if not _is_unix_family(getattr(sock, "family", None)):
            self.check(_host_of(address), via="socket.sendto")
        return self._saved["sendto"](sock, data, *args, **kwargs)


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
