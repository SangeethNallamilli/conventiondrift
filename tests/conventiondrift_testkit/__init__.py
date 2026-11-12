"""Test-only fault injection for the I-2 `components` seam (INTERFACES.md 1.0 I-2).

Never shipped (R8.1, AC-N3.15): the identifiers `conventiondrift_testkit`,
`InjectedFault` and `FaultyComponent` must not appear in any released file.

The only way a fault gets into the tool is in-process, through
`conventiondrift.core.run(argv, env, *, entry=..., components=...)` (I-14: `entry`
is required and is never inferred from `env`): there is no environment
variable, input, flag, config key or file trigger. Typical use (AC-F7.4):

    from conventiondrift_testkit import FaultyComponent, InjectedFault, replace_checker
    comps = make_components(checkers=replace_checker(default.checkers, "logging",
                            lambda c: FaultyComponent(c, fail_on={"ast_handlers"})))
    rc = run(argv, env, entry="cli", components=comps)

A FaultyComponent delegates everything to the wrapped component except the
methods named in `fail_on`, which raise `InjectedFault` (after `after_calls`
successful calls), so the tool's real error path is exercised: the failing
component is named, and no stack trace, file contents or token is shown.
"""

from __future__ import annotations

import dataclasses
import importlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

__all__ = [
    "REPLACEABLE_PARTS",
    "FaultyComponent",
    "InjectedFault",
    "components_class",
    "make_components",
    "replace_checker",
]


class InjectedFault(RuntimeError):
    """The exception a FaultyComponent raises. Its message is fixed and never quotes input."""

    def __init__(self, point: str) -> None:
        super().__init__(f"injected fault at {point}")
        self.point = point

    def __reduce__(self) -> tuple[Any, ...]:  # picklable across the process pool
        return (InjectedFault, (self.point,))


class FaultyComponent:
    """Wrap one component so chosen methods raise InjectedFault.

    wrapped     the real (or stand-in) component; every other attribute is delegated
    fail_on     method names that fail; None means every public callable attribute
    after_calls number of successful calls to a failing method before it starts failing
                (0 = the first call fails; lets a renderer fail "after analysis")
    fault       exception factory, called with the fault point name
    """

    def __init__(
        self,
        wrapped: Any,
        *,
        fail_on: Iterable[str] | str | None = None,
        after_calls: int = 0,
        fault: Callable[[str], BaseException] = InjectedFault,
    ) -> None:
        if isinstance(fail_on, str):
            fail_on = {fail_on}
        object.__setattr__(self, "_wrapped", wrapped)
        object.__setattr__(self, "_fail_on", None if fail_on is None else frozenset(fail_on))
        object.__setattr__(self, "_after_calls", after_calls)
        object.__setattr__(self, "_fault", fault)
        object.__setattr__(self, "calls", [])
        object.__setattr__(self, "faults_raised", 0)

    # pickling (ProcessPoolExecutor workers) must not go through __getattr__
    def __getstate__(self) -> dict[str, Any]:
        return {
            k: object.__getattribute__(self, k)
            for k in ("_wrapped", "_fail_on", "_after_calls", "_fault", "calls", "faults_raised")
        }

    def __setstate__(self, state: dict[str, Any]) -> None:
        for k, v in state.items():
            object.__setattr__(self, k, v)

    def _fails(self, name: str) -> bool:
        fail_on = object.__getattribute__(self, "_fail_on")
        return (not name.startswith("_")) if fail_on is None else name in fail_on

    def _point(self, name: str) -> str:
        wrapped = object.__getattribute__(self, "_wrapped")
        ident = getattr(wrapped, "id", None) or type(wrapped).__name__
        return f"{ident}.{name}"

    def _maybe_fail(self, name: str) -> None:
        calls = object.__getattribute__(self, "calls")
        calls.append(name)
        if self._fails(name) and calls.count(name) > object.__getattribute__(self, "_after_calls"):
            object.__setattr__(
                self, "faults_raised", object.__getattribute__(self, "faults_raised") + 1
            )
            raise object.__getattribute__(self, "_fault")(self._point(name))

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        wrapped = object.__getattribute__(self, "_wrapped")
        value = getattr(wrapped, name)
        if callable(value) and self._fails(name):

            def failing(*args: Any, **kwargs: Any) -> Any:
                self._maybe_fail(name)
                return value(*args, **kwargs)

            failing.__name__ = name
            return failing
        return value

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        wrapped = object.__getattribute__(self, "_wrapped")
        if self._fails("__call__") or (object.__getattribute__(self, "_fail_on") is None):
            self._maybe_fail("__call__")
        return wrapped(*args, **kwargs)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_wrapped"), name, value)

    def __repr__(self) -> str:
        return f"FaultyComponent({object.__getattribute__(self, '_wrapped')!r})"


REPLACEABLE_PARTS = frozenset(
    {
        "git_reader",
        "checkers",
        "extractor",
        "history",
        "renderer",
        "github_client",
        "github_base_url",
    }
)  # I-11


def replace_checker(
    registry: Mapping[str, Any], checker_id: str, wrap: Callable[[Any], Any]
) -> dict[str, Any]:
    """Copy of a checker registry with one checker replaced by `wrap(checker)`.

    I-11: the registry is a `Mapping[str, Checker]` keyed by the I-10 checker id and iterated
    in sorted id order; the copy keeps that order.
    """
    if not isinstance(registry, Mapping):
        raise TypeError(
            f"I-11 checker registry must be a Mapping[str, Checker], got {type(registry).__name__}"
        )
    if checker_id not in registry:
        raise KeyError(checker_id)
    return {cid: (wrap(c) if cid == checker_id else c) for cid, c in sorted(registry.items())}


def components_class() -> type:
    """`conventiondrift.Components` (defined in conventiondrift/components.py, DESIGN A-1)."""
    pkg = importlib.import_module("conventiondrift")
    cls = getattr(pkg, "Components", None)
    if cls is None:
        cls = importlib.import_module("conventiondrift.components").Components
    return cls  # type: ignore[no-any-return]


def make_components(base: Any = None, **replacements: Any) -> Any:
    """A `Components` with some I-11 parts replaced, via `dataclasses.replace`.

    I-11: `@dataclass(frozen=True, kw_only=True)`, `None` means "use the default". `base`
    defaults to `Components()`, i.e. all production defaults.
    """
    unknown = set(replacements) - REPLACEABLE_PARTS
    if unknown:
        raise TypeError(f"not an I-11 replaceable part: {sorted(unknown)}")
    if base is None:
        base = components_class()()
    return dataclasses.replace(base, **replacements)
