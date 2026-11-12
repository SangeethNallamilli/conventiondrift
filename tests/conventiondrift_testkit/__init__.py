"""Test-only fault injection for the I-2 `components` seam (INTERFACES.md 1.0 I-2).

Never shipped (R8.1, AC-N3.15): the identifiers `conventiondrift_testkit`,
`InjectedFault` and `FaultyComponent` must not appear in any released file.

The only way a fault gets into the tool is in-process, through
`conventiondrift.core.run(argv, env, components=...)`: there is no environment
variable, input, flag, config key or file trigger. Typical use (AC-F7.4):

    from conventiondrift_testkit import FaultyComponent, InjectedFault, replace_checker
    comps = make_components(checkers=replace_checker(default.checkers, "logging",
                            lambda c: FaultyComponent(c, fail_on={"ast_handlers"})))
    rc = run(argv, env, components=comps)

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


def replace_checker(registry: Any, checker_id: str, wrap: Callable[[Any], Any]) -> Any:
    """Return a copy of a checker registry with one checker (by I-10 `id`) replaced by
    `wrap(checker)`. Accepts a Mapping[id, Checker] or a sequence of checkers; I-11 does not
    pin the registry type."""
    if isinstance(registry, Mapping):
        if checker_id not in registry:
            raise KeyError(checker_id)
        out = dict(registry)
        out[checker_id] = wrap(registry[checker_id])
        return type(registry)(out) if type(registry) is not dict else out
    items = list(registry)
    hits = [i for i, c in enumerate(items) if getattr(c, "id", None) == checker_id]
    if len(hits) != 1:
        raise KeyError(checker_id)
    items[hits[0]] = wrap(items[hits[0]])
    return type(registry)(items) if isinstance(registry, tuple | list) else tuple(items)


def components_class() -> type:
    """`Components` from the production seam (DESIGN §12 A-1: conventiondrift.components)."""
    return importlib.import_module("conventiondrift.components").Components  # type: ignore[no-any-return]


def make_components(base: Any = None, **replacements: Any) -> Any:
    """Build a Components with some parts replaced (I-11 field names: git_reader, checkers,
    extractor, history, renderer, github_client, github_base_url). With `base`, it is copied
    with dataclasses.replace; otherwise `Components(**replacements)` is called, assuming
    unspecified fields default to the production parts (not pinned by I-2/I-11)."""
    unknown = set(replacements) - {
        "git_reader",
        "checkers",
        "extractor",
        "history",
        "renderer",
        "github_client",
        "github_base_url",
    }
    if unknown:
        raise TypeError(f"not an I-11 replaceable part: {sorted(unknown)}")
    if base is not None:
        return dataclasses.replace(base, **replacements)
    return components_class()(**replacements)
