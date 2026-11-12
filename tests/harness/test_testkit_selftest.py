"""Self-tests for conventiondrift_testkit (I-2). Uses stand-in components, no production code."""
# ruff: noqa: S105, S301  (fake canary token and pickling our own objects)

from __future__ import annotations

import pickle
from dataclasses import dataclass, field

import pytest

from conventiondrift_testkit import FaultyComponent, InjectedFault, make_components, replace_checker


class StandInChecker:
    id = "logging"
    experimental = False
    options = frozenset({"logging", "print"})

    def match_rule(self, text: str) -> str:
        return f"match:{text}"

    def ast_handlers(self) -> dict:
        return {"Call": "handler"}


def test_fails_only_named_method_and_delegates_rest() -> None:
    fc = FaultyComponent(StandInChecker(), fail_on={"ast_handlers"})
    assert fc.id == "logging" and fc.options == frozenset({"logging", "print"})
    assert fc.match_rule("x") == "match:x"
    with pytest.raises(InjectedFault) as err:
        fc.ast_handlers()
    assert err.value.point == "logging.ast_handlers"
    assert str(err.value) == "injected fault at logging.ast_handlers"
    assert fc.faults_raised == 1 and fc.calls == ["ast_handlers"]


def test_fail_on_none_fails_every_public_method() -> None:
    fc = FaultyComponent(StandInChecker())
    for name in ("match_rule", "ast_handlers"):
        with pytest.raises(InjectedFault):
            getattr(fc, name)(*(["t"] if name == "match_rule" else []))


def test_after_calls_lets_first_calls_succeed() -> None:
    class Renderer:
        def render(self, result: str) -> str:
            return f"<{result}>"

    fc = FaultyComponent(Renderer(), fail_on="render", after_calls=2)
    assert fc.render("a") == "<a>" and fc.render("b") == "<b>"
    with pytest.raises(InjectedFault):
        fc.render("c")


def test_fault_message_never_quotes_input() -> None:
    fc = FaultyComponent(StandInChecker(), fail_on="match_rule")
    secret = "ghp_FAKE0000000000000000000000000000canary"
    with pytest.raises(InjectedFault) as err:
        fc.match_rule(secret)
    assert secret not in str(err.value) and secret not in repr(err.value)


def test_picklable_for_process_pool() -> None:
    fc = FaultyComponent(StandInChecker(), fail_on={"ast_handlers"})
    clone = pickle.loads(pickle.dumps(fc))
    assert clone.id == "logging"
    with pytest.raises(InjectedFault):
        clone.ast_handlers()
    err = pickle.loads(pickle.dumps(InjectedFault("x.y")))
    assert err.point == "x.y"


def test_callable_component() -> None:
    fc = FaultyComponent(lambda x: x + 1, fail_on={"__call__"})
    with pytest.raises(InjectedFault):
        fc(1)
    assert FaultyComponent(lambda x: x + 1, fail_on={"other"})(1) == 2


@pytest.mark.parametrize("kind", ["dict", "tuple", "list"])
def test_replace_checker_in_registry(kind: str) -> None:
    a, b = StandInChecker(), StandInChecker()
    b.id = "http-client"
    reg = (
        {"logging": a, "http-client": b}
        if kind == "dict"
        else (a, b)
        if kind == "tuple"
        else [a, b]
    )
    new = replace_checker(reg, "logging", lambda c: FaultyComponent(c, fail_on="ast_handlers"))
    items = list(new.values()) if kind == "dict" else list(new)
    assert isinstance(items[0], FaultyComponent) and items[1] is b
    assert type(new) is type(reg)
    with pytest.raises(KeyError):
        replace_checker(reg, "money", lambda c: c)


def test_make_components_copies_base_and_rejects_unknown_parts() -> None:
    @dataclass(frozen=True)
    class StandInComponents:
        checkers: object = None
        renderer: object = None
        extra: list = field(default_factory=list)

    base = StandInComponents(checkers="real")
    out = make_components(base, renderer="faulty")
    assert out.checkers == "real" and out.renderer == "faulty"
    with pytest.raises(TypeError):
        make_components(base, fault_hook=True)
