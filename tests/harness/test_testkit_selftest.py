"""Self-tests for conventiondrift_testkit (I-2). Uses stand-in components, no production code."""

from __future__ import annotations

import dataclasses
import pickle
from dataclasses import dataclass

import pytest

from conventiondrift_testkit import (
    REPLACEABLE_PARTS,
    FaultyComponent,
    InjectedFault,
    make_components,
    replace_checker,
)


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
    secret = "ghp_FAKE0000000000000000000000000000canary"  # noqa: S105 - dummy test value, not a secret
    with pytest.raises(InjectedFault) as err:
        fc.match_rule(secret)
    assert secret not in str(err.value) and secret not in repr(err.value)


def test_picklable_for_process_pool() -> None:
    fc = FaultyComponent(StandInChecker(), fail_on={"ast_handlers"})
    clone = pickle.loads(pickle.dumps(fc))  # noqa: S301 - round-trips our own object
    assert clone.id == "logging"
    with pytest.raises(InjectedFault):
        clone.ast_handlers()
    err = pickle.loads(pickle.dumps(InjectedFault("x.y")))  # noqa: S301 - round-trips our own object
    assert err.point == "x.y"


def test_callable_component() -> None:
    fc = FaultyComponent(lambda x: x + 1, fail_on={"__call__"})
    with pytest.raises(InjectedFault):
        fc(1)
    assert FaultyComponent(lambda x: x + 1, fail_on={"other"})(1) == 2


def test_replace_checker_mapping_sorted_by_id() -> None:
    a, b = StandInChecker(), StandInChecker()
    b.id = "http-client"
    reg = {"logging": a, "http-client": b}  # I-11: Mapping[str, Checker] keyed by I-10 id
    new = replace_checker(reg, "logging", lambda c: FaultyComponent(c, fail_on="ast_handlers"))
    assert list(new) == ["http-client", "logging"]  # sorted id order
    assert new["http-client"] is b and isinstance(new["logging"], FaultyComponent)
    assert reg["logging"] is a  # the original is not modified
    with pytest.raises(KeyError):
        replace_checker(reg, "money", lambda c: c)


def test_replace_checker_rejects_non_mapping() -> None:
    with pytest.raises(TypeError):
        replace_checker([StandInChecker()], "logging", lambda c: c)  # type: ignore[arg-type]


def test_make_components_uses_dataclasses_replace() -> None:
    @dataclass(frozen=True, kw_only=True)
    class StandInComponents:
        git_reader: object = None
        checkers: object = None
        renderer: object = None

    base = StandInComponents(checkers="real")
    out = make_components(base, renderer="faulty")
    assert out.checkers == "real" and out.renderer == "faulty" and out.git_reader is None
    assert base.renderer is None
    with pytest.raises(TypeError):
        make_components(base, fault_hook=True)


@pytest.mark.xfail(
    strict=True,
    raises=(ImportError, ModuleNotFoundError),
    reason="T-006a: conventiondrift.components not on main yet",
)
def test_production_components_documented_shape() -> None:
    """I-11/I-14: frozen, keyword-only dataclass; None = default; dataclasses.replace for variants;
    the I-11 replaceable parts are fields.

    Imports `conventiondrift.components` directly (I-14). A failed import fails this
    test; the strict xfail is only for ImportError/ModuleNotFoundError until T-006a
    lands, at which point the marker must be removed (an XPASS fails the suite).
    """
    from conventiondrift.components import Components

    cls = Components
    assert dataclasses.is_dataclass(cls)
    assert cls.__dataclass_params__.frozen  # type: ignore[attr-defined]
    fields = {f.name: f for f in dataclasses.fields(cls)}
    assert REPLACEABLE_PARTS <= set(fields)
    assert all(f.kw_only for f in fields.values())
    default = cls()
    assert all(getattr(default, name) is None for name in REPLACEABLE_PARTS)
    with pytest.raises(TypeError):
        cls(None)  # positional construction is not allowed
    with pytest.raises(dataclasses.FrozenInstanceError):
        default.checkers = {}  # type: ignore[misc]
    variant = dataclasses.replace(default, github_base_url="http://127.0.0.1:1")
    assert variant.github_base_url == "http://127.0.0.1:1" and default.github_base_url is None
