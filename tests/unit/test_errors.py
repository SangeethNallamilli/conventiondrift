"""Unit tests for conventiondrift.errors (T-005, INTERFACES I-11)."""

import pytest

from conventiondrift.errors import ComponentError, FileSkipped, GitUnavailable


def test_file_skipped_carries_reason() -> None:
    err = FileSkipped("size limit")
    assert err.reason == "size limit"
    assert err.args == ("size limit",)


def test_component_error_carries_component_and_message() -> None:
    err = ComponentError("checker:logging", "boom")
    assert err.component == "checker:logging"
    assert err.message == "boom"
    assert err.args == ("checker:logging", "boom")


@pytest.mark.parametrize(
    "exc",
    [FileSkipped("binary"), ComponentError("gitread", "x"), GitUnavailable()],
)
def test_errors_are_raisable_exceptions(exc: Exception) -> None:
    with pytest.raises(type(exc)) as info:
        raise exc
    assert info.value is exc


def test_error_types_are_distinct() -> None:
    # Each outcome is handled differently (I-11), so none may catch another.
    types = (FileSkipped, ComponentError, GitUnavailable)
    for a in types:
        for b in types:
            assert issubclass(a, b) == (a is b)


def test_component_error_requires_both_arguments() -> None:
    with pytest.raises(TypeError):
        ComponentError("render")  # type: ignore[call-arg]
