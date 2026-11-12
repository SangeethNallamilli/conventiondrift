"""Unit tests for conventiondrift.errors (T-005, INTERFACES I-11)."""

import pytest

from conventiondrift.errors import (
    ComponentError,
    FileSkipped,
    GitTooOld,
    GitUnavailable,
    UnresolvableRevision,
)


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
    types = (FileSkipped, ComponentError, GitUnavailable, UnresolvableRevision)
    for a in types:
        for b in types:
            assert issubclass(a, b) == (a is b)


def test_component_error_requires_both_arguments() -> None:
    with pytest.raises(TypeError):
        ComponentError("render")  # type: ignore[call-arg]


def test_unresolvable_revision_has_fixed_message_and_takes_no_input() -> None:
    err = UnresolvableRevision()
    assert str(err) == "unresolvable revision"
    assert err.args == ("unresolvable revision",)
    with pytest.raises(TypeError):
        UnresolvableRevision("--output=/tmp/x")  # type: ignore[call-arg]


def test_unresolvable_revision_is_its_own_error_type() -> None:
    # C1/C2 map it to exit 2, so no other error handler may catch it (I-11 C3).
    for other in (FileSkipped, ComponentError, GitUnavailable):
        assert not issubclass(UnresolvableRevision, other)
        assert not issubclass(other, UnresolvableRevision)


def test_git_too_old_is_a_gitread_component_error_with_fixed_public_text() -> None:
    # I-14 / D-TL-18: fails closed like any ComponentError("gitread").
    err = GitTooOld()
    assert isinstance(err, ComponentError)
    assert err.component == "gitread"
    assert err.message == "git 2.30 or newer is required"
    assert err.args == ("gitread", "git 2.30 or newer is required")
    with pytest.raises(TypeError):
        GitTooOld("git version 2.29.0")  # type: ignore[call-arg]
    for other in (FileSkipped, GitUnavailable, UnresolvableRevision):
        assert not issubclass(GitTooOld, other)
