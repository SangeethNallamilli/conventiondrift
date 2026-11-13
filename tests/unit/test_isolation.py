"""Unit tests for C7's worker isolation (I-13 C7 ruling 8, SR C-1 on #31).

D-TL-25: each case starts from the clean baseline and changes one condition;
names and values come from the module's own constants, and the expected
values are written by hand.
"""

import os
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from conventiondrift import isolation
from conventiondrift.errors import ComponentError
from conventiondrift.isolation import (
    BACKSTOP_MESSAGE,
    CURRENT_FOLDER_SPELLINGS,
    SAFE_PATH_VALUE,
    SAFE_PATH_VAR,
    check_worker,
    path_key,
    pool_allowed,
    safe_path_still_set,
    unsafe_path_entries,
    worker_backstop,
)


@dataclass(frozen=True)
class FakeFlags:
    isolated: int = 0
    safe_path: bool = False
    ignore_environment: int = 0


PLAIN = FakeFlags()


def test_the_constants_are_the_ruling_values() -> None:
    assert SAFE_PATH_VAR == "PYTHONSAFEPATH"
    assert SAFE_PATH_VALUE == "1"
    assert BACKSTOP_MESSAGE == "worker isolation check failed"


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[str, str, str]:
    """(cwd, analyzed root, an unrelated site folder), all distinct."""
    paths = [tmp_path / name for name in ("cwd", "root", "site")]
    for p in paths:
        p.mkdir()
    return str(paths[0]), str(paths[1]), str(paths[2])


# --- parent pre-check ---------------------------------------------------------------------


def test_the_pre_check_allows_the_pool_and_sets_the_variable_when_nothing_is_set(
    dirs: tuple[str, str, str],
) -> None:
    cwd, root, site = dirs
    env: dict[str, str] = {}
    assert pool_allowed(root, flags=PLAIN, environ=env, path=[site], cwd=cwd) is True
    assert env == {"PYTHONSAFEPATH": "1"}


@pytest.mark.parametrize("flags", [replace(PLAIN, isolated=1), replace(PLAIN, safe_path=True)])
def test_the_pre_check_trusts_isolated_or_safe_path_and_leaves_the_env_alone(
    flags: FakeFlags, dirs: tuple[str, str, str]
) -> None:
    cwd, root, site = dirs
    env: dict[str, str] = {}
    assert pool_allowed(root, flags=flags, environ=env, path=[site], cwd=cwd) is True
    assert env == {}


def test_the_pre_check_refuses_the_pool_under_dash_e(dirs: tuple[str, str, str]) -> None:
    cwd, root, site = dirs
    env: dict[str, str] = {}
    flags = replace(PLAIN, ignore_environment=1)
    assert pool_allowed(root, flags=flags, environ=env, path=[site], cwd=cwd) is False
    assert env == {}


@pytest.mark.parametrize("which", ["empty", "cwd", "root", "cwd spelled relatively", "not str"])
def test_the_pre_check_refuses_an_unsafe_sys_path_entry(
    which: str, dirs: tuple[str, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cwd, root, site = dirs
    monkeypatch.chdir(cwd)
    bad: object = {
        "empty": "",
        "cwd": cwd,
        "root": root,
        "cwd spelled relatively": os.curdir,
        "not str": Path(site),
    }[which]
    env: dict[str, str] = {}
    assert pool_allowed(root, flags=PLAIN, environ=env, path=[site, bad], cwd=cwd) is False
    assert env == {}


def test_the_pre_check_compares_resolved_paths(tmp_path: Path) -> None:
    real = tmp_path / "repo"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("this account can't create symlinks (Windows without the privilege)")
    env: dict[str, str] = {}
    assert pool_allowed(None, flags=PLAIN, environ=env, path=[str(link)], cwd=str(real)) is False
    assert env == {}


def test_the_pre_check_reads_the_real_sys_path_and_cwd(monkeypatch: pytest.MonkeyPatch) -> None:
    env: dict[str, str] = {}
    monkeypatch.syspath_prepend(os.getcwd())
    assert pool_allowed(None, flags=PLAIN, environ=env) is False
    assert env == {}


def test_the_pre_check_writes_os_environ_by_default(
    dirs: tuple[str, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cwd, root, site = dirs
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    assert pool_allowed(root, flags=PLAIN, path=[site], cwd=cwd) is True
    assert os.environ["PYTHONSAFEPATH"] == "1"


def test_an_unresolvable_entry_counts_as_unsafe(dirs: tuple[str, str, str]) -> None:
    cwd, root, _ = dirs
    assert unsafe_path_entries(["bad\0entry"], cwd, root) is True


def test_without_a_root_only_empty_and_cwd_are_compared(dirs: tuple[str, str, str]) -> None:
    cwd, root, site = dirs
    assert unsafe_path_entries([site, root], cwd, None) is False
    assert unsafe_path_entries([site, cwd], cwd, None) is True


@pytest.mark.parametrize("value", ["0", "", "true", "yes", " 1", "1 ", "01"])
def test_the_pre_check_counts_pythonsafepath_only_when_it_is_exactly_1(
    value: str, dirs: tuple[str, str, str]
) -> None:
    cwd, root, site = dirs
    env = {"PYTHONSAFEPATH": value}
    assert pool_allowed(root, flags=PLAIN, environ=env, path=[site], cwd=cwd) is False
    assert env == {"PYTHONSAFEPATH": value}


def test_the_pre_check_keeps_an_existing_pythonsafepath_of_1(dirs: tuple[str, str, str]) -> None:
    cwd, root, site = dirs
    env = {"PYTHONSAFEPATH": "1"}
    assert pool_allowed(root, flags=PLAIN, environ=env, path=[site], cwd=cwd) is True
    assert env == {"PYTHONSAFEPATH": "1"}


def test_the_current_folder_spellings() -> None:
    assert CURRENT_FOLDER_SPELLINGS == ("", ".")


def test_dot_counts_as_the_current_folder_without_resolving_it(
    dirs: tuple[str, str, str],
) -> None:
    # The cwd passed in is not the process's real folder, so only the
    # spelling rule (not realpath) can catch ".".
    cwd, root, site = dirs
    assert unsafe_path_entries([site, "."], cwd, root) is True


@pytest.mark.parametrize("which", ["entry", "root"])
def test_trailing_separators_do_not_hide_the_root(which: str, dirs: tuple[str, str, str]) -> None:
    cwd, root, site = dirs
    slashed = root + os.sep + os.sep
    entry, given = (slashed, root) if which == "entry" else (root, slashed)
    assert unsafe_path_entries([site, entry], cwd, given) is True


def test_the_path_key_strips_trailing_separators_but_keeps_a_root(tmp_path: Path) -> None:
    folder = str(tmp_path)
    fs_root = os.path.abspath(os.sep)
    assert (
        path_key(folder + os.sep) == path_key(folder) == os.path.normcase(os.path.realpath(folder))
    )
    assert path_key(fs_root) == os.path.normcase(fs_root)
    assert path_key(fs_root).endswith(os.sep)


def test_the_path_key_is_case_normalized(tmp_path: Path) -> None:
    folder = os.path.realpath(tmp_path)
    assert path_key(folder) == os.path.normcase(folder)


def test_the_root_is_compared_through_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "repo"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    assert unsafe_path_entries([str(link)], str(cwd), str(real)) is True
    assert unsafe_path_entries([str(real)], str(cwd), str(link)) is True


# --- PYTHONSAFEPATH for the pool's lifetime ------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "env", "expected"),
    [
        (PLAIN, {"PYTHONSAFEPATH": "1"}, True),
        (PLAIN, {}, False),
        (PLAIN, {"PYTHONSAFEPATH": "0"}, False),
        (replace(PLAIN, isolated=1), {}, True),
        (replace(PLAIN, safe_path=True), {}, True),
    ],
)
def test_safe_path_still_set(flags: FakeFlags, env: dict[str, str], expected: bool) -> None:
    assert safe_path_still_set(flags=flags, environ=env) is expected


def test_safe_path_still_set_reads_os_environ_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONSAFEPATH", "1")
    assert safe_path_still_set(flags=PLAIN) is True
    monkeypatch.delenv("PYTHONSAFEPATH")
    assert safe_path_still_set(flags=PLAIN) is False


# --- worker backstop -----------------------------------------------------------------------

SAFE = replace(PLAIN, safe_path=True)


@pytest.mark.parametrize("flags", [SAFE, replace(PLAIN, isolated=1)])
def test_the_backstop_passes_a_clean_worker(flags: FakeFlags, dirs: tuple[str, str, str]) -> None:
    cwd, root, site = dirs
    check_worker(flags, [site], cwd, root)


@pytest.mark.parametrize("which", ["no flag", "empty", "cwd", "root"])
def test_the_backstop_fails_closed_on_each_condition(
    which: str, dirs: tuple[str, str, str]
) -> None:
    cwd, root, site = dirs
    flags = PLAIN if which == "no flag" else SAFE
    extra = {"no flag": [], "empty": [""], "cwd": [cwd], "root": [root]}[which]
    with pytest.raises(ComponentError) as info:
        check_worker(flags, [site, *extra], cwd, root)
    assert info.value.component == "checkers"
    assert info.value.message == "worker isolation check failed"
    assert all(d not in str(info.value) for d in dirs)


def test_the_initializer_checks_this_processes_flags_path_cwd_and_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[object, ...]] = []

    def record(flags: object, path: object, cwd: object, root: object) -> None:
        seen.append((flags, path, cwd, root))

    monkeypatch.setattr(isolation, "check_worker", record)
    worker_backstop("/the/root")
    assert seen == [(sys.flags, sys.path, os.getcwd(), "/the/root")]
