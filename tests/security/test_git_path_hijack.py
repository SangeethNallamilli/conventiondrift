"""SR-013 PATH-hijack tests for safe git resolution (INTERFACES I-14, D-TL-19).

A planted ``git``, ``git.exe``, ``git.cmd`` or ``git.bat`` in the checkout, the
cwd, an empty PATH entry, ``.``, or a relative PATH entry must never be
resolved or executed. When no trusted git remains, the result is the I-14
error — ``GitUnavailable`` if PATH had no git at all, or
``ComponentError("gitread")`` if every candidate was dropped — never a
fallback to the planted binary.

The filesystem-root cwd exemption (containers with ``WORKDIR /``) must still
refuse a git inside a checkout at ``/``, ``C:\\`` or another drive root.

These tests call the T-007 contract ``_find_git`` and ``_run_bounded``
directly. They live under ``tests/security`` so T-003's windows-latest leg
runs them on a real Windows runner.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError, GitUnavailable

_STDERR_PROBE = "ghp_FAKE0000_SR013_stderr_leak"
_GIT_NAMES = ("git", "git.exe", "git.cmd", "git.bat")
_WINDOWS_ONLY_REASON = (
    "Windows PATHEXT resolution of git.cmd and git.bat is a Windows-only PATH fact"
)


def _platform_git_name() -> str:
    return "git.exe" if os.name == "nt" else "git"


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _write_posix_fake(dest: Path, sentinel: Path, *, stderr_secret: str) -> None:
    lines = [
        "#!/bin/sh",
        f"printf 'hijacked\\n' > {_sh_quote(str(sentinel))}",
        f"printf '%s\\n' {_sh_quote(stderr_secret)} >&2",
        "exit 0",
    ]
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_windows_bat(dest: Path, sentinel: Path, *, stderr_secret: str) -> None:
    # echo ...>file writes the sentinel; the secret goes only to stderr.
    lines = [
        "@echo off",
        f'echo hijacked>"{sentinel}"',
        f"echo {stderr_secret} 1>&2",
        "exit /b 0",
    ]
    dest.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")


def _run_tool(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run ``argv`` if the executable is on PATH; ``None`` if it is missing."""
    resolved = shutil.which(argv[0])
    if resolved is None:
        return None
    return subprocess.run(  # noqa: S603
        [resolved, *argv[1:]], check=False, capture_output=True, text=True
    )


def _write_windows_exe(dest: Path, sentinel: Path, *, stderr_secret: str) -> None:
    """Compile a tiny console exe so a planted git.exe is actually runnable."""
    sentinel_lit = str(sentinel).replace("\\", "\\\\").replace('"', '\\"')
    secret_lit = stderr_secret.replace("\\", "\\\\").replace('"', '\\"')
    source = (
        "#include <stdio.h>\n"
        "int main(void) {\n"
        f'    FILE *f = fopen("{sentinel_lit}", "w");\n'
        '    if (f) { fputs("hijacked\\n", f); fclose(f); }\n'
        f'    fprintf(stderr, "%s\\n", "{secret_lit}");\n'
        "    return 0;\n"
        "}\n"
    )
    src = dest.with_suffix(".c")
    src.write_text(source, encoding="utf-8")
    compilers = (
        ["gcc", "-O0", "-s", "-o", str(dest), str(src)],
        ["clang", "-O0", "-s", "-o", str(dest), str(src)],
        ["cl", "/nologo", "/Fe" + str(dest), str(src)],
    )
    errors: list[str] = []
    for argv in compilers:
        completed = _run_tool(argv)
        if completed is None:
            continue
        if completed.returncode == 0 and dest.exists():
            return
        errors.append(f"{argv[0]}: {completed.stderr or completed.stdout}")
    # .NET Framework / PowerShell Add-Type, common on windows-latest.
    csharp = dest.with_suffix(".cs")
    verbatim = str(sentinel).replace('"', '""')
    csharp.write_text(
        "using System;\nusing System.IO;\n"
        "class FakeGit {\n"
        "  static void Main() {\n"
        f'    File.WriteAllText(@"{verbatim}", "hijacked\\n");\n'
        f'    Console.Error.WriteLine("{secret_lit}");\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    ps = (
        "Add-Type -OutputType ConsoleApplication "
        f"-OutputAssembly '{dest}' "
        f"-TypeDefinition (Get-Content -Raw '{csharp}')"
    )
    completed = _run_tool(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
    if completed is not None and completed.returncode == 0 and dest.exists():
        return
    if completed is not None:
        errors.append(f"powershell: {completed.stderr or completed.stdout}")
    raise RuntimeError(
        "could not compile a runnable git.exe test stub; tried gcc, clang, cl, "
        "and PowerShell Add-Type. " + " | ".join(errors)
    )


def _write_fake_git(
    folder: Path,
    name: str,
    sentinel: Path,
    *,
    stderr_secret: str = _STDERR_PROBE,
) -> Path:
    """Write a runnable fake git that records execution in ``sentinel``."""
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / name
    if os.name == "nt" and name.lower().endswith(".exe"):
        _write_windows_exe(dest, sentinel, stderr_secret=stderr_secret)
    elif os.name == "nt" and name.lower().endswith((".cmd", ".bat")):
        _write_windows_bat(dest, sentinel, stderr_secret=stderr_secret)
    else:
        _write_posix_fake(dest, sentinel, stderr_secret=stderr_secret)
    return dest


def _plant_all_names(folder: Path, sentinel: Path) -> list[Path]:
    return [_write_fake_git(folder, name, sentinel) for name in _GIT_NAMES]


def _plant_named(folder: Path, name: str) -> Path:
    """Create a file with ``name`` for PATH-walk tests; it is not executed."""
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / name
    if name.lower().endswith(".exe"):
        dest.write_bytes(b"")
    else:
        dest.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest


def _symlink_or_skip(link: Path, target: Path) -> None:
    """Create ``link`` -> ``target``.

    Skip only on a local non-Windows machine without CI, where symlink
    support may be missing. Under CI, GitHub Actions, or on Windows, a
    failure is a hard fail so a windows-latest run cannot hide the
    post-walk proof in the skipped count (CR2 S1, SR D-002).
    """
    try:
        link.symlink_to(target)
    except OSError as exc:
        message = f"failed to create symlink {link} -> {target}: {exc}"
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or sys.platform == "win32":
            pytest.fail(message)
        pytest.skip(message)


def _write_reader_git(folder: Path, name: str, marker: Path) -> Path:
    """Runnable fake git for a public GitReader call.

    Writes ``marker`` on every execution, prints a parseable 2.30 ``--version``,
    and answers ``--is-shallow-repository`` with ``false``.
    """
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / name
    if os.name == "nt" and name.lower().endswith(".exe"):
        sentinel_lit = str(marker).replace("\\", "\\\\").replace('"', '\\"')
        verbatim = str(marker).replace('"', '""')
        source = (
            "#include <stdio.h>\n#include <string.h>\n"
            "int main(int argc, char **argv) {\n"
            f'    FILE *f = fopen("{sentinel_lit}", "w");\n'
            '    if (f) { fputs("trusted\\n", f); fclose(f); }\n'
            "    for (int i = 1; i < argc; i++) {\n"
            '        if (strcmp(argv[i], "--version") == 0) {\n'
            '            fputs("git version 2.30.0\\n", stdout);\n'
            "            return 0;\n"
            "        }\n"
            '        if (strcmp(argv[i], "--is-shallow-repository") == 0) {\n'
            '            fputs("false\\n", stdout);\n'
            "            return 0;\n"
            "        }\n"
            "    }\n"
            "    return 1;\n"
            "}\n"
        )
        csharp = (
            "using System;\nusing System.IO;\n"
            "class FakeGit {\n"
            "  static int Main(string[] args) {\n"
            f'    File.WriteAllText(@"{verbatim}", "trusted\\n");\n'
            "    foreach (string arg in args) {\n"
            '      if (arg == "--version") {\n'
            '        Console.Write("git version 2.30.0\\n"); return 0;\n'
            "      }\n"
            '      if (arg == "--is-shallow-repository") {\n'
            '        Console.Write("false\\n"); return 0;\n'
            "      }\n"
            "    }\n"
            "    return 1;\n"
            "  }\n"
            "}\n"
        )
        src = dest.with_suffix(".c")
        src.write_text(source, encoding="utf-8")
        cs_path = dest.with_suffix(".cs")
        cs_path.write_text(csharp, encoding="utf-8")
        compilers = (
            ["gcc", "-O0", "-s", "-o", str(dest), str(src)],
            ["clang", "-O0", "-s", "-o", str(dest), str(src)],
            ["cl", "/nologo", "/Fe" + str(dest), str(src)],
        )
        errors: list[str] = []
        for argv in compilers:
            completed = _run_tool(argv)
            if completed is None:
                continue
            if completed.returncode == 0 and dest.exists():
                return dest
            errors.append(f"{argv[0]}: {completed.stderr or completed.stdout}")
        ps = (
            "Add-Type -OutputType ConsoleApplication "
            f"-OutputAssembly '{dest}' "
            f"-TypeDefinition (Get-Content -Raw '{cs_path}')"
        )
        completed = _run_tool(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
        if completed is not None and completed.returncode == 0 and dest.exists():
            return dest
        if completed is not None:
            errors.append(f"powershell: {completed.stderr or completed.stdout}")
        raise RuntimeError(
            "could not compile a runnable GitReader git stub; tried gcc, clang, "
            "cl, and PowerShell Add-Type. " + " | ".join(errors)
        )
    lines = [
        "#!/bin/sh",
        f"printf 'trusted\\n' > {_sh_quote(str(marker))}",
        'for arg in "$@"; do',
        '  if [ "$arg" = --version ]; then',
        "    printf 'git version 2.30.0\\n'",
        "    exit 0",
        "  fi",
        '  if [ "$arg" = --is-shallow-repository ]; then',
        "    printf 'false\\n'",
        "    exit 0",
        "  fi",
        "done",
        "exit 1",
    ]
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return dest


def _set_path(monkeypatch: pytest.MonkeyPatch, *entries: str | Path) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join(str(entry) for entry in entries))


def _is_inside(path: Path, folder: Path) -> bool:
    real = path.resolve()
    root = folder.resolve()
    return real == root or real.is_relative_to(root)


def _same_file(left: str | Path, right: str | Path) -> bool:
    """Compare real paths without constructing pathlib.Path after os.name patches."""
    return os.path.normcase(os.path.realpath(str(left))) == os.path.normcase(
        os.path.realpath(str(right))
    )


@contextlib.contextmanager
def _os_name(name: str) -> Iterator[None]:
    """Set ``os.name`` only around the call under test, then restore it.

    On Python 3.11, a failed assertion that builds ``pathlib.Path`` while
    ``os.name == "nt"`` on a POSIX host crashes pytest with INTERNALERROR
    (T26-6). Path objects used by the caller must be built before entering.
    """
    previous = os.name
    os.name = name
    try:
        yield
    finally:
        os.name = previous


def _search_entries(search_path: str) -> list[str]:
    return [entry for entry in search_path.split(os.pathsep) if entry]


def _assert_not_executed(sentinel: Path) -> None:
    assert not sentinel.exists(), "a planted git was executed (sentinel written)"


def _assert_no_secret(payload: str) -> None:
    assert _STDERR_PROBE not in payload


def _exc_text(exc: BaseException) -> str:
    parts = [str(exc), repr(exc.args)]
    message = getattr(exc, "message", None)
    if isinstance(message, str):
        parts.append(message)
    return "\n".join(parts)


def _assert_dropped_git_error(exc: BaseException) -> None:
    """I-14: a git existed only in dropped locations → ComponentError('gitread')."""
    assert type(exc) is ComponentError
    assert exc.component == "gitread"
    _assert_no_secret(_exc_text(exc))


@pytest.fixture
def hijack_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    workspace = tmp_path / "workspace"
    trusted = tmp_path / "trusted"
    relbin = cwd / "relbin"
    for folder in (repo, cwd, workspace, trusted, relbin):
        folder.mkdir(parents=True, exist_ok=True)
    sentinel = tmp_path / "sentinel"
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    return {
        "root": tmp_path,
        "repo": repo,
        "cwd": cwd,
        "workspace": workspace,
        "trusted": trusted,
        "relbin": relbin,
        "sentinel": sentinel,
    }


# ---------------------------------------------------------------------------
# SR-013 / I-14 step 1: planted git in untrusted locations is never used
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario",
    [
        "repo",
        "cwd",
        "empty_path_entry",
        "dot_path_entry",
        "relative_path_entry",
        "workspace",
    ],
)
def test_planted_git_is_neither_resolved_nor_executed(
    scenario: str,
    hijack_layout: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SR-013: git in the checkout, cwd, empty PATH, '.', or a relative entry.

    I-14 step 1 drops empty entries, ``.``, every relative entry, and every
    entry whose real path is inside the repo, GITHUB_WORKSPACE, or the cwd.
    I-14 step 2: if a git existed but every candidate was dropped, raise
    ComponentError("gitread") and never run the planted binary.
    """
    repo = hijack_layout["repo"]
    cwd = hijack_layout["cwd"]
    workspace = hijack_layout["workspace"]
    relbin = hijack_layout["relbin"]
    sentinel = hijack_layout["sentinel"]

    if scenario == "repo":
        _plant_all_names(repo, sentinel)
        _set_path(monkeypatch, repo)
    elif scenario == "cwd":
        _plant_all_names(cwd, sentinel)
        _set_path(monkeypatch, cwd)
    elif scenario == "empty_path_entry":
        # An empty PATH entry means the cwd on POSIX; I-14 drops it everywhere.
        _plant_all_names(cwd, sentinel)
        _set_path(monkeypatch, "", cwd / "no-such-bin")
    elif scenario == "dot_path_entry":
        _plant_all_names(cwd, sentinel)
        _set_path(monkeypatch, ".")
    elif scenario == "relative_path_entry":
        _plant_all_names(relbin, sentinel)
        _set_path(monkeypatch, "relbin")
    elif scenario == "workspace":
        _plant_all_names(workspace, sentinel)
        monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
        _set_path(monkeypatch, workspace)
    else:
        raise AssertionError(f"unknown scenario {scenario}")

    with pytest.raises(ComponentError) as info:
        gitread._find_git(repo)
    _assert_dropped_git_error(info.value)
    _assert_not_executed(sentinel)


def test_relative_path_to_git_outside_untrusted_folders_is_still_dropped(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-14: every relative PATH entry is dropped, even if it resolves outside
    the repo, workspace and cwd. Allowing relative entries would let PATH
    ``../outside`` resolve a planted git that the folder rules would miss.
    """
    outside = hijack_layout["root"] / "outside"
    sentinel = hijack_layout["sentinel"]
    _plant_all_names(outside, sentinel)
    _set_path(monkeypatch, "../outside")

    with pytest.raises(ComponentError) as info:
        gitread._find_git(hijack_layout["repo"])
    _assert_dropped_git_error(info.value)
    _assert_not_executed(sentinel)


def test_no_git_anywhere_on_path_raises_git_unavailable(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-14 step 2: no git exists anywhere on PATH → GitUnavailable (head-only)."""
    empty = hijack_layout["root"] / "empty-bin"
    empty.mkdir()
    _set_path(monkeypatch, empty)
    with pytest.raises(GitUnavailable) as info:
        gitread._find_git(hijack_layout["repo"])
    _assert_no_secret(_exc_text(info.value))
    _assert_not_executed(hijack_layout["sentinel"])


def test_cwd_git_is_not_used_when_cwd_is_not_on_path(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-013: shutil.which must be given the filtered PATH explicitly.

    On Windows, which() otherwise searches the cwd first, so a committed
    git.exe in the current folder would run even if cwd is not on PATH.
    """
    _plant_all_names(hijack_layout["cwd"], hijack_layout["sentinel"])
    empty = hijack_layout["root"] / "empty-bin"
    empty.mkdir()
    _set_path(monkeypatch, empty)
    with pytest.raises(GitUnavailable) as info:
        gitread._find_git(hijack_layout["repo"])
    _assert_no_secret(_exc_text(info.value))
    _assert_not_executed(hijack_layout["sentinel"])


def test_trusted_git_is_used_and_search_path_excludes_untrusted(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-14: resolve a trusted git; search_path omits repo, workspace and cwd.

    Untrusted locations also appear on PATH (absolute, empty, '.', relative)
    and hold planted binaries; none of those may be resolved or executed.
    """
    repo = hijack_layout["repo"]
    cwd = hijack_layout["cwd"]
    workspace = hijack_layout["workspace"]
    trusted = hijack_layout["trusted"]
    relbin = hijack_layout["relbin"]
    sentinel = hijack_layout["sentinel"]
    _plant_all_names(repo, sentinel)
    _plant_all_names(cwd, sentinel)
    _plant_all_names(workspace, sentinel)
    _plant_all_names(relbin, sentinel)
    trusted_git = _write_fake_git(trusted, _platform_git_name(), sentinel)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    _set_path(monkeypatch, repo, cwd, workspace, ".", "", "relbin", trusted)

    resolved = gitread._find_git(repo)

    assert isinstance(resolved, gitread._ResolvedGit)
    assert dataclasses.is_dataclass(type(resolved))
    assert type(resolved).__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert Path(resolved.path).resolve() == trusted_git.resolve()
    entries = _search_entries(resolved.search_path)
    for folder in (repo, cwd, workspace):
        for entry in entries:
            assert not _is_inside(Path(entry), folder), (
                f"search_path kept untrusted entry {entry!r} inside {folder}"
            )
    for dropped in (".", "relbin"):
        assert dropped not in entries
    # search_path is the PATH git runs with: no empty entries, and only the
    # kept trusted folder (exactly), so a kept "" cannot hide as an empty path.
    assert resolved.search_path == str(trusted)
    assert "" not in resolved.search_path.split(os.pathsep)
    assert any(Path(entry).resolve() == trusted.resolve() for entry in entries)
    _assert_not_executed(sentinel)


# ---------------------------------------------------------------------------
# I-14 filesystem-root cwd exemption, still refusing a root checkout
# ---------------------------------------------------------------------------


def test_cwd_at_filesystem_root_still_resolves_trusted_git_outside_checkout(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-14: skip the cwd drop rule at ``/`` or a drive root (e.g. WORKDIR /).

    A trusted git that lives under that root, but outside the checkout and
    GITHUB_WORKSPACE, must still be resolved. Removing the exemption would
    treat every PATH entry as inside the cwd and fail closed.
    """
    repo = hijack_layout["repo"]
    trusted = hijack_layout["trusted"]
    sentinel = hijack_layout["sentinel"]
    trusted_git = _write_fake_git(trusted, _platform_git_name(), sentinel)
    _set_path(monkeypatch, trusted)
    monkeypatch.chdir(Path(hijack_layout["root"].anchor))

    resolved = gitread._find_git(repo)

    assert Path(resolved.path).resolve() == trusted_git.resolve()
    _assert_not_executed(sentinel)


@pytest.mark.parametrize("empty_kind", ["leading", "trailing", "doubled"])
def test_empty_path_entries_are_dropped_when_cwd_is_filesystem_root(
    empty_kind: str,
    hijack_layout: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I-14: drop empty PATH entries even when the cwd is a filesystem root.

    The cwd containment rule is skipped at ``/`` or a drive root (WORKDIR /).
    Empty entries must still be dropped by the empty-entry rule itself, not
    sent through the realpath / containment check. ``realpath('')`` is the
    cwd, so a mutant that routes ``''`` through that check keeps the empty
    entry when the cwd is a root, and ``search_path`` becomes ``:<trusted>``
    or ``<trusted>::``. I-14 says to drop empty entries and that
    ``search_path`` is the kept entries joined with ``os.pathsep``, so the
    expected value is the trusted folder alone.
    """
    repo = hijack_layout["repo"]
    trusted = hijack_layout["trusted"]
    sentinel = hijack_layout["sentinel"]
    trusted_git = _write_fake_git(trusted, _platform_git_name(), sentinel)
    trusted_str = str(trusted)
    # Three empty-entry classes from I-14 ("Drop empty entries"): a leading
    # separator, a trailing separator, and a doubled separator. Expected
    # search_path is written from that rule, not from _split_path.
    sep = os.pathsep
    if empty_kind == "leading":
        path_value = f"{sep}{trusted_str}"
    elif empty_kind == "trailing":
        path_value = f"{trusted_str}{sep}"
    elif empty_kind == "doubled":
        path_value = f"{trusted_str}{sep}{sep}"
    else:
        raise AssertionError(f"unknown empty_kind {empty_kind}")
    monkeypatch.setenv("PATH", path_value)
    monkeypatch.chdir(Path(hijack_layout["root"].anchor))
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)

    resolved = gitread._find_git(repo)

    assert Path(resolved.path).resolve() == trusted_git.resolve()
    assert resolved.search_path == trusted_str
    _assert_not_executed(sentinel)


def test_checkout_at_filesystem_root_never_uses_git_inside_the_checkout(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-14: repo and GITHUB_WORKSPACE rules still apply when they are a root.

    With the checkout at ``/`` or ``C:\\``, ``/usr/bin/git`` sits inside the
    repo. The cwd exemption must not let that binary be chosen or run. This
    is simulated on every OS by treating a tmp checkout as a filesystem root.
    """
    fake_root = hijack_layout["root"] / "fsroot"
    fake_root.mkdir()
    sentinel = hijack_layout["sentinel"]
    _plant_all_names(fake_root / "usr" / "bin", sentinel)

    real_is_root = gitread._is_filesystem_root

    def is_root(path: str) -> bool:
        try:
            if Path(path).resolve() == fake_root.resolve():
                return True
        except OSError:
            pass
        return real_is_root(path)

    monkeypatch.setattr(gitread, "_is_filesystem_root", is_root)
    monkeypatch.chdir(fake_root)
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    _set_path(monkeypatch, fake_root / "usr" / "bin")

    with pytest.raises(ComponentError) as info:
        gitread._find_git(fake_root)
    _assert_dropped_git_error(info.value)
    _assert_not_executed(sentinel)


@pytest.mark.parametrize(
    ("scenario", "path_entry"),
    [
        ("empty_path_entry", ""),
        ("dot_path_entry", "."),
        ("relative_path_entry", "relbin"),
    ],
)
def test_relative_or_empty_path_entry_is_dropped_when_cwd_is_filesystem_root(
    scenario: str,
    path_entry: str,
    hijack_layout: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I-14: drop empty, ``.`` and plain-relative PATH entries even at a root cwd.

    The cwd containment rule is skipped when the cwd is a filesystem root
    (WORKDIR /). A planted git in that cwd, or in a plain-relative folder
    under it, is then protected only by the relative-entry rule (I-14 step 1:
    drop empty entries, ``.``, and every relative entry). Each class is its
    own case so a mutant that keeps only that class is killed on its own row
    (D-TL-25). The expected result is written from I-14 step 2, not from the
    code: a git existed but every candidate was dropped, so
    ComponentError("gitread"), and the planted binary is never run.
    """
    # The checkout is a different folder from the simulated root. If they
    # were the same, the repo rule would still drop the planted git and a
    # relative-entry mutant would survive (CR2 B1).
    repo = hijack_layout["repo"]
    fake_root = hijack_layout["root"] / "fsroot"
    fake_root.mkdir()
    relbin = fake_root / "relbin"
    relbin.mkdir()
    sentinel = hijack_layout["sentinel"]
    if scenario == "relative_path_entry":
        _plant_all_names(relbin, sentinel)
    elif scenario in ("empty_path_entry", "dot_path_entry"):
        _plant_all_names(fake_root, sentinel)
    else:
        raise AssertionError(f"unknown scenario {scenario}")

    real_is_root = gitread._is_filesystem_root

    def is_root(path: str) -> bool:
        try:
            if Path(path).resolve() == fake_root.resolve():
                return True
        except OSError:
            pass
        return real_is_root(path)

    monkeypatch.setattr(gitread, "_is_filesystem_root", is_root)
    monkeypatch.chdir(fake_root)
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    _set_path(monkeypatch, path_entry)

    with pytest.raises(ComponentError) as info:
        gitread._find_git(repo)
    _assert_dropped_git_error(info.value)
    _assert_not_executed(sentinel)


# ---------------------------------------------------------------------------
# SR-013 Windows: only git.exe is considered
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "nt", reason=_WINDOWS_ONLY_REASON)
def test_windows_git_cmd_and_git_bat_are_never_chosen(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-013: on Windows, look up ``git.exe`` only, never ``git.cmd`` / ``git.bat``.

    The shims sit in an otherwise trusted absolute PATH directory (outside the
    repo, workspace and cwd). They must not be resolved or executed; with no
    git.exe on PATH the result is GitUnavailable.
    """
    trusted = hijack_layout["trusted"]
    sentinel = hijack_layout["sentinel"]
    _write_fake_git(trusted, "git.cmd", sentinel)
    _write_fake_git(trusted, "git.bat", sentinel)
    _set_path(monkeypatch, trusted)

    with pytest.raises(GitUnavailable) as info:
        gitread._find_git(hijack_layout["repo"])
    _assert_no_secret(_exc_text(info.value))
    _assert_not_executed(sentinel)


# ---------------------------------------------------------------------------
# SR-014 bounds used by the git runner (timeout, cap, stderr must not leak)
# ---------------------------------------------------------------------------


def _python_env() -> dict[str, str]:
    return dict(os.environ)


def test_run_bounded_timeout_raises_component_error_and_kills_process(
    tmp_path: Path,
) -> None:
    """I-14 / SR-014: past ``timeout`` the process is killed; ComponentError('gitread')."""
    marker = tmp_path / "after-sleep"
    code = (
        "import time, pathlib\n"
        "time.sleep(30)\n"
        f"pathlib.Path({str(marker)!r}).write_text('slept\\n')\n"
    )
    with pytest.raises(ComponentError) as info:
        gitread._run_bounded(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            env=_python_env(),
            label="sleep",
            max_stdout=4096,
            timeout=0.4,
        )
    assert info.value.component == "gitread"
    text = _exc_text(info.value)
    _assert_no_secret(text)
    assert code not in text
    assert str(marker) not in text
    assert not marker.exists(), "timed-out process was not killed"


def test_run_bounded_max_stdout_plus_one_raises_component_error(tmp_path: Path) -> None:
    """I-14 / SR-014: stdout of max_stdout+1 bytes fails closed as ComponentError."""
    payload = "X" * 9
    with pytest.raises(ComponentError) as info:
        gitread._run_bounded(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'X'*9)"],
            cwd=tmp_path,
            env=_python_env(),
            label="stdout",
            max_stdout=8,
            timeout=10.0,
        )
    assert info.value.component == "gitread"
    _assert_no_secret(_exc_text(info.value))
    assert payload not in _exc_text(info.value)


def test_run_bounded_exact_max_stdout_succeeds(tmp_path: Path) -> None:
    out = gitread._run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'X'*8)"],
        cwd=tmp_path,
        env=_python_env(),
        label="stdout",
        max_stdout=8,
        timeout=10.0,
    )
    assert isinstance(out, gitread._Output)
    assert out.returncode == 0
    assert out.stdout == b"X" * 8
    assert "stderr" not in {f.name for f in dataclasses.fields(out)}


def test_run_bounded_stderr_secret_is_never_echoed(tmp_path: Path) -> None:
    """I-14 / SR-014: stderr is drained and discarded; messages never contain it."""
    success_code = (
        "import sys\n"
        f"sys.stderr.write({_STDERR_PROBE!r} + '\\n')\n"
        "sys.stdout.buffer.write(b'ok\\n')\n"
    )
    out = gitread._run_bounded(
        [sys.executable, "-c", success_code],
        cwd=tmp_path,
        env=_python_env(),
        label="secret",
        max_stdout=4096,
        timeout=10.0,
    )
    assert out.returncode == 0
    assert out.stdout == b"ok\n"
    _assert_no_secret(out.stdout.decode("latin1"))
    assert "stderr" not in {f.name for f in dataclasses.fields(out)}

    timeout_code = (
        "import sys, time\n"
        f"sys.stderr.write({_STDERR_PROBE!r} + '\\n')\n"
        "sys.stderr.flush()\n"
        "time.sleep(30)\n"
    )
    with pytest.raises(ComponentError) as info:
        gitread._run_bounded(
            [sys.executable, "-c", timeout_code],
            cwd=tmp_path,
            env=_python_env(),
            label="secret-timeout",
            max_stdout=4096,
            timeout=0.4,
        )
    assert info.value.component == "gitread"
    _assert_no_secret(_exc_text(info.value))


# ---------------------------------------------------------------------------
# T26-1: public GitReader path really executes the resolved git
# ---------------------------------------------------------------------------


def test_gitreader_runs_trusted_git_and_never_executes_a_planted_one(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A public GitReader call would run a planted git if resolution slipped.

    The trusted fake must actually run (its marker is written) for ``is_shallow``.
    The env ``PATH`` given to ``_run_bounded`` equals ``search_path``, not the
    unfiltered process PATH (I-14: git runs with the filtered PATH).
    """
    repo = hijack_layout["repo"]
    cwd = hijack_layout["cwd"]
    workspace = hijack_layout["workspace"]
    trusted = hijack_layout["trusted"]
    planted_sentinel = hijack_layout["sentinel"]
    trusted_marker = hijack_layout["root"] / "trusted-marker"
    _plant_all_names(repo, planted_sentinel)
    _plant_all_names(cwd, planted_sentinel)
    trusted_git = _write_reader_git(trusted, _platform_git_name(), trusted_marker)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    _set_path(monkeypatch, repo, cwd, workspace, ".", "", "relbin", trusted)
    unfiltered = os.environ["PATH"]

    recorded: list[dict[str, str]] = []
    real_run = gitread._run_bounded

    def spy(
        argv: Sequence[str],
        *,
        cwd: Path,
        env: dict[str, str],
        label: str,
        max_stdout: int,
        timeout: float,
    ) -> gitread._Output:
        recorded.append(env)
        return real_run(
            argv,
            cwd=cwd,
            env=env,
            label=label,
            max_stdout=max_stdout,
            timeout=timeout,
        )

    monkeypatch.setattr(gitread, "_run_bounded", spy)

    resolved = gitread._find_git(repo)
    assert Path(resolved.path).resolve() == trusted_git.resolve()
    assert resolved.search_path == str(trusted)
    assert gitread.GitReader(repo).is_shallow() is False

    _assert_not_executed(planted_sentinel)
    assert trusted_marker.is_file(), "trusted git was not executed on the public path"
    assert trusted_marker.read_text(encoding="utf-8") == "trusted\n"
    assert recorded, "GitReader issued no bounded git call"
    for env in recorded:
        assert env["PATH"] == resolved.search_path
        assert env["PATH"] != unfiltered


# ---------------------------------------------------------------------------
# T26-3: second-check and per-entry realpath (symlink mutants)
# ---------------------------------------------------------------------------


def _raise_symlink_oserror(*_args: object, **_kwargs: object) -> None:
    raise OSError("simulated symlink failure")


def test_symlink_or_skip_fails_under_ci_when_symlink_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CR2 S1 / SR D-002: a symlink OSError is a hard fail when CI is set."""
    monkeypatch.setattr(os, "symlink", _raise_symlink_oserror)
    monkeypatch.setenv("CI", "1")
    link = tmp_path / "link"
    target = tmp_path / "target"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(pytest.fail.Exception, match="simulated symlink failure"):
        _symlink_or_skip(link, target)


def test_symlink_or_skip_skips_locally_when_symlink_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CR2 S1: skip remains only for local non-Windows development without CI."""
    monkeypatch.setattr(os, "symlink", _raise_symlink_oserror)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    link = tmp_path / "link"
    target = tmp_path / "target"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(pytest.skip.Exception, match="simulated symlink failure"):
        _symlink_or_skip(link, target)


def test_git_symlink_in_a_kept_folder_to_a_planted_binary_is_refused(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-14 second path check: realpath of the binary must not be in the repo.

    The PATH entry itself stays outside the checkout, so only the post-walk
    realpath re-check refuses a ``git`` that is a symlink to a planted binary.
    Skipping that check would resolve the planted git.
    """
    repo = hijack_layout["repo"]
    sentinel = hijack_layout["sentinel"]
    planted = _write_fake_git(repo, _platform_git_name(), sentinel)
    outside = hijack_layout["root"] / "outside"
    outside.mkdir()
    _symlink_or_skip(outside / _platform_git_name(), planted)
    _set_path(monkeypatch, outside)

    with pytest.raises(ComponentError) as info:
        gitread._find_git(repo)
    _assert_dropped_git_error(info.value)
    _assert_not_executed(sentinel)


def test_symlink_path_entry_into_the_repo_is_dropped_when_trusted_git_follows(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """I-14 per-entry realpath: a PATH folder symlinked into the repo is dropped.

    Without realpath the entry looks innocent, the walk would hit the planted
    git first, and the binary re-check would fail closed instead of using the
    later trusted git.
    """
    repo = hijack_layout["repo"]
    trusted = hijack_layout["trusted"]
    sentinel = hijack_layout["sentinel"]
    _plant_all_names(repo / "tools", sentinel)
    innocent = hijack_layout["root"] / "innocent"
    _symlink_or_skip(innocent, repo / "tools")
    trusted_git = _write_fake_git(trusted, _platform_git_name(), sentinel)
    _set_path(monkeypatch, innocent, trusted)

    resolved = gitread._find_git(repo)

    assert Path(resolved.path).resolve() == trusted_git.resolve()
    assert resolved.search_path == str(trusted)
    _assert_not_executed(sentinel)


# ---------------------------------------------------------------------------
# T26-2 / N-6: simulated Windows (os.name = nt, as in test_gitread.py @ 153d43c)
# ---------------------------------------------------------------------------


def test_windows_pathext_order_never_picks_cmd_bat_or_com(
    hijack_layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """SR-013 / N-6: PATHEXT is ignored; only git.exe counts on Windows.

    ``git.cmd``, ``git.bat`` and ``git.com`` sit in an earlier PATH folder than
    ``git.exe``, and PATHEXT lists ``.CMD``, ``.BAT`` and ``.COM`` before
    ``.EXE``. The walk must still resolve the later git.exe and must not raise
    ComponentError.
    """
    # Build every Path and plant every file before patching os.name. On
    # Python 3.11, constructing pathlib.Path with os.name == "nt" on a POSIX
    # host crashes (T26-6).
    shims = hijack_layout["root"] / "shims"
    exe_dir = hijack_layout["trusted"]
    repo = hijack_layout["repo"]
    for name in ("git.cmd", "git.bat", "git.com"):
        _plant_named(shims, name)
    trusted = _plant_named(exe_dir, "git.exe")
    _set_path(monkeypatch, shims, exe_dir)
    monkeypatch.setenv("PATHEXT", ".CMD;.BAT;.COM;.EXE")
    expected_search_path = os.pathsep.join([str(shims), str(exe_dir)])
    trusted_as_str = str(trusted)

    with _os_name("nt"):
        resolved = gitread._find_git(repo)
        resolved_path = resolved.path
        resolved_search_path = resolved.search_path

    assert _same_file(resolved_path, trusted_as_str)
    assert resolved_search_path == expected_search_path


@pytest.mark.parametrize("where", ["repo", "cwd"])
def test_planted_windows_git_exe_does_not_knock_out_trusted_git(
    where: str,
    hijack_layout: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SR N-6: a git.exe in the checkout root or cwd must not hide a trusted git.

    Simulated ``os.name == "nt"`` as in test_gitread.py at 153d43c. ``shutil.which``
    on Windows prepends the current folder even when ``path=`` is given, so a
    planted git.exe would fail the containment re-check and raise ComponentError
    instead of using the later trusted git. The walk must resolve the trusted
    one and must not raise. The ``[repo]`` case chdirs into the checkout so it
    models the Actions layout where the checkout is the cwd (T26-7).
    """
    # Build every Path and plant every file before patching os.name (T26-6).
    repo = hijack_layout["repo"]
    cwd = hijack_layout["cwd"]
    trusted_dir = hijack_layout["trusted"]
    planted_in = repo if where == "repo" else cwd
    _plant_named(planted_in, "git.exe")
    trusted = _plant_named(trusted_dir, "git.exe")
    _set_path(monkeypatch, trusted_dir)
    if where == "repo":
        monkeypatch.chdir(repo)
    expected_search_path = str(trusted_dir)
    trusted_as_str = str(trusted)

    with _os_name("nt"):
        resolved = gitread._find_git(repo)
        resolved_path = resolved.path
        resolved_search_path = resolved.search_path

    assert _same_file(resolved_path, trusted_as_str)
    assert resolved_search_path == expected_search_path
