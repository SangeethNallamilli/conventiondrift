"""I-14 item 9 diff-config pins (T-008): repo config can't change gitread's output.

A hostile ``.git/config`` and ``.gitattributes`` set every key the pins override.
``changed_files`` and ``tree`` must stay byte-identical; ``patches`` must too,
except for the text after the second ``@@`` on hunk-header lines (repo
``xfuncname``, which git 2.30 can't turn off). A gpg program that leaves a marker
file must never run. Controls prove the hostile setup really changes plain git's
output, so the comparisons can fail.
"""

import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.errors import ComponentError
from conventiondrift.gitread import GitReader

_REAL_RUN = subprocess.run
_GIT = shutil.which("git") or "git"
_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}
SHA = "ab" * 20
SHA2 = "cd" * 20
_HUNK = re.compile(rb"(@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@).*")


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    """Test helper only: plain git, no hardening."""
    out = _REAL_RUN(
        [_GIT, *args],
        cwd=repo,
        env=dict(_ENV, HOME=str(repo)),
        check=True,
        capture_output=True,
        input=stdin,
    )
    return out.stdout


def _write(repo: Path, rel: str, data: str | bytes) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def _commit(repo: Path, msg: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return _git(repo, "rev-parse", "HEAD").decode().strip()


def _strip_hunk_tails(text: bytes) -> list[bytes]:
    """Lines of ``text``; only on ``@@ -a,b +c,d @@`` header lines, drop what follows."""
    return [
        m[1] if (m := _HUNK.fullmatch(line)) is not None else line for line in text.split(b"\n")
    ]


def _assert_same_patches(clean: bytes, hostile: bytes) -> None:
    assert clean.count(b"\n") == hostile.count(b"\n")
    for a, b in zip(_strip_hunk_tails(clean), _strip_hunk_tails(hostile), strict=True):
        assert a == b


# Found by search: myers and patience disagree on ALG, and the indent heuristic
# moves a hunk in IND, so dropping either pin changes the output.
ALG = ("  y\n{\n\n{\n{\n{\nf()\n", "{\n  x\nf()\n}\n  x\nf()\n{\n  y\n}\ng()\n  x\n  x\n")
IND = ("}\n\n}\nf()\n}\ng()\n  x\n\n{\n  x\ng()\n  y\n", "}\nf()\nf()\ng()\n\n")
_PY = "".join(f"value_{i} = {i}\n" for i in range(30))
_TXT = "# section one\n" + "".join(f"item {i}\n" for i in range(20))


@pytest.fixture
def history(tmp_path: Path) -> tuple[Path, str, str, Path]:
    """A repo whose history exercises every pin: (repo, root, head, gpg marker path)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _write(repo, "a.py", "def first():\n" + _PY)
    _write(repo, "z.py", "z = 1\n")
    _write(repo, "alg.py", ALG[0])
    _write(repo, "ind.py", IND[0])
    _write(repo, "notes.txt", _TXT)
    _write(repo, "old/one.py", "".join(f"one_{i} = {i}\n" for i in range(10)))
    _write(repo, "old/two.py", "".join(f"two_{i} = {i}\n" for i in range(10)))
    _write(repo, "caf\xe9.py", "x = 1\n")
    (repo / "sub").mkdir()  # an unpopulated submodule, so `add -A` keeps the gitlink
    _git(repo, "add", "-A")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{SHA},sub")
    root = _commit(repo, "root")
    # one commit touching everything the pins cover
    lines = ("def first():\n" + _PY).splitlines(keepends=True)
    lines[6] = "value_5 = 'changed'\n"
    lines[10] = "value_9 = 'changed'\n"  # 3 lines apart: interHunkContext=5 would merge
    _write(repo, "a.py", "".join(lines))
    _write(repo, "z.py", "z = 2\n")
    _write(repo, "alg.py", ALG[1])
    _write(repo, "ind.py", IND[1])
    _write(repo, "notes.txt", _TXT.replace("item 15", "item fifteen"))
    (repo / "new").mkdir()
    for name, new in (("one", "uno"), ("two", "dos")):  # other basenames: real -M work
        body = (repo / f"old/{name}.py").read_text().replace(f"{name}_0 = 0", f"{name}_0 = -1")
        (repo / f"old/{name}.py").unlink()
        _write(repo, f"new/{new}.py", body)
    _write(repo, "caf\xe9.py", "x = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{SHA2},sub")
    _commit(repo, "everything")
    # a commit carrying a (fake) signature, so log.showSignature would run gpg
    _write(repo, "z.py", "z = 3\n")
    _git(repo, "add", "-A")
    tree = _git(repo, "write-tree").decode().strip()
    parent = _git(repo, "rev-parse", "HEAD").decode().strip()
    raw = (
        f"tree {tree}\nparent {parent}\n"
        "author t <t@example.invalid> 1767225600 +0000\n"
        "committer t <t@example.invalid> 1767225600 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n"
        "\nsigned\n"
    ).encode()
    head = _git(repo, "hash-object", "-t", "commit", "-w", "--stdin", stdin=raw).decode().strip()
    _git(repo, "update-ref", "HEAD", head)
    return repo, root, head, tmp_path / "gpg-ran"


#: Every hostile key the I-14 item 9 test names, with its value. ``{gpg}`` and
#: ``{order}`` become paths to a marker-writing gpg program and an order file.
HOSTILE_CONFIG: tuple[tuple[str, str], ...] = (
    ("diff.noprefix", "true"),
    ("diff.mnemonicPrefix", "true"),
    ("diff.renames", "false"),
    ("diff.renameLimit", "1"),
    ("diff.algorithm", "patience"),
    ("diff.indentHeuristic", "false"),  # git's default is true
    ("diff.interHunkContext", "5"),
    ("diff.relative", "true"),
    ("diff.submodule", "log"),
    ("diff.orderFile", "{order}"),
    ("diff.evil.xfuncname", "^(# .*)$"),
    ("core.quotePath", "false"),
    ("i18n.logOutputEncoding", "latin1"),
    ("log.showSignature", "true"),
    ("gpg.program", "{gpg}"),
    ("color.ui", "always"),
    ("color.diff", "always"),
)
HOSTILE_ATTRIBUTES: tuple[str, ...] = ("*.py -diff", "*.txt diff=evil")


def _make_hostile(
    repo: Path,
    marker: Path,
    config: tuple[tuple[str, str], ...] = HOSTILE_CONFIG,
    attributes: tuple[str, ...] = HOSTILE_ATTRIBUTES,
) -> None:
    gpg = repo.parent / "fake-gpg"
    gpg.write_text(f"#!/bin/sh\necho ran >> '{marker}'\nexit 1\n")
    gpg.chmod(0o755)
    order = repo.parent / "order.txt"
    order.write_text("z.py\nnotes.txt\nsub\n")
    for key, value in config:
        _git(repo, "config", key, value.format(gpg=gpg, order=order))
    if attributes:
        _write(repo, ".gitattributes", "".join(line + "\n" for line in attributes))


def _outputs(repo: Path, root: str, head: str) -> tuple[bytes, Any, Any]:
    reader = GitReader(repo)
    try:
        return (
            b"".join(reader.patches(None, head)),
            reader.changed_files(root, head),
            reader.tree(head),
        )
    finally:
        reader.close()


_POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="the fake gpg is a POSIX shell script")


@_POSIX_ONLY
def test_hostile_repo_config_does_not_change_any_output(
    history: tuple[Path, str, str, Path],
) -> None:
    repo, root, head, marker = history
    clean = _outputs(repo, root, head)
    _make_hostile(repo, marker)
    hostile = _outputs(repo, root, head)
    _assert_same_patches(clean[0], hostile[0])
    assert hostile[1] == clean[1]  # changed_files: strictly identical
    assert hostile[2] == clean[2]  # tree: strictly identical
    assert not marker.exists()  # gpg never ran
    # the clean output really covers the pinned shapes
    patch = clean[0]
    assert b"rename from old/one.py\nrename to new/uno.py\n" in patch
    assert b'+++ "b/caf\\303\\251.py"\n' in patch  # C-quoted (core.quotePath=true)
    assert b"-Subproject commit " + SHA.encode() in patch  # --submodule=short
    assert patch.count(b"\n@@ -7 +7 @@") == 1 and b"\n@@ -11 +11 @@" in patch  # two hunks
    assert b"\x1b[" not in patch and b"Binary files" not in patch
    assert ("R", "old/one.py", "new/uno.py") in clean[1]
    everything = patch.split(b"\x00")[2]  # newest first: signed, everything, root
    assert everything.index(b"a/a.py") < everything.index(b"a/z.py")  # not orderFile's


@_POSIX_ONLY
def test_control_hostile_config_changes_plain_git(history: tuple[Path, str, str, Path]) -> None:
    """Without the pins, the same hostile files do change git's output and run gpg."""
    repo, root, head, marker = history
    hardening = [arg for setting in gitread.HARDENING_CONFIG for arg in ("-c", setting)]
    base = ["log", "--first-parent", "-m", "--root", "-p", "-U0", "--format=%x00%H", head]
    names = ["diff-tree", "-r", "-z", "--name-status", "-M", root, head]
    clean_log = _git(repo, *hardening, *base)
    clean_names = _git(repo, *hardening, *names)
    _make_hostile(repo, marker)
    hostile_log = _git(repo, *hardening, *base)
    assert _strip_hunk_tails(hostile_log) != _strip_hunk_tails(clean_log)
    assert _git(repo, *hardening, *names) != clean_names  # renames off, limit 1
    _git(repo, "log", "-1", head)  # no -c log.showSignature=false: gpg runs
    assert marker.exists()


@_POSIX_ONLY
def test_hostile_funcname_text_is_the_only_difference(
    history: tuple[Path, str, str, Path],
) -> None:
    repo, _, head, marker = history
    clean = b"".join(GitReader(repo).patches(None, head))
    _make_hostile(repo, marker)
    hostile = b"".join(GitReader(repo).patches(None, head))
    assert clean != hostile  # the xfuncname tail differs ...
    _assert_same_patches(clean, hostile)  # ... and nothing else does
    assert b"@@ # section one" in hostile and b"@@ item 14" in clean


def test_strip_touches_only_hunk_header_lines() -> None:
    text = b"@@ -1,2 +3 @@ def f():\n+@@ -1 +1 @@ kept\n@@ -1 +1 @@\n@@ x @@ y\n"
    assert _strip_hunk_tails(text) == [
        b"@@ -1,2 +3 @@",
        b"+@@ -1 +1 @@ kept",
        b"@@ -1 +1 @@",
        b"@@ x @@ y",
        b"",
    ]
    with pytest.raises(AssertionError):
        _assert_same_patches(b"+a\n", b"+b\n")


def test_huge_hostile_funcname_stays_bounded(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    huge = "F" + "x" * (3 * 1024 * 1024)  # a 3 MiB line that a funcname rule matches
    _write(repo, "big.txt", huge + "\n" + "".join(f"line {i}\n" for i in range(5)))
    base = _commit(repo, "base")
    _write(repo, "big.txt", huge + "\n" + "".join(f"line {i}\n" for i in range(4)) + "end\n")
    head = _commit(repo, "head")
    _git(repo, "config", "diff.evil.xfuncname", "^(F.*)$")
    _write(repo, ".gitattributes", "*.txt diff=evil\n")
    reader = GitReader(repo)
    chunks = list(reader.patches(base, head))
    assert max(map(len, chunks)) <= gitread.PATCH_CHUNK_BYTES
    headers = [line for line in b"".join(chunks).split(b"\n") if line.startswith(b"@@ ")]
    assert headers and all(len(h) < 1024 for h in headers)  # git truncates the tail
    assert reader.changed_files(base, head) == [("M", None, "big.txt")]
    assert reader.tree(head)[0][2] == len(huge) + 1 + 5 * 7 - 7 + 4
    reader.close()


# --- the order file ----------------------------------------------------------------


def test_orderfile_is_a_fresh_empty_0600_file_in_home(tmp_path: Path) -> None:
    argv = gitread._with_orderfile(["git", "log", "-O<orderfile>", "x"], str(tmp_path))
    path = tmp_path / "conventiondrift-orderfile"
    assert argv == ["git", "log", f"-O{path}", "x"]
    info = os.lstat(path)
    assert stat.S_ISREG(info.st_mode) and info.st_size == 0
    if os.name != "nt":
        assert stat.S_IMODE(info.st_mode) == 0o600


def test_no_placeholder_means_no_orderfile(tmp_path: Path) -> None:
    assert gitread._with_orderfile(["git", "ls-tree"], str(tmp_path)) == ["git", "ls-tree"]
    assert os.listdir(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="symlinks need a POSIX filesystem")
def test_a_planted_orderfile_is_refused_not_reused(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("keep")
    home = tmp_path / "home"
    home.mkdir()
    os.symlink(target, home / "conventiondrift-orderfile")
    with pytest.raises(ComponentError, match="order file could not be created"):
        gitread._with_orderfile(["-O<orderfile>"], str(home))
    assert target.read_text() == "keep"


def _watch(monkeypatch: pytest.MonkeyPatch, name: str) -> list[os.stat_result]:
    """Record the order file's lstat as each matching git starts."""
    seen: list[os.stat_result] = []
    real: Callable[..., Any] = getattr(gitread, name)

    def wrapper(argv: list[str], **kwargs: Any) -> Any:
        for arg in argv:
            if arg.startswith("-O"):
                seen.append(os.lstat(arg[2:]))
                assert Path(arg[2:]).parent == Path(kwargs["env"]["HOME"])
        return real(argv, **kwargs)

    monkeypatch.setattr(gitread, name, wrapper)
    return seen


def test_real_calls_get_an_empty_orderfile_in_their_home(
    history: tuple[Path, str, str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, root, head, _ = history
    runs = _watch(monkeypatch, "_run_bounded")
    starts = _watch(monkeypatch, "_start_batch")
    reader = GitReader(repo)
    reader.changed_files(root, head)
    list(reader.patches(root, head))
    reader.close()
    assert len(runs) == 1 and len(starts) == 1
    for info in runs + starts:
        assert stat.S_ISREG(info.st_mode) and info.st_size == 0


def test_the_placeholder_is_the_only_allowed_order_option() -> None:
    for sub in ("log", "diff-tree"):
        count = ["--max-count=1"] if sub == "log" else []
        gitread._check_options(sub, [*count, "-O<orderfile>"])
        for bad in ("-O/tmp/x", "-O", "--orderfile=/tmp/x", "-M", "-l1"):
            if sub == "diff-tree" and bad == "-M":
                continue  # T-007's diff-tree entry
            with pytest.raises(ComponentError, match="not allowed"):
                gitread._check_options(sub, [*count, bad])


# --- D-TL-25: every hostile key and every pin, one at a time --------------------

#: Each I-14 item 9 pin, keyed by the exact string in gitread's constants, with the
#: hostile setting that the pin defeats (and that the drop test shows it defeats).
PIN_DEFEATS: dict[str, str] = {
    "--src-prefix=a/": "diff.noprefix / diff.mnemonicPrefix",
    "--dst-prefix=b/": "diff.noprefix / diff.mnemonicPrefix",
    "-M50%": "diff.renames=false",
    "-l1000": "diff.renameLimit=1",
    "--diff-algorithm=myers": "diff.algorithm=patience",
    "--no-indent-heuristic": "diff.indentHeuristic=false",
    "--inter-hunk-context=0": "diff.interHunkContext=5",
    "--submodule=short": "diff.submodule=log",
    "--text": "*.py -diff",
    "-O<orderfile>": "diff.orderFile",
    "--no-color": "color.ui / color.diff",
    "core.quotePath=true": "core.quotePath=false",
}
#: Pins whose hostile key can't change gitread's output on its own, and why. I-14
#: item 9 ("Argv and stream details") keeps them as defence in depth, pinned by an
#: argv-presence test only.
PIN_UNOBSERVABLE: dict[str, str] = {
    "--no-relative": "gitread always runs git at the repo root, where diff.relative is a no-op",
    "i18n.logOutputEncoding=UTF-8": "gitread never prints commit messages (--format=%x00%H)",
}
#: Two guards against log.showSignature; each alone keeps gpg from running.
PIN_PAIRED: frozenset[str] = frozenset({"--no-show-signature", "log.showSignature=false"})
#: The rest of the constants: what to output (pinned by the argv tests) and T-007's
#: security flags (pinned by test_gitread.py and the fsmonitor/hostile-config tests).
NOT_DIFF_CONFIG_PINS: frozenset[str] = frozenset(
    {"--first-parent", "--max-count=10000", "-m", "--root", "-p", "-U0", "--format=%x00%H"}
    | {"-r", "-z", "--name-status", "--no-ext-diff", "--no-textconv"}
    | {"core.fsmonitor=false", "core.hooksPath=/dev/null", "core.untrackedCache=false"}
    | {"diff.external=", "core.pager=cat", "protocol.allow=never"}
    | {"safe.bareRepository=explicit"}
)
_PIN_CONSTANTS = ("_PATCHES_ARGS", "_CHANGED_FILES_ARGS", "HARDENING_CONFIG", "_DIFF_FLAGS")


def _all_pinned_strings() -> set[str]:
    return {arg for name in _PIN_CONSTANTS for arg in getattr(gitread, name)}


def test_every_constant_entry_is_classified() -> None:
    classified = set(PIN_DEFEATS) | set(PIN_UNOBSERVABLE) | PIN_PAIRED | NOT_DIFF_CONFIG_PINS
    assert _all_pinned_strings() == classified
    assert not set(PIN_DEFEATS) & (set(PIN_UNOBSERVABLE) | PIN_PAIRED | NOT_DIFF_CONFIG_PINS)


#: Which gitread pin answers each hostile setting (xfuncname has none: its text is
#: the hunk-header tail the comparison strips, per I-14 item 9).
KEY_PINNED_BY: dict[str, str | None] = {
    "diff.noprefix": "--src-prefix=a/",
    "diff.mnemonicPrefix": "--dst-prefix=b/",
    "diff.renames": "-M50%",
    "diff.renameLimit": "-l1000",
    "diff.algorithm": "--diff-algorithm=myers",
    "diff.indentHeuristic": "--no-indent-heuristic",
    "diff.interHunkContext": "--inter-hunk-context=0",
    "diff.relative": "--no-relative",
    "diff.submodule": "--submodule=short",
    "diff.orderFile": "-O<orderfile>",
    "diff.evil.xfuncname": None,
    "core.quotePath": "core.quotePath=true",
    "i18n.logOutputEncoding": "i18n.logOutputEncoding=UTF-8",
    "log.showSignature": "--no-show-signature",
    "gpg.program": "log.showSignature=false",
    "color.ui": "--no-color",
    "color.diff": "--no-color",
    "*.py -diff": "--text",
    "*.txt diff=evil": None,
}


def test_every_hostile_setting_maps_to_a_real_pin() -> None:
    settings = [key for key, _ in HOSTILE_CONFIG] + list(HOSTILE_ATTRIBUTES)
    assert sorted(KEY_PINNED_BY) == sorted(settings)
    pins = _all_pinned_strings()
    assert all(pin in pins for pin in KEY_PINNED_BY.values() if pin is not None)
    covered = {pin for pin in KEY_PINNED_BY.values() if pin is not None}
    assert covered == set(PIN_DEFEATS) | set(PIN_UNOBSERVABLE) | PIN_PAIRED


def _drop(monkeypatch: pytest.MonkeyPatch, *pins: str) -> None:
    for name in _PIN_CONSTANTS:
        kept = tuple(arg for arg in getattr(gitread, name) if arg not in pins)
        monkeypatch.setattr(gitread, name, kept)


@_POSIX_ONLY
@pytest.mark.parametrize("pin", sorted(PIN_DEFEATS))
def test_dropping_any_one_pin_breaks_the_comparison(
    history: tuple[Path, str, str, Path], monkeypatch: pytest.MonkeyPatch, pin: str
) -> None:
    repo, root, head, marker = history
    _drop(monkeypatch, pin)
    clean = _outputs(repo, root, head)
    _make_hostile(repo, marker)
    hostile = _outputs(repo, root, head)
    with pytest.raises(AssertionError):
        _assert_same_patches(clean[0], hostile[0])
        assert hostile[1:] == clean[1:]


#: Where each defence-in-depth pin must appear, written out from I-14 item 9: the
#: ``-c`` pins on every git call, the flags on the calls whose argv lists them.
BACKSTOP_CALLS: dict[str, frozenset[str]] = {
    "--no-relative": frozenset({"log", "diff-tree"}),
    "--no-show-signature": frozenset({"log"}),
    "i18n.logOutputEncoding=UTF-8": frozenset({"ls-tree", "cat-file", "diff-tree", "log"}),
    "log.showSignature=false": frozenset({"ls-tree", "cat-file", "diff-tree", "log"}),
}


def test_backstop_table_covers_every_unobservable_and_paired_pin() -> None:
    assert set(BACKSTOP_CALLS) == set(PIN_UNOBSERVABLE) | PIN_PAIRED


def _recorded_calls(
    repo: Path, root: str, head: str, monkeypatch: pytest.MonkeyPatch
) -> list[list[str]]:
    seen: list[list[str]] = []
    for name in ("_run_bounded", "_start_batch"):
        real: Callable[..., Any] = getattr(gitread, name)

        def wrapper(argv: list[str], _real: Callable[..., Any] = real, **kwargs: Any) -> Any:
            if argv[1:] != ["--version"]:
                seen.append(list(argv))
            return _real(argv, **kwargs)

        monkeypatch.setattr(gitread, name, wrapper)
    reader = GitReader(repo)
    reader.blob(reader.tree(head)[0][1], 1 << 20)
    reader.changed_files(root, head)
    b"".join(reader.patches(None, head))
    reader.close()
    return seen


def _subcommand(argv: list[str]) -> str:
    i = 1
    while argv[i] == "-c":
        i += 2
    return argv[i]


@pytest.mark.parametrize("pin", sorted(BACKSTOP_CALLS))
def test_each_backstop_pin_is_present_where_i14_lists_it(
    history: tuple[Path, str, str, Path], monkeypatch: pytest.MonkeyPatch, pin: str
) -> None:
    repo, root, head, _ = history
    calls = _recorded_calls(repo, root, head, monkeypatch)
    assert {_subcommand(c) for c in calls} == {"ls-tree", "cat-file", "diff-tree", "log"}
    for argv in calls:
        sub = _subcommand(argv)
        before = argv[: argv.index(sub)]
        options = (
            argv[argv.index(sub) + 1 : argv.index("--end-of-options")]
            if "--end-of-options" in argv
            else argv[argv.index(sub) + 1 :]
        )
        if "=" in pin and not pin.startswith("-"):
            present = any(before[i : i + 2] == ["-c", pin] for i in range(len(before)))
        else:
            present = pin in options
        assert present == (sub in BACKSTOP_CALLS[pin]), (pin, sub)


@_POSIX_ONLY
def test_dropping_both_signature_guards_runs_gpg(
    history: tuple[Path, str, str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _, head, marker = history
    _drop(monkeypatch, *PIN_PAIRED)
    _make_hostile(repo, marker)
    b"".join(GitReader(repo).patches(None, head))
    assert marker.exists()


@_POSIX_ONLY
@pytest.mark.parametrize(
    ("config", "attributes"),
    [((item,), ()) for item in HOSTILE_CONFIG] + [((), (line,)) for line in HOSTILE_ATTRIBUTES],
    ids=[key for key, _ in HOSTILE_CONFIG] + list(HOSTILE_ATTRIBUTES),
)
def test_each_hostile_setting_alone_changes_nothing(
    history: tuple[Path, str, str, Path],
    config: tuple[tuple[str, str], ...],
    attributes: tuple[str, ...],
) -> None:
    repo, root, head, marker = history
    clean = _outputs(repo, root, head)
    _make_hostile(repo, marker, config, attributes)
    hostile = _outputs(repo, root, head)
    _assert_same_patches(clean[0], hostile[0])
    assert hostile[1:] == clean[1:]
    assert not marker.exists()
