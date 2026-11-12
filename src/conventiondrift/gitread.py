"""C3 ``gitread``: the only module that runs git (DESIGN §3, §12 A-1; INTERFACES I-11 C3).

Every call goes through :meth:`GitReader._run`, which:

* runs ``git`` from one real absolute path, resolved once by the safe rule in
  I-14 (SR-013: absolute ``PATH`` entries only, never inside the repository,
  ``GITHUB_WORKSPACE`` or the current folder; the cwd rule is skipped when the
  cwd is a filesystem root), as an argv list, never through a
  shell;
* passes a fixed environment (DESIGN §3) with ``HOME`` set to a fresh, empty
  temporary directory; only ``PATH`` is inherited, plus ``SYSTEMROOT`` on
  Windows (``os.name == "nt"``, I-11 C3);
* puts the full ``-c`` hardening set before every subcommand;
* allows only the eight read-only subcommands in DESIGN §3, each with its own
  option allowlist, and ``rev-list``/``log`` only with one bounded ``--max-count``;
* adds ``--no-ext-diff --no-textconv --no-color`` to diff and log calls;
* drains and discards stderr, and never puts stderr or caller input in an
  error message;
* kills git after :data:`GIT_TIMEOUT_SECONDS` or once stdout passes its cap
  (SR-014) and reports a fixed-text ``ComponentError("gitread")``.

Revisions from input are resolved once by :meth:`GitReader.resolve`; every other
operation accepts only validated lowercase hex SHAs, placed after ``--end-of-options``.

Errors (I-11 C3): ``GitUnavailable`` only when git is missing or cannot start;
``UnresolvableRevision`` only from ``resolve``; everything else, including "not a
git repository" and ``safe.directory`` refusals, is ``ComponentError("gitread")``.
Requires git >= 2.30 (``rev-parse --end-of-options``; D-TL-18): the first call of
each reader runs ``git --version`` and anything older or unparsable raises
``GitTooOld`` (I-14), failing closed.

Part 1 (T-007): the runner, ``resolve``, ``is_shallow``, ``has_object``,
``merge_base`` and ``commit_date``. Part 2 (T-008): ``tree``, ``blob``,
``changed_files``, ``first_parent_chain`` and ``patches``, through the same
bounded runner, each with its own stdout cap. ``blob`` reads the
``cat-file --batch-check`` header first, so an oversized body is never read.
Signatures follow INTERFACES I-14 ``GitReaderProtocol``.
"""

import contextlib
import io
import ntpath
import os
import queue
import re
import signal
import string
import subprocess
import tempfile
import threading
import time
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from conventiondrift.components import ChangedFile, TreeEntry
from conventiondrift.errors import (
    ComponentError,
    FileSkipped,
    GitTooOld,
    GitUnavailable,
    UnresolvableRevision,
)

_COMPONENT = "gitread"
# Debug-only ComponentError message (I-14). Only GitTooOld has public text;
# this string is never written to any user-facing output.
_UNTRUSTED_GIT = "git found only in the repository, workspace or current folder"

#: D-TL-18 / I-14: the oldest supported git (``rev-parse --end-of-options``).
MIN_GIT_VERSION: tuple[int, int] = (2, 30)
_VERSION_RE = re.compile(r"^git version (\d+)\.(\d+)", re.ASCII)

#: Wall-clock limit for one git call, in seconds (I-14 bounds, SR-014).
#: Hitting the limit kills git and raises ``ComponentError("gitread")``.
GIT_TIMEOUT_SECONDS: float = 60.0

#: Default stdout cap for small-output calls (``--version``, ``rev-parse`` and
#: the like), in bytes (I-14 bounds, SR-014). Hitting the cap kills git and
#: raises ``ComponentError("gitread")``. T-008 passes a larger cap for patches.
SMALL_OUTPUT_MAX_BYTES: int = 4096

#: Read size for the stdout and stderr pipes; also the most stderr held at once.
_CHUNK_BYTES = 65536

#: DESIGN §3 "Allowed subcommands only". ``show`` is for the object form only (T-008).
ALLOWED_SUBCOMMANDS: frozenset[str] = frozenset(
    {"cat-file", "rev-parse", "rev-list", "merge-base", "ls-tree", "diff-tree", "log", "show"}
)

#: DESIGN §3 "On every call", in the design's order.
HARDENING_CONFIG: tuple[str, ...] = (
    # Needed defence: plain `diff-tree` runs a repo's fsmonitor (confirmed on
    # git 2.30, 2.37 and 2.47). A load-bearing behaviour test belongs to T-008.
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.untrackedCache=false",
    "diff.external=",
    "core.pager=cat",
    "protocol.allow=never",
    "log.showSignature=false",
    # SR-014 low: never discover a bare repository implicitly (git >= 2.38; older
    # git ignores the unknown key, and the run is then as before).
    "safe.bareRepository=explicit",
)

#: DESIGN §3 "Diff and log calls".
_DIFF_FLAGS: tuple[str, ...] = ("--no-ext-diff", "--no-textconv", "--no-color")
_DIFF_SUBCOMMANDS: frozenset[str] = frozenset({"log", "show", "diff-tree"})

#: DESIGN §3 "Environment" (HOME is added per call).
FIXED_ENV: dict[str, str] = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_ATTR_NOSYSTEM": "1",
    # SR-014 low: never lazily fetch a missing object from a promisor remote
    # (git >= 2.44; ``protocol.allow=never`` blocks it on older git).
    "GIT_NO_LAZY_FETCH": "1",
}

#: R2.6 (DESIGN §10 S4): at most 10,000 first-parent commits walked.
MAX_COUNT_CAP: int = 10_000
#: Largest chunk ``patches`` yields (I-14 item 9). C8 counts patch bytes, not C3.
PATCH_CHUNK_BYTES: int = 1024 * 1024
#: Most stdout chunks held between a long-lived git and its reader (back-pressure).
_QUEUE_CHUNKS = 16
#: Stdout cap for the ``ls-tree`` and ``diff-tree`` listings (I-14 bounds; T-008).
#: About 500,000 entries at 128 bytes each, well past R2.6's 100,000 ``.py`` files.
LISTING_MAX_BYTES: int = 64 * 1024 * 1024
_MAX_COUNT_RE = re.compile(r"--max-count=([1-9][0-9]*)", re.ASCII)
#: SR-014 low: these must carry exactly one ``--max-count=N`` with 1 <= N <= the cap.
_MAX_COUNT_SUBCOMMANDS: frozenset[str] = frozenset({"rev-list", "log"})

#: SR-014 low: the options each subcommand may take, before ``--end-of-options``.
#: Everything after ``--end-of-options`` is an operand (validated by the caller).
#: T-008 extends this for its operations; anything not listed is refused.
OPTION_ALLOWLIST: dict[str, frozenset[str]] = {
    "rev-parse": frozenset({"--verify", "--is-shallow-repository"}),
    # T-008 blob: object ids go on stdin, never on the command line (DESIGN §3).
    "cat-file": frozenset({"-e", "--batch-check", "--batch"}),
    "merge-base": frozenset(),
    "log": frozenset(
        {"--no-walk", "--format=%cI", "--first-parent", "-p", "-U0"}
        # T-008 patches: merge diffs against the first parent (F-1), explicit renames
        # and root diff (no repo config decides), and a commit marker with no message.
        | {"-m", "-M", "--root", "--format=%x00%H"}
    ),
    "rev-list": frozenset({"--first-parent", "--timestamp"}),
    "ls-tree": frozenset({"-r", "-l", "-z", "--full-tree"}),
    "diff-tree": frozenset({"-r", "-z", "-M", "-p", "--no-commit-id", "--name-status"}),
    "show": frozenset(),
}


def _check_options(subcommand: str, args: Sequence[str]) -> None:
    """Refuse options outside :data:`OPTION_ALLOWLIST` and enforce ``--max-count``."""
    end = args.index("--end-of-options") if "--end-of-options" in args else len(args)
    max_counts = 0
    for option in args[:end]:
        count = _MAX_COUNT_RE.fullmatch(option)
        if count is not None and subcommand in _MAX_COUNT_SUBCOMMANDS:
            if int(count[1]) > MAX_COUNT_CAP:
                raise ComponentError(_COMPONENT, "git --max-count over the cap")
            max_counts += 1
        elif option not in OPTION_ALLOWLIST[subcommand]:
            raise ComponentError(_COMPONENT, "git option not allowed")
    if subcommand in _MAX_COUNT_SUBCOMMANDS and max_counts != 1:
        raise ComponentError(_COMPONENT, "git call needs exactly one --max-count")


# I-11 C3: SHAs are lowercase 40 or 64 hex only.
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}", re.ASCII)


def is_valid_sha(value: str) -> bool:
    """True iff ``value`` is exactly 40 or 64 lowercase hex characters."""
    return _SHA_RE.fullmatch(value) is not None


def _require_sha(value: str) -> str:
    if not is_valid_sha(value):
        raise ComponentError(_COMPONENT, "invalid object id")
    return value


def _is_filesystem_root(path: str) -> bool:
    """True iff ``path`` is a filesystem root (``/``, or a drive root such as ``C:\\``).

    I-14: the cwd PATH-drop rule (and the matching real-path check) is skipped
    when ``Path(cwd).resolve()`` equals its anchor, because containers often
    run with ``WORKDIR /``. The repo and ``GITHUB_WORKSPACE`` rules still apply,
    including when they themselves are a filesystem root.
    """
    if os.name == "nt":
        real = os.path.realpath(path)
        drive, tail = os.path.splitdrive(real)
        return bool(drive) and tail in ("\\", "/", "")
    resolved = Path(path).resolve()
    return resolved == Path(resolved.anchor)


# Win32 prefixes that name the same file as a plain path (SR N-7), matched
# after normcase and in this order (the UNC forms first). Each is replaced by
# the plain form, so ``\\?\C:\repo`` compares as ``c:\repo`` and
# ``\\?\UNC\server\share`` as ``\\server\share``.
_NT_PATH_PREFIXES: tuple[tuple[str, str], ...] = (
    ("\\\\?\\unc\\", "\\\\"),
    ("\\\\.\\unc\\", "\\\\"),
    ("\\\\?\\", ""),
    ("\\\\.\\", ""),
)


def _is_plain_nt_drive(drive: str) -> bool:
    """True iff ``drive`` is ``x:`` or ``\\\\server\\share`` (normcased, prefix-free)."""
    if len(drive) == 2 and drive[1] == ":" and drive[0] in string.ascii_lowercase:
        return True
    if not drive.startswith("\\\\"):
        return False
    parts = drive[2:].split("\\")
    return len(parts) == 2 and all(parts) and parts[0] not in ("?", ".")


def _nt_comparable(path: str) -> str | None:
    """``path`` in one canonical Windows form for containment, or ``None`` if unsure.

    Case is folded and ``/`` becomes ``\\`` (normcase), the extended-length
    and device prefixes are removed, and a bare drive or share root gains its
    root separator, because ``ntpath.commonpath`` raises on ``\\\\server\\share``
    against a path below it. Anything that is still not a plain absolute
    drive or share path (``\\\\?\\Volume{...}``, pipes, drive-relative forms)
    gives ``None``.
    """
    path = os.path.normcase(path)
    for prefix, plain in _NT_PATH_PREFIXES:
        if path.startswith(prefix):
            path = plain + path[len(prefix) :]
            break
    drive, tail = os.path.splitdrive(path)
    if not _is_plain_nt_drive(drive):
        return None
    if not tail:
        tail = "\\"
    elif not tail.startswith("\\"):
        return None
    return os.path.normpath(drive + tail)


def _is_within(path: str, folder: str) -> bool:
    """True iff ``path`` is ``folder`` or below it (both already real, absolute paths).

    Fails closed (SR N-7): when the answer can't be decided, ``path`` counts
    as inside, so a PATH entry is dropped and a found git is refused. Only a
    really different drive or share is "not within". On Windows both sides
    are first put in one form by ``_nt_comparable`` (keyed on the path module,
    which is ``ntpath`` exactly when ``os.name == "nt"``).
    """
    if os.path is ntpath:
        nt_path = _nt_comparable(path)
        nt_folder = _nt_comparable(folder)
        if nt_path is None or nt_folder is None:
            return True
        if os.path.splitdrive(nt_path)[0] != os.path.splitdrive(nt_folder)[0]:
            return False
        path, folder = nt_path, nt_folder
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # undecidable: fail closed
        return True


@dataclass(frozen=True)
class _ResolvedGit:
    """The git executable for a run and the ``PATH`` it runs with (I-14, SR-013)."""

    #: Absolute real path of git; every call, the version check included, runs it.
    path: str
    #: The filtered ``PATH`` (the kept entries) that git was found on and runs with.
    search_path: str


def _untrusted_folders(repo_dir: Path) -> list[str]:
    """Real paths git must never come from: the repo, ``GITHUB_WORKSPACE`` and the cwd.

    The cwd rule is skipped when the cwd is a filesystem root (I-14). The repo
    and ``GITHUB_WORKSPACE`` rules still apply, including when they equal a root.
    """
    folders = [os.path.realpath(repo_dir)]
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        folders.append(os.path.realpath(workspace))
    cwd = os.path.realpath(os.getcwd())
    if not _is_filesystem_root(cwd):
        folders.append(cwd)
    return folders


def _split_path(untrusted: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split ``PATH`` into kept entries and dropped ones (I-14 step 1).

    Dropped: empty entries, ``.`` and every other relative entry (returned as the
    absolute folder they would mean), and every entry whose real path is inside an
    ``untrusted`` folder.
    """
    raw = os.environ.get("PATH")
    kept: list[str] = []
    dropped: list[str] = []
    for entry in [] if raw is None else raw.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            dropped.append(os.path.abspath(entry or os.curdir))
        elif any(_is_within(os.path.realpath(entry), f) for f in untrusted):
            dropped.append(entry)
        else:
            kept.append(entry)
    return kept, dropped


def _git_executable_name() -> str:
    """``git.exe`` on Windows; ``git`` elsewhere. ``PATHEXT`` is ignored (I-14)."""
    return "git.exe" if os.name == "nt" else "git"


def _is_runnable_git(path: str) -> bool:
    """True iff ``path`` is a file and, outside Windows, is executable (I-14)."""
    if not os.path.isfile(path):
        return False
    if os.name != "nt" and not os.access(path, os.X_OK):
        return False
    return True


def _look_for_git(folders: Sequence[str]) -> str | None:
    """First runnable git in ``folders``, in PATH order, or ``None``.

    Each folder is probed for exactly one name (``git.exe`` on Windows, ``git``
    otherwise). The current folder is never prepended; it is only considered
    when it appears as an absolute kept ``PATH`` entry (I-14, SR N-6).
    """
    name = _git_executable_name()
    for folder in folders:
        candidate = os.path.join(folder, name)
        if _is_runnable_git(candidate):
            return candidate
    return None


def _find_git(repo_dir: Path) -> _ResolvedGit:
    """Resolve git once, by the safe rule in INTERFACES I-14 (SR-013, SR N-6).

    The kept ``PATH`` entries are walked in order, without ``shutil.which``.
    ``shutil.which`` prepends the current folder even when ``path=`` is given
    (Python 3.11 and 3.13 on Windows), so a ``git.exe`` at the checkout root
    would win, fail the containment re-check, and knock the run out. For each
    kept folder, exactly one name is tested: ``git.exe`` when ``os.name == "nt"``
    (``PATHEXT`` is ignored; ``.cmd``, ``.bat`` and ``.com`` are never used)
    and ``git`` elsewhere. A candidate is accepted when it is a file and,
    outside Windows, is executable (``os.X_OK``). The first accepted candidate
    wins. The current folder is never searched unless it appears as an
    absolute kept ``PATH`` entry that survived the drops above.

    The match is made absolute and real, and must not lie inside the repo,
    ``GITHUB_WORKSPACE`` or the cwd (defence in depth). The cwd real-path
    check is skipped only when the cwd is a filesystem root; the repo and
    ``GITHUB_WORKSPACE`` checks still apply when they equal a root.

    Raises ``GitUnavailable`` if no git exists anywhere on ``PATH`` (head-only
    mode), and a fixed-text ``ComponentError("gitread")`` if the only git
    found is in a dropped location (fail closed: a git inside the checkout is
    never run).
    """
    untrusted = _untrusted_folders(repo_dir)
    kept, dropped = _split_path(untrusted)
    found = _look_for_git(kept)
    if found is not None:
        real = os.path.realpath(os.path.abspath(found))
        if not any(_is_within(real, f) for f in untrusted):
            return _ResolvedGit(real, os.pathsep.join(kept))
        raise ComponentError(_COMPONENT, _UNTRUSTED_GIT)
    if dropped and _look_for_git(dropped) is not None:
        raise ComponentError(_COMPONENT, _UNTRUSTED_GIT)
    raise GitUnavailable("git executable not found")


def _environment(home: str, search_path: str, repo_dir: Path) -> dict[str, str]:
    """The fixed git environment (DESIGN §3, I-11 C3, I-14).

    The DESIGN §3 values and ``HOME``, ``GIT_NO_LAZY_FETCH``, plus
    ``GIT_CEILING_DIRECTORIES`` set to the parent of the repo's real path (so git
    never discovers a repository above ``repo_dir``), plus ``search_path`` as
    ``PATH`` (the filtered ``PATH`` that git was resolved from), plus
    ``SYSTEMROOT`` if set and only when ``os.name == "nt"`` (Git for Windows needs
    it to start).
    """
    env = dict(FIXED_ENV)
    env["GIT_CEILING_DIRECTORIES"] = os.path.dirname(os.path.realpath(repo_dir))
    env["PATH"] = search_path
    if os.name == "nt":
        systemroot = os.environ.get("SYSTEMROOT")
        if systemroot is not None:
            env["SYSTEMROOT"] = systemroot
    env["HOME"] = home
    return env


# T-008 output formats. Object ids are 40 or 64 lowercase hex (I-11 C3).
_OID = rb"(?:[0-9a-f]{40}|[0-9a-f]{64})"
# ls-tree -r -l -z: "<mode> <type> <oid> <padded size or ->\t<path>"; -r lists no trees.
_TREE_RECORD = re.compile(
    rb"([0-7]{6}) (blob|commit) (" + _OID + rb") +(-|[0-9]{1,20})\t(.+)", re.S
)
# cat-file --batch-check / --batch header: "<oid> <type> <size>\n".
_BATCH_HEADER = re.compile(rb"(" + _OID + rb") ([a-z]{1,8}) ([0-9]{1,20})\n")
# rev-list --timestamp: "<committer epoch seconds> <sha>".
_CHAIN_LINE = re.compile(rb"(-?[0-9]{1,20}) (" + _OID + rb")")
_CHAIN_LINE_MAX = 1 + 20 + 1 + 64 + 1
# diff-tree --name-status -z: a status letter (with a score for R and C), then paths.
_STATUS = re.compile(rb"([ADMT])|([RC])[0-9]{1,3}")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _bad_output() -> ComponentError:
    return ComponentError(_COMPONENT, "unexpected git output")


def _nul_records(data: bytes) -> list[bytes]:
    """Split ``-z`` output; it must be empty or end in NUL, with no empty record."""
    if not data:
        return []
    records = data.split(b"\0")
    if records.pop() != b"" or b"" in records:
        raise _bad_output()
    return records


def _path(raw: bytes) -> str:
    """A repo path from git's raw bytes: UTF-8, with ``surrogateescape`` for the rest.

    Lossless and never fails the run on one odd name; any lone surrogate left in
    the text is shown as ``U+XXXX`` by ``render/escape.py`` (category Cs, I-14).
    """
    return raw.decode("utf-8", "surrogateescape")


@dataclass(frozen=True)
class _Output:
    returncode: int
    stdout: bytes


def _one_line(out: _Output) -> str:
    """Exactly one ``\\n``-terminated ASCII line, without the newline."""
    data = out.stdout
    if not data.endswith(b"\n") or data.count(b"\n") != 1 or not data.isascii():
        raise ComponentError(_COMPONENT, "unexpected git output")
    return data[:-1].decode("ascii")


def _drain(
    stream: io.BufferedIOBase, keep: int, chunks: list[bytes], over: threading.Event
) -> None:
    """Read ``stream`` in chunks until EOF, keeping at most ``keep + 1`` bytes.

    Sets ``over`` and stops reading once more than ``keep`` bytes have arrived, so
    the caller can kill the process. With ``keep == -1`` nothing is kept and the
    stream is read and discarded until EOF (stderr). A stream closed under the
    reader (after a kill) just ends the read.
    """
    total = 0
    try:
        while chunk := stream.read1(_CHUNK_BYTES):  # whatever has arrived, up to a chunk
            if keep < 0:
                continue
            chunks.append(chunk[: keep + 1 - total])
            total += len(chunks[-1])
            if total > keep:
                over.set()
                return
    except (OSError, ValueError):
        return


#: Windows ``CREATE_NEW_PROCESS_GROUP`` (the constant exists only on Windows Pythons).
_CREATE_NEW_PROCESS_GROUP = 0x00000200
#: Wall-clock limit for ``taskkill`` itself, in seconds.
_TASKKILL_TIMEOUT_SECONDS = 10.0


def _process_group_kwargs() -> dict[str, Any]:
    """Popen options that put git and everything it starts in one killable group (SR N-4).

    POSIX: a new session, so its process group id is git's pid. Windows: a new
    process group, so ``taskkill /T`` can end the ``git.exe`` launcher's children.
    """
    if os.name == "nt":
        return {"creationflags": _CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _system32() -> str:
    """The absolute Windows system folder, from the OS, never from ``PATH`` or env."""
    import ctypes

    buffer = ctypes.create_unicode_buffer(260)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, 260)  # type: ignore[attr-defined,unused-ignore]
    if not 0 < length < 260:
        raise OSError("system directory not found")
    return buffer.value


def _kill_tree(proc: "subprocess.Popen[bytes]") -> None:
    """Kill git and every process it started, then reap git (SR N-4).

    POSIX: ``SIGKILL`` to git's process group (its own session, see
    :func:`_process_group_kwargs`); this also reaches a grandchild that outlived
    git. Windows: ``<System32>\\taskkill.exe /T /F /PID <pid>`` by absolute path,
    never looked up on ``PATH``. Either way ``proc.kill()`` follows as a fallback,
    and git is always reaped.
    """
    if os.name == "nt":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(  # noqa: S603 (absolute System32 path, fixed argv, no shell)
                [os.path.join(_system32(), "taskkill.exe"), "/T", "/F", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=_TASKKILL_TIMEOUT_SECONDS,
                check=False,
            )
    else:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        proc.kill()
    proc.wait()


def _run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    label: str,
    max_stdout: int,
    timeout: float,
) -> _Output:
    """Run ``argv`` with a wall-clock timeout and a stdout cap (SR-014).

    stdout is read in chunks and capped at ``max_stdout + 1`` bytes; past the cap,
    or past ``timeout`` seconds, git and every process it started are killed
    (:func:`_kill_tree`) and a fixed-text ``ComponentError("gitread")`` naming only
    ``label`` is raised. stderr is drained in chunks and discarded, never held
    whole and never put in a message. stdin is ``DEVNULL``. A process that can't
    start raises ``GitUnavailable``.
    """
    try:
        proc = subprocess.Popen(  # noqa: S603 (argv list, resolved git, no shell)
            list(argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **_process_group_kwargs(),
        )
    except OSError as exc:
        raise GitUnavailable("git could not be started") from exc
    assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 (PIPE above)
    chunks: list[bytes] = []
    over = threading.Event()
    readers = [
        threading.Thread(target=_drain, args=(proc.stdout, max_stdout, chunks, over), daemon=True),
        threading.Thread(target=_drain, args=(proc.stderr, -1, [], threading.Event()), daemon=True),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    failure: str | None = None
    try:
        for reader in readers:
            reader.join(max(0.0, deadline - time.monotonic()))
            if over.is_set():
                failure = "output too large"
                break
            if reader.is_alive():
                failure = "timed out"
                break
        if failure is None:
            try:
                returncode = proc.wait(max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = "timed out"
    finally:
        if failure is not None or proc.poll() is None:
            _kill_tree(proc)
        for reader in readers:
            reader.join(1.0)
        proc.stdout.close()
        proc.stderr.close()
    if failure is not None:
        # Fixed text: never the argv (which may hold a REV), stdout or stderr.
        raise ComponentError(_COMPONENT, f"git {label} {failure}")
    return _Output(returncode, b"".join(chunks))


class _BatchProcess:
    """A long-lived git with piped stdin and stdout, read with per-request deadlines.

    Started only by :func:`_start_batch` (I-14 item 9). A pump thread moves stdout
    into a bounded queue, so a slow reader stops git instead of buffering its
    output; stderr is drained and discarded. Every read waits at most until its
    ``deadline`` (``time.monotonic()``); past it, or on a short read, a fixed-text
    ``ComponentError("gitread")`` is raised and the caller kills the process.
    """

    def __init__(self, proc: "subprocess.Popen[bytes]", label: str) -> None:
        self._proc = proc
        self._label = label
        self._queue: queue.Queue[bytes] = queue.Queue(maxsize=_QUEUE_CHUNKS)
        self._buffer = bytearray()
        self._eof = False
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._pump, daemon=True),
            threading.Thread(target=_drain, args=(proc.stderr, -1, [], threading.Event())),
        ]
        for thread in self._threads:
            thread.daemon = True
            thread.start()

    def _pump(self) -> None:
        stdout = cast(io.BufferedIOBase, self._proc.stdout)  # a pipe (_start_batch)
        with contextlib.suppress(OSError, ValueError):
            while chunk := stdout.read1(_CHUNK_BYTES):
                if not self._put(chunk):
                    return
        self._put(b"")  # end of output

    def _put(self, chunk: bytes) -> bool:
        while not self._stop.is_set():
            try:
                self._queue.put(chunk, timeout=0.05)
            except queue.Full:
                continue
            return True
        return False

    def _error(self, what: str) -> ComponentError:
        return ComponentError(_COMPONENT, f"git {self._label} {what}")

    def send(self, data: bytes) -> None:
        """Write one request; a git that already exited is a ``ComponentError``."""
        stdin = cast(io.BufferedIOBase, self._proc.stdin)  # a pipe (_start_batch)
        try:
            stdin.write(data)
            stdin.flush()
        except (OSError, ValueError) as exc:
            raise self._error("stopped") from exc

    def close_stdin(self) -> None:
        with contextlib.suppress(OSError):
            cast(io.BufferedIOBase, self._proc.stdin).close()

    def _fill(self, deadline: float) -> bool:
        """Wait for the next stdout chunk; False at end of output."""
        if self._eof:
            return False
        try:
            chunk = self._queue.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            raise self._error("timed out") from None
        if not chunk:
            self._eof = True
            return False
        self._buffer += chunk
        return True

    def read_line(self, limit: int, deadline: float) -> bytes:
        """One ``\\n``-terminated line of at most ``limit`` bytes."""
        while (end := self._buffer.find(b"\n", 0, limit)) < 0:
            if len(self._buffer) >= limit or not self._fill(deadline):
                raise _bad_output()
        line = bytes(self._buffer[: end + 1])
        del self._buffer[: end + 1]
        return line

    def read_exact(self, size: int, deadline: float) -> bytes:
        """Exactly ``size`` bytes; output that ends sooner is a short read."""
        while len(self._buffer) < size:
            if not self._fill(deadline):
                raise _bad_output()
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def read_some(self, limit: int, deadline: float) -> bytes:
        """Up to ``limit`` bytes as soon as any are there; ``b""`` at end of output."""
        if not self._buffer and not self._fill(deadline):
            return b""
        data = bytes(self._buffer[:limit])
        del self._buffer[:limit]
        return data

    def wait(self, deadline: float) -> int:
        """git's exit code, waiting at most until ``deadline``."""
        try:
            return self._proc.wait(max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise self._error("timed out") from None

    def kill(self) -> None:
        """Kill git's process tree if it still runs (N-4), reap it and stop the threads."""
        self._stop.set()
        if self._proc.poll() is None:
            _kill_tree(self._proc)
        self.close_stdin()
        for thread in self._threads:
            thread.join(1.0)
        for stream in (self._proc.stdout, self._proc.stderr):
            cast(io.BufferedIOBase, stream).close()


def _start_batch(
    argv: Sequence[str], *, cwd: Path, env: dict[str, str], label: str
) -> _BatchProcess:
    """Start a long-lived git (I-14 items 8 and 9) in its own process group.

    The same argv rules, environment and git as :func:`_run_bounded` (the caller
    builds ``argv`` with :meth:`GitReader._command`), with piped stdin and stdout.
    A process that can't start raises ``GitUnavailable``.
    """
    try:
        proc = subprocess.Popen(  # noqa: S603 (argv list, resolved git, no shell)
            list(argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            **_process_group_kwargs(),
        )
    except OSError as exc:
        raise GitUnavailable("git could not be started") from exc
    return _BatchProcess(proc, label)


class GitReader:
    """Read-only, hardened access to the git repository at ``repo_dir`` (I-11 C3).

    ``repo_dir`` must be the repository root itself, not a subfolder (I-14).
    Callers pass that root: ``GITHUB_WORKSPACE`` in the Action, and whatever
    T-031 resolves in the CLI. ``GIT_CEILING_DIRECTORIES`` is set to its parent,
    so a subfolder is treated as not a git repository.
    """

    def __init__(self, repo_dir: str | os.PathLike[str]) -> None:
        self._repo_dir = Path(repo_dir)
        self._git: _ResolvedGit | None = None
        self._version_ok = False
        # T-008 blob: one long-lived cat-file per mode, started lazily (I-14 item 9).
        self._batch_check: _BatchProcess | None = None
        self._batch: _BatchProcess | None = None
        self._batch_home: tempfile.TemporaryDirectory[str] | None = None

    def _resolved_git(self) -> _ResolvedGit:
        """Git, resolved once per reader and cached (I-14 step 1)."""
        if self._git is None:
            self._git = _find_git(self._repo_dir)
        return self._git

    # -- runner ---------------------------------------------------------------

    def _command(self, subcommand: str, args: Sequence[str]) -> list[str]:
        """Build the full argv, refusing anything outside the allowlist."""
        if subcommand not in ALLOWED_SUBCOMMANDS:
            raise ComponentError(_COMPONENT, "git subcommand not allowed")
        if any("\x00" in arg for arg in args):
            raise ComponentError(_COMPONENT, "NUL in git argument")
        _check_options(subcommand, args)
        # I-11 C3: GitUnavailable means only "git is missing or cannot start".
        argv = [self._resolved_git().path]
        for setting in HARDENING_CONFIG:
            argv += ["-c", setting]
        argv.append(subcommand)
        if subcommand in _DIFF_SUBCOMMANDS:
            argv += _DIFF_FLAGS
        argv += args
        return argv

    def _check_version(self, home: str) -> None:
        """Run ``<git> --version`` once, before any other call (I-14 step 3, D-TL-18).

        Fixed env, no ``-c`` flags, through the bounded runner. Below 2.30, or
        output that doesn't parse, raises ``GitTooOld`` (fail closed). The version
        found is never put in the error.
        """
        git = self._resolved_git()
        out = _run_bounded(
            [git.path, "--version"],
            cwd=self._repo_dir,
            env=_environment(home, git.search_path, self._repo_dir),
            label="--version",
            max_stdout=SMALL_OUTPUT_MAX_BYTES,
            timeout=GIT_TIMEOUT_SECONDS,
        )
        text = out.stdout.decode("ascii", errors="replace")
        match = _VERSION_RE.match(text) if out.returncode == 0 else None
        if match is None or (int(match[1]), int(match[2])) < MIN_GIT_VERSION:
            raise GitTooOld
        self._version_ok = True

    def _run(
        self, subcommand: str, args: Sequence[str], *, max_stdout: int = SMALL_OUTPUT_MAX_BYTES
    ) -> _Output:
        """Run one allowed git subcommand and return its exit code and stdout.

        The first call checks the git version (:meth:`_check_version`). Bounded by
        :data:`GIT_TIMEOUT_SECONDS` and ``max_stdout`` (SR-014, see
        :func:`_run_bounded`). Every T-007 call prints at most one short line, so
        the default :data:`SMALL_OUTPUT_MAX_BYTES` applies; T-008 passes larger caps.
        """
        argv = self._command(subcommand, args)
        if not self._repo_dir.is_dir():
            raise ComponentError(_COMPONENT, "repository directory not found")
        git = self._resolved_git()
        with tempfile.TemporaryDirectory(prefix="conventiondrift-home-") as home:
            if not self._version_ok:
                self._check_version(home)
            return _run_bounded(
                argv,
                cwd=self._repo_dir,
                env=_environment(home, git.search_path, self._repo_dir),
                label=subcommand,
                max_stdout=max_stdout,
                timeout=GIT_TIMEOUT_SECONDS,
            )

    def _start(self, argv: list[str], home: str, label: str) -> _BatchProcess:
        """Start a long-lived git through :func:`_start_batch`, after the version check."""
        if not self._repo_dir.is_dir():
            raise ComponentError(_COMPONENT, "repository directory not found")
        if not self._version_ok:
            self._check_version(home)
        env = _environment(home, self._resolved_git().search_path, self._repo_dir)
        return _start_batch(argv, cwd=self._repo_dir, env=env, label=label)

    def _batch_process(self, mode: str) -> _BatchProcess:
        """The reader's ``cat-file --batch-check`` or ``--batch`` process, started once."""
        current = self._batch_check if mode == "--batch-check" else self._batch
        if current is not None:
            return current
        argv = self._command("cat-file", [mode])
        if self._batch_home is None:
            self._batch_home = tempfile.TemporaryDirectory(prefix="conventiondrift-home-")
        started = self._start(argv, self._batch_home.name, "cat-file")
        if mode == "--batch-check":
            self._batch_check = started
        else:
            self._batch = started
        return started

    def close(self) -> None:
        """Kill and reap both long-lived ``cat-file`` processes (I-14 item 9).

        Idempotent, and safe when they were never started. T-028 calls it in a
        ``finally``. A later ``blob`` call starts new processes.
        """
        for process in (self._batch_check, self._batch):
            if process is not None:
                process.kill()
        self._batch_check = self._batch = None
        if self._batch_home is not None:
            self._batch_home.cleanup()
            self._batch_home = None

    def _fail(self, subcommand: str, out: _Output) -> ComponentError:
        # Fixed text: never stderr, never a revision or path from input (DESIGN §4).
        return ComponentError(_COMPONENT, f"git {subcommand} failed (exit {out.returncode})")

    # -- operations -----------------------------------------------------------

    def resolve(self, rev: str) -> str:
        """Resolve a user revision once to a commit SHA (I-4, I-11 C3).

        Raises ``UnresolvableRevision`` (fixed message, never the REV) if git can't
        resolve it to exactly one commit; C1/C2 map that to exit 2.
        """
        if "\x00" in rev:
            raise UnresolvableRevision
        out = self._run("rev-parse", ["--verify", "--end-of-options", f"{rev}^{{commit}}"])
        # I-4: the output must be exactly one 40/64-hex SHA, or the run fails with exit 2.
        if out.returncode != 0 or not out.stdout.isascii():
            raise UnresolvableRevision
        line = out.stdout.decode("ascii")
        if not line.endswith("\n") or not is_valid_sha(line[:-1]):
            raise UnresolvableRevision
        return line[:-1]

    def is_shallow(self) -> bool:
        """``rev-parse --is-shallow-repository`` (DESIGN §2 step 2)."""
        out = self._run("rev-parse", ["--is-shallow-repository"])
        if out.returncode != 0:
            raise self._fail("rev-parse", out)
        value = _one_line(out)
        if value not in ("true", "false"):
            raise ComponentError(_COMPONENT, "unexpected git output")
        return value == "true"

    def has_object(self, sha: str) -> bool:
        """Whether the object exists locally (``cat-file -e``); never fetches."""
        out = self._run("cat-file", ["-e", "--end-of-options", _require_sha(sha)])
        if out.returncode == 0:
            return True
        if out.returncode == 1:
            return False
        raise self._fail("cat-file", out)

    def merge_base(self, a: str, b: str) -> str | None:
        """The merge base of two commits, or ``None`` if they share no history."""
        out = self._run("merge-base", ["--end-of-options", _require_sha(a), _require_sha(b)])
        if out.returncode == 1 and out.stdout == b"":
            return None
        if out.returncode != 0:
            raise self._fail("merge-base", out)
        return _require_sha(_one_line(out))

    def commit_date(self, sha: str) -> datetime:
        """The committer date of a commit as a timezone-aware UTC datetime (I-11 C3)."""
        out = self._run(
            "log",
            ["--no-walk", "--max-count=1", "--format=%cI", "--end-of-options", _require_sha(sha)],
        )
        if out.returncode != 0:
            raise self._fail("log", out)
        try:
            when = datetime.fromisoformat(_one_line(out))
        except ValueError as exc:
            raise ComponentError(_COMPONENT, "unexpected git output") from exc
        if when.tzinfo is None:
            raise ComponentError(_COMPONENT, "unexpected git output")
        return when.astimezone(UTC)

    # -- part 2 (T-008) -------------------------------------------------------

    def tree(self, sha: str) -> Sequence[TreeEntry]:
        """Every file of a commit's tree with its size, before any content is read.

        ``ls-tree -r -l -z --full-tree``, capped at :data:`LISTING_MAX_BYTES`. The
        size is ``None`` only for gitlinks (submodules, I-14 ``TreeEntry``).
        """
        out = self._run(
            "ls-tree",
            ["-r", "-l", "-z", "--full-tree", "--end-of-options", _require_sha(sha)],
            max_stdout=LISTING_MAX_BYTES,
        )
        if out.returncode != 0:
            raise self._fail("ls-tree", out)
        entries: list[TreeEntry] = []
        for record in _nul_records(out.stdout):
            m = _TREE_RECORD.fullmatch(record)
            if m is None or (m[2] == b"commit") != (m[4] == b"-"):
                raise _bad_output()
            size = None if m[4] == b"-" else int(m[4])
            entries.append((m[1].decode("ascii"), m[3].decode("ascii"), size, _path(m[5])))
        return entries

    def blob(self, oid: str, max_bytes: int) -> bytes:
        """A blob's bytes, by object id on ``cat-file`` stdin (DESIGN §3, I-14 item 9).

        The reader's long-lived ``--batch-check`` gives the header first (capped at
        :data:`SMALL_OUTPUT_MAX_BYTES`); a blob over ``max_bytes`` raises
        ``FileSkipped("size limit")`` and ``--batch`` is never asked for it (R2.3).
        Otherwise ``--batch`` gives the same header, then exactly the body and its
        trailing LF. Each request waits at most :data:`GIT_TIMEOUT_SECONDS`. A
        timeout, short read or protocol mismatch kills both processes and raises
        ``ComponentError("gitread")``; so do a missing object and a non-blob, which
        leave the processes in step and running.
        """
        request = _require_sha(oid).encode("ascii") + b"\n"
        if max_bytes < 0:
            raise ComponentError(_COMPONENT, "invalid size limit")
        try:
            check = self._batch_process("--batch-check")
            check.send(request)
            header = check.read_line(SMALL_OUTPUT_MAX_BYTES, time.monotonic() + GIT_TIMEOUT_SECONDS)
            m = _BATCH_HEADER.fullmatch(header)
            missing = header == request[:-1] + b" missing\n"
            if not missing and (m is None or m[1] + b"\n" != request):
                raise _bad_output()
        except ComponentError:
            self.close()
            raise
        if m is None:  # "<oid> missing": the protocol is still in step
            raise ComponentError(_COMPONENT, "object not found")
        if m[2] != b"blob":
            raise ComponentError(_COMPONENT, "object is not a blob")
        size = int(m[3])
        if size > max_bytes:
            raise FileSkipped("size limit")
        try:
            batch = self._batch_process("--batch")
            batch.send(request)
            deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
            if batch.read_line(SMALL_OUTPUT_MAX_BYTES, deadline) != header:
                raise _bad_output()
            body = batch.read_exact(size + 1, deadline)
            if not body.endswith(b"\n"):
                raise _bad_output()
        except ComponentError:
            self.close()
            raise
        return body[:-1]

    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]:
        """Files changed from ``base`` to ``head``, renames detected (-M, ADR-0004).

        ``diff-tree -r -M -z --name-status``, capped at :data:`LISTING_MAX_BYTES`.
        Each entry is (status letter without the score, old path, new path) with
        the old path set only for R and C (I-14 item 9): a deleted file is
        ``("D", None, deleted_path)``. Paths are in git's order.
        """
        args = ["-r", "-M", "-z", "--name-status", "--end-of-options"]
        out = self._run(
            "diff-tree",
            [*args, _require_sha(base), _require_sha(head)],
            max_stdout=LISTING_MAX_BYTES,
        )
        if out.returncode != 0:
            raise self._fail("diff-tree", out)
        records = _nul_records(out.stdout)
        changes: list[ChangedFile] = []
        i = 0
        while i < len(records):
            m = _STATUS.fullmatch(records[i])
            count = 2 if m is not None and m[2] is not None else 1
            paths = records[i + 1 : i + 1 + count]
            if m is None or len(paths) != count:
                raise _bad_output()
            status = (m[1] or m[2]).decode("ascii")
            old = _path(paths[0]) if count == 2 else None
            changes.append((status, old, _path(paths[-1])))
            i += 1 + count
        return changes

    def first_parent_chain(self, sha: str, limit: int) -> Sequence[tuple[str, datetime]]:
        """``sha`` and its first-parent ancestors, newest first, at most ``limit``.

        ``rev-list --first-parent --max-count=<limit> --timestamp``. Each entry is
        (commit SHA, committer date as a timezone-aware UTC datetime, like
        :meth:`commit_date`). ``limit`` must be 1 to the R2.6 cap
        (:data:`MAX_COUNT_CAP`); anything else is a caller bug and is refused.
        """
        _require_sha(sha)
        if not 1 <= limit <= MAX_COUNT_CAP:
            raise ComponentError(_COMPONENT, "first-parent limit outside the R2.6 cap")
        out = self._run(
            "rev-list",
            ["--first-parent", f"--max-count={limit}", "--timestamp", "--end-of-options", sha],
            max_stdout=limit * _CHAIN_LINE_MAX,
        )
        if out.returncode != 0:
            raise self._fail("rev-list", out)
        lines = out.stdout.split(b"\n")
        if lines.pop() != b"" or not lines or len(lines) > limit:
            raise _bad_output()
        chain: list[tuple[str, datetime]] = []
        for line in lines:
            m = _CHAIN_LINE.fullmatch(line)
            if m is None:
                raise _bad_output()
            try:
                when = _EPOCH + timedelta(seconds=int(m[1]))
            except OverflowError as exc:
                raise _bad_output() from exc
            chain.append((m[2].decode("ascii"), when))
        return chain

    def patches(self, from_sha: str | None, to_sha: str) -> Generator[bytes, None, None]:
        """Raw first-parent patch text for ``from_sha..to_sha``, newest commit first.

        I-14 item 9: ``log --first-parent -m -M --root -p -U0 --no-ext-diff
        --no-textconv --no-color --format=%x00%H --max-count=10000``, then
        ``--end-of-options <to_sha> [^<from_sha>]``. ``from_sha`` is excluded, and
        ``None`` means back to the root. Merges diff against their first parent.
        Each commit starts with ``\\x00<sha>\\n``; commit messages are never printed.

        The result is a generator of raw stdout chunks of at most
        :data:`PATCH_CHUNK_BYTES`; git starts on the first ``next()``. C3 doesn't
        count patch bytes: C8 stops at its R2.6 cap and calls ``close()``, and the
        generator's ``finally`` kills git's process tree and reaps it. Waiting more
        than :data:`GIT_TIMEOUT_SECONDS` for a chunk or for git to exit, or a
        non-zero exit, raises ``ComponentError("gitread")``.
        """
        revs = [_require_sha(to_sha)]
        if from_sha is not None:
            revs.append("^" + _require_sha(from_sha))
        args = ["--first-parent", "-m", "-M", "--root", "-p", "-U0", "--format=%x00%H"]
        argv = self._command(
            "log", [*args, f"--max-count={MAX_COUNT_CAP}", "--end-of-options", *revs]
        )
        return self._stream_patches(argv)

    def _stream_patches(self, argv: list[str]) -> Generator[bytes, None, None]:
        with tempfile.TemporaryDirectory(prefix="conventiondrift-home-") as home:
            process = self._start(argv, home, "log")
            try:
                process.close_stdin()
                while chunk := process.read_some(
                    PATCH_CHUNK_BYTES, time.monotonic() + GIT_TIMEOUT_SECONDS
                ):
                    yield chunk
                code = process.wait(time.monotonic() + GIT_TIMEOUT_SECONDS)
                if code != 0:
                    raise ComponentError(_COMPONENT, f"git log failed (exit {code})")
            finally:
                process.kill()
