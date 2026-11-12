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
import re
import string
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
#: R2.6 (DESIGN §10 S4): at most 256 MiB of patch text read for history.
PATCH_BYTES_CAP: int = 256 * 1024 * 1024
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
        | {"-m", "-M", "--root", "--reverse", "--format=%x00%H"}
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


def _lines(data: bytes) -> Iterator[bytes]:
    """``data`` split after each ``\n``, newlines kept; a last unterminated line too."""
    start = 0
    while start < len(data):
        end = data.find(b"\n", start) + 1 or len(data)
        yield data[start:end]
        start = end


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


def _run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    label: str,
    max_stdout: int,
    timeout: float,
) -> _Output:
    """Run ``argv`` with stdin ``DEVNULL``, a timeout and a stdout cap (SR-014).

    See :func:`_bounded_process`.
    """
    return _bounded_process(
        argv, cwd=cwd, env=env, label=label, max_stdout=max_stdout, timeout=timeout, stdin=None
    )


def _run_bounded_input(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    label: str,
    max_stdout: int,
    timeout: float,
    stdin: bytes,
) -> _Output:
    """:func:`_run_bounded`, but with ``stdin`` written to a pipe and closed (T-008).

    Used only for ``cat-file --batch-check``/``--batch`` requests, so object ids go
    on stdin and never on the command line (DESIGN §3).
    """
    return _bounded_process(
        argv, cwd=cwd, env=env, label=label, max_stdout=max_stdout, timeout=timeout, stdin=stdin
    )


def _bounded_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    label: str,
    max_stdout: int,
    timeout: float,
    stdin: bytes | None,
) -> _Output:
    """Run ``argv`` with a wall-clock timeout and a stdout cap (SR-014).

    stdout is read in chunks and capped at ``max_stdout + 1`` bytes; past the cap,
    or past ``timeout`` seconds, the process is killed and a fixed-text
    ``ComponentError("gitread")`` naming only ``label`` is raised. stderr is drained
    in chunks and discarded, never held whole and never put in a message. stdin is
    ``DEVNULL`` when ``stdin`` is None, or else a pipe that gets those few bytes
    and is then closed. A process that can't start raises ``GitUnavailable``.
    """
    try:
        proc = subprocess.Popen(  # noqa: S603 (argv list, resolved git, no shell)
            list(argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
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
    if proc.stdin is not None:
        # A few request bytes (one object id per line); git exiting early just
        # closes the pipe, and the exit code or short output reports it.
        with contextlib.suppress(OSError):
            proc.stdin.write(stdin or b"")
        with contextlib.suppress(OSError):
            proc.stdin.close()
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
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for reader in readers:
            reader.join(1.0)
        proc.stdout.close()
        proc.stderr.close()
    if failure is not None:
        # Fixed text: never the argv (which may hold a REV), stdout or stderr.
        raise ComponentError(_COMPONENT, f"git {label} {failure}")
    return _Output(returncode, b"".join(chunks))


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
        self,
        subcommand: str,
        args: Sequence[str],
        *,
        max_stdout: int = SMALL_OUTPUT_MAX_BYTES,
        stdin: bytes | None = None,
    ) -> _Output:
        """Run one allowed git subcommand and return its exit code and stdout.

        The first call checks the git version (:meth:`_check_version`). Bounded by
        :data:`GIT_TIMEOUT_SECONDS` and ``max_stdout`` (SR-014, see
        :func:`_run_bounded`). Every T-007 call prints at most one short line, so
        the default :data:`SMALL_OUTPUT_MAX_BYTES` applies; T-008 passes larger caps,
        and ``stdin`` for ``cat-file --batch`` requests.
        """
        argv = self._command(subcommand, args)
        if not self._repo_dir.is_dir():
            raise ComponentError(_COMPONENT, "repository directory not found")
        git = self._resolved_git()
        with tempfile.TemporaryDirectory(prefix="conventiondrift-home-") as home:
            if not self._version_ok:
                self._check_version(home)
            env = _environment(home, git.search_path, self._repo_dir)
            if stdin is not None:
                return _run_bounded_input(
                    argv,
                    cwd=self._repo_dir,
                    env=env,
                    label=subcommand,
                    max_stdout=max_stdout,
                    timeout=GIT_TIMEOUT_SECONDS,
                    stdin=stdin,
                )
            return _run_bounded(
                argv,
                cwd=self._repo_dir,
                env=env,
                label=subcommand,
                max_stdout=max_stdout,
                timeout=GIT_TIMEOUT_SECONDS,
            )

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
        """A blob's bytes, by object id on ``cat-file`` stdin (DESIGN §3, I-11 C3).

        The header size is checked against ``max_bytes`` before the body is read: a
        ``--batch-check`` request reads only the header, and a blob over the limit
        raises ``FileSkipped("size limit")`` without its body ever being requested
        (R2.3). Otherwise ``--batch`` reads it, capped at exactly that header plus
        the body. Objects are immutable by id, so both requests see the same object.
        """
        request = _require_sha(oid).encode("ascii") + b"\n"
        if max_bytes < 0:
            raise ComponentError(_COMPONENT, "invalid size limit")
        check = self._run("cat-file", ["--batch-check"], stdin=request)
        if check.returncode != 0:
            raise self._fail("cat-file", check)
        m = _BATCH_HEADER.fullmatch(check.stdout)
        if m is None or m[1] + b"\n" != request:
            raise _bad_output()  # includes "<oid> missing"
        if m[2] != b"blob":
            raise ComponentError(_COMPONENT, "object is not a blob")
        size = int(m[3])
        if size > max_bytes:
            raise FileSkipped("size limit")
        header = check.stdout
        out = self._run("cat-file", ["--batch"], stdin=request, max_stdout=len(header) + size + 1)
        if out.returncode != 0:
            raise self._fail("cat-file", out)
        body = out.stdout
        if len(body) != len(header) + size + 1 or not body.startswith(header):
            raise _bad_output()
        if not body.endswith(b"\n"):
            raise _bad_output()
        return body[len(header) : -1]

    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]:
        """Files changed from ``base`` to ``head``, renames detected (-M, ADR-0004).

        ``diff-tree -r -M -z --name-status``, capped at :data:`LISTING_MAX_BYTES`.
        Each entry is (status letter without the score, old path, new path): old is
        ``None`` only for an added file, and for a deleted file new is the deleted
        path. Paths are in git's order.
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
            old = None if status == "A" else _path(paths[0])
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

    def patches(self, from_sha: str, to_sha: str) -> Iterator[bytes]:
        """The first-parent patch text for ``from_sha..to_sha``, oldest commit first.

        ``log --first-parent -m -p -U0 -M --root --reverse --format=%x00%H`` (F-1),
        plus ``--no-ext-diff --no-textconv --no-color``: ``from_sha`` itself is
        excluded, as in git's ``A..B``. Merges diff against their first parent, so
        lines a merge brings in take the merge's date. Each commit starts with a
        ``b"\\0<sha>\\n"`` line and a blank line, then its patch; commit messages are
        never printed.
        The lines (newlines kept) are yielded one by one.

        Bounded by R2.6: ``--max-count`` at :data:`MAX_COUNT_CAP` commits, and
        :data:`PATCH_BYTES_CAP` bytes of output; past the byte cap, or past
        :data:`GIT_TIMEOUT_SECONDS`, git is killed and ``ComponentError("gitread")``
        is raised before anything is yielded.
        """
        args = ["--first-parent", "-m", "-p", "-U0", "-M", "--root", "--reverse"]
        rev = f"{_require_sha(from_sha)}..{_require_sha(to_sha)}"
        out = self._run(
            "log",
            [*args, "--format=%x00%H", f"--max-count={MAX_COUNT_CAP}", "--end-of-options", rev],
            max_stdout=PATCH_BYTES_CAP,
        )
        if out.returncode != 0:
            raise self._fail("log", out)
        return _lines(out.stdout)
