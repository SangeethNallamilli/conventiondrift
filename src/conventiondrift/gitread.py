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
``merge_base`` and ``commit_date``. ``tree``, ``blob``, ``changed_files``,
``first_parent_chain`` and ``patches`` are T-008; they reuse :meth:`_command`
and :func:`_environment` (``blob`` needs a streamed ``cat-file --batch``, so it
can check the header size before reading the body).
"""

import io
import os
import re
import subprocess
import tempfile
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conventiondrift.errors import (
    ComponentError,
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
_MAX_COUNT_RE = re.compile(r"--max-count=([1-9][0-9]*)", re.ASCII)
#: SR-014 low: these must carry exactly one ``--max-count=N`` with 1 <= N <= the cap.
_MAX_COUNT_SUBCOMMANDS: frozenset[str] = frozenset({"rev-list", "log"})

#: SR-014 low: the options each subcommand may take, before ``--end-of-options``.
#: Everything after ``--end-of-options`` is an operand (validated by the caller).
#: T-008 extends this for its operations; anything not listed is refused.
OPTION_ALLOWLIST: dict[str, frozenset[str]] = {
    "rev-parse": frozenset({"--verify", "--is-shallow-repository"}),
    "cat-file": frozenset({"-e"}),
    "merge-base": frozenset(),
    "log": frozenset({"--no-walk", "--format=%cI", "--first-parent", "-p", "-U0"}),
    "rev-list": frozenset({"--first-parent"}),
    "ls-tree": frozenset({"-r", "-l", "-z", "--full-tree"}),
    "diff-tree": frozenset({"-r", "-z", "-M", "-p", "--no-commit-id"}),
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


def _is_within(path: str, folder: str) -> bool:
    """True iff ``path`` is ``folder`` or below it (both already real, absolute paths)."""
    path = os.path.normcase(path)
    folder = os.path.normcase(folder)
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # different drives on Windows
        return False


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
    """Run ``argv`` with a wall-clock timeout and a stdout cap (SR-014).

    stdout is read in chunks and capped at ``max_stdout + 1`` bytes; past the cap,
    or past ``timeout`` seconds, the process is killed and a fixed-text
    ``ComponentError("gitread")`` naming only ``label`` is raised. stderr is drained
    in chunks and discarded, never held whole and never put in a message. stdin is
    ``DEVNULL``. A process that can't start raises ``GitUnavailable``. Reusable by
    T-008 with its own cap (for example R2.6's patch-byte cap).
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
