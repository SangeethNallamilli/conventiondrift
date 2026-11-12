"""C3 ``gitread``: the only module that runs git (DESIGN §3, §12 A-1; INTERFACES I-11 C3).

Every call goes through :meth:`GitReader._run`, which:

* runs ``git`` from a resolved absolute path found only on absolute ``PATH``
  entries and never inside the repository or current folder (SR-013), as an
  argv list, never through a shell;
* passes a fixed environment (DESIGN §3) with ``HOME`` set to a fresh, empty
  temporary directory; only ``PATH`` is inherited, plus ``SYSTEMROOT`` on
  Windows (``os.name == "nt"``, I-11 C3);
* puts the full ``-c`` hardening set before every subcommand;
* allows only the eight read-only subcommands in DESIGN §3;
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
Requires git >= 2.24 (``--end-of-options``); there is no runtime version check.

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

from conventiondrift.errors import ComponentError, GitUnavailable, UnresolvableRevision

_COMPONENT = "gitread"

# QUESTION(A?): DESIGN.md, SECURITY-RULES.md and INTERFACES.md state no per-call git
# timeout. 60 s is the whole-run limit of AC-N2.1 (B10k < 60 s), so no single git
# call may take longer; the calls in this module normally take milliseconds.
#: Wall-clock limit for one git call, in seconds (SR-014).
GIT_TIMEOUT_SECONDS: float = 60.0

# QUESTION(A?): R2.6 (DESIGN §10 S4) caps only patch bytes (256 MiB, T-008's
# ``patches``). No cap is stated for the one-line plumbing calls; every T-007 call
# prints at most one 64-hex SHA or ISO date line, so 4 KiB is far above any valid
# output and far below anything that could hurt memory.
#: Default stdout cap for one git call, in bytes; more is a fixed-text error (SR-014).
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
}

# I-11 C3: SHAs are lowercase 40 or 64 hex only.
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}", re.ASCII)


def is_valid_sha(value: str) -> bool:
    """True iff ``value`` is exactly 40 or 64 lowercase hex characters."""
    return _SHA_RE.fullmatch(value) is not None


def _require_sha(value: str) -> str:
    if not is_valid_sha(value):
        raise ComponentError(_COMPONENT, "invalid object id")
    return value


def _trusted_path_entries() -> list[str]:
    """The inherited ``PATH`` entries that may be searched for git (SR-013).

    Only absolute entries are kept: empty entries, ``.`` and every other relative
    entry would make the search depend on the current folder, which may be an
    untrusted checkout.
    """
    raw = os.environ.get("PATH")
    if raw is None:
        return []
    return [entry for entry in raw.split(os.pathsep) if entry and os.path.isabs(entry)]


def _is_within(path: str, folder: str) -> bool:
    """True iff the real ``path`` is ``folder`` or below it (both already resolved).

    A filesystem root is never treated as a folder to refuse: everything is below
    it, and absolute ``PATH`` entries carry no current-folder risk there.
    """
    path = os.path.normcase(path)
    folder = os.path.normcase(folder)
    if os.path.dirname(folder) == folder:
        return False
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # different drives on Windows
        return False


def _find_git(repo_dir: Path) -> str:
    """The resolved absolute path of a trusted git executable (SR-013, I-11 C3).

    Searches only absolute ``PATH`` entries, never the current folder, for ``git``
    (``git.exe`` only on Windows, never ``.cmd``/``.bat``). The first match is
    resolved once; if it lies inside the repository or the current folder the run
    refuses it with a fixed-text ``GitUnavailable`` rather than run a binary that
    the checkout may have supplied.
    """
    name = "git.exe" if os.name == "nt" else "git"
    for entry in _trusted_path_entries():
        candidate = os.path.join(entry, name)
        if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
            continue
        real = os.path.realpath(candidate)
        for folder in (os.path.realpath(repo_dir), os.path.realpath(os.getcwd())):
            if _is_within(real, folder):
                raise GitUnavailable("git executable is not trusted")
        return real
    raise GitUnavailable("git executable not found")


def _environment(home: str) -> dict[str, str]:
    """The fixed git environment (DESIGN §3, I-11 C3).

    The DESIGN §3 values and ``HOME``, plus ``PATH`` (only its absolute entries,
    the same filtered list :func:`_find_git` searched; SR-013) if set, plus
    ``SYSTEMROOT`` if set and only when ``os.name == "nt"`` (Git for Windows
    needs it to start).
    """
    env = dict(FIXED_ENV)
    if "PATH" in os.environ:
        env["PATH"] = os.pathsep.join(_trusted_path_entries())
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
    """Read-only, hardened access to the git repository at ``repo_dir`` (I-11 C3)."""

    def __init__(self, repo_dir: str | os.PathLike[str]) -> None:
        self._repo_dir = Path(repo_dir)

    # -- runner ---------------------------------------------------------------

    def _command(self, subcommand: str, args: Sequence[str]) -> list[str]:
        """Build the full argv, refusing anything outside the allowlist."""
        if subcommand not in ALLOWED_SUBCOMMANDS:
            raise ComponentError(_COMPONENT, "git subcommand not allowed")
        if any("\x00" in arg for arg in args):
            raise ComponentError(_COMPONENT, "NUL in git argument")
        # I-11 C3: GitUnavailable means only "git is missing or cannot start".
        argv = [_find_git(self._repo_dir)]
        for setting in HARDENING_CONFIG:
            argv += ["-c", setting]
        argv.append(subcommand)
        if subcommand in _DIFF_SUBCOMMANDS:
            argv += _DIFF_FLAGS
        argv += args
        return argv

    def _run(
        self, subcommand: str, args: Sequence[str], *, max_stdout: int = SMALL_OUTPUT_MAX_BYTES
    ) -> _Output:
        """Run one allowed git subcommand and return its exit code and stdout.

        Bounded by :data:`GIT_TIMEOUT_SECONDS` and ``max_stdout`` (SR-014, see
        :func:`_run_bounded`). Every T-007 call prints at most one short line, so
        the default :data:`SMALL_OUTPUT_MAX_BYTES` applies; T-008 passes larger caps.
        """
        argv = self._command(subcommand, args)
        if not self._repo_dir.is_dir():
            raise ComponentError(_COMPONENT, "repository directory not found")
        with tempfile.TemporaryDirectory(prefix="conventiondrift-home-") as home:
            return _run_bounded(
                argv,
                cwd=self._repo_dir,
                env=_environment(home),
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
        out = self._run("log", ["--no-walk", "--format=%cI", "--end-of-options", _require_sha(sha)])
        if out.returncode != 0:
            raise self._fail("log", out)
        try:
            when = datetime.fromisoformat(_one_line(out))
        except ValueError as exc:
            raise ComponentError(_COMPONENT, "unexpected git output") from exc
        if when.tzinfo is None:
            raise ComponentError(_COMPONENT, "unexpected git output")
        return when.astimezone(UTC)
