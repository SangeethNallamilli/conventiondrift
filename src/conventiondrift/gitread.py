"""C3 ``gitread``: the only module that runs git (DESIGN §3, §12 A-1; INTERFACES I-11 C3).

Every call goes through :meth:`GitReader._run`, which:

* runs ``git`` from an absolute path, as an argv list, never through a shell;
* passes a fixed environment (DESIGN §3) with ``HOME`` set to a fresh, empty
  temporary directory; only ``PATH`` is inherited;
* puts the full ``-c`` hardening set before every subcommand;
* allows only the eight read-only subcommands in DESIGN §3;
* adds ``--no-ext-diff --no-textconv --no-color`` to diff and log calls;
* never puts stderr or caller input in an error message.

Revisions from input are resolved once by :meth:`GitReader.resolve`; every other
operation accepts only validated hex SHAs, placed after ``--end-of-options``.

Part 1 (T-007): the runner, ``resolve``, ``is_shallow``, ``has_object``,
``merge_base`` and ``commit_date``. ``tree``, ``blob``, ``changed_files``,
``first_parent_chain`` and ``patches`` are T-008; they reuse :meth:`_command`
and :func:`_environment` (``blob`` needs a streamed ``cat-file --batch``, so it
can check the header size before reading the body).
"""

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from conventiondrift.errors import ComponentError, GitUnavailable

_COMPONENT = "gitread"

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

# QUESTION(A?): DESIGN §3 says "40 or 64 hex characters" without a case. Git always
# prints lowercase and the event payload carries lowercase SHAs, so only lowercase
# is accepted here (the stricter reading).
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}", re.ASCII)


def is_valid_sha(value: str) -> bool:
    """True iff ``value`` is exactly 40 or 64 lowercase hex characters."""
    return _SHA_RE.fullmatch(value) is not None


def _require_sha(value: str) -> str:
    if not is_valid_sha(value):
        raise ComponentError(_COMPONENT, "invalid object id")
    return value


def _environment(home: str) -> dict[str, str]:
    """The fixed git environment: DESIGN §3 values, ``HOME``, and ``PATH`` only if set."""
    # QUESTION(A?): DESIGN §3 inherits PATH and nothing else. On Windows (the CLI
    # supports it, D-PM-21) git may also need SYSTEMROOT; not added without a ruling.
    env = dict(FIXED_ENV)
    path = os.environ.get("PATH")
    if path is not None:
        env["PATH"] = path
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
        # QUESTION(A?): T-008's row owns "GitUnavailable mapping". Here only "git is not
        # installed or cannot start" maps to GitUnavailable; every nonzero exit is a
        # ComponentError unless the operation defines its meaning (I-11 C3).
        git = shutil.which("git")
        if git is None:
            raise GitUnavailable("git executable not found")
        argv = [os.path.abspath(git)]
        for setting in HARDENING_CONFIG:
            argv += ["-c", setting]
        argv.append(subcommand)
        if subcommand in _DIFF_SUBCOMMANDS:
            argv += _DIFF_FLAGS
        argv += args
        return argv

    def _run(self, subcommand: str, args: Sequence[str]) -> _Output:
        """Run one allowed git subcommand and return its exit code and stdout."""
        argv = self._command(subcommand, args)
        if not self._repo_dir.is_dir():
            raise ComponentError(_COMPONENT, "repository directory not found")
        with tempfile.TemporaryDirectory(prefix="conventiondrift-home-") as home:
            try:
                proc = subprocess.run(  # noqa: S603 (argv list, fixed git, no shell)
                    argv,
                    cwd=self._repo_dir,
                    env=_environment(home),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    shell=False,
                    check=False,
                )
            except OSError as exc:
                raise GitUnavailable("git could not be started") from exc
        return _Output(proc.returncode, proc.stdout)

    def _fail(self, subcommand: str, out: _Output) -> ComponentError:
        # Fixed text: never stderr, never a revision or path from input (DESIGN §4).
        return ComponentError(_COMPONENT, f"git {subcommand} failed (exit {out.returncode})")

    # -- operations -----------------------------------------------------------

    def resolve(self, rev: str) -> str:
        """Resolve a user revision once to a commit SHA (I-4, I-11 C3)."""
        # QUESTION(A?): I-4 makes an unresolvable REV exit 2, but I-11 C3 only names
        # GitUnavailable and ComponentError("gitread"). Without a ruling this raises
        # ComponentError, so the CLI (T-031) can't yet tell it apart from a git fault.
        if "\x00" in rev:
            raise ComponentError(_COMPONENT, "unresolvable revision")
        out = self._run("rev-parse", ["--verify", "--end-of-options", f"{rev}^{{commit}}"])
        if out.returncode != 0:
            raise ComponentError(_COMPONENT, "unresolvable revision")
        return _require_sha(_one_line(out))

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
        """The committer date of a commit, timezone-aware (ISO 8601 with offset)."""
        # QUESTION(A?): I-11 gives no return type for commit_date. A tz-aware datetime
        # matches I-13 Window.end and the ISO-with-offset summary text (TEST-STRATEGY).
        out = self._run("log", ["--no-walk", "--format=%cI", "--end-of-options", _require_sha(sha)])
        if out.returncode != 0:
            raise self._fail("log", out)
        try:
            when = datetime.fromisoformat(_one_line(out))
        except ValueError as exc:
            raise ComponentError(_COMPONENT, "unexpected git output") from exc
        if when.tzinfo is None:
            raise ComponentError(_COMPONENT, "unexpected git output")
        return when
