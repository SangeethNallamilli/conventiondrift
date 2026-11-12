"""Real-git fixture repo builder with fully controlled dates (T-044).

Test tooling only. Never shipped (R8.1). Every commit must be given an explicit
date: nothing here reads the wall clock, so the same calls always produce the
same commit SHAs (SPEC §5 "Fixture repo", TRACEABILITY §1.1).

Git runs with a fixed, isolated environment: no system or global config, a
private HOME, fixed author/committer identity and explicit
GIT_AUTHOR_DATE / GIT_COMMITTER_DATE on every commit.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterable, Mapping
from pathlib import Path

UTC = _dt.UTC

DEFAULT_AUTHOR = ("Fixture Author", "fixture-author@example.invalid")
DEFAULT_COMMITTER = ("Fixture Committer", "fixture-committer@example.invalid")

_HEX_SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")

DateLike = "_dt.datetime | str"


def to_datetime(value: _dt.datetime | str) -> _dt.datetime:
    """Parse an ISO 8601 string or pass through an aware datetime. Naive values are rejected."""
    if isinstance(value, str):
        value = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("fixture dates must carry a UTC offset (no naive datetimes)")
    return value


def git_date(value: _dt.datetime | str) -> str:
    """Render a date in git's internal format '<epoch> <+hhmm>' (exact, offset preserved)."""
    d = to_datetime(value)
    off = d.utcoffset() or _dt.timedelta(0)
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    epoch = int((d - _dt.datetime(1970, 1, 1, tzinfo=UTC)).total_seconds())
    # "@" forces a raw timestamp, so small epochs (1971) are not misparsed.
    return f"@{epoch} {sign}{total // 3600:02d}{(total % 3600) // 60:02d}"


def days_before(anchor: _dt.datetime | str, days: float) -> _dt.datetime:
    return to_datetime(anchor) - _dt.timedelta(days=days)


def base_git_env(home: Path) -> dict[str, str]:
    """A fixed environment for the fixture's own git calls (not the tool's)."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    return env


@dataclasses.dataclass(frozen=True)
class PullRequest:
    """SHAs describing a fixture PR. `base_tip` is `pull_request.base.sha`."""

    number: int
    base_branch: str
    head_branch: str
    base_tip: str
    head: str
    merge_base: str
    merge_commit: str | None = None  # GitHub's refs/pull/<n>/merge, when created

    def event_payload(
        self,
        repo_full_name: str = "fixture-owner/fixture-repo",
        head_repo_full_name: str | None = None,
        author_login: str = "fixture-user",
    ) -> dict:
        """A minimal `pull_request` event payload (GITHUB_EVENT_PATH contents)."""
        head_repo = head_repo_full_name or repo_full_name
        return {
            "action": "synchronize",
            "number": self.number,
            "pull_request": {
                "number": self.number,
                "user": {"login": author_login, "type": "User"},
                "base": {
                    "ref": self.base_branch,
                    "sha": self.base_tip,
                    "repo": {"full_name": repo_full_name},
                },
                "head": {
                    "ref": self.head_branch,
                    "sha": self.head,
                    "repo": {"full_name": head_repo, "fork": head_repo != repo_full_name},
                },
            },
            "repository": {"full_name": repo_full_name},
        }

    def write_event(self, path: Path, **kw) -> Path:
        path.write_text(
            json.dumps(self.event_payload(**kw), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return path


class GitRepo:
    """A real git repository built step by step with explicit dates."""

    def __init__(
        self,
        path: Path,
        *,
        home: Path | None = None,
        author: tuple[str, str] = DEFAULT_AUTHOR,
        committer: tuple[str, str] = DEFAULT_COMMITTER,
    ) -> None:
        self.path = Path(path)
        self.home = Path(home) if home else self.path.parent / (self.path.name + ".home")
        self.home.mkdir(parents=True, exist_ok=True)
        self.author = author
        self.committer = committer

    # ------------------------------------------------------------------ setup
    @classmethod
    def init(cls, path: Path, *, default_branch: str = "main", **kw) -> GitRepo:
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        repo = cls(path, **kw)
        repo.git("init", "-q", "-b", default_branch, ".")
        for key, value in (
            ("core.autocrlf", "false"),
            ("commit.gpgsign", "false"),
            ("tag.gpgsign", "false"),
            ("core.fileMode", "true"),
            ("user.useConfigOnly", "true"),
        ):
            repo.git("config", key, value)
        return repo

    # ------------------------------------------------------------------ git
    def env(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        env = base_git_env(self.home)
        env.update(
            {
                "GIT_AUTHOR_NAME": self.author[0],
                "GIT_AUTHOR_EMAIL": self.author[1],
                "GIT_COMMITTER_NAME": self.committer[0],
                "GIT_COMMITTER_EMAIL": self.committer[1],
            }
        )
        if extra:
            env.update(extra)
        return env

    def git(
        self,
        *args: str,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        stdin_data: bytes | None = None,
        cwd: Path | None = None,
    ) -> str:
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            ["git", *args],  # noqa: S607 - git from PATH by design
            cwd=cwd or self.path,
            env=self.env(env),
            input=stdin_data,
            capture_output=True,
            check=False,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"git {' '.join(args)} failed ({proc.returncode}):\n"
                f"{proc.stderr.decode(errors='replace')}"
            )
        return proc.stdout.decode("utf-8", errors="surrogateescape").strip()

    # ------------------------------------------------------------------ files
    def write(self, relpath: str, content: str | bytes, *, executable: bool = False) -> Path:
        target = self.path / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        target.write_bytes(data)
        if executable:
            target.chmod(0o755)
        self.git("add", "--", relpath)
        return target

    def write_many(self, files: Mapping[str, str | bytes]) -> None:
        for rel, content in sorted(files.items()):
            self.write(rel, content)

    def read(self, relpath: str) -> str:
        return (self.path / relpath).read_text(encoding="utf-8")

    def delete(self, relpath: str) -> None:
        self.git("rm", "-q", "-r", "--", relpath)

    def move(self, src: str, dst: str) -> None:
        (self.path / dst).parent.mkdir(parents=True, exist_ok=True)
        self.git("mv", "--", src, dst)

    def symlink(self, relpath: str, target: str) -> None:
        link = self.path / relpath
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link)
        self.git("add", "--", relpath)

    # ------------------------------------------------------------------ commits
    def _date_env(self, date, author_date=None) -> dict[str, str]:
        if date is None:
            raise ValueError("every fixture commit needs an explicit date")
        return {
            "GIT_COMMITTER_DATE": git_date(date),
            "GIT_AUTHOR_DATE": git_date(author_date if author_date is not None else date),
        }

    def commit(self, message: str, *, date, author_date=None, allow_empty: bool = False) -> str:
        """Commit the index. `date` is the committer date; `author_date` defaults to it."""
        args = ["commit", "-q", "--no-verify", "-m", message]
        if allow_empty:
            args.append("--allow-empty")
        self.git(*args, env=self._date_env(date, author_date))
        return self.rev_parse("HEAD")

    def commit_files(
        self, message: str, files: Mapping[str, str | bytes], *, date, author_date=None
    ) -> str:
        self.write_many(files)
        return self.commit(message, date=date, author_date=author_date)

    def branch(self, name: str, start: str = "HEAD") -> None:
        self.git("branch", name, start)

    def checkout(self, ref: str) -> None:
        self.git("checkout", "-q", ref)

    def current_branch(self) -> str:
        return self.git("rev-parse", "--abbrev-ref", "HEAD")

    def merge(self, branch: str, *, date, message: str | None = None, no_ff: bool = True) -> str:
        """Merge `branch` into the current branch with a controlled merge-commit date."""
        args = ["merge", "-q", "--no-edit", "--no-verify"]
        if no_ff:
            args.append("--no-ff")
        args += ["-m", message or f"Merge branch '{branch}'", branch]
        self.git(*args, env=self._date_env(date))
        return self.rev_parse("HEAD")

    def commit_tree(self, tree: str, parents: Iterable[str], message: str, *, date) -> str:
        args = ["commit-tree", tree]
        for p in parents:
            args += ["-p", p]
        args += ["-m", message]
        return self.git(*args, env=self._date_env(date))

    def tag(self, name: str, rev: str = "HEAD") -> None:
        self.git("tag", name, rev)

    def update_ref(self, ref: str, sha: str) -> None:
        self.git("update-ref", ref, sha)

    # ------------------------------------------------------------------ queries
    def rev_parse(self, rev: str) -> str:
        sha = self.git("rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}")
        assert _HEX_SHA.match(sha), sha
        return sha

    def tree_of(self, rev: str) -> str:
        return self.git("rev-parse", "--verify", f"{rev}^{{tree}}")

    def merge_base(self, a: str, b: str) -> str | None:
        out = self.git("merge-base", a, b, check=False)
        return out or None

    def commit_date(self, rev: str) -> _dt.datetime:
        """Committer date of `rev` (with its own offset)."""
        return _dt.datetime.fromisoformat(self.git("show", "-s", "--format=%cI", rev))

    def author_date(self, rev: str) -> _dt.datetime:
        return _dt.datetime.fromisoformat(self.git("show", "-s", "--format=%aI", rev))

    def parents(self, rev: str) -> list[str]:
        return self.git("show", "-s", "--format=%P", rev).split()

    def first_parent_chain(self, rev: str) -> list[str]:
        return self.git("rev-list", "--first-parent", rev).split()

    def is_shallow(self) -> bool:
        return self.git("rev-parse", "--is-shallow-repository") == "true"

    def has_object(self, sha: str) -> bool:
        return (
            subprocess.run(  # noqa: S603 - argv list, no shell
                ["git", "cat-file", "-e", f"{sha}^{{commit}}"],  # noqa: S607 - git from PATH by design
                cwd=self.path,
                env=self.env(),
                capture_output=True,
            ).returncode
            == 0
        )

    def ls_files(self, rev: str = "HEAD") -> list[str]:
        return self.git("ls-tree", "-r", "--name-only", rev).splitlines()

    def show_file(self, rev: str, path: str) -> str:
        return self.git("show", f"{rev}:{path}")

    # ------------------------------------------------------------------ PR helpers
    def start_pr_branch(self, name: str, base_branch: str = "main") -> str:
        """Branch `name` off the tip of `base_branch`, check it out, return the fork point."""
        self.checkout(base_branch)
        fork = self.rev_parse("HEAD")
        self.git("checkout", "-q", "-b", name)
        return fork

    def advance_base(
        self,
        base_branch: str,
        files: Mapping[str, str | bytes],
        *,
        date,
        message: str = "base: commit after the merge base",
    ) -> str:
        """Add a commit on the base branch after the PR forked (TRACEABILITY §1.5 ruling)."""
        back = self.current_branch()
        self.checkout(base_branch)
        sha = self.commit_files(message, files, date=date)
        self.checkout(back)
        return sha

    def pull_request(
        self, *, number: int, base_branch: str, head_branch: str, require_base_ahead: bool = True
    ) -> PullRequest:
        base_tip = self.rev_parse(base_branch)
        head = self.rev_parse(head_branch)
        mb = self.merge_base(base_tip, head)
        if mb is None:
            raise AssertionError("fixture PR has no merge base")
        if require_base_ahead and mb == base_tip:
            raise AssertionError(
                "fixture rule (TRACEABILITY §1.5): the base branch must have at least one "
                "commit after the merge base, so tip-vs-merge-base mix-ups fail a test"
            )
        return PullRequest(number, base_branch, head_branch, base_tip, head, mb)

    def github_merge_commit(self, pr: PullRequest, *, date) -> PullRequest:
        """Create refs/pull/<n>/merge the way GitHub does: parents (base tip, PR head)."""
        tree = self.git("merge-tree", "--write-tree", pr.base_tip, pr.head).splitlines()[0]
        sha = self.commit_tree(
            tree, [pr.base_tip, pr.head], f"Merge {pr.head} into {pr.base_tip}", date=date
        )
        self.update_ref(f"refs/pull/{pr.number}/merge", sha)
        self.update_ref(f"refs/pull/{pr.number}/head", pr.head)
        return dataclasses.replace(pr, merge_commit=sha)

    def shallow_clone(self, dest: Path, ref: str, *, depth: int = 1) -> GitRepo:
        """Emulate actions/checkout fetch-depth N: fetch only `ref`, check it out detached."""
        dest = Path(dest)
        clone = GitRepo.init(dest, home=self.home, author=self.author, committer=self.committer)
        clone.git("fetch", "-q", f"--depth={depth}", "--no-tags", self.path.resolve().as_uri(), ref)
        clone.git("checkout", "-q", "--detach", "FETCH_HEAD")
        return clone

    def full_clone(self, dest: Path) -> GitRepo:
        dest = Path(dest)
        GitRepo(self.path, home=self.home).git(
            "clone",
            "-q",
            "--no-local",
            str(self.path.resolve()),
            str(dest.resolve()),
            cwd=self.path.parent,
        )
        return GitRepo(dest, home=self.home, author=self.author, committer=self.committer)

    def snapshot(self) -> dict[str, str]:
        """All refs → SHAs; used by determinism tests."""
        out = self.git("for-each-ref", "--format=%(refname) %(objectname)")
        return dict(line.split(" ", 1) for line in out.splitlines() if line)

    def remove(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)


# ---------------------------------------------------------------------- oracle
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def line_dates_first_parent(repo: GitRepo, rev: str) -> dict[str, list[_dt.datetime]]:
    """Independent test oracle for AC-F4.1 / DESIGN §10 S4.

    Replays the first-parent history of `rev` forward (each commit diffed
    against its first parent, `-U0`, renames followed) and returns, for every
    file at `rev`, the committer date of the first-parent commit that last
    changed each line. Lines brought in by a merge take the merge commit's date.
    Selection is by topology, never by date order.
    """
    chain = list(reversed(repo.first_parent_chain(rev)))
    state: dict[str, list[_dt.datetime]] = {}
    for sha in chain:
        date = repo.commit_date(sha)
        parents = repo.parents(sha)
        if parents:
            raw = repo.git(
                "diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M", "-U0", parents[0], sha
            )
        else:
            raw = repo.git(
                "show", "--no-color", "--no-ext-diff", "--no-textconv", "--format=", "-U0", sha
            )
        _apply_patch(state, raw, date)
    return state


def _apply_patch(state: dict[str, list[_dt.datetime]], raw: str, date: _dt.datetime) -> None:
    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.startswith("diff --git "):
            i += 1
            continue
        old = new = None
        rename_from = rename_to = None
        deleted = False
        i += 1
        while (
            i < len(lines)
            and not lines[i].startswith("diff --git ")
            and not lines[i].startswith("@@")
        ):
            h = lines[i]
            if h.startswith("--- "):
                old = None if h == "--- /dev/null" else h[6:]
            elif h.startswith("+++ "):
                new = None if h == "+++ /dev/null" else h[6:]
            elif h.startswith("rename from "):
                rename_from = h[len("rename from ") :]
            elif h.startswith("rename to "):
                rename_to = h[len("rename to ") :]
            elif h.startswith("deleted file mode"):
                deleted = True
            i += 1
        if rename_from and rename_to:
            state[rename_to] = state.pop(rename_from, [])
            old = old or rename_from
            new = new or rename_to
        target = new or rename_to
        if deleted or (old and not new and target is None):
            state.pop(old or rename_from or "", None)
        current = state.get(target, []) if target else []
        result = list(current)
        offset = 0
        while i < len(lines) and lines[i].startswith("@@"):
            m = _HUNK.match(lines[i])
            assert m, lines[i]
            o_start, o_len = int(m.group(1)), int(m.group(2) or 1)
            n_len = int(m.group(4) or 1)
            i += 1
            while i < len(lines) and (
                lines[i][:1] in ("+", "-", "\\") and not lines[i].startswith("diff --git ")
            ):
                i += 1
            # position in the old file (1-based); for pure insertions o_start is the line before
            pos = (o_start - 1 if o_len else o_start) + offset
            result[pos : pos + o_len] = [date] * n_len
            offset += n_len - o_len
        if target and not deleted:
            state[target] = result


def recent_lines(
    repo: GitRepo, rev: str, *, days: int = 90, anchor: _dt.datetime | None = None
) -> dict[str, set[int]]:
    """Lines whose last-change date d satisfies start <= d <= end (end = anchor or rev's date)."""
    end = anchor or repo.commit_date(rev)
    start = end - _dt.timedelta(days=days)
    out: dict[str, set[int]] = {}
    for path, dates in line_dates_first_parent(repo, rev).items():
        hits = {n for n, d in enumerate(dates, 1) if start <= d <= end}
        if hits:
            out[path] = hits
    return out
