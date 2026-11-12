#!/usr/bin/env python3
"""Seeded generator for the benchmark repositories B10k and B500 (T-052).

Test tooling, never shipped. Composition follows SPEC.md AC-N2.1/AC-N2.2 as
amended by SC-2.32 (D-PM-13's text still says 4 KiB; SC-2.32 made it 16 KiB):

* B10k: 10,000 `.py` files, mean size 16 KiB (+-10%), long tail with >= 10 files
  in [512 KiB, 1 MiB]; 2,000 commits spread evenly over 730 days (about 250
  inside the 90-day window); ~3 files changed per commit; ~10% merge commits;
  AGENTS.md with >= 10 recognized rules covering all 7 default checkers;
  benchmark PR (`bench-pr`) changing 50 `.py` files. Also `bench-pr-5000`, the
  AC-E.12 variant changing 5,000 `.py` files, with labeled expected findings.
* B500: 500 `.py` files, same size rules with >= 2 tail files; 500 commits over
  730 days; same AGENTS.md; benchmark PR changing 10 `.py` files.

Usage:
    gen_bench_repo.py --profile b10k|b500 --seed N --out DIR [--manifest PATH]

The repo is built with `git fast-import` from a stream that depends only on
(profile, seed, this script), with fixed identities and explicit dates, so the
same seed gives the same tree and commit SHAs. The manifest (default
`<DIR>.manifest.json`, outside the repo so scan mode never sees it) records
the seed, this script's SHA-256 and the composition measured back from git.
"""

from __future__ import annotations

import argparse
import atexit
import dataclasses
import hashlib
import json
import math
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GENERATOR_VERSION = "2"
KIB = 1024
SIZE_CAP = 1_048_576  # DESIGN §5 / D-PM-05 #12 file cap; files must stay <= this
TAIL_LOW = 512 * KIB
TAIL_GEN_LOW, TAIL_GEN_HIGH = 540 * KIB, 1000 * KIB  # margin inside [512 KiB, 1 MiB]
MIN_FILE = 1536
END_EPOCH = 1_790_856_000  # 2026-10-01T12:00:00Z: date of the last main commit
DAY = 86_400
IDENT = "Bench Generator <bench-generator@example.invalid>"


@dataclasses.dataclass(frozen=True)
class Profile:
    name: str
    py_files: int
    commits: int
    span_days: int
    merge_ratio: float
    tail_min: int
    pr_files: int
    large_pr_files: int  # 0 = no AC-E.12 variant
    requests_share: float  # share of HTTP call sites that use requests at base
    test_share: float


PROFILES = {
    "b10k": Profile("b10k", 10_000, 2_000, 730, 0.10, 10, 50, 5_000, 0.30, 0.05),
    "b500": Profile("b500", 500, 500, 730, 0.10, 2, 10, 0, 0.30, 0.05),
    # Test-only profile for the generator's own unit tests (not a spec repo).
    "smoke": Profile("smoke", 60, 40, 730, 0.10, 1, 5, 20, 0.30, 0.10),
}

# Rules use only sentences the SPEC itself gives as recognized (AC-F2.3, F2.5,
# F3.7, F5.1), so the bench never depends on extractor guesses. Pairs on one
# checker share the same preferred option (or both have none), so there is no
# conflict in the D-PM-05 #5 sense.
RULES = [
    ("Use logging, not print.", "logging"),
    ("Use requests for HTTP calls.", "http-client"),
    ("Use pytest, not unittest.", "test-framework"),
    ("Prefer pytest over unittest.", "test-framework"),
    ("Use f-strings for string formatting.", "string-format"),
    ("Always use f-strings.", "string-format"),
    ("Do not use bare except.", "exceptions"),
    ("Do not use bare except or catch Exception.", "exceptions"),
    ("Always use type hints.", "type-hints"),
    ("Use uv for dependencies.", "package-manager"),
]
AGENTS_HEADER = ["# Agent instructions", "", "Conventions for this repository:", ""]


def agents_md() -> tuple[str, list[dict]]:
    lines = list(AGENTS_HEADER)
    out = []
    for text, checker in RULES:
        lines.append(f"- {text}")
        out.append({"file": "AGENTS.md", "line": len(lines), "text": text, "checker": checker})
    return "\n".join(lines) + "\n", out


PYPROJECT = """[project]
name = "benchapp"
version = "0.0.0"
requires-python = ">=3.11"

[tool.uv]
dev-dependencies = []
"""
# Every benchmark PR also renames one non-.py file, so I-12 `counts.changed_files` (every path
# from changed_files(base, head), any type, a rename once) differs from the .py count.
DOC_OLD, DOC_NEW = "docs/README.md", "docs/OVERVIEW.md"
DOC_TEXT = "# Benchmark repository\n\nSynthetic code for conventiondrift benchmarks.\n"
PR_RENAME = {DOC_OLD: DOC_NEW}

UV_LOCK = """version = 1
requires-python = ">=3.11"

[[package]]
name = "benchapp"
version = "0.0.0"
source = { editable = "." }
"""


# ----------------------------------------------------------------------------- content
@dataclasses.dataclass
class PyFile:
    index: int
    path: str
    is_test: bool
    http: str | None  # "requests" | "httpx" | None
    prefix: str  # header + http block
    suffix: str  # filler after the churn region
    rev: int = 0

    def churn(self, seed: int) -> str:
        """The only region history commits touch. Never contains HTTP lines."""
        r = random.Random(f"{seed}:churn:{self.index}:{self.rev}")  # noqa: S311 - seeded PRNG for determinism, not crypto
        body = []
        for k in range(4):
            if r.random() < 0.05:
                body.append(f'    print("churn {self.index} r{self.rev} k{k}", value)')
            else:
                body.append(f'    logger.debug(f"churn {self.index} r{self.rev} k{k} {{value}}")')
        return (
            "# churn-begin\n"
            f"def churn_hook_{self.index}(value: int) -> int:\n"
            + "\n".join(body)
            + f"\n    return value + {self.rev}\n# churn-end\n\n"
        )

    def content(self, seed: int) -> bytes:
        return (self.prefix + self.churn(seed) + self.suffix).encode("utf-8")


def _filler_module(r: random.Random, i: int, n: int) -> str:
    x = r.random()
    k1, k2 = r.randint(1, 999), r.randint(1, 999)
    tag = f"{i}_{n}"
    if x < 0.30:
        return (
            f"def compute_{tag}(a: int, b: int) -> str:\n"
            f"    acc = a * {k1} + b\n"
            f'    logger.info(f"compute_{tag} {{acc}}")\n'
            f'    return f"{{a}}:{{b}}:{{acc}}"\n\n\n'
        )
    if x < 0.55:
        return (
            f"def parse_{tag}(text: str) -> int:\n"
            "    try:\n"
            f"        return int(text) + {k1}\n"
            "    except ValueError:\n"
            f'        logger.warning("parse_{tag} failed")\n'
            f"        return {k2}\n\n\n"
        )
    if x < 0.83:
        return (
            f"class Widget{tag}:\n"
            "    def __init__(self, size: int) -> None:\n"
            "        self.size = size\n\n"
            "    def grow(self, by: int) -> int:\n"
            f'        logger.debug("grow {tag}")\n'
            "        self.size += by\n"
            "        return self.size\n\n\n"
        )
    if x < 0.89:
        return f"def legacy_{tag}(a, b):\n    return a + b + {k1}\n\n\n"
    if x < 0.94:
        return (
            f'def label_{tag}(name: str) -> str:\n    return "item {{}} #{k1}".format(name)\n\n\n'
        )
    if x < 0.975:
        return f'def debug_{tag}(value: int) -> None:\n    print("debug_{tag}", value)\n\n\n'
    if x < 0.99:
        return (
            f"def safe_{tag}(x: int) -> int:\n"
            "    try:\n"
            f"        return {k1} // x\n"
            "    except:\n"
            "        return 0\n\n\n"
        )
    if x < 0.995:
        return (
            f"def keyed_{tag}(d: dict[str, int], key: str) -> int:\n"
            "    try:\n"
            "        return d[key]\n"
            "    except KeyError:\n"
            f"        return {k2}\n\n\n"
        )
    # except Exception: follows "Do not use bare except." but contradicts the paired
    # "... or catch Exception." rule, so the two exceptions rules get different counts.
    return (
        f"def guarded_{tag}(d: dict[str, int], key: str) -> int:\n"
        "    try:\n"
        "        return d[key]\n"
        "    except Exception:\n"
        f"        return {k2}\n\n\n"
    )


def _filler_test(r: random.Random, i: int, n: int) -> str:
    k = r.randint(1, 999)
    return f"def test_case_{i}_{n}() -> None:\n    assert {k} + 1 == {k + 1}\n\n\n"


def _http_block(kind: str, i: int) -> str:
    return f"def fetch_{i}(url: str) -> object:\n    return {kind}.get(url, timeout=5)\n\n\n"


def build_file(
    seed: int,
    prof: Profile,
    i: int,
    path: str,
    is_test: bool,
    http: str | None,
    target: int,
    legacy_case: bool,
) -> PyFile:
    r = random.Random(f"{seed}:file:{i}")  # noqa: S311 - seeded PRNG for determinism, not crypto
    head = [f'"""Benchmark module {i} for {prof.name}."""', ""]
    if is_test:
        if legacy_case:
            head.append("import unittest")
        head.append("import logging")
    else:
        head.append("import logging")
        if http:
            head.append(f"import {http}")
    head += ["", "logger = logging.getLogger(__name__)", "", ""]
    prefix = "\n".join(head)
    if http:
        prefix += _http_block(http, i)
    pf = PyFile(i, path, is_test, http, prefix, "")
    size = len(prefix) + len(pf.churn(seed))
    parts: list[str] = []
    if is_test and legacy_case:
        block = (
            f"class TestLegacy{i}(unittest.TestCase):\n"
            "    def test_legacy(self) -> None:\n"
            "        self.assertEqual(1, 1)\n\n\n"
        )
        parts.append(block)
        size += len(block)
    n = 0
    filler = _filler_test if is_test else _filler_module
    while size < target:
        block = filler(r, i, n)
        parts.append(block)
        size += len(block)
        n += 1
    pf.suffix = "".join(parts)
    return pf


def plan_sizes(seed: int, prof: Profile, modules: list[int]) -> dict[int, int]:
    r = random.Random(f"{seed}:sizes")  # noqa: S311 - seeded PRNG for determinism, not crypto
    target_mean = 16 * KIB
    sigma = 1.0
    mu = math.log(target_mean) - sigma * sigma / 2
    sizes = {i: int(r.lognormvariate(mu, sigma)) for i in range(prof.py_files)}
    tail = set(r.sample(modules, prof.tail_min))
    for i in tail:
        sizes[i] = r.randint(TAIL_GEN_LOW, TAIL_GEN_HIGH)
    for i in sizes:  # natural draws stay below the tail band; the forced ones make the tail
        if i not in tail:
            sizes[i] = max(MIN_FILE, min(sizes[i], TAIL_LOW - 32 * KIB))
    for _ in range(6):  # rescale the non-tail files so the overall mean is ~16 KiB
        rest = [i for i in sizes if i not in tail]
        need = target_mean * prof.py_files - sum(sizes[i] for i in tail)
        have = sum(sizes[i] for i in rest)
        f = need / have
        for i in rest:
            sizes[i] = max(MIN_FILE, min(int(sizes[i] * f), TAIL_LOW - 32 * KIB))
    return sizes


# ----------------------------------------------------------------------------- fast-import
class Stream:
    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc = proc
        self.mark = 0
        if proc.stdin is None:
            raise RuntimeError("git fast-import has no stdin pipe")
        self.w = proc.stdin

    def _data(self, payload: bytes) -> None:
        self.w.write(b"data %d\n" % len(payload))
        self.w.write(payload)
        self.w.write(b"\n")

    def commit(
        self,
        ref: str,
        epoch: int,
        message: str,
        parent: int | None,
        merge: int | None,
        files: dict[str, bytes],
        renames: dict[str, str] | None = None,
    ) -> int:
        self.mark += 1
        w = self.w
        w.write(f"commit {ref}\nmark :{self.mark}\n".encode())
        w.write(f"author {IDENT} {epoch} +0000\ncommitter {IDENT} {epoch} +0000\n".encode())
        self._data(message.encode())
        if parent is not None:
            w.write(f"from :{parent}\n".encode())
        if merge is not None:
            w.write(f"merge :{merge}\n".encode())
        for old, new in sorted((renames or {}).items()):
            w.write(f"R {old} {new}\n".encode())
        for path in sorted(files):
            w.write(f"M 100644 inline {path}\n".encode())
            self._data(files[path])
        w.write(b"\n")
        return self.mark


# Unique per-process home; never reuse gettempdir()/cd-bench-git-home, which
# older revisions shared across runs and only created isolated.gitconfig once.
_GIT_HOME: Path | None = None


def _bench_git_home() -> Path:
    global _GIT_HOME
    if _GIT_HOME is None:
        _GIT_HOME = Path(tempfile.mkdtemp(prefix="cd-bench-git-home-"))
        atexit.register(shutil.rmtree, _GIT_HOME, ignore_errors=True)
    return _GIT_HOME


def git_env() -> dict[str, str]:
    """Isolated git env that still starts git.exe on Windows."""
    home = _bench_git_home()
    cfg = home / "isolated.gitconfig"
    cfg.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(cfg),
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    for key in (
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "SYSTEMDRIVE",
        "TMP",
        "TEMP",
        "TMPDIR",
    ):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    return env


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(  # noqa: S603 - argv list, no shell
        ["git", *args],  # noqa: S607 - git from PATH by design
        cwd=repo,
        env=git_env(),
        check=True,
        capture_output=True,
    )
    return out.stdout.decode().strip()


# ----------------------------------------------------------------------------- generator
def generate(prof: Profile, seed: int, out: Path) -> dict:
    t0 = time.monotonic()
    r = random.Random(f"{seed}:plan:{prof.name}")  # noqa: S311 - seeded PRNG for determinism, not crypto
    n_test = max(1, round(prof.py_files * prof.test_share))
    modules = list(range(n_test, prof.py_files))
    paths = {}
    for i in range(prof.py_files):
        if i < n_test:
            paths[i] = f"tests/group_{i // 100:03d}/test_mod_{i:05d}.py"
        else:
            paths[i] = f"src/benchapp/pkg_{i // 100:03d}/mod_{i:05d}.py"
    n_req = round(len(modules) * prof.requests_share)
    req_set = set(r.sample(modules, n_req))
    if prof.large_pr_files and prof.large_pr_files < n_req:
        raise SystemExit("profile error: the E.12 PR must contain every requests file")
    legacy_tests = set(r.sample(range(n_test), max(1, n_test // 10)))
    sizes = plan_sizes(seed, prof, modules)
    files = {
        i: build_file(
            seed,
            prof,
            i,
            paths[i],
            i < n_test,
            None if i < n_test else ("requests" if i in req_set else "httpx"),
            sizes[i],
            i in legacy_tests,
        )
        for i in range(prof.py_files)
    }
    agents, rules = agents_md()

    # ---- event plan: root, then L linear commits and M merge groups (side, main, merge)
    n_merge = round(prof.commits * prof.merge_ratio)
    n_linear = prof.commits - 1 - 3 * n_merge
    tokens = ["L"] * n_linear + ["G"] * n_merge
    r.shuffle(tokens)
    kinds = ["root"]
    for t in tokens:
        kinds += ["linear"] if t == "L" else ["side", "main", "merge"]
    if len(kinds) != prof.commits:
        raise RuntimeError(f"event plan has {len(kinds)} commits, expected {prof.commits}")
    start = END_EPOCH - prof.span_days * DAY
    step = prof.span_days * DAY / (prof.commits - 1)
    dates = [start + round(k * step) for k in range(prof.commits)]

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    git(out, "init", "-q", "-b", "main", ".")
    proc = subprocess.Popen(
        ["git", "fast-import", "--quiet", "--done"],  # noqa: S607 - git from PATH by design
        cwd=out,
        env=git_env(),
        stdin=subprocess.PIPE,
    )
    s = Stream(proc)
    churnable = list(range(prof.py_files))
    main_tip: int | None = None
    side_files: dict[str, bytes] = {}
    side_mark = 0
    pending_main: int | None = None
    files_per_commit: list[int] = []

    def pick(k: int, exclude: set[int]) -> list[int]:
        chosen: list[int] = []
        while len(chosen) < k:
            c = churnable[r.randrange(len(churnable))]
            if c not in exclude and c not in chosen:
                chosen.append(c)
        return chosen

    side_used: set[int] = set()
    for n, (kind, epoch) in enumerate(zip(kinds, dates, strict=True)):
        msg = f"bench {prof.name}: commit {n:04d} ({kind})\n"
        if kind == "root":
            tree = {f.path: f.content(seed) for f in files.values()}
            tree.update(
                {
                    "AGENTS.md": agents.encode(),
                    "pyproject.toml": PYPROJECT.encode(),
                    "uv.lock": UV_LOCK.encode(),
                    DOC_OLD: DOC_TEXT.encode(),
                }
            )
            main_tip = s.commit("refs/heads/main", epoch, msg, None, None, tree)
            continue
        if kind == "merge":
            main_tip = s.commit("refs/heads/main", epoch, msg, pending_main, side_mark, side_files)
            side_files, side_used = {}, set()
            continue
        k = r.randint(1, 5)  # mean 3 files per non-merge commit
        chosen = pick(k, side_used if kind == "main" else set())
        changed = {}
        for c in chosen:
            files[c].rev += 1
            changed[files[c].path] = files[c].content(seed)
        files_per_commit.append(k)
        if kind == "side":
            side_used = set(chosen)
            side_files = dict(changed)
            side_mark = s.commit("refs/heads/_bench_side", epoch, msg, main_tip, None, changed)
        elif kind == "main":
            pending_main = s.commit("refs/heads/main", epoch, msg, main_tip, None, changed)
        else:
            main_tip = s.commit("refs/heads/main", epoch, msg, main_tip, None, changed)

    # ---- PR branches (one commit each, dated one day after the main tip)
    pr_epoch = END_EPOCH + DAY
    neutral_pool = [i for i in modules if i not in req_set]
    rp = random.Random(f"{seed}:pr:{prof.name}")  # noqa: S311 - seeded PRNG for determinism, not crypto
    bench_pr = sorted(rp.sample(neutral_pool, prof.pr_files))
    saved = {i: files[i].rev for i in bench_pr}
    changed = {}
    for i in bench_pr:
        files[i].rev += 1
        changed[files[i].path] = files[i].content(seed)
    s.commit(
        "refs/heads/bench-pr",
        pr_epoch,
        f"bench {prof.name}: benchmark PR ({prof.pr_files} files, churn only)\n",
        main_tip,
        None,
        changed,
        PR_RENAME,
    )
    for i, rev in saved.items():
        files[i].rev = rev

    large = None
    if prof.large_pr_files:
        extra = sorted(rp.sample(neutral_pool, prof.large_pr_files - n_req))
        changed = {}
        for i in sorted(req_set):
            f = files[i]
            changed[f.path] = (
                f.prefix.replace("import requests\n", "import httpx\n").replace(
                    "requests.get(", "httpx.get("
                )
                + f.churn(seed)
                + f.suffix
            ).encode()
        for i in extra:
            files[i].rev += 1
            changed[files[i].path] = files[i].content(seed)
        s.commit(
            "refs/heads/bench-pr-5000",
            pr_epoch,
            f"bench {prof.name}: AC-E.12 PR "
            f"({prof.large_pr_files} files: requests->httpx in {n_req}, churn in "
            f"{len(extra)})\n",
            main_tip,
            None,
            changed,
            PR_RENAME,
        )
        large = {"requests_files": n_req, "churn_files": len(extra)}
    s.w.write(b"done\n")
    s.w.close()
    if proc.wait() != 0:
        raise SystemExit("git fast-import failed")
    git(out, "update-ref", "-d", "refs/heads/_bench_side")
    git(out, "reset", "-q", "--hard", "main")
    gen_seconds = time.monotonic() - t0

    expected = {"bench-pr": []}
    if large:
        rule = next(x for x in rules if x["checker"] == "http-client")
        expected["bench-pr-5000"] = [
            {
                "id": f"{rule['file']}:{rule['line']}",
                "file": rule["file"],
                "line": rule["line"],
                "text": rule["text"],
                "case": "made-stale-by-code",
                "base_verdict": "Contested",
                "head_verdict": "Stale",
                "head_following": 0,
            }
        ]
    return {
        "rules": rules,
        "expected_findings": expected,
        "large_pr": large,
        "oracle_http_sites_base": {"requests": n_req, "httpx": len(modules) - n_req},
        "planned_files_per_noncommit_mean": sum(files_per_commit) / len(files_per_commit),
        "generation_seconds": round(gen_seconds, 1),
    }


# ----------------------------------------------------------------------------- measurement
_PRINT = re.compile(rb"^\s+print\(", re.M)
_LOGGER = re.compile(rb"^\s+(?:return )?logger\.\w+\(", re.M)


def measure(repo: Path, prof: Profile) -> dict:
    """Composition read back from git, independent of the generator's bookkeeping."""
    tree = git(repo, "ls-tree", "-r", "-l", "main").splitlines()
    py = [
        (int(line.split()[3]), line.split("\t", 1)[1])
        for line in tree
        if line.split("\t", 1)[1].endswith(".py")
    ]
    sizes = sorted(sz for sz, _ in py)
    total = git(repo, "rev-list", "--count", "main")
    merges = git(repo, "rev-list", "--count", "--merges", "main")
    fp = git(repo, "rev-list", "--count", "--first-parent", "main")
    log = git(repo, "log", "--format=%ct", "main").split()
    epochs = sorted(int(x) for x in log)
    pr_epoch = int(git(repo, "show", "-s", "--format=%ct", "bench-pr"))
    in_window = sum(1 for e in epochs if pr_epoch - 90 * DAY <= e <= pr_epoch)
    fp_epochs = [int(x) for x in git(repo, "log", "--first-parent", "--format=%ct", "main").split()]
    fp_in_window = sum(1 for e in fp_epochs if pr_epoch - 90 * DAY <= e <= pr_epoch)
    # files changed per non-merge, non-root commit
    raw = git(repo, "log", "--no-merges", "--format=format:@%H %P", "--name-only", "main")
    per = []
    cur = None
    for line in raw.splitlines():
        if line.startswith("@"):
            if cur is not None:
                per.append(cur)
            cur = None if len(line.split()) == 1 else 0
        elif line and cur is not None:
            cur += 1
    if cur is not None:
        per.append(cur)
    # `git log --diff-merges=first-parent` needs git 2.36+; diff each merge
    # against its first parent, which exists in 2.30 (D-TL-18).
    mper = []
    for sha in git(repo, "rev-list", "--merges", "main").split():
        names = git(repo, "diff", "--name-only", f"{sha}^1", sha)
        mper.append(len([line for line in names.splitlines() if line]))
    # rough site census at the tip (regex on the controlled templates)
    prints = loggers = 0
    for _, path in py:
        if path.startswith("tests/"):
            continue
        blob = (repo / path).read_bytes()
        prints += len(_PRINT.findall(blob))
        loggers += len(_LOGGER.findall(blob))

    def pr_stats(ref: str) -> dict:
        mb = git(repo, "merge-base", "main", ref)
        status = git(repo, "diff", "--name-status", "-M", mb, ref).splitlines()
        names = [line.split("\t")[-1] for line in status]
        return {
            "files_changed": len(names),
            "py_files_changed": sum(1 for n in names if n.endswith(".py")),
            "non_py_paths_changed": sum(1 for n in names if not n.endswith(".py")),
            "renames": sum(1 for line in status if line.startswith("R")),
            "sha": git(repo, "rev-parse", ref),
        }

    refs = {
        name: git(repo, "rev-parse", name)
        for name in ("main", "bench-pr", "bench-pr-5000")
        if subprocess.run(  # noqa: S603 - argv list, no shell
            ["git", "rev-parse", "--verify", "-q", name],  # noqa: S607 - git from PATH by design
            cwd=repo,
            env=git_env(),
            capture_output=True,
        ).returncode
        == 0
    }
    root = git(repo, "rev-list", "--max-parents=0", "main")
    root_epoch = int(git(repo, "show", "-s", "--format=%ct", root))
    exc = {ref: exception_census(repo, ref) for ref in refs}
    mean = sum(sizes) / len(sizes)
    return {
        "root_commit": {
            "sha": root,
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(root_epoch)),
            "is_earliest": root_epoch == epochs[0],
            "days_before_last_main_commit": round((epochs[-1] - root_epoch) / DAY, 2),
        },
        "exception_census": exc,
        "refs": refs,
        "trees": {k: git(repo, "rev-parse", f"{k}^{{tree}}") for k in refs},
        "py_files": len(py),
        "size_bytes": {
            "mean": round(mean, 1),
            "mean_kib": round(mean / KIB, 2),
            "median": sizes[len(sizes) // 2],
            "min": sizes[0],
            "max": sizes[-1],
            "p90": sizes[int(len(sizes) * 0.9)],
            "p99": sizes[int(len(sizes) * 0.99)],
            "files_512k_to_1m": sum(1 for x in sizes if TAIL_LOW <= x <= SIZE_CAP),
            "files_over_cap": sum(1 for x in sizes if x > SIZE_CAP),
            "total": sum(sizes),
        },
        "commits": {
            "total": int(total),
            "merges": int(merges),
            "merge_ratio": round(int(merges) / int(total), 4),
            "first_parent": int(fp),
            "first_date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epochs[0])),
            "last_date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epochs[-1])),
            "span_days": round((epochs[-1] - epochs[0]) / DAY, 2),
            "in_90d_window_before_pr_head": in_window,
            "first_parent_in_90d_window": fp_in_window,
            "files_per_nonmerge_commit_mean": round(sum(per) / len(per), 3),
            "files_per_merge_vs_first_parent_mean": round(sum(mper) / max(1, len(mper)), 3),
            "files_per_commit_mean_excl_root": round(
                (sum(per) + sum(mper)) / (len(per) + len(mper)), 3
            ),
        },
        "pr_head_date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(pr_epoch)),
        "prs": {ref: pr_stats(ref) for ref in refs if ref != "main"},
        "site_census_non_test": {"print_calls": prints, "logger_calls": loggers},
        "instruction_files": ["AGENTS.md"],
        "manifests": ["pyproject.toml", "uv.lock"],
    }


_EXCEPT = {
    "bare": r"^[[:space:]]+except:",
    "Exception": r"^[[:space:]]+except Exception\b",
    "all": r"^[[:space:]]+except\b",
}


def exception_census(repo: Path, ref: str) -> dict[str, int]:
    """except-clause counts in all .py files at `ref` (regex on the controlled templates)."""
    out = {}
    for key, pattern in _EXCEPT.items():
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            ["git", "grep", "-c", "-E", pattern, ref, "--", "*.py"],  # noqa: S607 - git on PATH
            cwd=repo,
            env=git_env(),
            capture_output=True,
            text=True,
            check=False,
        )
        out[key] = sum(int(line.rsplit(":", 1)[1]) for line in proc.stdout.splitlines())
    return out


EXCEPTION_RULES = {  # D-PM-27 (5): not a conflict; each rule is evaluated on its own
    "Do not use bare except.": ("bare",),
    "Do not use bare except or catch Exception.": ("bare", "Exception"),
}


def exception_rule_verdicts(census: dict[str, dict[str, int]]) -> dict[str, dict]:
    """Expected verdict per exceptions rule and ref, from overall adherence (Holds >= 80%)."""
    out = {}
    for text, prohibited in EXCEPTION_RULES.items():
        per_ref = {}
        for ref, c in sorted(census.items()):
            contradicting = sum(c[k] for k in prohibited)
            following = c["all"] - contradicting
            pct = 100 * following / c["all"] if c["all"] else 0.0
            per_ref[ref] = {
                "following": following,
                "contradicting": contradicting,
                "relevant": c["all"],
                "overall_percent": round(pct, 2),
                "expected_verdict": "Holds" if following * 100 >= 80 * c["all"] else None,
            }
        out[text] = per_ref
    return out


def check_composition(prof: Profile, comp: dict) -> list[str]:
    """The spec's composition rules; any message is a generator bug."""
    errs = []
    sb, c = comp["size_bytes"], comp["commits"]
    if comp["py_files"] != prof.py_files:
        errs.append(f"py_files {comp['py_files']} != {prof.py_files}")
    if prof.name != "smoke":
        if not 0.9 * 16 * KIB <= sb["mean"] <= 1.1 * 16 * KIB:
            errs.append(f"mean size {sb['mean']} outside 16 KiB +-10%")
        if sb["files_512k_to_1m"] < prof.tail_min:
            errs.append(f"only {sb['files_512k_to_1m']} files in [512 KiB, 1 MiB]")
    if sb["files_over_cap"] or sb["max"] > SIZE_CAP:
        errs.append("a file exceeds the 1 MiB cap")
    if c["total"] != prof.commits:
        errs.append(f"commits {c['total']} != {prof.commits}")
    if abs(c["merge_ratio"] - prof.merge_ratio) > 0.02:
        errs.append(f"merge ratio {c['merge_ratio']}")
    if abs(c["span_days"] - prof.span_days) > 0.01:
        errs.append(f"span {c['span_days']} days")
    if not 2.5 <= c["files_per_commit_mean_excl_root"] <= 3.5:
        errs.append(f"files/commit {c['files_per_commit_mean_excl_root']}")
    rc = comp["root_commit"]
    if not rc["is_earliest"] or abs(rc["days_before_last_main_commit"] - prof.span_days) > 0.01:
        errs.append(f"root commit not dated at the start of the {prof.span_days}-day span")
    for ref, pr in comp["prs"].items():
        if pr["renames"] != 1 or pr["non_py_paths_changed"] != 1:
            errs.append(f"{ref}: expected exactly one non-.py rename")
        if pr["files_changed"] != pr["py_files_changed"] + 1:
            errs.append(f"{ref}: files_changed must count the renamed non-.py path once")
    for text, refs in exception_rule_verdicts(comp["exception_census"]).items():
        for ref, v in refs.items():
            if v["expected_verdict"] != "Holds":
                errs.append(f"{text!r} at {ref}: {v['overall_percent']}% is not a clear Holds")
    if comp["prs"]["bench-pr"]["py_files_changed"] != prof.pr_files:
        errs.append("bench-pr file count")
    if (
        prof.large_pr_files
        and comp["prs"]["bench-pr-5000"]["py_files_changed"] != prof.large_pr_files
    ):
        errs.append("bench-pr-5000 file count")
    return errs


def script_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--profile", required=True, choices=sorted(PROFILES))
    ap.add_argument("--seed", required=True, type=int)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--manifest", type=Path, help="default: <OUT>.manifest.json")
    a = ap.parse_args(argv)
    prof = PROFILES[a.profile]
    out = a.out.resolve()
    gen = generate(prof, a.seed, out)
    t1 = time.monotonic()
    comp = measure(out, prof)
    errs = check_composition(prof, comp)
    measure_s = round(time.monotonic() - t1, 1)
    manifest = {
        "schema": "conventiondrift-bench-manifest/1",
        "generator_version": GENERATOR_VERSION,
        "profile": prof.name,
        "profile_spec": dataclasses.asdict(prof),
        "seed": a.seed,
        "script_sha256": script_sha256(),
        "composition": comp,
        "rules": gen["rules"],
        "exception_rule_verdicts": exception_rule_verdicts(comp["exception_census"]),
        "expected_findings": gen["expected_findings"],
        "large_pr": gen["large_pr"],
        "oracle_http_sites_base": gen["oracle_http_sites_base"],
        "composition_errors": errs,
    }
    path = a.manifest or out.with_name(out.name + ".manifest.json")
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Timings vary between runs, so they go to stderr, never into the manifest.
    print(
        json.dumps(
            {
                "profile": prof.name,
                "seed": a.seed,
                "generate_s": gen["generation_seconds"],
                "measure_s": measure_s,
                "manifest": str(path),
                "main": comp["refs"]["main"],
            }
        ),
        file=sys.stderr,
    )
    if errs:
        print("composition errors: " + "; ".join(errs), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
