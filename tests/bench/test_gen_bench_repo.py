"""Tests for tools/gen_bench_repo.py (T-052): composition, determinism, E.12 labels."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from bench import benchlib

GEN = benchlib.GENERATOR


def _gen(profile: str, seed: int, out: Path) -> dict:
    subprocess.run(  # noqa: S603 - argv list, no shell
        [
            sys.executable,
            str(GEN),
            "--profile",
            profile,
            "--seed",
            str(seed),
            "--out",
            str(out),
        ],
        check=True,
        capture_output=True,
    )
    return json.loads(out.with_name(out.name + ".manifest.json").read_text(encoding="utf-8"))


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 - argv list, no shell
        ["git", *args],  # noqa: S607 - git from PATH by design
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.fixture(scope="module")
def b500_pair(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict, Path, dict]:
    d = tmp_path_factory.mktemp("gen")
    a, b = d / "b500_a", d / "b500_b"
    return a, _gen("b500", benchlib.BENCH_SEED, a), b, _gen("b500", benchlib.BENCH_SEED, b)


@pytest.fixture(scope="module")
def smoke(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    out = tmp_path_factory.mktemp("gen") / "smoke"
    return out, _gen("smoke", 7, out)


def test_git_env_isolates_config_and_keeps_windows_runtime() -> None:
    """The generator's git env is isolated and keeps Windows runtime variables."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_bench_repo", GEN)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    env = mod.git_env()
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    cfg = Path(env["GIT_CONFIG_GLOBAL"])
    assert cfg.is_file()
    assert cfg.read_text(encoding="utf-8") == ""
    assert cfg != Path(os.devnull)
    assert env["USERPROFILE"] == env["HOME"]
    assert env["PATH"] == os.environ.get("PATH", os.defpath)


def test_git_env_ignores_poisoned_shared_gitconfig() -> None:
    """A planted config in the old shared cd-bench-git-home location has no effect."""
    import importlib.util

    old_home = Path(tempfile.gettempdir()) / "cd-bench-git-home"
    old_home.mkdir(parents=True, exist_ok=True)
    poison = old_home / "isolated.gitconfig"
    previous = poison.read_text(encoding="utf-8") if poison.exists() else None
    poison.write_text("[user]\n\tname = poison\n[alias]\n\tident = !echo pwned\n", encoding="utf-8")
    try:
        spec = importlib.util.spec_from_file_location("gen_bench_repo", GEN)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        env = mod.git_env()
        cfg = Path(env["GIT_CONFIG_GLOBAL"])
        assert cfg.resolve() != poison.resolve()
        assert Path(env["HOME"]).resolve() != old_home.resolve()
        assert cfg.read_text(encoding="utf-8") == ""
        # --global + a non-repo cwd, so this worktree's config cannot leak in.
        empty = Path(tempfile.mkdtemp())
        try:
            got_name = subprocess.run(
                ["git", "config", "--global", "--get", "user.name"],  # noqa: S607 - git from PATH by design
                env=env,
                cwd=empty,
                capture_output=True,
                text=True,
                check=False,
            )
            assert "poison" not in got_name.stdout
            assert got_name.returncode != 0
            alias = subprocess.run(
                ["git", "ident"],  # noqa: S607 - git from PATH by design
                env=env,
                cwd=empty,
                capture_output=True,
                text=True,
                check=False,
            )
            assert "pwned" not in alias.stdout
            assert alias.returncode != 0
        finally:
            shutil.rmtree(empty, ignore_errors=True)
    finally:
        if previous is None:
            try:
                poison.unlink()
            except OSError:
                pass
        else:
            poison.write_text(previous, encoding="utf-8")


def test_b500_composition_matches_spec(b500_pair: tuple) -> None:
    _, m, _, _ = b500_pair
    assert m["composition_errors"] == []
    c = m["composition"]
    assert c["py_files"] == 500
    assert 0.9 * 16384 <= c["size_bytes"]["mean"] <= 1.1 * 16384
    assert c["size_bytes"]["files_512k_to_1m"] >= 2
    assert c["size_bytes"]["max"] <= 1_048_576
    assert c["commits"]["total"] == 500
    assert c["commits"]["merges"] == 50
    assert c["commits"]["span_days"] == 730.0
    assert 2.5 <= c["commits"]["files_per_commit_mean_excl_root"] <= 3.5
    assert c["prs"]["bench-pr"]["py_files_changed"] == 10
    assert len(m["rules"]) >= 10
    default_checkers = {
        "logging",
        "http-client",
        "test-framework",
        "string-format",
        "exceptions",
        "type-hints",
        "package-manager",
    }
    assert {r["checker"] for r in m["rules"]} == default_checkers


def test_b500_same_seed_identical_shas_and_trees(b500_pair: tuple) -> None:
    a, ma, b, mb = b500_pair
    assert ma == mb  # manifest is byte-for-byte content-identical (no timings in it)
    assert _git(a, "for-each-ref") == _git(b, "for-each-ref")
    assert _git(a, "rev-list", "--all") == _git(b, "rev-list", "--all")
    assert _git(a, "rev-parse", "main^{tree}") == _git(b, "rev-parse", "main^{tree}")


def test_manifest_records_seed_and_script_hash(b500_pair: tuple) -> None:
    _, m, _, _ = b500_pair
    assert m["seed"] == benchlib.BENCH_SEED
    assert m["script_sha256"] == hashlib.sha256(GEN.read_bytes()).hexdigest()


def test_different_seed_different_repo(tmp_path: Path, smoke: tuple) -> None:
    _, m7 = smoke
    m8 = _gen("smoke", 8, tmp_path / "smoke8")
    assert m7["composition"]["refs"]["main"] != m8["composition"]["refs"]["main"]


def test_every_py_file_parses_and_is_not_generated_marked(b500_pair: tuple) -> None:
    repo = b500_pair[0]
    for p in repo.rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        ast.parse(text, filename=str(p))
        head = "".join(text.splitlines(True)[:5]).lower()
        assert not ("generated" in head and "do not edit" in head), p  # AC-F3.11 exclude


def test_no_default_excluded_paths(b500_pair: tuple) -> None:
    files = _git(b500_pair[0], "ls-tree", "-r", "--name-only", "main").splitlines()
    banned = (
        "venv/",
        "env/",
        ".tox/",
        "vendor/",
        "third_party/",
        "build/",
        "dist/",
        "migrations/",
        "site-packages/",
        "node_modules/",
        "__pycache__/",
    )
    assert not [f for f in files if any(f"/{b}" in f"/{f}" for b in banned)]


def test_e12_labels_hold_by_construction(smoke: tuple) -> None:
    """The E.12 label (one case-1 finding on the requests rule) needs: no HTTP line changes after
    the root commit, every requests site changed in bench-pr-5000, and no requests left."""
    repo, m = smoke
    root = _git(repo, "rev-list", "--max-parents=0", "main").strip()
    hist = _git(repo, "log", "-p", "-U0", "--format=", f"{root}..main")
    changed = [
        ln for ln in hist.splitlines() if ln[:1] in "+-" and not ln.startswith(("+++", "---"))
    ]
    assert not [ln for ln in changed if "requests" in ln or "httpx" in ln]
    pr = m["composition"]["prs"]["bench-pr-5000"]
    assert pr["py_files_changed"] == m["profile_spec"]["large_pr_files"]
    grep = subprocess.run(
        ["git", "grep", "-l", "requests.get(", "bench-pr-5000"],  # noqa: S607 - git from PATH by design
        cwd=repo,
        capture_output=True,
        text=True,
    )
    assert grep.stdout == ""
    exp = m["expected_findings"]["bench-pr-5000"]
    assert [(e["text"], e["case"]) for e in exp] == [
        ("Use requests for HTTP calls.", "made-stale-by-code")
    ]
    share = m["oracle_http_sites_base"]
    pct = 100 * share["requests"] / (share["requests"] + share["httpx"])
    assert 20 <= pct < 80  # base Contested on overall alone, whatever recent says
    assert m["expected_findings"]["bench-pr"] == []


def test_root_commit_dated_at_start_of_span(b500_pair: tuple) -> None:
    """D-PM-27 (2): the root commit carries the first date of the 730-day span."""
    repo, m, _, _ = b500_pair
    root = _git(repo, "rev-list", "--max-parents=0", "main").split()
    assert len(root) == 1
    root_ct = int(_git(repo, "show", "-s", "--format=%ct", root[0]))
    all_ct = [int(x) for x in _git(repo, "log", "--format=%ct", "main").split()]
    assert root_ct == min(all_ct)
    assert max(all_ct) - root_ct == 730 * 86400
    assert (
        m["composition"]["root_commit"]["date_utc"] == m["composition"]["commits"]["first_date_utc"]
    )


def test_pr_changed_files_counts_every_path_and_rename_once(smoke: tuple) -> None:
    """I-12: counts.changed_files = every path of changed_files(base, head), any type."""
    repo, m = smoke
    for ref, pr in m["composition"]["prs"].items():
        mb = _git(repo, "merge-base", "main", ref).strip()
        status = _git(repo, "diff", "--name-status", "-M", mb, ref).splitlines()
        renames = [line for line in status if line.startswith("R")]
        assert len(renames) == 1, ref
        assert renames[0].split("\t")[1:] == ["docs/README.md", "docs/OVERVIEW.md"]
        assert pr["files_changed"] == len(status) == pr["py_files_changed"] + 1
        assert pr["non_py_paths_changed"] == 1


def _except_census(repo: Path, ref: str) -> dict[str, int]:
    """Independent recount with ast (the generator uses git grep on its templates)."""
    counts = {"bare": 0, "Exception": 0, "all": 0}
    paths = [
        p for p in _git(repo, "ls-tree", "-r", "--name-only", ref).split() if p.endswith(".py")
    ]
    for path in paths:
        tree = ast.parse(_git(repo, "show", f"{ref}:{path}"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                counts["all"] += 1
                if node.type is None:
                    counts["bare"] += 1
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    counts["Exception"] += 1
    return counts


def test_exceptions_rules_have_separate_expected_verdicts(smoke: tuple) -> None:
    """D-PM-27 (5): the paired exceptions rules are not a conflict; each has its own verdict."""
    repo, m = smoke
    verdicts = m["exception_rule_verdicts"]
    narrow, wide = "Do not use bare except.", "Do not use bare except or catch Exception."
    assert set(verdicts) == {narrow, wide}
    for ref in ("main", *m["composition"]["prs"]):
        c = _except_census(repo, ref)
        assert c["Exception"] > 0, "the two rules must be distinguishable"
        n, w = verdicts[narrow][ref], verdicts[wide][ref]
        assert (n["relevant"], n["contradicting"]) == (c["all"], c["bare"])
        assert (w["relevant"], w["contradicting"]) == (c["all"], c["bare"] + c["Exception"])
        for v in (n, w):
            assert v["following"] * 100 >= 80 * v["relevant"]
            assert v["expected_verdict"] == "Holds"
    findings = [f for per_ref in m["expected_findings"].values() for f in per_ref]
    assert not {f["text"] for f in findings} & {narrow, wide}
