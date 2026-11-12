"""Tests for tools/gen_bench_repo.py (T-052): composition, determinism, E.12 labels."""
# ruff: noqa: S603, S607  (test tooling: fixed argv lists to git/python, seeded non-crypto RNG by design)

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from bench import benchlib

GEN = benchlib.GENERATOR


def _gen(profile: str, seed: int, out: Path) -> dict:
    subprocess.run(
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
    return subprocess.run(
        ["git", *args],
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
        ["git", "grep", "-l", "requests.get(", "bench-pr-5000"],
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
