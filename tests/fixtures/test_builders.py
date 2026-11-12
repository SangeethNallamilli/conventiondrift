"""Self-tests for the fx.* builders: AC-text counts, dates, merge base and determinism."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fixtures import builders as fx
from fixtures.gitrepo import recent_lines


def _calls(text: str, lib: str) -> list[int]:
    return [n for n, line in enumerate(text.splitlines(), 1) if re.search(rf"\b{lib}\.get\(", line)]


def _http_census(repo, rev: str, recent: dict[str, set[int]] | None = None) -> dict:
    out = {"requests": 0, "httpx": 0, "recent_requests": 0, "recent_total": 0}
    for path in repo.ls_files(rev):
        if not path.endswith(".py"):
            continue
        text = repo.show_file(rev, path)
        for lib in ("requests", "httpx"):
            for line in _calls(text, lib):
                out[lib] += 1
                if recent is not None and line in recent.get(path, set()):
                    out["recent_total"] += 1
                    out["recent_requests"] += lib == "requests"
    return out


# ------------------------------------------------------------------ AC-F5.1
def test_f5_1_counts_from_ac_text(tmp_path: Path) -> None:
    f = fx.f5_1_requests_to_httpx(tmp_path)
    r, pr = f.repo, f.pr
    assert r.show_file(pr.head, "AGENTS.md").splitlines()[8] == "- Use requests for HTTP calls"
    assert len(r.show_file(pr.head, "AGENTS.md").splitlines()) == f.facts["recognized_rules"]
    # Base = merge base, window anchored at the PR head commit's date.
    anchor = r.commit_date(pr.head)
    assert anchor == fx.T
    base = _http_census(r, pr.merge_base, recent_lines(r, pr.merge_base, anchor=anchor))
    assert (base["requests"], base["requests"] + base["httpx"]) == f.facts["base_overall"]
    assert (base["recent_requests"], base["recent_total"]) == f.facts["base_recent"]
    head = _http_census(r, pr.head)
    assert (head["requests"], head["requests"] + head["httpx"]) == f.facts["head_overall"]
    changed = r.git("diff", "--name-only", pr.merge_base, pr.head).splitlines()
    assert changed == ["src/api/client.py"]
    # The base tip has sites the comparison must never see.
    tip = _http_census(r, pr.base_tip)
    assert tip["requests"] == 5 and pr.base_tip != pr.merge_base


def test_f5_1_deterministic(tmp_path: Path) -> None:
    a = fx.f5_1(tmp_path / "a")
    b = fx.f5_1(tmp_path / "b")
    assert a.repo.snapshot() == b.repo.snapshot()
    assert a.pr == b.pr


# ------------------------------------------------------------------ AC-F4.15
@pytest.mark.parametrize("variant", fx.F4_15_VARIANTS)
def test_f4_15_labels_match_first_parent_oracle(tmp_path: Path, variant: str) -> None:
    f = fx.f4_15_forged_dates(tmp_path, variant)
    r, pr = f.repo, f.pr
    assert r.commit_date(pr.head).isoformat() == f.facts["anchor"]
    rec = recent_lines(r, pr.head, days=90)
    for path, lines in f.facts["recent"].items():
        assert set(lines) <= rec.get(path, set()), (path, lines, rec)
    for path, lines in f.facts["not_recent"].items():
        assert not set(lines) & rec.get(path, set()), (path, lines, rec)
    assert pr.base_tip != pr.merge_base


def test_f4_15_forged_commit_dates(tmp_path: Path) -> None:
    f = fx.f4_15_forged_dates(tmp_path, "future_dated_commit")
    forged = f.repo.rev_parse(f"{f.pr.head}~1")
    assert f.repo.commit_date(forged) == fx.FORGED_FUTURE
    assert f.repo.author_date(forged) < f.repo.commit_date(f.pr.head)
    added = f.repo.show_file(forged, "src/feature.py").count("print(")
    assert added == f.facts["forged_sites"] == 3
    g = fx.f4_15_forged_dates(tmp_path / "g", "head_1971")
    assert g.repo.commit_date(g.pr.head) == fx.FORGED_PAST


def test_f4_15_out_of_order_topology(tmp_path: Path) -> None:
    f = fx.f4_15_forged_dates(tmp_path, "parent_newer_than_child")
    r = f.repo
    assert r.commit_date(f"{f.pr.head}~1") < r.commit_date(f"{f.pr.head}~2")
    m = fx.f4_15_forged_dates(tmp_path / "m", "merge_older_than_side")
    merge = m.repo.rev_parse(f"{m.pr.head}~1")
    side = m.repo.parents(merge)[1]
    assert m.repo.commit_date(merge) < m.repo.commit_date(side)


# ------------------------------------------------------------------ AC-F4.11
@pytest.mark.parametrize("variant", fx.F4_11_VARIANTS)
def test_f4_11_shallow_checkout(tmp_path: Path, variant: str) -> None:
    f = fx.f4_11_shallow_clone(tmp_path, variant)
    c, pr = f.checkout, f.pr
    assert c.is_shallow()
    assert c.rev_parse("HEAD") == f.facts["analyzed_sha"]
    assert not c.has_object(pr.merge_base) and not c.has_object(pr.base_tip)
    assert c.has_object(pr.head) == (variant == "pr_head_in_clone")
    # The two variants analyze different trees: base_extra.py exists only in the merge commit.
    assert ("src/base_extra.py" in c.ls_files("HEAD")) == (variant == "merge_commit_only")
    logging_verdict, (following, relevant) = f.facts["verdicts"]["AGENTS.md:1"]
    text = "".join(c.show_file("HEAD", p) for p in c.ls_files("HEAD") if p.endswith(".py"))
    assert text.count("logger.info(") == following
    assert text.count("logger.info(") + text.count("print(") == relevant
    assert (100 * following / relevant < 20) == (logging_verdict == "Stale")
    import json

    event = json.loads(f.event_path.read_text())
    assert event["pull_request"]["head"]["sha"] == pr.head


def test_f4_11_head_config_in_analyzed_commit(tmp_path: Path) -> None:
    f = fx.f4_11_shallow_clone(tmp_path, "merge_commit_only", head_config=True)
    assert ".conventiondrift.yml" in f.checkout.ls_files("HEAD")
    assert ".conventiondrift.yml" not in f.repo.ls_files(f.pr.base_tip)
    assert f.facts["verdicts"]["AGENTS.md:2"][0] == "Stale"


# ------------------------------------------------------------------ AC-F3.12
@pytest.mark.parametrize("variant", list(fx.F3_12_TEST_FILE_VARIANTS))
def test_f3_12_contents(tmp_path: Path, variant: str | None) -> None:
    f = fx.f3_12_script_contexts(tmp_path, variant)
    r = f.repo
    files = r.ls_files()
    for required in (
        "tests/test_x.py",
        "conftest.py",
        "scripts/run.py",
        "bin/tool.py",
        "cli.py",
        "src/lib.py",
        "pyproject.toml",
        "src/mytool/entry.py",
    ):
        assert required in files
    assert 'if __name__ == "__main__":' in r.show_file("HEAD", "cli.py")
    assert 'mytool = "mytool.entry:main"' in r.show_file("HEAD", "pyproject.toml")
    assert r.show_file("HEAD", "src/lib.py").count("logger.info(") == f.facts["relevant_sites"]
    non_lib_prints = [
        p
        for p in files
        if p.endswith(".py") and p != "src/lib.py" and "print(" in r.show_file("HEAD", p)
    ]
    assert sorted(non_lib_prints) == f.facts["print_files_not_sites"]
    assert "print(" not in r.show_file("HEAD", "src/lib.py")
