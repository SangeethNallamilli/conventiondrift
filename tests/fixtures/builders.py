"""Named fixture builders `fx.*` (TRACEABILITY §1.3). Contents come from the AC text.

Usage:  from fixtures import builders as fx;  f = fx.f5_1_requests_to_httpx(tmp_path)

Every builder makes a fresh real git repo under the given directory with explicit
committer and author dates, so it is deterministic: same call, same SHAs. The
returned `Fixture.facts` holds the expected values stated by the AC (and only
those, plus values implied by construction, each marked in a comment).
Values the AC leaves open are chosen here and listed in `Fixture.choices` so a
reviewer can see them (and they are reported as ambiguities).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from pathlib import Path
from typing import Any

from fixtures.gitrepo import GitRepo, PullRequest, days_before

# Fixed PR head date used by every builder (never the wall clock).
PR_HEAD_DATE = _dt.datetime(2026, 6, 15, 12, 0, 0, tzinfo=_dt.UTC)
T = PR_HEAD_DATE


@dataclasses.dataclass
class Fixture:
    name: str
    repo: GitRepo
    pr: PullRequest | None = None
    facts: dict[str, Any] = dataclasses.field(default_factory=dict)
    choices: dict[str, str] = dataclasses.field(default_factory=dict)
    checkout: GitRepo | None = None  # e.g. the shallow clone the tool runs in
    event_path: Path | None = None


def _fn(name: str, body: str) -> str:
    return f"def {name}(url: str) -> object:\n    return {body}\n\n\n"


def _http_module(doc: str, imports: list[str], funcs: list[tuple[str, str]]) -> str:
    head = f'"""{doc}"""\n\n' + "".join(f"import {m}\n" for m in imports) + "\n\n"
    return head + "".join(_fn(n, f"{lib}.get(url, timeout=5)") for n, lib in funcs)


# ---------------------------------------------------------------------------- AC-F5.1
F5_1_OTHER_RULES = [
    "Use logging, not print.",
    "Use pytest, not unittest.",
    "Use f-strings for string formatting.",
    "Do not use bare except.",
    "Always use type hints.",
    "Use uv for dependencies.",
    "Prefer pytest over unittest.",
    "Always use f-strings.",
]
F5_1_RULE = "Use requests for HTTP calls"


def f5_1_requests_to_httpx(root: Path, *, number: int = 1) -> Fixture:
    """AC-F5.1 (also F6.2, F6.3, F6.7, F6.8, F9.4, F9.8 ...).

    AGENTS.md line 9 "Use requests for HTTP calls"; base has 40 HTTP call sites, 3 requests;
    5 recent sites, 2 of them requests (recent 40% -> Contested at base). The PR replaces the
    last 3 requests sites in src/api/client.py with httpx -> 0 of 40 (Stale at head, case 1).
    9 recognized rules in total (AC-F6.7).
    """
    repo = GitRepo.init(root / "f5_1")
    agents = "".join(f"- {r}\n" for r in F5_1_OTHER_RULES) + f"- {F5_1_RULE}\n"
    old_client = [(f"client_get_{k}", "httpx") for k in range(1, 8)] + [
        ("legacy_fetch", "requests")
    ]
    files_c1 = {
        "AGENTS.md": agents,
        "src/api/client.py": _http_module("API client.", ["httpx", "requests"], old_client),
        "src/api/users.py": _http_module(
            "Users.", ["httpx"], [(f"users_get_{k}", "httpx") for k in range(1, 11)]
        ),
        "src/services/payments.py": _http_module(
            "Payments.", ["httpx"], [(f"payments_get_{k}", "httpx") for k in range(1, 11)]
        ),
        "src/services/search.py": _http_module(
            "Search.", ["httpx"], [(f"search_get_{k}", "httpx") for k in range(1, 8)]
        ),
    }
    repo.commit_files("initial code (old sites)", files_c1, date=days_before(T, 200))
    recent_client = [*old_client, ("recent_fetch_a", "requests"), ("recent_fetch_b", "requests")]
    recent_search = [(f"search_get_{k}", "httpx") for k in range(1, 11)]
    repo.commit_files(
        "add recent sites",
        {
            "src/api/client.py": _http_module("API client.", ["httpx", "requests"], recent_client),
            "src/services/search.py": _http_module("Search.", ["httpx"], recent_search),
        },
        date=days_before(T, 30),
    )
    fork = repo.start_pr_branch("feature/httpx-client", "main")
    # The PR: the last 3 requests sites in src/api/client.py become httpx.
    pr_client = [(n, "httpx") for n, _ in recent_client]
    repo.commit_files(
        "Switch client to httpx",
        {
            "src/api/client.py": _http_module("API client.", ["httpx"], pr_client),
        },
        date=T,
    )
    # Base branch moves on after the merge base (TRACEABILITY §1.5): 2 more requests sites
    # that a tip-vs-merge-base mix-up would wrongly count ("3 of 42"/"5 of 42").
    repo.advance_base(
        "main",
        {
            "src/jobs/sync.py": _http_module(
                "Sync job.", ["requests"], [("sync_a", "requests"), ("sync_b", "requests")]
            ),
        },
        date=days_before(T, 2),
    )
    pr = repo.pull_request(number=number, base_branch="main", head_branch="feature/httpx-client")
    assert pr.merge_base == fork
    return Fixture(
        "f5_1_requests_to_httpx",
        repo,
        pr,
        facts={
            "rule_file": "AGENTS.md",
            "rule_line": 9,
            "rule_text": F5_1_RULE,
            "recognized_rules": 9,  # AC-F6.7
            "base_overall": (3, 40),
            "head_overall": (0, 40),  # following, relevant
            "base_recent": (2, 5),  # AC-F5.1: 5 recent sites, 2 requests (40%)
            "base_verdict": "Contested",
            "head_verdict": "Stale",
            "case": "made-stale-by-code",
            "causing_file": "src/api/client.py",
            "comments": 1,
            "rules_changed": 1,
            "rules_unchanged": 8,  # AC-F6.7 count line
            "suggested_text": "Use httpx for HTTP calls",  # AC-F6.3 #7 / F6.7
            "window_end": T.isoformat(),
            "window_days": 90,
            "base_tip_only_sites": {"src/jobs/sync.py": 2},  # must never be counted
        },
        choices={
            "other_8_rules": "AC-F6.7 says 9 rules but names only line 9; lines 1-8 are the "
            "8 other SPEC canonical sentences above (no sites -> unchanged)",
            "site_files": "40 sites split client 10 / users 10 / payments 10 / search 10",
            "imports": "`import requests`/`import httpx` lines are assumed not to be sites "
            "(snapshot says 'call sites'); the PR drops `import requests`",
            "dates": "old sites T-200d, recent sites T-30d, PR head T, base advance T-2d",
        },
    )


f5_1 = f5_1_requests_to_httpx


# ---------------------------------------------------------------------------- AC-F4.15
LOGGING_RULE = "Use logging, not print."
F4_15_VARIANTS = (
    "future_dated_commit",
    "head_1971",
    "parent_newer_than_child",
    "merge_older_than_side",
)
FORGED_FUTURE = _dt.datetime(2099, 1, 1, tzinfo=_dt.UTC)
FORGED_PAST = _dt.datetime(1971, 1, 1, tzinfo=_dt.UTC)


def _py(lines: list[str]) -> str:
    return (
        '"""Fixture module."""\nimport logging\n\nlogger = logging.getLogger(__name__)\n\n\n'
        + "".join(f"{ln}\n" for ln in lines)
    )


def _logger_lines(prefix: str, n: int) -> list[str]:
    return [f'logger.info("{prefix} {k}")' for k in range(1, n + 1)]


def _print_lines(prefix: str, n: int) -> list[str]:
    return [f'print("{prefix} {k}")' for k in range(1, n + 1)]


PY_HEADER_LINES = 6  # lines before the first site in _py()


def f4_15_forged_dates(
    root: Path, variant: str = "future_dated_commit", *, number: int = 1
) -> Fixture:
    """AC-F4.15 forged committer dates, plus the CR S4 out-of-order-topology variants.

    `facts["recent"]` / `facts["not_recent"]` map file -> site line numbers at the PR head,
    labeled from the AC text (and DESIGN §10 S4 for the S4 variants).
    """
    if variant not in F4_15_VARIANTS:
        raise ValueError(variant)
    repo = GitRepo.init(root / f"f4_15_{variant}")
    repo.commit_files(
        "initial",
        {"AGENTS.md": f"- {LOGGING_RULE}\n", "src/app.py": _py(_logger_lines("app", 10))},
        date=days_before(T, 200),
    )
    repo.start_pr_branch("feature", "main")
    facts: dict[str, Any] = {"rule_line": 1, "rule_text": LOGGING_RULE}
    first = PY_HEADER_LINES + 1
    head_date = T
    if variant == "future_dated_commit":
        # An earlier PR commit, committer date 2099-01-01, adds 3 relevant sites.
        repo.commit_files(
            "forged future date",
            {"src/feature.py": _py(_print_lines("f", 3))},
            date=FORGED_FUTURE,
            author_date=days_before(T, 5),
        )
        repo.commit_files(
            "head, dated normally",
            {"src/feature.py": _py(_print_lines("f", 3) + _logger_lines("h", 2))},
            date=T,
        )
        facts["recent"] = {"src/feature.py": [first + 3, first + 4]}
        facts["not_recent"] = {
            "src/feature.py": [first, first + 1, first + 2],
            "src/app.py": list(range(first, first + 10)),
        }
        facts["forged_sites"] = 3
    elif variant == "head_1971":
        repo.commit_files(
            "normal commit", {"src/feature.py": _py(_print_lines("f", 3))}, date=days_before(T, 5)
        )
        head_date = FORGED_PAST
        repo.commit_files(
            "head with forged 1971 date",
            {"src/feature.py": _py(_print_lines("f", 3) + _logger_lines("h", 2))},
            date=FORGED_PAST,
        )
        # Window [1970-10-03, 1971-01-01]: only the head's own lines fall inside (end inclusive).
        facts["recent"] = {"src/feature.py": [first + 3, first + 4]}
        facts["not_recent"] = {"src/feature.py": [first, first + 1, first + 2]}
    elif variant == "parent_newer_than_child":
        repo.commit_files(
            "p1 (T-10d)", {"src/feature.py": _py(_print_lines("a", 2))}, date=days_before(T, 10)
        )
        repo.commit_files(
            "p2 (T-100d, older than its parent)",
            {"src/feature.py": _py(_print_lines("a", 2) + _print_lines("b", 2))},
            date=days_before(T, 100),
        )
        repo.commit_files(
            "p3 head",
            {
                "src/feature.py": _py(
                    _print_lines("a", 2) + _print_lines("b", 2) + _logger_lines("c", 2)
                )
            },
            date=T,
        )
        facts["recent"] = {"src/feature.py": [first, first + 1, first + 4, first + 5]}
        facts["not_recent"] = {"src/feature.py": [first + 2, first + 3]}
    else:  # merge_older_than_side
        repo.commit_files(
            "f1 (T-15d)", {"src/feature.py": _py(_logger_lines("f", 1))}, date=days_before(T, 15)
        )
        repo.git("checkout", "-q", "-b", "side", "HEAD~1")
        repo.commit_files(
            "s1 (T-10d)", {"src/side.py": _py(_print_lines("s", 3))}, date=days_before(T, 10)
        )
        repo.checkout("feature")
        repo.merge("side", date=days_before(T, 120), message="merge side (dated T-120d)")
        repo.commit_files(
            "head", {"src/feature.py": _py(_logger_lines("f", 1) + _logger_lines("h", 2))}, date=T
        )
        # AC-F4.1: lines brought in by a merge take the merge commit's date (T-120d).
        facts["recent"] = {"src/feature.py": [first, first + 1, first + 2]}
        facts["not_recent"] = {"src/side.py": [first, first + 1, first + 2]}
    repo.advance_base("main", {"docs/notes.md": "base moved on\n"}, date=days_before(T, 3))
    pr = repo.pull_request(number=number, base_branch="main", head_branch="feature")
    facts.update({"anchor": head_date.isoformat(), "window_days": 90, "internal_errors": 0})
    return Fixture(
        f"f4_15_{variant}",
        repo,
        pr,
        facts=facts,
        choices={
            "rule_and_sites": "AC-F4.15 names no rule; 'Use logging, not print.' with 10 old "
            "logger sites in src/app.py; the 3 forged sites are print()",
            "author_date": "forged commit's author date is T-5d (AC forges the committer date)",
        },
    )


# ---------------------------------------------------------------------------- AC-F4.11
F4_11_VARIANTS = ("pr_head_in_clone", "merge_commit_only")


def f4_11_shallow_clone(
    root: Path, variant: str = "pr_head_in_clone", *, head_config: bool = False, number: int = 7
) -> Fixture:
    """AC-F4.11 / F4.12: a `fetch-depth: 1` checkout, head-only report.

    pr_head_in_clone: the clone holds only the PR head commit.
    merge_commit_only: the clone holds only GitHub's refs/pull/N/merge commit (PR head absent).
    The base tip has a commit after the merge base that changes the logging verdict, so the two
    variants analyze trees with different verdicts (and must name different SHAs).
    """
    if variant not in F4_11_VARIANTS:
        raise ValueError(variant)
    origin = GitRepo.init(root / f"f4_11_origin_{variant}")
    origin.commit_files(
        "initial",
        {
            "AGENTS.md": f"- {LOGGING_RULE}\n- Use requests for HTTP calls.\n",
            "src/app.py": _py(_logger_lines("app", 1) + _print_lines("app", 9)),  # 10% -> Stale
            "src/http.py": _http_module(
                "HTTP.",
                ["httpx", "requests"],
                [(f"r{k}", "requests") for k in range(3)] + [(f"h{k}", "httpx") for k in range(7)],
            ),  # 30%
        },
        date=days_before(T, 200),
    )
    origin.start_pr_branch("feature", "main")
    pr_files = {"src/feature.py": _py(_print_lines("feat", 1))}
    if head_config:
        pr_files[".conventiondrift.yml"] = (
            "version: 1\nthresholds:\n  stale: { overall: 40, recent: 40 }\n"
        )
    origin.commit_files("PR change", pr_files, date=T)
    origin.advance_base(
        "main", {"src/base_extra.py": _py(_logger_lines("base", 12))}, date=days_before(T, 2)
    )
    pr = origin.pull_request(number=number, base_branch="main", head_branch="feature")
    pr = origin.github_merge_commit(pr, date=T + _dt.timedelta(hours=1))
    ref = "refs/heads/feature" if variant == "pr_head_in_clone" else f"refs/pull/{number}/merge"
    clone = origin.shallow_clone(root / f"f4_11_checkout_{variant}", ref, depth=1)
    analyzed = pr.head if variant == "pr_head_in_clone" else pr.merge_commit
    event = pr.write_event(root / f"f4_11_event_{variant}.json")
    # Head-only verdicts use overall adherence only (AC-F4.11, F4.12).
    if variant == "pr_head_in_clone":
        logging_counts, logging_verdict = (1, 11), "Stale"  # app.py 1/10 + feature 0/1
    else:
        logging_counts, logging_verdict = (13, 23), "Contested"  # + base_extra 12 loggers
    http_verdict = "Stale" if head_config else "Contested"  # 30% vs stale.overall 40 / 20
    return Fixture(
        f"f4_11_{variant}",
        origin,
        pr,
        checkout=clone,
        event_path=event,
        facts={
            "analyzed_sha": analyzed,
            "analyzed_is": "PR head" if variant == "pr_head_in_clone" else "checked-out commit",
            "github_sha": pr.merge_commit,
            "summary_contains": ["fetch-depth: 0"],
            "comments": 0,
            "annotations": 0,
            "exit_code_every_fail_on": 0,
            "recent": "unavailable",
            "verdicts": {
                "AGENTS.md:1": (logging_verdict, logging_counts),
                "AGENTS.md:2": (http_verdict, (3, 10)),
            },
            "policy_from": "analyzed commit",
            "head_config": head_config,
        },
        choices={
            "rules": "AC-F4.11 names none; F4.12's 10%-Stale and 30%-Contested shapes are used",
            "merge_commit": "refs/pull/N/merge = (base tip, PR head), dated T+1h like GitHub's",
            "head_config": "optional PR-head config stale 40/40 to show policy comes from the "
            "analyzed commit (both variants contain it, base tip does not)",
        },
    )


# ---------------------------------------------------------------------------- AC-F3.12
F3_12_TEST_FILE_VARIANTS = {
    None: {},
    "root_conftest": {},  # the AC's conftest.py is already at the root
    "test_star": {"src/test_helpers.py": "test_*.py"},
    "star_test": {"src/helpers_test.py": "*_test.py"},
    "nested_pkg_tests": {"src/pkg/tests/helpers.py": "nested tests/ dir"},
    "nested_conftest": {"src/pkg/conftest.py": "nested conftest.py"},
}


def f3_12_script_contexts(root: Path, variant: str | None = None) -> Fixture:
    """AC-F3.12: print() in tests/scripts/bin/__main__/console-script modules is not a site.

    Relevant sites = 5 (the logger calls in src/lib.py), with or without the CR B2 variants.
    """
    if variant not in F3_12_TEST_FILE_VARIANTS:
        raise ValueError(variant)
    repo = GitRepo.init(root / f"f3_12_{variant or 'base'}")
    files = {
        "AGENTS.md": f"- {LOGGING_RULE}\n",
        "tests/test_x.py": 'def test_x() -> None:\n    print("in a test")\n',
        "conftest.py": 'print("conftest")\n',
        "scripts/run.py": 'print("script")\n',
        "bin/tool.py": 'print("bin tool")\n',
        "cli.py": (
            'def main() -> None:\n    print("cli main")\n\n\n'
            'if __name__ == "__main__":\n    print("starting")\n    main()\n'
        ),
        "pyproject.toml": (
            '[project]\nname = "mytool"\nversion = "0.0.0"\n\n'
            '[project.scripts]\nmytool = "mytool.entry:main"\n'
        ),
        "src/mytool/__init__.py": "",
        "src/mytool/entry.py": 'def main() -> None:\n    print("console script")\n',
        "src/lib.py": _py(_logger_lines("lib", 5)),
    }
    for path in F3_12_TEST_FILE_VARIANTS[variant]:
        files[path] = 'print("test-like file")\n'
    repo.commit_files("fixture", files, date=days_before(T, 10))
    print_files = sorted(p for p in files if p.endswith(".py") and "print(" in files[p])
    return Fixture(
        f"f3_12_{variant or 'base'}",
        repo,
        None,
        facts={
            "rule_text": LOGGING_RULE,
            "relevant_sites": 5,
            "following": 5,
            "contradicting": 0,
            "adherence": 100.0,
            "site_files": ["src/lib.py"],
            "print_files_not_sites": print_files,
            "console_script_module": "src/mytool/entry.py",
        },
        choices={
            "cli_prints": "cli.py has a print() in a function and in the __main__ block; the AC "
            "says none of its prints are sites, i.e. the whole file is a script",
            "console_script": "[project.scripts] mytool = 'mytool.entry:main' resolved to "
            "src/mytool/entry.py (DESIGN §12 A-4)",
            "conftest": "AC says `conftest.py` without a folder; placed at the root",
        },
    )
