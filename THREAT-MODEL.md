# THREAT-MODEL.md: conventiondrift v1

**Owner:** Security Reviewer · **Status:** v1.0, 2026-11-12. Aligned with the locked design (DESIGN.md 1.0, INTERFACES.md 1.0, ADRs 0001-0005 Accepted, D-TL-08) and SPEC rev 2 through SC-2.45. Revised whenever a stable contract changes.
**Inputs:** SPEC.md §5 (N3), §9, DECISIONS.md D-PM-05, D-PM-06.

Severity scale (from the Security Reviewer role): **Critical** blocks everything · **High** blocks merge and release · **Medium** must be fixed before release · **Low** logged for later.
Likelihood/impact: H / M / L. Each threat lists its required defense and the test that proves it. "NEW TEST" means no AC covers it yet; the Test Engineer and I will write it.

## 1. What's valuable (assets)

| ID | Asset | Why it matters |
|---|---|---|
| A1 | The user's CI runner and job | Code execution there can tamper with the PR, other steps and artifacts. |
| A2 | `GITHUB_TOKEN` (`contents: read`, `pull-requests: write`, `security-events: write`) | Write access to PR comments and code scanning on the user's repo. |
| A3 | Integrity of results (comment, annotations, summary, SARIF, outputs, exit status) | Users and agents act on them; `fail-on` turns them into a merge gate. |
| A4 | The PR conversation and the people in it | The comment is posted under the repo's bot identity; abuse lands on maintainers. |
| A5 | Files outside the analyzed scope (runner FS, `/etc`, home dir) | Must never be read, echoed or written. |
| A6 | The project's release channel (PyPI package, Action tags, Marketplace listing, release signing) | Compromise reaches every user at once. |
| A7 | Developer machines running the CLI on a cloned, possibly hostile repo | Same no-execution guarantee as the Action. |

## 2. Who could attack

| ID | Attacker | Capability |
|---|---|---|
| X1 | Fork-PR author | Controls every file at PR head: instruction files, `.py`, manifests, config, file names, symlinks, git history of the head branch, PR title/branch name. Token is read-only. |
| X2 | Same-repo contributor with push access | Everything X1 can, but the run gets a **write** token. |
| X3 | Any GitHub user who can comment on the PR | Controls other comment bodies the Action reads to find its sticky comment. |
| X4 | Compromised or squatted dependency / third-party action / setup-time download | Code runs inside the Action with the token. |
| X5 | Attacker impersonating the project | Squatted PyPI name, lookalike Action, hijacked or re-pointed `v1` tag. |
| X6 | Insider/CI compromise of the project repo | Tampered build or publishing credentials. |

## 3. Where they get in (entry points)

From SPEC.md §9.2: E1 instruction files · E2 `.py` files · E3 manifests and lockfiles (incl. `setup.py`/`setup.cfg` as text) · E4 packaging entry-point metadata · E5 config file (read from PR **head**) · E6 Action inputs · E7 git metadata and history · E8 event payload · E9 runner env vars and file paths (`GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`) · E10 existing PR comments · E11 file and folder **names** (not listed in §9.2; added here) · E12 the tool's own install path (dependencies, setup-time fetch, Action metadata).

## 4. Threats, ranking and required defenses

| ID | Threat | Entry | L | I | Sev if undefended | Required defense | Proven by |
|---|---|---|---|---|---|---|---|
| T-01 | Repository code is imported, executed or evaluated (import for analysis, `setup.py`, `conftest.py`, entry-point resolution via `importlib`, `pip`/build backends to read metadata) | E2–E4 | M | H | Critical | Parse only: `ast.parse` / TOML / text reads. Never `import`, `exec`, `eval`, `compile` to code objects that run, `runpy`, `pip`, `setuptools`, `importlib.metadata` on the repo, or any build backend. Entry points read from `pyproject.toml` / `setup.cfg` text only; `setup.py` read as AST without executing. | AC-N3.1, plus a static CI check banning those calls in the source (NEW TEST) |
| T-02 | Unsafe deserialization of config/manifest (e.g. YAML with arbitrary object tags) | E3, E5 | M | H | Critical | YAML parsed with a safe loader only (no Python object tags); TOML with the stdlib parser. | NEW TEST: config with `!!python/object` tag is rejected, no side effect |
| T-03 | Workflow-command / output injection: rule text, file names or messages containing newlines, `::`, `%` inject runner commands (`::add-mask::`, `::stop-commands::`, fake annotations) or extra step outputs via `GITHUB_OUTPUT` | E1, E2, E11 → E9 | H | H | High | Escape all annotation data and properties per GitHub's rules (`%`→`%25`, `\r`→`%0D`, `\n`→`%0A`, and `:`/`,` in properties). Write outputs with a random, per-run heredoc delimiter that is checked not to appear in the value. Prefer writing via the files over stdout commands. | AC-N3.13 |
| T-04 | Markdown/HTML injection in comment, summary or SARIF (mentions, images, links, tracking pixels, fake "resolved" text) via rule text **or file paths** | E1, E11 | H | M | High | Escape rule text and every path everywhere shown. Covers file names too, not only rule text. | AC-N3.10 (rule text and paths) |
| T-05 | Script injection in the Action's own metadata: `${{ github.head_ref }}`, PR title, or inputs interpolated into `run:` shell | E6, E8 | M | H | Critical | `action.yml` never interpolates `${{ }}` expressions into `run:` scripts; inputs and event data pass via `env:` and are quoted. | AC-N3.14, plus a static check of `action.yml` (security test) |
| T-06 | `pull_request_target` or other privileged trigger runs PR-head code with a write token | E8 | M | H | Critical | Refuse under `pull_request_target`; no project workflow uses it; never check out or read PR head under any privileged trigger. | AC-N3.5 |
| T-07 | Path traversal / out-of-repo reads via `paths`, `config`, `exclude`, config ignore entries, absolute paths, Windows `..\` and drive paths | E5, E6 | H | H | High | Canonicalize every path against the repo root; reject anything outside it (including the `config` input itself) and list it as rejected. | AC-N3.8 |
| T-08 | Symlink escapes: instruction file, `.py`, config file, or a **parent folder** symlinked outside the repo | E1, E2, E5, E11 | H | H | High | Never follow symlinks at any level (files and directories), including the config file. Read via `lstat` and `O_NOFOLLOW`-style checks; also guard against a path component being a symlink. | AC-N3.9 |
| T-09 | Resource exhaustion / DoS: huge files, deeply nested Python (parser recursion), YAML alias bombs, ReDoS in rule extraction, thousands of instruction files or rules, huge history | E1–E5, E7 | H | M | Medium | Size limits on **every** file read (instruction, `.py`, config, manifests, lockfiles), not only the two in AC-N3.7; catch parser recursion/memory errors and skip the file; linear-time regexes only (no nested quantifiers on rule text) or a regex engine without backtracking; caps on instruction-file count and rules per file; bounded git history walk. Skips are listed, never crash. | AC-N3.7, AC-E.12, AC-E.14; NEW TESTS for nesting depth, YAML aliases, ReDoS strings, config/lockfile size |
| T-10 | Git used as an execution vector: hooks, `core.fsmonitor`, external diff, `textconv` drivers, `filter` drivers in an attacker-provided `.git` (CLI case) | E7 | L | H | Medium | Invoke git only for read-only plumbing, with `-c core.fsmonitor=false -c core.hooksPath=<empty> --no-ext-diff --no-textconv`, or read objects through a library that never runs drivers. | NEW TEST: repo whose `.git/config` sets fsmonitor/textconv to create a sentinel |
| T-11 | Policy bypass from PR head: since config and inline ignores are read from **head**, a PR can raise thresholds, disable a checker, or add an ignore marker to silence its own finding or pass `fail-on: new-stale` | E1, E5 | H | M | Medium | Resolved (D-PM-12): when `fail-on` is not `none`, all policy (config, thresholds, enabled checkers, ignores, inline ignores, config `fail-on`) comes from base; head changes are noted in the summary. | AC-F9.12–F9.15 |
| T-12 | Sticky-comment hijack: another user posts a comment containing the hidden marker, and the Action edits or trusts it | E10 | M | M | Medium | Identify the sticky comment by **author = the workflow token's bot identity AND marker**; never edit a comment by another author; never parse or render other comments' content. | NEW TEST: decoy comment by another user with the marker |
| T-13 | Token exposure: `GITHUB_TOKEN` printed in logs, error messages, summary, report or passed on a command line | A2 | L | H | Critical | Token only via env to the HTTP client; never logged, never in argv, scrubbed from exceptions; internal-error output has no file contents or headers. | AC-N4.2; NEW TEST: grep all outputs for the token value |
| T-14 | Network egress beyond GitHub API (telemetry, model calls, dependency resolution at runtime) | E12 | M | M | High | Only the GitHub API host at run time; no setup-time fetch (ADR-0002). | AC-F2.1, AC-N3.2, AC-R.7 |
| T-15 | Compromised or squatted dependency / unpinned action | E12, X4 | M | H | High | Every dependency vetted by the Security Reviewer before use; exact versions + hashes in a lockfile; third-party actions pinned to 40-char SHAs; dependency scan in CI. Keep runtime dependencies to the minimum. | AC-N3.11 |
| T-16 | Setup-time download replaced or tampered (mutable URL, unpinned `pip install`, Docker tag) | E12 | M | H | High | No setup fetch (ADR-0002): composite Action runs vendored source from the tagged tree on the runner's preinstalled Python ≥ 3.11; the only vendored library is PyYAML 6.0.3, hash-listed in `_vendor/MANIFEST` and re-verified in CI. | AC-N3.2 + NEW TEST verifying hash failure aborts |
| T-17 | Impersonation: squatted `conventiondrift` on PyPI, lookalike Action, mutable `v1` tag re-pointed | X5 | M | H | High | Reserve the PyPI name and Marketplace listing early; publish via PyPI trusted publishing only; protect release tags (tag protection / immutable releases); README shows a SHA-pinned usage example. | AC-N3.12, AC-R.9; release checklist |
| T-18 | Build or publishing compromise | X6 | L | H | High | Signed artifacts with provenance; publishing credentials scoped to the release job only; release job runs only from protected tags; minimal `permissions:` per workflow. | AC-N3.12 |
| T-19 | Fork PR causes a failure or a write attempt with a read-only token, or leaks base-repo data into a public fork context | X1 | H | L | Low | Detect fork; skip writes; never fail because of it. | AC-N3.6 |
| T-20 | `suggest-precedence` or the CLI writes to the repo or home dir | A5, A7 | L | M | Low | No writes except explicit output files in the workspace. | AC-F8.2 |
| T-21 | Forged git committer dates (any PR author controls them on their own commits) push sites into or out of the recent window to flip a verdict, e.g. Stale to Migrating to silence a finding | E7 | M | L | Low | Accept for v1 (the tool is advisory and silence is the safe direction), but the window anchor must come from the event payload's head SHA as the Architect proposes, never from wall clock or a merge commit; summary shows the anchor date. | AC-F4.14, AC-F4.15 (D-PM-14: forging can also make the forger's own PR warn, which harms only the forger) |
| T-22 | Test-only fault-injection hook (AC-F7.4, AC-N4.2) reachable in production, letting a PR force errors or alter results | E1, E5, E6, E9 | M | M | Medium | The hook must not be reachable through any Action input, config key, instruction-file content, file name, or environment variable read by the shipped Action. Preferred: injection only from the test harness in-process (monkeypatching or a test-only module not packaged in the wheel or Action). The released artifact must not contain it. | AC-N3.15 + I-2 packaging test (SR-001 resolved) |
| T-23 | On `pull_request`, the workflow file (and so the `fail-on` input and any env) comes from the PR itself; a contributor can weaken or remove the check in their own PR | E6 | M | M | Low (accepted, D-PM-12) | Outside the tool's control. Docs must tell users to make the check a **required status check** in branch protection and to protect `.github/workflows/` with CODEOWNERS review. | Docs gate (Technical Writer) |
| T-24 | Repository content or job environment hijacks the Python interpreter: a PR adds a root-level `conventiondrift/` package or a stdlib-shadowing module, or an earlier step sets `PYTHONPATH`/`PYTHONSTARTUP` | E1, E6 | M | H | Critical | Interpreter launched by absolute path with `-I` on an entry script in the Action's own tree, which adds only its own `src` to the import path; the tool-cache picker accepts only real `3.x.y` directories and never writes `GITHUB_ENV`/`GITHUB_PATH` (ADR-0002 Amendments 2-3). | SEC-SR004 (joint test), QA S-05 |
| T-25 | Resource exhaustion in scan mode: huge or deep trees, FIFOs or device files, many or pathological `.gitignore` patterns, quadratic line diffs | E1 | M | M | Medium | Files opened with no symlink following and checked as regular files on the open handle; special files skipped; walk entry and depth caps; `.gitignore` size and pattern caps with linear-time matching; per-file and per-run diff budgets (DESIGN §12 A-3). | SEC-T09 (joint tests) |
| T-26 | Duplicate-comment cleanup deletes or edits a comment it doesn't own, or a slow run overwrites a newer result | E10 | L | M | Medium | Deletes only on the current PR, only comments passing both identity checks (bot author and marker), never the kept lowest-id comment, at most 5 per run; body rewritten only if the run's head SHA is still the PR head; read-only tokens attempt no writes (INTERFACES I-3). | T-027 tests, QA concurrent-push check |

## 5. Security tightening of PM defaults (per D-PM-05 #12, "Security Reviewer may tighten")

- The 1 MiB limit stays for instruction files and `.py` files.
- **Added:** the same limit applies to manifests and lockfiles; the config file gets a **64 KiB** limit. Oversized files are skipped and listed with "size limit", never parsed.
- Caps on instruction-file count and rules per file: numbers to be proposed by the Architect against AC-N2.1 and confirmed here.

## 6. Spec-gate findings (for the Product Manager)

**Status (SPEC rev 2):** S-1, S-3, S-4, S-5, S-6 resolved by AC-F9.12–F9.15, AC-N3.7–N3.10, AC-N3.13–N3.15 and §9.2 items 11–12. S-2 resolved by ADR-0002 (Accepted). Remaining NEW TEST rows in §4 (T-01 static ban, T-02, T-09, T-10, T-12, T-13, T-16) are security tests owned by the Security Reviewer and Test Engineer in TRACEABILITY.md, not spec ACs.

- **S-1 (Medium): config and inline ignores come from PR head (T-11).** A PR can silence its own finding or loosen the `fail-on` gate. Options: (a) when `fail-on` is not `none`, read thresholds, enabled checkers and ignores from **base**, and report head changes in the summary; or (b) keep head, but always list config and ignore changes made in the PR in the summary and comment. I recommend (a). Needs a PM decision and an AC.
- **S-2 (resolved by ADR-0002): setup-time fetch (D-PM-06 #1).** My preference, in order: (1) no fetch at all, the Action ships everything it needs in the tagged repo; (2) a container image pinned by **digest**; (3) `pip install` of exact versions with `--require-hashes --no-deps` from a lockfile, from PyPI only. Any fetch must be named in the ADR and in AC-N3.2. Runtime dependency resolution is not acceptable.
- **S-3 (Medium): §9.2 inventory is missing file and folder names (E11)** as an attacker-controlled input. AC-N3.10's escaping should cover paths too.
- **S-4 (Medium): AC-N3.7 covers only instruction and `.py` files.** Extend to config, manifests and lockfiles (see §5).
- **S-5 (Medium): AC-N3.8/N3.9 should also cover the `config` input path, directory symlinks and a symlinked config file.**
- **S-6 (High if missed): no AC covers workflow-command / output injection (T-03) or script injection in `action.yml` (T-05).** Please add criteria, or let me and the Test Engineer own them as security tests in TRACEABILITY.md.

## 7. Open items

- Revise against DESIGN.md: components, trust boundaries, parsers chosen, git access method, dependency list.
- Caps (T-09, T-25) are set in DESIGN §12; the setup method (S-2) is settled by ADR-0002.
