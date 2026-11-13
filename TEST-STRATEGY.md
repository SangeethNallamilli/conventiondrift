# TEST-STRATEGY.md: conventiondrift v1

**Owner:** Test Engineer · **Status:** working rules, 2026-11-13 (America/New_York).
The per-AC map is TRACEABILITY.md (team docs; not yet in this repository).
The historical spec-gate review lives in the team copy of this file.

## 1. Test levels

| Level | Meaning | Where |
|---|---|---|
| unit / spec | In-process component tests, or CLI / `run(argv, env)` against a fixture repo. Expected values come from SPEC.md and INTERFACES.md, not from the implementation. | every PR, fast stage |
| integration | Multi-component runs on fixture repos (real git, controlled dates) | every PR, fast stage |
| e2e | The real Action on GitHub-hosted runners in the TE sandbox (Set T) | sandbox workflow |
| property | Hypothesis tests; fixed seed in CI, random seeds nightly | fast stage + nightly |
| snapshot | Raw comment/summary Markdown compared byte-for-byte with `tests/snapshot/approved/`. Changes need PM sign-off (AC-F6.7). | fast stage |
| regression | Every closed bug has a test that names the issue | every PR |
| security | Joint TE+SR tests under `tests/security/`, including PATH-hijack cases | every PR; also the required Windows leg |

## 2. Coverage gates (GATES.md; do not lower)

- Whole package, fast stage: **≥ 90% lines**, **≥ 85% branches**.
- A-2 critical modules: **≥ 95% branch coverage** and **≥ 90% mutation score**. The paths are rule extraction, checker-to-rule mapping (including each checker's `match_rule` under A-2's working reading), the verdict engine, base/head comparison, and text escaping: `rules/extract.py`, `rules/mapping.py`, every `checkers/<id>/match.py`, `verdicts.py`, `compare.py`, `render/escape.py`.

## 3. Mutation testing (T-003 mutmut gate)

- Whole package: mutation score **≥ 80%** (killed ÷ (killed + survived)). Equivalent mutants are excluded only with a logged justification.
- A-2 critical modules: **≥ 90%**.
- Mutate each class separately (D-TL-25). A test that kills several rules at once is not enough if one of those rules can be deleted on its own and still survive.

## 4. D-TL-25 (negative tests and oracles)

- Expected answers are written from the spec or the locked interface, never from the code's own predicate.
- Pin the code's category or normalization constants to the spec's literal lists (an assertion that the two are equal is enough).
- Negative-test parameters are built from that same constant, or the test asserts that it covers the constant.
- Mutate each class separately, as in §3.

## 5. Python 3.11 and `os.name` patching

Never construct a `pathlib.Path` (or a platform-specific `Path` subclass) while `os.name` is patched to `"nt"`. On Python 3.11 that raises an internal pytest error and stops the whole run. Build Windows paths beforehand (`PureWindowsPath` or strings), and restore `os.name` in `try`/`finally` *before* any asserts.

## 6. Windows leg (D-TL-19)

A required `windows-latest` job must run `tests/security`, including the PATH-hijack tests, and be green before T-007 (and later the SR-013 stack) merges. Tests that are meaningful only on Windows must actually run there; a skip under `CI`/`GITHUB_ACTIONS` is a failure of that gate, not a pass.

T-008 behaviour tests that can be set up on Windows run there (sentinels, process-tree kills, `core.symlinks=true`, planted orderfile/graft symlinks). A test may be skipped on an OS only if its precondition cannot be set up there (D-PM-21, AC-N5.2). The platform skip register is TRACEABILITY.md §5.7 in the team docs; after the T-008 variants, the T-008 Windows / old-git skips are only the five legitimate ones listed there, plus the leftover `test_tree_keeps_ntfs_illegal_names` row (colon, newline, and a raw 0xff byte). Distinct additional rows cover `test_real_non_utf8_tree_name_is_unsupported` (non-Linux: the fixture needs a file system that can store a raw `0xff` name) and `test_non_executable_posix_git_is_skipped_for_a_later_folder` (Windows has no execute bit; the Windows counterpart already runs).

## 7. xfail policy

- Use `pytest.mark.xfail(strict=True, reason="needs T-NNN …")`, naming the owning task.
- Strict is required: if the behaviour lands and the marker is left in place, the suite fails XPASS and the marker must be removed.
- Do not skip, weaken, or delete a test to make it pass. Behaviour that has not landed yet is a strict xfail, not a skip, except for an optional `pytest.importorskip` when a whole module is absent (this repository prefers a strict xfail on `ImportError` naming the owning task).
