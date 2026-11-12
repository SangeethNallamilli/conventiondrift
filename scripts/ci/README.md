# CI helper scripts (T-003)

**Owner:** Release / DevOps.

These scripts are invoked by `.github/workflows/ci.yml`. They are not part of
the shipped package and must not be imported by `src/`.

## Release / vendor checks

When `tests/release/test_vendor_manifest.py` is on the tree (PR #12,
`te/t004-vendor-release-tests`):

- The fast, offline `test` job runs the whole `tests/` tree under coverage,
  with the TE's default deselection (`-m "not network"` once that marker is
  on the tree). That includes import-resolution, wheel-contents, the
  traceability tool tests, and `tests/security` when present (D-TL-19:
  Windows legs must run the SR-013 PATH-hijack tests).
- The network-enabled `vendor-network` job runs
  `pytest -m network tests/release` so `test_vendor_manifest` can fetch the
  pinned PyYAML 6.0.3 sdist.

Until PR #12 is on `main`, `vendor-network` falls back to `check_vendor.py`
and `check_import_resolution.py` here so the checks still exist. Once the TE
tests are on `main`, the fallback is unused; the Test Engineer owns the
assertions under `tests/release/` (they can later replace or drop these
scripts).

Ruff excludes `src/conventiondrift/_vendor/`, so the S506 unsafe-loader lint
covers only our own code. The vendored tree is checked by the TE tests or, as
a fallback, by `check_vendor.py` (byte-identity, MANIFEST, and a ban on
`cyaml.py` / `_yaml*`).

`install_git_min.py` builds the Tech Lead's minimum Git (currently 2.30.9,
D-TL-18) from the kernel.org tarball. The version and sha256 are job-level
env vars (`GIT_MIN_VERSION`, `GIT_MIN_SHA256`) in the `git-minimum` job,
verified against kernel.org `sha256sums.asc`.

`check_mutation.py` runs mutmut 3.8.1 from the separate hashed lock
`requirements/mutation.txt` and enforces GATES.md (overall ≥80%; critical
modules ≥90% when present). That lock is a new dependency and needs Security
Review. The job runs on pull requests and on pushes to `main`.
