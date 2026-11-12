# CI helper scripts (T-003)

**Owner:** Release / DevOps.

These scripts are invoked by `.github/workflows/ci.yml`. They are not part of
the shipped package and must not be imported by `src/`.

## Release / vendor checks

When `tests/release/` is on the tree (PR #12, `te/t004-vendor-release-tests`):

- The fast, offline `test` job includes `tests/release` under the coverage
  run, with the TE's default deselection (`-m "not network"`), so
  import-resolution and wheel-contents tests are covered there.
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

`install_git_min.py` builds the Architect's minimum Git 2.24.4 from the
kernel.org tarball, pinned by the published sha256.
