# CI helper scripts (T-003)

**Owner:** Release / DevOps.

These scripts are invoked by `.github/workflows/ci.yml`. They are not part of
the shipped package and must not be imported by `src/`.

## Release / vendor checks

When `tests/release/test_vendor_manifest.py` is on the tree (PR #12,
`te/t004-vendor-release-tests`), the `release` job runs `pytest tests/release`.
That includes `test_vendor_manifest`, which needs network access to fetch the
pinned PyYAML 6.0.3 sdist, plus the import-resolution and wheel-contents tests.
Those tests are not run in an offline job.

Until PR #12 is on `main`, the same job falls back to `check_vendor.py` and
`check_import_resolution.py` here so the checks still exist. Once the TE tests
are on `main`, the fallback is unused; the Test Engineer owns the assertions
under `tests/release/` (they can later replace or drop these scripts).

Ruff excludes `src/conventiondrift/_vendor/`, so the S506 unsafe-loader lint
covers only our own code. The vendored tree is checked by the TE tests or, as
a fallback, by `check_vendor.py` (byte-identity, MANIFEST, and a ban on
`cyaml.py` / `_yaml*`).

`install_git_min.py` builds the Architect's minimum Git 2.24.4 from the
kernel.org tarball, pinned by the published sha256.
