# CI helper scripts (T-003)

**Owner:** Release / DevOps.

These scripts are invoked by `.github/workflows/ci.yml`. They are not part of
the shipped package and must not be imported by `src/`.

The vendor re-extract and import-resolution checks live here because
`tests/release/` does not yet have TE-owned tests for SEC-T16 /
`test_sec_t16_vendor_manifest_hash_mismatch_fails` and
`test_sec_t16_imports_resolve_only_stdlib_pkg_vendor`. The Test Engineer can
move the assertions into `tests/release/` later; this directory should then
call those tests rather than duplicate them.

Ruff excludes `src/conventiondrift/_vendor/`, so the S506 unsafe-loader lint
covers only our own code. The vendored tree is checked by `check_vendor.py`
instead (byte-identity, MANIFEST, and a ban on `cyaml.py` / `_yaml*`).
