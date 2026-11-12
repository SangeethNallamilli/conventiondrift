# CI helper scripts (T-003)

**Owner:** Release / DevOps.

These scripts are invoked by `.github/workflows/ci.yml`. They are not part of
the shipped package and must not be imported by `src/`.

## Release / vendor checks

PR #12 (`tests/release`) is on `main`. The scripts/ci vendor and import
fallbacks are no longer invoked by CI.

- The fast, offline `test` job runs the whole `tests/` tree under coverage,
  with the TE's default deselection (`-m "not network"`). That includes
  import-resolution, wheel-contents, the traceability tool tests, and
  `tests/security` when present (D-TL-19: Windows legs must run the SR-013
  PATH-hijack tests).
- The network-enabled `vendor-network` job always runs
  `pytest -m network tests/release` so `test_vendor_manifest` can fetch the
  pinned PyYAML 6.0.3 sdist.

`check_vendor.py` and `check_import_resolution.py` are kept in this tree but
are unused by CI. `tests/release` already covers sdist re-extract, the
SR-011 `cyaml.py` / `_yaml*` ban, MANIFEST equality, decoy-`yaml` import
resolution, no-libyaml probes, and wheel vendor contents. The scripts still
have two extras the TE tests do not spell out separately: Debian
`sitecustomize` handling in isolated-mode import resolution, and treating
`yaml/__pycache__` as a banned extra in the vendor tree. CI checkouts are
clean, and those extras are not invoked as a fallback.

Ruff excludes `src/conventiondrift/_vendor/`, so the S506 unsafe-loader lint
covers only our own code.

`check_no_pypi_yaml.py` is an assertion on the test, lint, and
vendor-network jobs: `importlib.util.find_spec('yaml')` /
`find_spec('yaml_ft')` must not resolve to a top-level install outside the
vendored package. PyPI PyYAML and pyyaml-ft are allowed only in the mutation
job (via libcst).

`install_git_min.py` builds the Tech Lead's minimum Git (2.30.9, D-TL-18)
from the kernel.org tarball. The version, tarball sha256, and signer
fingerprint are job-level env vars (`GIT_MIN_VERSION`, `GIT_MIN_SHA256`,
`GIT_MIN_SIGNER_FPR`) in the `git-minimum` job. The script imports only the
pinned key in `scripts/ci/keys/kernelorg-autosigner.asc` into a temporary
`GNUPGHOME`, requires a `gpg --status-fd` `VALIDSIG` matching that
fingerprint, then checks the `sha256sums.asc` line and the tarball hash.
There is no keyserver fetch at runtime. See `scripts/ci/keys/README.md`.

`check_mutation.py` runs mutmut 3.8.1 from the separate hashed lock
`requirements/mutation.txt` and enforces GATES.md (overall ≥80%; critical
modules ≥90% when present). That lock is a new dependency and needs Security
Review. The job runs on pull requests and on pushes to `main`. Before
mutmut, and again at pytest session start inside the mutated tree
(`-p mutation_yaml_guard`), `check_mutation_yaml.py` requires that
conventiondrift's yaml import resolves under `_vendor/yaml/` and that no
`_yaml` / `cyaml` module is in `sys.modules`.
