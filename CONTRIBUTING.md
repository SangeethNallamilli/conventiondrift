# Contributing to conventiondrift

Thanks for helping. This guide covers how to set up the project, run the tests, and get a change merged.

## Before you start

- **Bugs and false warnings:** open an issue with the matching template. A false warning is the bug we care about most, so it has its own template.
- **New checkers:** open a "New checker request" issue first, so we can agree on what counts as following and breaking the rule before you write code.
- **Security problems:** never in a public issue. See [SECURITY.md](SECURITY.md).
- **First contribution?** Look for issues labeled `good first issue`.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by:` line. It certifies that you wrote the change or have the right to submit it under the project's license, as described in the [Developer Certificate of Origin](https://developercertificate.org/). We don't ask for a contributor license agreement (CLA).

Add the line automatically with `-s`:

```sh
git commit -s -m "Describe your change"
```

To sign off commits you already made on your branch:

```sh
git rebase --signoff main
```

A CI check fails any pull request that has a commit without a sign-off.

## Set up a development environment

You need Python 3.11 or newer and git. The commands below are for macOS and Linux.

Clone the repository, then create a virtual environment and install the pinned development tools. Every dependency is pinned with a hash, so `pip` refuses anything that doesn't match.

```sh
git clone https://github.com/SangeethNallamilli/conventiondrift.git
cd conventiondrift
python3 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r requirements/build.txt -r requirements/dev.txt
.venv/bin/pip install --no-deps --no-build-isolation -e .
```

Check that it worked:

```sh
.venv/bin/conventiondrift --version
```

## Run the checks

Lint and type-check the code:

```sh
.venv/bin/ruff check src
.venv/bin/mypy --strict src
```

Run the tests:

```sh
.venv/bin/pytest
```

<!-- TW-OPEN: pytest collects no tests until T-044 lands; re-test this section then, and add coverage and mutation commands from T-003. -->

## How the project is organized

- `src/conventiondrift/`: the package. `cli.py` is the command-line entry point.
- `src/conventiondrift/_vendor/`: third-party code copied in so the tool has no runtime dependencies. Don't edit it by hand.
- `tests/`: the test suite, split by kind (`unit/`, `spec/`, `snapshot/`, `property/`, `security/`, `e2e/` and others).
- `requirements/`: the pinned, hashed development and build dependencies. The `.in` files list what we want; the `.txt` files are the locked versions.

For how and why it's built this way, read [the design](docs/design/DESIGN.md) and the architecture decision records (ADRs) in [`docs/design/`](docs/design/).

<!-- TW-OPEN: confirm the exact file paths under docs/design/ once they're published, then check the links resolve. -->

## Make a change

1. Open or pick an issue, and say in it that you're working on it.
2. Branch from `main`, keep the change focused, and add tests for it.
3. If the change is something users will notice, add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md), written for users.
4. Sign off every commit, then open a pull request that links the issue.
5. A maintainer reviews every pull request. CI must pass before it can merge.

## Code of conduct

Everyone taking part follows our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
