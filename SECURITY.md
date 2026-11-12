# Security Policy

conventiondrift reads untrusted repository content on pull requests, so we take security reports seriously.

## Supported versions

| Version | Supported |
|---|---|
| Latest `0.x` minor release | Yes |
| Older releases | No; please upgrade |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's **"Report a vulnerability"** button on the repository's Security tab (GitHub private vulnerability reporting). Include:
- the affected version or commit,
- what an attacker can do, and under which trigger (fork PR, same-repo PR, CLI),
- a minimal reproduction (a repository or files, and the workflow used),
- any suggested fix, if you have one.

Never include real secrets or tokens in a report.

If the "Report a vulnerability" button isn't available, open a public issue with the **"Security contact request"** form and leave out every detail of the problem. A maintainer will reply with a private way to send the report.

## What to expect

- **Acknowledgement:** within 3 business days.
- **Triage and severity:** within 7 days, using Critical / High / Medium / Low as defined in THREAT-MODEL.md.
- **Fix target:** Critical within 7 days of triage, High within 30 days, Medium in the next release, Low as scheduled.
- We keep you updated at least every 14 days until it is resolved.
- We publish a GitHub Security Advisory with a CVE where applicable once a fixed release is available, and credit you unless you prefer otherwise.
- Please keep details private until the advisory is published, or until 90 days after your report, whichever comes first. We may ask to extend that for a complex fix.

## Scope

In scope: the conventiondrift Action, CLI, PyPI package, and the project's release and CI workflows. Examples: code execution from repository content, path traversal or symlink escapes, token exposure, workflow-command or output injection, comment content injection, supply-chain or release-integrity issues.

Out of scope: findings that require the attacker to already control the user's workflow file or runner; false positive or false negative verdicts (please use the false-positive issue template); vulnerabilities in GitHub itself.

## Our security design

See [THREAT-MODEL.md](THREAT-MODEL.md) for the threats we defend against and how each is tested.
