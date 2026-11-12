#!/usr/bin/env python3
"""Approval-check gate (D-RD-01). Standard library only.

Every agent pushes, comments and reviews as one shared GitHub account, so
GitHub's own required reviews and CODEOWNERS approvals cannot tell roles
apart. Instead, reviewers record approvals as PR conversation comments:

    APPROVED-BY: <Role> @ <full 40-character head SHA>
    CHANGES-REQUESTED-BY: <Role>            (an "@ <sha>" suffix is optional)

This check proves that the required approvals were RECORDED for the exact
current head commit. It does NOT prove who posted them: anyone holding the
shared account can post any role's line. It catches process mistakes
(missing, stale or wrong-commit approvals, open change requests), not malice.

Rules (policy in .github/approval-policy.json, read from the PR BASE commit):
- An APPROVED-BY counts only if its SHA is exactly the PR's current head SHA
  (40 hex chars, case-insensitive). Short, mismatched or missing SHAs never
  count. There is no "posted after the last push" timing rule.
- A CHANGES-REQUESTED-BY from a role blocks until that role posts a
  counting APPROVED-BY (at the current head) in a LATER comment.
- Only comments whose author_association is in trusted_associations count
  (the repo is public).
- Lines must match exactly (surrounding whitespace allowed); quoted lines
  ("> ...") and lines inside ``` fences are ignored.
- Required roles: one of CR1/CR2 always; both CRs if an INTERFACES.md
  changes or additions+deletions exceed the threshold; Security Reviewer and
  Test Engineer by changed path (see the policy file).
- Process hint, not enforcement: the author role (an "Author-Role: <Role>"
  line in the PR body, else the branch prefix) is not counted as approving its
  own PR, and a substitute role is asked for instead. With one shared account
  this is a consistency check only. A PR with no determinable author role
  fails, so the hint can always be evaluated.

Exit codes: 0 all required approvals recorded, 1 not satisfied, 2 error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

API = "https://api.github.com"
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
LINE_RE = re.compile(
    r"^(?P<kind>APPROVED-BY|CHANGES-REQUESTED-BY):[ \t]*(?P<role>[^@\r\n]*?)"
    r"(?:[ \t]*@[ \t]*(?P<sha>\S+))?[ \t]*$"
)
AUTHOR_ROLE_RE = re.compile(r"^[ \t]*Author-Role:[ \t]*(?P<role>.+?)[ \t]*$", re.MULTILINE)


class CheckError(Exception):
    """Configuration or API problem (exit code 2)."""


# --------------------------------------------------------------------------
# Policy and role names


def norm_key(text: str) -> str:
    """Lowercase, collapse whitespace, and drop spaces around '/'."""
    text = " ".join(text.strip().split()).lower()
    return re.sub(r"\s*/\s*", "/", text)


@dataclass
class Policy:
    raw: dict[str, Any]
    roles: list[str] = field(default_factory=list)
    lookup: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> Policy:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CheckError(f"cannot read policy {path}: {exc}") from exc
        pol = cls(raw=raw, roles=list(raw["roles"]))
        for role in pol.roles:
            pol.lookup[norm_key(role)] = role
        for alias, role in raw.get("aliases", {}).items():
            if role not in pol.roles:
                raise CheckError(f"alias {alias!r} points at unknown role {role!r}")
            pol.lookup[norm_key(alias)] = role
        for key in ("branch_prefixes", "self_review_substitutes"):
            for k, role in raw.get(key, {}).items():
                for r in (role, k) if key == "self_review_substitutes" else (role,):
                    if r not in pol.roles:
                        raise CheckError(f"{key}: unknown role {r!r}")
        for r in raw["code_review"]["any_of"]:
            if r not in pol.roles:
                raise CheckError(f"code_review.any_of: unknown role {r!r}")
        for rule in raw.get("path_rules", []):
            if rule["role"] not in pol.roles:
                raise CheckError(f"path rule {rule.get('id')}: unknown role {rule['role']!r}")
        return pol

    def role(self, text: str) -> str | None:
        return self.lookup.get(norm_key(text))


# --------------------------------------------------------------------------
# Globs


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """'**' crosses '/', '*' and '?' stay inside one segment. '**/' may be empty."""
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def matches_any(path: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        if glob_to_regex(pat).match(path):
            return pat
    return None


# --------------------------------------------------------------------------
# Comment parsing


@dataclass
class Mark:
    kind: str  # "approve" | "changes"
    role: str
    sha: str | None
    order: int  # comment position (created_at order); later is larger
    created_at: str
    comment_id: int


def parse_comment(body: str) -> list[tuple[str, str, str | None]]:
    """Return (kind, raw_role, sha) for each structured line outside code fences."""
    found: list[tuple[str, str, str | None]] = []
    in_fence = False
    for raw_line in (body or "").splitlines():
        line = raw_line.strip()
        if line.startswith("```") or line.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = LINE_RE.match(line)
        if not m:
            continue
        kind = "approve" if m.group("kind") == "APPROVED-BY" else "changes"
        found.append((kind, m.group("role"), m.group("sha")))
    return found


def collect_marks(comments: list[dict[str, Any]], policy: Policy, notes: list[str]) -> list[Mark]:
    trusted = set(policy.raw.get("trusted_associations", []))
    ordered = sorted(comments, key=lambda c: (c.get("created_at") or "", c.get("id") or 0))
    marks: list[Mark] = []
    for order, c in enumerate(ordered):
        lines = parse_comment(c.get("body") or "")
        if not lines:
            continue
        assoc = c.get("author_association") or ""
        if assoc not in trusted:
            notes.append(
                f"ignored comment {c.get('id')}: author_association {assoc or '?'} is not trusted"
            )
            continue
        for kind, raw_role, sha in lines:
            role = policy.role(raw_role)
            if role is None:
                notes.append(f"ignored comment {c.get('id')}: unknown role {raw_role.strip()!r}")
                continue
            marks.append(Mark(kind, role, sha, order, c.get("created_at") or "", c.get("id") or 0))
    return marks


@dataclass
class RoleState:
    approved: bool = False  # a counting approval exists that is not superseded
    blocked: bool = False  # an open change request exists
    detail: str = ""


def role_states(marks: list[Mark], head_sha: str, notes: list[str]) -> dict[str, RoleState]:
    """Walk marks in comment order; a counting approval clears earlier change requests."""
    head = head_sha.lower()
    states: dict[str, RoleState] = {}
    for m in sorted(marks, key=lambda x: x.order):
        st = states.setdefault(m.role, RoleState())
        if m.kind == "changes":
            st.blocked = True
            st.approved = False
            st.detail = f"changes requested (comment {m.comment_id}, {m.created_at})"
            continue
        if m.sha is None:
            notes.append(
                f"{m.role}: approval in comment {m.comment_id} has no SHA; "
                f"use 'APPROVED-BY: {m.role} @ <40-char head SHA>'"
            )
            continue
        if not FULL_SHA_RE.match(m.sha):
            notes.append(
                f"{m.role}: approval in comment {m.comment_id} has {m.sha!r}, "
                "not a full 40-character SHA"
            )
            continue
        if m.sha.lower() != head:
            notes.append(
                f"{m.role}: approval in comment {m.comment_id} is for {m.sha[:12]}, "
                f"not the current head {head[:12]} (stale)"
            )
            continue
        st.approved = True
        st.blocked = False
        st.detail = f"approved at head (comment {m.comment_id}, {m.created_at})"
    return states


# --------------------------------------------------------------------------
# Requirements


@dataclass
class Requirement:
    label: str
    any_of: list[str]
    reason: str


def author_role(pr: dict[str, Any], policy: Policy) -> tuple[str | None, str]:
    body = pr.get("body") or ""
    m = AUTHOR_ROLE_RE.search(body)
    if m:
        role = policy.role(m.group("role"))
        if role:
            return role, "Author-Role line in PR body"
        return None, f"Author-Role {m.group('role')!r} is not a known role"
    ref = ((pr.get("head") or {}).get("ref") or "").lower()
    for prefix, role in policy.raw.get("branch_prefixes", {}).items():
        if ref.startswith(prefix.lower()):
            return role, f"branch prefix {prefix}"
    return None, "no Author-Role line and no known branch prefix"


def substitute(role: str, author: str | None, policy: Policy) -> tuple[str, str]:
    if author and role == author:
        sub = policy.raw.get("self_review_substitutes", {}).get(role)
        if sub and sub != author:
            return sub, f"{role} authored this PR (process hint): {sub} approves instead"
    return role, ""


def requirements(
    pr: dict[str, Any], files: list[dict[str, Any]], policy: Policy, author: str | None
) -> list[Requirement]:
    cr = policy.raw["code_review"]
    reqs: list[Requirement] = []
    paths: list[str] = []
    for f in files:
        paths.append(f["filename"])
        if f.get("previous_filename"):
            paths.append(f["previous_filename"])

    changed = int(pr.get("additions") or 0) + int(pr.get("deletions") or 0)
    threshold = int(cr["both_cr_line_threshold"])
    iface = next((p for p in paths if matches_any(p, cr["interfaces_paths"])), None)
    both_reasons = []
    if iface:
        both_reasons.append(f"changes {iface}")
    if changed > threshold:
        both_reasons.append(f"{changed} changed lines > {threshold}")

    if both_reasons:
        for role in cr["any_of"]:
            r, note = substitute(role, author, policy)
            reqs.append(
                Requirement(
                    r, [r], "both CRs: " + "; ".join(both_reasons) + (f"; {note}" if note else "")
                )
            )
    else:
        pool = [r for r in cr["any_of"] if r != author]
        note = (
            f" ({author} authored this PR, process hint)" if len(pool) < len(cr["any_of"]) else ""
        )
        reqs.append(
            Requirement(
                " or ".join(pool),
                pool,
                f"one CR always ({changed} changed lines, no INTERFACES.md change){note}",
            )
        )

    for rule in policy.raw.get("path_rules", []):
        hit = None
        for p in paths:
            pat = matches_any(p, rule["paths"])
            if pat:
                hit = f"{p} matches {pat}"
                break
        if hit is None:
            for trig in rule.get("patch_triggers", []):
                for f in files:
                    if not matches_any(f["filename"], trig["paths"]):
                        continue
                    words = [w.lower() for w in trig["contains"]]
                    for line in (f.get("patch") or "").splitlines():
                        if line.startswith(("+++", "---")):
                            continue
                        if line.startswith(("+", "-", "@@")) and any(
                            w in line.lower() for w in words
                        ):
                            hit = f"{f['filename']} diff mentions {'/'.join(trig['contains'])}"
                            break
                    if hit:
                        break
                if hit:
                    break
        if hit:
            r, note = substitute(rule["role"], author, policy)
            reqs.append(
                Requirement(r, [r], f"{rule['reason']}: {hit}" + (f"; {note}" if note else ""))
            )
    # De-duplicate by label, merging reasons.
    merged: dict[str, Requirement] = {}
    for req in reqs:
        if req.label in merged:
            merged[req.label].reason += f" | {req.reason}"
        else:
            merged[req.label] = req
    return list(merged.values())


@dataclass
class Row:
    requirement: str
    status: str
    reason: str
    detail: str


def evaluate(
    pr: dict[str, Any],
    files: list[dict[str, Any]],
    comments: list[dict[str, Any]],
    policy: Policy,
    head_sha: str,
) -> tuple[bool, list[Row], list[str]]:
    notes: list[str] = []
    if not FULL_SHA_RE.match(head_sha or ""):
        raise CheckError(f"head SHA {head_sha!r} is not 40 hex characters")
    pr_head = ((pr.get("head") or {}).get("sha") or "").lower()
    if pr_head and pr_head != head_sha.lower():
        notes.append(
            f"PR head moved to {pr_head[:12]} since this run started ({head_sha[:12]}); "
            "evaluating the run's head. A newer run checks the new head."
        )
    rows: list[Row] = []
    ok = True
    author, how = author_role(pr, policy)
    if author is None:
        ok = False
        rows.append(
            Row(
                "Author role",
                "MISSING",
                f"{how}; add 'Author-Role: <Role>' to the PR body",
                "process hint, not enforcement",
            )
        )
    else:
        rows.append(Row("Author role", "OK", f"{author} ({how})", "process hint, not enforcement"))

    marks = collect_marks(comments, policy, notes)
    states = role_states(marks, head_sha, notes)
    reqs = requirements(pr, files, policy, author)

    for req in reqs:
        good = []
        blocked = []
        for role in req.any_of:
            st = states.get(role)
            if st and st.blocked:
                blocked.append(f"{role}: {st.detail}")
            elif st and st.approved:
                if author and role == author:
                    notes.append(
                        f"{role} approval not counted: {role} is the author role (process hint)"
                    )
                    continue
                good.append(f"{role}: {st.detail}")
        if blocked and (len(req.any_of) == 1 or not good):
            ok = False
            rows.append(Row(req.label, "BLOCKED", req.reason, "; ".join(blocked)))
        elif good:
            detail = "; ".join(good + [f"also open: {b}" for b in blocked])
            if blocked:
                ok = False
                rows.append(Row(req.label, "BLOCKED", req.reason, detail))
            else:
                rows.append(Row(req.label, "OK", req.reason, detail))
        else:
            ok = False
            rows.append(Row(req.label, "MISSING", req.reason, f"needs APPROVED-BY at {head_sha}"))

    # Any open change request blocks the PR, required role or not.
    required_roles = {r for req in reqs for r in req.any_of}
    for role, st in sorted(states.items()):
        if st.blocked and role not in required_roles:
            ok = False
            rows.append(
                Row(role, "BLOCKED", "open change request (role not otherwise required)", st.detail)
            )
    return ok, rows, notes


def render(rows: list[Row], notes: list[str], ok: bool, head_sha: str) -> str:
    headers = ("Requirement", "Status", "Why required", "Detail")
    data = [(r.requirement, r.status, r.reason, r.detail) for r in rows]
    widths = [
        max(len(h), *(len(d[i]) for d in data)) if data else len(h) for i, h in enumerate(headers)
    ]
    widths = [min(w, 90) for w in widths]

    def fmt(cells: tuple[str, ...]) -> str:
        return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    out = [f"Approval check for head {head_sha}", fmt(headers), "-+-".join("-" * w for w in widths)]
    out += [fmt(d) for d in data]
    if notes:
        out.append("")
        out.append("Notes:")
        out += [f"  - {n}" for n in notes]
    out.append("")
    out.append(
        "RESULT: PASS (required approvals are recorded for this head)"
        if ok
        else "RESULT: FAIL (see MISSING/BLOCKED rows)"
    )
    out.append(
        "This check proves approvals were RECORDED for this exact commit, not who posted them "
        "(all agents share one GitHub account)."
    )
    return "\n".join(out)


def render_markdown(rows: list[Row], notes: list[str], ok: bool, head_sha: str) -> str:
    def esc(s: str) -> str:
        return s.replace("|", "\\|").replace("\n", " ")

    md = [
        f"### Approval check: {'PASS' if ok else 'FAIL'}",
        f"Head `{head_sha}`. Post approvals as `APPROVED-BY: <Role> @ {head_sha}`.",
        "",
        "| Requirement | Status | Why required | Detail |",
        "|---|---|---|---|",
    ]
    md += [
        f"| {esc(r.requirement)} | {r.status} | {esc(r.reason)} | {esc(r.detail)} |" for r in rows
    ]
    if notes:
        md += ["", "Notes:"] + [f"- {esc(n)}" for n in notes]
    md += [
        "",
        "_Proves approvals were recorded for this commit, not who posted them (shared account)._",
    ]
    return "\n".join(md) + "\n"


# --------------------------------------------------------------------------
# GitHub API (read-only GETs)


def gh_get_all(url: str, token: str) -> Any:
    results: list[Any] = []
    next_url: str | None = url
    pages = 0
    while next_url:
        pages += 1
        if pages > 50:
            raise CheckError(f"too many pages for {url}")
        req = urllib.request.Request(next_url)  # noqa: S310 (https://api.github.com only)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https host)
                data = json.loads(resp.read().decode("utf-8"))
                link = resp.headers.get("Link") or ""
        except urllib.error.HTTPError as exc:
            raise CheckError(f"GET {next_url.split('?')[0]} failed: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise CheckError(f"GET {next_url.split('?')[0]} failed: {exc}") from exc
        if not isinstance(data, list):
            return data
        results.extend(data)
        next_url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part.split(";")[0].strip().strip("<>")
                if not next_url.startswith(API + "/"):
                    raise CheckError("unexpected pagination host")
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=os.environ.get("REPO", ""))
    ap.add_argument("--pr", type=int, default=int(os.environ.get("PR_NUMBER") or 0))
    ap.add_argument("--head-sha", default=os.environ.get("HEAD_SHA", ""))
    ap.add_argument(
        "--policy",
        default=str(Path(__file__).resolve().parents[1] / "approval-policy.json"),
    )
    args = ap.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        if not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", args.repo or ""):
            raise CheckError("--repo owner/name is required")
        if args.pr <= 0:
            raise CheckError("--pr is required")
        policy = Policy.load(Path(args.policy))
        base = f"{API}/repos/{args.repo}"
        pr = gh_get_all(f"{base}/pulls/{args.pr}", token)
        head_sha = args.head_sha or (pr.get("head") or {}).get("sha", "")
        files = gh_get_all(f"{base}/pulls/{args.pr}/files?per_page=100", token)
        comments = gh_get_all(f"{base}/issues/{args.pr}/comments?per_page=100", token)
        ok, rows, notes = evaluate(pr, files, comments, policy, head_sha)
    except CheckError as exc:
        print(f"approval-check error: {exc}", file=sys.stderr)
        return 2
    print(render(rows, notes, ok, head_sha))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(render_markdown(rows, notes, ok, head_sha))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
