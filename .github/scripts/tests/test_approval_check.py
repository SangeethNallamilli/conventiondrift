"""Unit tests for .github/scripts/approval_check.py (stdlib unittest, no network).

Run: python3 -m unittest discover -s .github/scripts/tests -v
These live outside tests/ so they never join the product suite or coverage.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "approval_check.py"
POLICY = HERE.parents[1] / "approval-policy.json"

spec = importlib.util.spec_from_file_location("approval_check", SCRIPT)
if spec is None or spec.loader is None:
    raise ImportError(SCRIPT)
ac = importlib.util.module_from_spec(spec)
sys.modules["approval_check"] = ac
spec.loader.exec_module(ac)

HEAD = "a" * 40
OLD = "b" * 40


def pr(
    body: str = "Author-Role: Software Engineer 1",
    ref: str = "feature",
    add: int = 10,
    dele: int = 5,
):
    return {"body": body, "head": {"ref": ref, "sha": HEAD}, "additions": add, "deletions": dele}


def f(name: str, patch: str = "", prev: str | None = None):
    d = {"filename": name, "patch": patch}
    if prev:
        d["previous_filename"] = prev
    return d


_ids = iter(range(1, 10_000))


def c(body: str, t: str = "2026-11-12T18:00:00Z", assoc: str = "OWNER"):
    return {"id": next(_ids), "body": body, "created_at": t, "author_association": assoc}


def approve(role: str, sha: str = HEAD, t: str = "2026-11-12T18:00:00Z"):
    return c(f"APPROVED-BY: {role} @ {sha}", t)


class Base(unittest.TestCase):
    policy = ac.Policy.load(POLICY)

    def run_eval(self, the_pr, files, comments):
        ok, rows, notes = ac.evaluate(the_pr, files, comments, self.policy, HEAD)
        return ok, {r.requirement: r for r in rows}, notes


class TestParsing(Base):
    def test_exact_lines(self):
        body = f"LGTM\nAPPROVED-BY: Code Reviewer 1 @ {HEAD}\n  CHANGES-REQUESTED-BY: SR  \n"
        self.assertEqual(
            ac.parse_comment(body),
            [("approve", "Code Reviewer 1", HEAD), ("changes", "SR", None)],
        )

    def test_quotes_fences_and_inline_ignored(self):
        body = "\n".join(
            [
                f"> APPROVED-BY: Code Reviewer 1 @ {HEAD}",
                "```",
                f"APPROVED-BY: Code Reviewer 1 @ {HEAD}",
                "```",
                f"I think APPROVED-BY: Code Reviewer 1 @ {HEAD}",
                "approved-by: Code Reviewer 1",
                f"APPROVED-BY: Code Reviewer 1 @ {HEAD} trailing words",
            ]
        )
        self.assertEqual(ac.parse_comment(body), [])

    def test_role_normalization_and_aliases(self):
        p = self.policy
        self.assertEqual(p.role("qa/verifier"), "QA / Verifier")
        self.assertEqual(p.role("  QA   /  VERIFIER "), "QA / Verifier")
        self.assertEqual(p.role("release / devops"), "Release/DevOps")
        self.assertEqual(p.role("cr2"), "Code Reviewer 2")
        self.assertEqual(p.role("SR"), "Security Reviewer")
        self.assertIsNone(p.role("Random Person"))

    def test_glob(self):
        self.assertIsNotNone(
            ac.matches_any(
                "src/conventiondrift/discover/safefs.py", ["src/conventiondrift/discover/**"]
            )
        )
        self.assertIsNotNone(ac.matches_any("INTERFACES.md", ["**/INTERFACES.md"]))
        self.assertIsNotNone(ac.matches_any("docs/x/INTERFACES.md", ["**/INTERFACES.md"]))
        self.assertIsNone(ac.matches_any("src/a/b.py", ["src/*.py"]))
        self.assertIsNotNone(
            ac.matches_any("src/conventiondrift/gitread.py", ["src/conventiondrift/gitread*.py"])
        )


class TestShaRules(Base):
    def test_plain_cr_approval_passes(self):
        ok, rows, _ = self.run_eval(pr(), [f("src/conventiondrift/core.py")], [approve("CR1")])
        self.assertTrue(ok)
        self.assertEqual(rows["Code Reviewer 1 or Code Reviewer 2"].status, "OK")

    def test_missing_sha_does_not_count(self):
        ok, rows, notes = self.run_eval(
            pr(), [f("src/conventiondrift/core.py")], [c("APPROVED-BY: Code Reviewer 1")]
        )
        self.assertFalse(ok)
        self.assertEqual(rows["Code Reviewer 1 or Code Reviewer 2"].status, "MISSING")
        self.assertTrue(any("no SHA" in n for n in notes))

    def test_short_sha_does_not_count(self):
        ok, _, notes = self.run_eval(pr(), [f("x.md")], [approve("CR1", HEAD[:12])])
        self.assertFalse(ok)
        self.assertTrue(any("not a full 40-character" in n for n in notes))

    def test_stale_sha_does_not_count(self):
        ok, _, notes = self.run_eval(pr(), [f("x.md")], [approve("CR1", OLD)])
        self.assertFalse(ok)
        self.assertTrue(any("stale" in n for n in notes))

    def test_uppercase_sha_ok(self):
        ok, _, _ = self.run_eval(pr(), [f("x.md")], [approve("CR2", HEAD.upper())])
        self.assertTrue(ok)

    def test_untrusted_commenter_ignored(self):
        cm = c(f"APPROVED-BY: Code Reviewer 1 @ {HEAD}", assoc="NONE")
        ok, _, notes = self.run_eval(pr(), [f("x.md")], [cm])
        self.assertFalse(ok)
        self.assertTrue(any("not trusted" in n for n in notes))

    def test_unknown_role_noted(self):
        ok, _, notes = self.run_eval(pr(), [f("x.md")], [c(f"APPROVED-BY: Janitor @ {HEAD}")])
        self.assertFalse(ok)
        self.assertTrue(any("unknown role" in n for n in notes))

    def test_bad_head_sha_errors(self):
        with self.assertRaises(ac.CheckError):
            ac.evaluate(pr(), [], [], self.policy, "abc")


class TestChangesRequested(Base):
    def test_request_blocks_until_later_head_approval(self):
        files = [f("x.md")]
        req = c("CHANGES-REQUESTED-BY: Code Reviewer 1", "2026-11-12T17:00:00Z")
        ok, rows, _ = self.run_eval(pr(), files, [req])
        self.assertFalse(ok)
        self.assertEqual(rows["Code Reviewer 1 or Code Reviewer 2"].status, "BLOCKED")
        ok, _, _ = self.run_eval(pr(), files, [req, approve("CR1", t="2026-11-12T18:00:00Z")])
        self.assertTrue(ok)

    def test_stale_approval_does_not_clear_request(self):
        req = c(f"CHANGES-REQUESTED-BY: Code Reviewer 1 @ {OLD}", "2026-11-12T17:00:00Z")
        ok, _, _ = self.run_eval(
            pr(), [f("x.md")], [req, approve("CR1", OLD, "2026-11-12T18:00:00Z")]
        )
        self.assertFalse(ok)

    def test_approval_before_request_does_not_clear(self):
        ok, _, _ = self.run_eval(
            pr(),
            [f("x.md")],
            [
                approve("CR1", t="2026-11-12T17:00:00Z"),
                c("CHANGES-REQUESTED-BY: CR1", "2026-11-12T18:00:00Z"),
            ],
        )
        self.assertFalse(ok)

    def test_other_cr_approval_does_not_clear_open_request(self):
        ok, rows, _ = self.run_eval(
            pr(),
            [f("x.md")],
            [c("CHANGES-REQUESTED-BY: CR1", "2026-11-12T17:00:00Z"), approve("CR2")],
        )
        self.assertFalse(ok)
        self.assertEqual(rows["Code Reviewer 1 or Code Reviewer 2"].status, "BLOCKED")

    def test_request_from_non_required_role_blocks(self):
        ok, rows, _ = self.run_eval(
            pr(), [f("x.md")], [approve("CR1"), c("CHANGES-REQUESTED-BY: Architect")]
        )
        self.assertFalse(ok)
        self.assertEqual(rows["Architect"].status, "BLOCKED")


class TestRequiredRoles(Base):
    def test_both_crs_for_interfaces(self):
        ok, rows, _ = self.run_eval(pr(), [f("INTERFACES.md")], [approve("CR1")])
        self.assertFalse(ok)
        self.assertEqual(rows["Code Reviewer 2"].status, "MISSING")
        ok, _, _ = self.run_eval(pr(), [f("INTERFACES.md")], [approve("CR1"), approve("CR2")])
        self.assertTrue(ok)

    def test_both_crs_over_400_lines(self):
        ok, rows, _ = self.run_eval(pr(add=300, dele=101), [f("x.md")], [approve("CR1")])
        self.assertFalse(ok)
        self.assertIn("401 changed lines", rows["Code Reviewer 2"].reason)
        ok, _, _ = self.run_eval(pr(add=300, dele=100), [f("x.md")], [approve("CR1")])
        self.assertTrue(ok)

    def test_security_paths(self):
        for path in [
            "src/conventiondrift/discover/safefs.py",
            "src/conventiondrift/policy/config.py",
            "src/conventiondrift/github.py",
            "src/conventiondrift/gitread.py",
            "pyproject.toml",
            "requirements/dev.txt",
            ".github/workflows/ci.yml",
            ".github/scripts/approval_check.py",
            ".github/CODEOWNERS",
            ".github/approval-policy.json",
            "scripts/ci/check_dco.py",
        ]:
            with self.subTest(path=path):
                ok, rows, _ = self.run_eval(pr(), [f(path)], [approve("CR1")])
                self.assertFalse(ok)
                self.assertEqual(rows["Security Reviewer"].status, "MISSING")

    def test_security_satisfied_only_with_head_sha(self):
        files = [f(".github/workflows/approval.yml")]
        ok, _, _ = self.run_eval(pr(), files, [approve("CR1"), c("APPROVED-BY: Security Reviewer")])
        self.assertFalse(ok)
        ok, _, _ = self.run_eval(pr(), files, [approve("CR1"), approve("SR")])
        self.assertTrue(ok)

    def test_rename_from_security_path_counts(self):
        _ok, rows, _ = self.run_eval(
            pr(), [f("src/x.py", prev="src/conventiondrift/discover/a.py")], [approve("CR1")]
        )
        self.assertIn("Security Reviewer", rows)

    def test_test_engineer_paths(self):
        for path in [
            "tests/spec/test_x.py",
            "tests/fixtures/builders.py",
            "TEST-STRATEGY.md",
            "scripts/ci/check_coverage.py",
        ]:
            with self.subTest(path=path):
                _ok, rows, _ = self.run_eval(pr(), [f(path)], [approve("CR1")])
                self.assertEqual(rows["Test Engineer"].status, "MISSING")

    def test_coverage_settings_in_pyproject(self):
        patch = "@@ -81,3 +81,3 @@ [tool.coverage.run]\n-branch = true\n+branch = false\n"
        _, rows, _ = self.run_eval(pr(), [f("pyproject.toml", patch)], [approve("CR1")])
        self.assertIn("Test Engineer", rows)
        _, rows, _ = self.run_eval(
            pr(), [f("pyproject.toml", "@@ -1 +1 @@\n-a\n+b\n")], [approve("CR1")]
        )
        self.assertNotIn("Test Engineer", rows)

    def test_unit_tests_do_not_need_te(self):
        _, rows, _ = self.run_eval(pr(), [f("tests/unit/test_x.py")], [approve("CR1")])
        self.assertNotIn("Test Engineer", rows)
        self.assertNotIn("Security Reviewer", rows)


class TestAuthorRoleHint(Base):
    def test_missing_author_role_fails(self):
        ok, rows, _ = self.run_eval(pr(body="", ref="feature"), [f("x.md")], [approve("CR1")])
        self.assertFalse(ok)
        self.assertEqual(rows["Author role"].status, "MISSING")

    def test_branch_prefix(self):
        ok, rows, _ = self.run_eval(pr(body="", ref="se2/T-027-x"), [f("x.md")], [approve("CR1")])
        self.assertTrue(ok)
        self.assertIn("Software Engineer 2", rows["Author role"].reason)

    def test_body_overrides_branch(self):
        _, rows, _ = self.run_eval(
            pr(body="Author-Role: Release/DevOps", ref="se2/x"), [f("x.md")], []
        )
        self.assertIn("Release/DevOps", rows["Author role"].reason)

    def test_cr_author_needs_other_cr(self):
        ok, rows, _ = self.run_eval(pr(body="Author-Role: CR1"), [f("x.md")], [approve("CR1")])
        self.assertFalse(ok)
        self.assertEqual(rows["Code Reviewer 2"].status, "MISSING")

    def test_sr_author_substitute(self):
        files = [f(".github/workflows/ci.yml")]
        ok, rows, _ = self.run_eval(
            pr(body="Author-Role: SR"), files, [approve("CR1"), approve("SR")]
        )
        self.assertFalse(ok)
        self.assertEqual(rows["Tech Lead"].status, "MISSING")
        ok, _, _ = self.run_eval(pr(body="Author-Role: SR"), files, [approve("CR1"), approve("TL")])
        self.assertTrue(ok)

    def test_te_author_substitute(self):
        ok, _rows, _ = self.run_eval(
            pr(body="", ref="te/spec"), [f("tests/spec/t.py")], [approve("CR2"), approve("QA")]
        )
        self.assertTrue(ok)


class TestMainAndPolicy(Base):
    def test_policy_rejects_unknown_alias_target(self):
        raw = json.loads(POLICY.read_text())
        raw["aliases"]["X"] = "Nobody"
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "p.json"
            p.write_text(json.dumps(raw))
            with self.assertRaises(ac.CheckError):
                ac.Policy.load(p)

    def test_main_end_to_end_with_fake_api(self):
        responses = {
            "/pulls/7": pr(body="Author-Role: Release/DevOps"),
            "/pulls/7/files": [f(".github/workflows/approval.yml")],
            "/issues/7/comments": [approve("CR1"), approve("SR")],
        }

        def fake(url, token):
            path = url.split("/repos/o/r", 1)[1].split("?")[0]
            return responses[path]

        out = io.StringIO()
        with (
            mock.patch.object(ac, "gh_get_all", fake),
            redirect_stdout(out),
            mock.patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": ""}, clear=False),
        ):
            rc = ac.main(
                ["--repo", "o/r", "--pr", "7", "--head-sha", HEAD, "--policy", str(POLICY)]
            )
        self.assertEqual(rc, 0, out.getvalue())
        self.assertIn("RESULT: PASS", out.getvalue())
        self.assertIn("RECORDED", out.getvalue())

        responses["/issues/7/comments"] = [approve("CR1")]
        out = io.StringIO()
        with mock.patch.object(ac, "gh_get_all", fake), redirect_stdout(out):
            rc = ac.main(
                ["--repo", "o/r", "--pr", "7", "--head-sha", HEAD, "--policy", str(POLICY)]
            )
        self.assertEqual(rc, 1)
        self.assertIn("MISSING", out.getvalue())

    def test_main_bad_args(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(ac.main(["--repo", "bad", "--pr", "1", "--policy", str(POLICY)]), 2)


if __name__ == "__main__":
    unittest.main()
