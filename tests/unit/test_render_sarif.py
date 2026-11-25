"""Unit tests for the C11 SARIF 2.1.0 log (T-026).

Names avoid the ``test_ac_`` prefix. Finding cases, caps and hostile character classes come
from the code's own constants (D-TL-25).
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, get_args

import pytest
from render_support import item, policy, replace, result, rule, side

import conventiondrift
from conventiondrift.model import Alternative, Case, Rule, RuleResult, Suggestion, Verdict
from conventiondrift.render import escape
from conventiondrift.render.comment import finding_lines, render_comment
from conventiondrift.render.escape import sarif_text, sarif_uri
from conventiondrift.render.findings import FINDING_CASES, MAX_FINDING_ANNOTATIONS, is_finding
from conventiondrift.render.sarif import (
    SARIF_LEVEL,
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    render_sarif,
    sarif_message,
    sarif_object,
)
from conventiondrift.render.strings import SARIF_RULES

HOSTILE_CHARS = (
    "\x00",
    "\n",
    "\r",
    "\x1b",
    "\x7f",
    "\x85",
    "\u202e",
    "\u2066",
    "\u200b",
    "\ufeff",
    "\u2028",
    "\u2029",
    "\ud800",
)
# AC-N3.10's rule string, plus every invisible class above.
INJECTION = (
    "Use requests, ping @someone <img src=x onerror=alert(1)> "
    "[link](https://evil.example) **bold** #123 ```"
)
# RFC 3986 relative reference: unreserved, "/" and %XX only (no scheme, query or fragment).
_URI_REFERENCE = re.compile(r"(?:[A-Za-z0-9\-._~/]|%[0-9A-F]{2})*")
_UNESCAPE = re.compile(r"\\([\\\[\]])")


def _unescape(text: str) -> str:
    """What a SARIF viewer shows after undoing the ``message.text`` escapes for ``\\ [ ]``."""
    return _UNESCAPE.sub(r"\1", text)


def _log(*args: Any, **kwargs: Any) -> Any:
    return json.loads(render_sarif(result(*args, **kwargs)))


def _results(*args: Any, **kwargs: Any) -> list[Any]:
    runs = _log(*args, **kwargs)["runs"]
    assert len(runs) == 1
    return list(runs[0]["results"])


def _findings(count: int) -> list[RuleResult]:
    return [item(rule(f"Use option {n}", line=n + 1)) for n in range(count)]


# --- SARIF 2.1.0 shape -----------------------------------------------------------------------


def _check_sarif_shape(log: Any) -> None:
    """The SARIF 2.1.0 schema's required properties and constraints for what we emit."""
    assert set(log) == {"$schema", "version", "runs"}
    assert log["version"] == "2.1.0"
    for run in log["runs"]:
        driver = run["tool"]["driver"]
        assert isinstance(driver["name"], str) and driver["name"]
        ids = [d["id"] for d in driver["rules"]]
        assert len(ids) == len(set(ids))
        for descriptor in driver["rules"]:
            assert isinstance(descriptor["id"], str)
            assert isinstance(descriptor["shortDescription"]["text"], str)
            assert descriptor["defaultConfiguration"]["level"] in {
                "none",
                "note",
                "warning",
                "error",
            }
        for res in run["results"]:
            assert isinstance(res["message"]["text"], str)
            assert res["level"] in {"none", "note", "warning", "error"}
            assert driver["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
            (location,) = res["locations"]
            physical = location["physicalLocation"]
            uri = physical["artifactLocation"]["uri"]
            assert isinstance(uri, str) and _URI_REFERENCE.fullmatch(uri)
            assert isinstance(physical["region"]["startLine"], int)
            assert physical["region"]["startLine"] >= 1


def test_hostile_samples_cover_every_escaper_category() -> None:
    seen = {unicodedata.category(ch) for ch in HOSTILE_CHARS}
    assert seen == set(escape._LABEL_CATEGORIES)


def test_log_header_tool_and_descriptors() -> None:
    log = _log([item()])
    _check_sarif_shape(log)
    assert log["$schema"] == SARIF_SCHEMA
    assert log["version"] == SARIF_VERSION == "2.1.0"
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == TOOL_NAME
    assert driver["version"] == conventiondrift.__version__
    assert driver["rules"] == [
        {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": short},
            "defaultConfiguration": {"level": SARIF_LEVEL},
        }
        for rule_id, name, short in SARIF_RULES
    ]


def test_one_descriptor_per_finding_case() -> None:
    ids = [rule_id for rule_id, _, _ in SARIF_RULES]
    assert sorted(ids) == sorted(FINDING_CASES)
    assert set(ids) <= set(get_args(Case))


def test_output_style_matches_the_json_report() -> None:
    text = render_sarif(result([item()]))
    assert text.isascii() and "\r" not in text
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert text == json.dumps(json.loads(text), sort_keys=True, indent=2) + "\n"
    assert render_sarif(result([item()])) == text


def test_empty_result_is_a_valid_log_with_no_results() -> None:
    log = _log()
    _check_sarif_shape(log)
    assert log["runs"][0]["results"] == []


# --- results ---------------------------------------------------------------------------------


@pytest.mark.parametrize("case", sorted(FINDING_CASES))
def test_each_finding_is_one_result_at_the_rule_file_and_line(case: Case) -> None:
    the_rule = rule(file="docs/AGENTS.md", line=12, also_at=(30,))
    (res,) = _results([item(the_rule, case=case)])
    assert res["ruleId"] == case
    assert res["level"] == SARIF_LEVEL
    assert res["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "docs/AGENTS.md"},
                "region": {"startLine": 12},
            }
        }
    ]


@pytest.mark.parametrize(
    "rule_result",
    [
        pytest.param(item(case=None), id="no-case"),
        pytest.param(item(case="fixed"), id="fixed"),
        pytest.param(item(case="pre-existing-stale"), id="pre-existing"),
        pytest.param(item(case="removed", omit_head=True), id="removed"),
        pytest.param(item(rule(ignored=True)), id="ignored"),
        pytest.param(item(rule(disabled=True)), id="disabled"),
        pytest.param(item(conflict_with=("CLAUDE.md:3",), conflict_total=1), id="conflicting"),
        pytest.param(item(conflict_total=1, conflict_incomplete=True), id="conflict-lower-bound"),
    ],
)
def test_non_findings_give_no_result(rule_result: RuleResult) -> None:
    assert not is_finding(rule_result)
    assert _results([rule_result]) == []


def test_every_case_outside_the_finding_cases_gives_no_result() -> None:
    for case in sorted(set(get_args(Case)) - FINDING_CASES):
        assert _results([item(case=case)]) == []


def test_every_finding_is_kept_past_the_annotation_cap_in_report_order() -> None:
    findings = _findings(MAX_FINDING_ANNOTATIONS + 2)
    results = _results(findings)
    assert len(results) == len(findings)
    lines = [r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results]
    assert lines == [f.head_rule.line for f in findings if f.head_rule is not None]


@pytest.mark.parametrize("mode", ["head-only", "scan"])
def test_head_only_and_scan_logs_have_no_results(mode: str) -> None:
    rules = [item(rule(line=n + 1), case=None, head=side(0, 9)) for n in range(3)]
    log = _log(rules, mode=mode, base_sha=None)
    _check_sarif_shape(log)
    assert log["runs"][0]["results"] == []


def test_mixed_rules_give_results_for_findings_only() -> None:
    rules = [
        item(rule(line=1), case="fixed"),
        item(rule(line=2)),
        item(rule(line=3), case="pre-existing-stale"),
        item(rule(line=4), case="stale-rule-added", omit_base=True),
    ]
    results = _results(rules)
    assert [r["ruleId"] for r in results] == ["made-stale-by-code", "stale-rule-added"]
    assert [r["ruleIndex"] for r in results] == [0, 1]


def test_sarif_object_and_render_sarif_agree() -> None:
    res = result([item()])
    assert json.loads(render_sarif(res)) == sarif_object(res)


# --- message text ------------------------------------------------------------------------------


def _parts(rule_result: RuleResult) -> tuple[Rule, Any]:
    rule_ = rule_result.head_rule
    assert rule_ is not None and rule_result.head is not None
    return rule_, rule_result.head


def test_message_is_the_comment_finding_lines_each_escaped() -> None:
    rule_result = item(suggestion=replace("Use httpx for HTTP calls", ("httpx", 37)))
    expected_lines = [line for line in finding_lines(rule_result, *_parts(rule_result)) if line]
    (res,) = _results([rule_result])
    assert res["message"]["text"] == "\n".join(sarif_text(line) for line in expected_lines)
    assert res["message"]["text"] == sarif_message(rule_result)


def test_message_first_line_names_the_rule_without_the_comment_prefix() -> None:
    rule_result = item()
    text = sarif_message(rule_result)
    assert text.split("\n")[0] == 'AGENTS.md line 9: "Use requests for HTTP calls"'
    body = render_comment(result([rule_result]), previous_comment=False)
    assert body is not None and f"\u26a0\ufe0f {text.split(chr(10))[0]}" in body


def test_replace_with_new_text_shows_the_suggested_fix() -> None:
    text = sarif_message(item(suggestion=replace("Use httpx for HTTP calls", ("httpx", 37))))
    assert "Suggested fix:" in text
    assert "\n- Use requests for HTTP calls\n+ Use httpx for HTTP calls" in text


def test_replace_without_new_text_shows_the_finding_and_option_only() -> None:
    """D-PM-38: no suggested text, but the finding and the most-used option are shown."""
    rule_result = item(suggestion=replace(None, ("httpx", 37)))
    (res,) = _results([rule_result])
    text = res["message"]["text"]
    assert "Suggested fix" not in text and "\n+ " not in text
    assert "Most-used option now: httpx (37 of 40 sites)" in text
    assert text.startswith('AGENTS.md line 9: "Use requests for HTTP calls"')


def test_replace_without_new_text_or_candidates_shows_only_the_finding() -> None:
    text = sarif_message(item(suggestion=replace(None)))
    assert "Suggested fix" not in text and "Most-used" not in text
    assert text.startswith('AGENTS.md line 9: "Use requests for HTTP calls"')


def test_tie_and_remove_or_rewrite_wording() -> None:
    tie = Suggestion(
        "tie", "requests", (Alternative("aiohttp", 10), Alternative("httpx", 10)), None
    )
    assert "No single replacement: aiohttp and httpx are tied at 10 sites each." in (
        sarif_message(item(suggestion=tie))
    )
    prohibition = rule(
        "Never use print()",
        checker="logging",
        preferred=frozenset(),
        prohibited=frozenset({"print"}),
    )
    remove = Suggestion("remove-or-rewrite", None, (Alternative("print", 18),), None)
    text = sarif_message(item(prohibition, suggestion=remove, head=side(2, 20)))
    assert "Observed now: print: 18 of 20 sites" in text
    assert text.endswith("Consider removing or rewriting this rule.")


def test_message_for_a_non_finding_is_a_caller_error() -> None:
    with pytest.raises(ValueError, match="not a finding"):
        sarif_message(item(case="fixed"))


def test_message_has_no_blank_line_and_is_plain_text() -> None:
    text = sarif_message(item(suggestion=replace("Use httpx", ("httpx", 1))))
    assert "" not in text.split("\n")
    assert "```" not in text and "<" not in text


# --- hostile text ------------------------------------------------------------------------------


def test_injection_rule_text_is_verbatim_after_unescaping() -> None:
    the_rule = rule(INJECTION)
    (res,) = _results([item(the_rule)])
    text = res["message"]["text"]
    assert "[link]" not in text and "\\[link\\](https://evil.example)" in text
    assert INJECTION in _unescape(text)


def test_every_invisible_class_is_shown_visibly_and_lines_stay_put() -> None:
    hostile = INJECTION + "\\ ::warning::x %0A " + "".join(HOSTILE_CHARS)
    hostile_rule = rule(hostile, file="docs/AGENTS.md")
    suggestion = replace(hostile, (hostile, 3))
    benign = item(rule("x", file="docs/AGENTS.md"), suggestion=replace("y", ("z", 3)))
    rule_result = item(hostile_rule, suggestion=suggestion)
    text = render_sarif(result([rule_result]))
    assert text.isascii()
    message = json.loads(text)["runs"][0]["results"][0]["message"]["text"]
    lines = message.split("\n")
    assert len(lines) == len(sarif_message(benign).split("\n"))
    for line in lines:
        assert not any(unicodedata.category(ch) in escape._LABEL_CATEGORIES for ch in line)
        assert not line.startswith("::")
    expected = sarif_text(hostile)
    assert expected in lines[0]
    assert f"+ {expected}" in lines
    for char in HOSTILE_CHARS:
        if char not in "\n":
            assert char not in message


def test_message_uses_http_client_noun_and_verdict_counts() -> None:
    text = sarif_message(item(head=side(3, 40, verdict=Verdict.STALE)))
    assert "Before this PR: 30 of 40 call sites used requests" in text
    assert "After this PR:  3 of 40" in text


def test_policy_does_not_change_the_log() -> None:
    one = render_sarif(result([item()], the_policy=policy(notes=("a",))))
    two = render_sarif(result([item()], the_policy=policy()))
    assert one == two


# --- artifact URI (D-TL-97) ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "uri"),
    [
        ("docs/my rules/AGENTS.md", "docs/my%20rules/AGENTS.md"),
        ("docs/100%/AGENTS.md", "docs/100%25/AGENTS.md"),
        ("docs/a#b?c/AGENTS.md", "docs/a%23b%3Fc/AGENTS.md"),
        ("docs/caf\u00e9/AGENTS.md", "docs/caf%C3%A9/AGENTS.md"),
    ],
)
def test_artifact_uri_is_percent_encoded(path: str, uri: str) -> None:
    (res,) = _results([item(rule(file=path))])
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == uri
    assert sarif_uri(path) == uri


def test_hostile_artifact_uri_is_one_ascii_reference_per_result() -> None:
    hostile = "docs/@x/<b> ?#%\u202e\u200b\ud800\n\r::warning::/" + "".join(HOSTILE_CHARS) + ".md"
    log = _log([item(rule(file=hostile))])
    _check_sarif_shape(log)
    uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == sarif_uri(hostile)
    assert uri.isascii() and _URI_REFERENCE.fullmatch(uri)
    for char in (*HOSTILE_CHARS, " ", "#", "?", ":", "<", "@"):
        assert char not in uri
    assert "U%2B202E" in uri and "U%2BD800" in uri
    assert uri.startswith("docs/") and uri.endswith(".md")
