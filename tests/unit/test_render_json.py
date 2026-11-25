"""Unit tests for the C11 JSON report, INTERFACES I-9 (T-026).

Names avoid the ``test_ac_`` prefix. Hostile characters are drawn from the escaper's own
category set and every category is asserted covered (D-TL-25).
"""

from __future__ import annotations

import dataclasses
import json
import unicodedata
from datetime import UTC, datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal
from fractions import Fraction
from typing import Any, get_args

import pytest
from render_support import (
    HEAD_SHA,
    SHA,
    item,
    policy,
    replace,
    result,
    rule,
    side,
    site,
    window_at,
)

import conventiondrift
from conventiondrift.checkers import REGISTRY
from conventiondrift.fallback import GIT_TOO_OLD_TEXT, WITHHELD
from conventiondrift.model import (
    Alternative,
    CausingFile,
    CheckerId,
    Conflict,
    Counts,
    InternalError,
    ReportCounts,
    SkippedFile,
    SkipReason,
    Suggestion,
    Verdict,
)
from conventiondrift.render import escape
from conventiondrift.render.jsonreport import (
    EXPERIMENTAL_CHECKERS,
    REPORT_SCHEMA,
    dump_json,
    percent,
    render_json,
    report_object,
)

TOP_KEYS = {
    "schema",
    "tool_version",
    "mode",
    "base",
    "head",
    "window",
    "policy",
    "instruction_files",
    "skipped_files",
    "rules",
    "conflicts",
    "internal_errors",
    "counts",
}
RULE_KEYS = {
    "id",
    "file",
    "line",
    "also_at",
    "text",
    "checker",
    "experimental",
    "ignored",
    "disabled",
    "conflict_with",
    "conflict_with_total",
    "conflict_incomplete",
    "base",
    "head",
    "case",
    "causing_files",
    "suggestion",
}
SIDE_KEYS = {"verdict", "sites", "overall", "recent", "recent_unavailable_reason"}
COUNT_KEYS = {"following", "contradicting", "relevant", "percent"}
REPORT_COUNT_KEYS = {
    "stale",
    "new_stale",
    "rules_changed",
    "rules_unchanged",
    "conflicts_unlisted",
    "conflicts_incomplete",
}

# One or more stable samples per escaper category (Cc, Cf, Zl, Zp, Cs), incl. CR/LF, DEL, C1,
# bidi, zero-width, BOM and a lone surrogate.
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
HOSTILE_TEXT = (
    "Use requests <img src=x onerror=alert(1)> [l](https://evil.example) @someone #123 "
    "```\n::warning::x %0A \\ " + "".join(HOSTILE_CHARS)
)


def _loads(text: str) -> Any:
    return json.loads(text)


def _report(*args: Any, **kwargs: Any) -> Any:
    return _loads(render_json(result(*args, **kwargs)))


# --- style and determinism -------------------------------------------------------------


def test_hostile_samples_cover_every_escaper_category() -> None:
    seen = {unicodedata.category(ch) for ch in HOSTILE_CHARS}
    assert seen == set(escape._LABEL_CATEGORIES)


def test_top_level_keys_schema_version_and_shas() -> None:
    report = _report([item()])
    assert set(report) == TOP_KEYS
    assert report["schema"] == REPORT_SCHEMA
    assert report["tool_version"] == conventiondrift.__version__
    assert (report["mode"], report["base"], report["head"]) == ("compare", SHA, HEAD_SHA)


def test_output_style_is_sorted_two_space_lf_ascii_with_one_final_newline() -> None:
    text = render_json(result([item()]))
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert "\r" not in text and text.isascii()
    assert text == json.dumps(json.loads(text), sort_keys=True, indent=2) + "\n"
    assert all(line == line.rstrip() for line in text.split("\n"))


def test_keys_are_sorted_at_every_level() -> None:
    def check(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [k for k, _ in pairs]
        assert keys == sorted(keys)
        return dict(pairs)

    json.loads(render_json(result([item()])), object_pairs_hook=check)


def test_dump_json_rejects_nan() -> None:
    with pytest.raises(ValueError):
        dump_json({"x": float("nan")})


def test_same_input_gives_same_bytes_whatever_the_input_file_order() -> None:
    skipped = (SkippedFile("src/b.py", "binary"), SkippedFile("src/a.py", "syntax error"))
    one = render_json(result(instruction_paths=("b/AGENTS.md", "AGENTS.md"), skipped=skipped))
    two = render_json(
        result(instruction_paths=("AGENTS.md", "b/AGENTS.md"), skipped=tuple(reversed(skipped)))
    )
    assert one == two
    report = _loads(one)
    assert report["instruction_files"] == ["AGENTS.md", "b/AGENTS.md"]
    assert [s["path"] for s in report["skipped_files"]] == ["src/a.py", "src/b.py"]


def test_skipped_files_with_the_same_path_sort_by_reason() -> None:
    reasons = sorted(get_args(SkipReason))
    skipped = [SkippedFile("x.py", r) for r in reversed(reasons)]
    report = _report(skipped=skipped)
    assert report["skipped_files"] == [{"path": "x.py", "reason": r} for r in reasons]


def test_analyzer_python_is_never_written() -> None:
    marker = "3.99.42-analyzer-marker"
    assert marker not in render_json(result([item()], analyzer_python=marker))


def test_extra_result_fields_are_not_written() -> None:
    text = render_json(
        result(notes=("cap-note-marker",), markers=(("MARKER.md", 3),), head_only_reason=None)
    )
    assert "cap-note-marker" not in text and "MARKER.md" not in text


# --- window, policy, counts, conflicts ----------------------------------------------------


def test_window_without_end_is_null() -> None:
    assert _report()["window"] == {
        "end": None,
        "days": 90,
        "available": False,
        "unavailable_reason": "no history",
    }


@pytest.mark.parametrize(
    ("tz", "suffix"),
    [(UTC, "+00:00"), (timezone(timedelta(hours=-5)), "-05:00")],
)
def test_window_end_is_iso_8601_with_offset(tz: timezone, suffix: str) -> None:
    end = datetime(2026, 11, 12, 15, 4, 5, tzinfo=tz)
    report = _report(window=window_at(end))
    assert report["window"]["end"] == f"2026-11-12T15:04:05{suffix}"
    assert report["window"]["available"] is True
    assert report["window"]["unavailable_reason"] is None


@pytest.mark.parametrize("source", ["base", "head"])
def test_policy_source_and_notes(source: str) -> None:
    notes = ("first note", "second note")
    report = _report(the_policy=policy(notes=notes, source=source))
    assert report["policy"] == {"source": source, "notes": list(notes)}


def test_counts_carry_all_six_fields() -> None:
    counts = ReportCounts(1, 2, 3, 4, 5, 6)
    assert _report(counts=counts)["counts"] == dict(
        zip(
            sorted(REPORT_COUNT_KEYS),
            [
                counts.conflicts_incomplete,
                counts.conflicts_unlisted,
                counts.new_stale,
                counts.rules_changed,
                counts.rules_unchanged,
                counts.stale,
            ],
            strict=True,
        )
    )


def test_conflicts_keep_their_order_and_pair() -> None:
    conflicts = (
        Conflict(("AGENTS.md:3", "CLAUDE.md:3"), "http-client"),
        Conflict(("AGENTS.md:4", "AGENTS.md:9"), "logging"),
    )
    assert _report(conflicts=conflicts)["conflicts"] == [
        {"rules": ["AGENTS.md:3", "CLAUDE.md:3"], "checker": "http-client"},
        {"rules": ["AGENTS.md:4", "AGENTS.md:9"], "checker": "logging"},
    ]


def test_empty_result_has_empty_lists() -> None:
    report = _report(instruction_paths=())
    for key in ("instruction_files", "skipped_files", "rules", "conflicts", "internal_errors"):
        assert report[key] == []


# --- internal errors -----------------------------------------------------------------------


def test_internal_error_with_the_fixed_message_is_written() -> None:
    message = f"KeyError: {WITHHELD}"
    report = _report(errors=(InternalError("checker:logging", message),))
    assert report["internal_errors"] == [{"component": "checker:logging", "message": message}]


def test_git_too_old_keeps_its_public_text() -> None:
    report = _report(errors=(InternalError("gitread", GIT_TOO_OLD_TEXT),))
    assert report["internal_errors"][0]["message"] == GIT_TOO_OLD_TEXT


def test_internal_error_outside_the_allowlist_is_withheld() -> None:
    hostile = "<img src=x>\n::warning::" + "".join(HOSTILE_CHARS)
    text = render_json(result(errors=(InternalError(hostile, hostile),)))
    assert _loads(text)["internal_errors"] == [
        {"component": "core", "message": f"Exception: {WITHHELD}"}
    ]
    assert "img" not in text


# --- rules --------------------------------------------------------------------------------


def test_rule_object_has_exactly_the_i9_keys_and_values() -> None:
    the_rule = rule(also_at=(20, 31))
    suggestion = Suggestion(
        "replace", "requests", (Alternative("httpx", 40),), "Use httpx for HTTP calls"
    )
    causing = (CausingFile("src/api/client.py", -3, 3),)
    report = _report(
        [
            item(
                the_rule,
                causing=causing,
                suggestion=suggestion,
                conflict_with=(),
                conflict_total=0,
            )
        ]
    )
    (entry,) = report["rules"]
    assert set(entry) == RULE_KEYS
    assert entry["id"] == "AGENTS.md:9"
    assert (entry["file"], entry["line"], entry["also_at"]) == ("AGENTS.md", 9, [20, 31])
    assert entry["text"] == the_rule.text
    assert (entry["checker"], entry["experimental"]) == ("http-client", False)
    assert (entry["ignored"], entry["disabled"]) == (False, False)
    assert entry["case"] == "made-stale-by-code"
    assert entry["causing_files"] == [
        {"file": "src/api/client.py", "following_delta": -3, "contradicting_delta": 3}
    ]
    assert entry["suggestion"] == {
        "kind": "replace",
        "named_option": "requests",
        "alternatives": [{"option": "httpx", "sites": 40}],
        "new_text": "Use httpx for HTTP calls",
    }


def test_rules_record_the_file_and_exact_lines() -> None:
    rules = [item(rule(f"Use option {n}", line=n), case=None) for n in (4, 9, 17)]
    report = _report(rules)
    assert [(r["file"], r["line"]) for r in report["rules"]] == [
        ("AGENTS.md", 4),
        ("AGENTS.md", 9),
        ("AGENTS.md", 17),
    ]


def test_conflict_fields_are_written_as_given() -> None:
    entry = _report(
        [
            item(
                conflict_with=("AGENTS.md:3", "CLAUDE.md:3"),
                conflict_total=7,
                conflict_incomplete=True,
            )
        ]
    )["rules"][0]
    assert entry["conflict_with"] == ["AGENTS.md:3", "CLAUDE.md:3"]
    assert (entry["conflict_with_total"], entry["conflict_incomplete"]) == (7, True)


def test_experimental_flag_follows_the_checker_registry() -> None:
    assert {c.id for c in REGISTRY if c.experimental} == EXPERIMENTAL_CHECKERS
    assert EXPERIMENTAL_CHECKERS  # the registry has at least one experimental checker
    ids: list[CheckerId | None] = [*sorted(get_args(CheckerId)), None]
    rules = [item(rule(f"Use x {n}", line=n + 1, checker=cid)) for n, cid in enumerate(ids)]
    report = _report(rules)
    flags = {r["checker"]: r["experimental"] for r in report["rules"]}
    assert flags == {cid: cid in EXPERIMENTAL_CHECKERS for cid in ids}


def test_flags_ignored_and_disabled() -> None:
    entry = _report([item(rule(ignored=True, disabled=True), case=None)])["rules"][0]
    assert (entry["ignored"], entry["disabled"]) == (True, True)


def test_sides_have_sites_counts_and_recent() -> None:
    sites = (
        site("src/a.py", 1, 0, "httpx", follows=False),
        site("src/a.py", 2, 4, "requests", follows=True),
    )
    head = side(1, 2, sites=sites, recent=Counts(1, 1, 2))
    entry = _report([item(head=head)])["rules"][0]
    assert set(entry["head"]) == SIDE_KEYS
    assert entry["head"]["verdict"] == "Stale"
    assert entry["head"]["sites"] == [
        {
            "file": "src/a.py",
            "line": 1,
            "col": 0,
            "option": "httpx",
            "follows": False,
            "recent": False,
        },
        {
            "file": "src/a.py",
            "line": 2,
            "col": 4,
            "option": "requests",
            "follows": True,
            "recent": False,
        },
    ]
    overall = entry["head"]["overall"]
    assert set(overall) == COUNT_KEYS
    assert len(entry["head"]["sites"]) == overall["following"] + overall["contradicting"]
    assert overall == {"following": 1, "contradicting": 1, "relevant": 2, "percent": 50.0}
    assert entry["head"]["recent"] == {
        "following": 1,
        "contradicting": 1,
        "relevant": 2,
        "percent": 50.0,
    }
    assert entry["head"]["recent_unavailable_reason"] is None
    assert entry["base"]["verdict"] == "Holds"
    assert entry["base"]["recent"] is None
    assert entry["base"]["recent_unavailable_reason"] == "no history"


@pytest.mark.parametrize("verdict", list(Verdict))
def test_every_verdict_is_written_by_its_value(verdict: Verdict) -> None:
    entry = _report([item(head=side(1, 2, verdict=verdict))])["rules"][0]
    assert entry["head"]["verdict"] == verdict.value


@pytest.mark.parametrize("mode", ["head-only", "scan"])
def test_head_only_and_scan_have_a_null_base_side(mode: str) -> None:
    head_only_item = dataclasses.replace(item(case=None), base=None)
    report = _report([head_only_item], mode=mode, base_sha=None)
    assert report["base"] is None
    entry = report["rules"][0]
    assert entry["base"] is None and entry["head"]["verdict"] == "Stale"


def test_removed_rule_is_written_from_its_base_rule() -> None:
    entry = _report([item(rule(line=5), case="removed", omit_head=True)])["rules"][0]
    assert (entry["id"], entry["line"], entry["head"], entry["case"]) == (
        "AGENTS.md:5",
        5,
        None,
        "removed",
    )


@pytest.mark.parametrize(
    "suggestion",
    [
        replace(None, ("httpx", 4)),
        Suggestion("tie", "requests", (Alternative("aiohttp", 10), Alternative("httpx", 10)), None),
        Suggestion("remove-or-rewrite", None, (Alternative("print", 18),), None),
        Suggestion("none", "requests", (), None),
    ],
)
def test_suggestions_without_new_text_write_null(suggestion: Suggestion) -> None:
    """D-PM-38 and I-9: ``new_text`` is null; the kind and alternatives stay."""
    written = _report([item(suggestion=suggestion)])["rules"][0]["suggestion"]
    assert written["kind"] == suggestion.kind
    assert written["new_text"] is None
    assert written["named_option"] == suggestion.named_option
    assert written["alternatives"] == [
        {"option": a.option, "sites": a.sites} for a in suggestion.alternatives
    ]


def test_causing_files_keep_c10_order() -> None:
    causing = (CausingFile("src/z.py", -5, 5), CausingFile("src/a.py", -1, 1))
    entry = _report([item(causing=causing)])["rules"][0]
    assert [c["file"] for c in entry["causing_files"]] == ["src/z.py", "src/a.py"]


# --- hostile text ---------------------------------------------------------------------------


def test_hostile_text_is_lossless_ascii_json_with_no_raw_invisible_character() -> None:
    hostile_rule = rule(HOSTILE_TEXT, file="docs/@x/<b>y</b>\u202e.md")
    suggestion = replace(HOSTILE_TEXT, (HOSTILE_TEXT, 3))
    the_site = site(HOSTILE_TEXT, 1, 0, HOSTILE_TEXT, follows=False)
    text = render_json(
        result(
            [item(hostile_rule, suggestion=suggestion, head=side(0, 1, sites=(the_site,)))],
            the_policy=policy(notes=(HOSTILE_TEXT,)),
            skipped=(SkippedFile(HOSTILE_TEXT, "binary"),),
            instruction_paths=(HOSTILE_TEXT,),
        )
    )
    benign = render_json(
        result(
            [
                item(
                    rule("x", file="x"),
                    suggestion=replace("x", ("x", 3)),
                    head=side(0, 1, sites=(site("x", 1, 0, "x", follows=False),)),
                )
            ],
            the_policy=policy(notes=("x",)),
            skipped=(SkippedFile("x", "binary"),),
            instruction_paths=("x",),
        )
    )
    assert text.isascii()
    for char in HOSTILE_CHARS:
        assert char == "\n" or char not in text
    # Raw newlines are only the serializer's own layout: same line count as benign input.
    assert text.count("\n") == benign.count("\n")
    assert not any(line.lstrip().startswith("::") for line in text.split("\n"))
    report = _loads(text)
    entry = report["rules"][0]
    assert entry["text"] == HOSTILE_TEXT
    assert entry["file"] == hostile_rule.file
    assert entry["suggestion"]["new_text"] == HOSTILE_TEXT
    assert entry["suggestion"]["alternatives"][0]["option"] == HOSTILE_TEXT
    assert entry["head"]["sites"][0]["file"] == HOSTILE_TEXT
    assert report["policy"]["notes"] == [HOSTILE_TEXT]
    assert report["skipped_files"][0]["path"] == HOSTILE_TEXT
    assert report["instruction_files"] == [HOSTILE_TEXT]


# --- percent -------------------------------------------------------------------------------


def _reference(following: int, relevant: int) -> float:
    exact = Fraction(following * 100, relevant)
    value = Decimal(exact.numerator) / Decimal(exact.denominator)
    # Decimal division is exact enough here: denominators below are tiny.
    return float(value.quantize(Decimal("0.1"), rounding=ROUND_HALF_EVEN))


@pytest.mark.parametrize(
    ("following", "relevant", "expected"),
    [
        (3, 40, 7.5),
        (2, 5, 40.0),
        (1, 16, 6.2),  # 6.25: tie, rounds to even
        (3, 16, 18.8),  # 18.75: tie, rounds to even
        (5, 16, 31.2),  # 31.25: tie, rounds to even
        (1, 3, 33.3),
        (2, 3, 66.7),
        (0, 7, 0.0),
        (7, 7, 100.0),
    ],
)
def test_percent_rounds_half_even_to_one_decimal(
    following: int, relevant: int, expected: float
) -> None:
    assert percent(following, relevant) == expected


def test_percent_matches_an_exact_reference_on_a_grid() -> None:
    for relevant in range(1, 161):
        for following in range(relevant + 1):
            assert percent(following, relevant) == _reference(following, relevant)


def test_percent_is_null_without_relevant_sites() -> None:
    assert percent(0, 0) is None
    entry = _report([item(head=side(0, 0, verdict=Verdict.INSUFFICIENT))])["rules"][0]
    assert entry["head"]["overall"]["percent"] is None


def test_report_object_and_render_json_agree() -> None:
    res = result([item()])
    assert render_json(res) == dump_json(report_object(res))
