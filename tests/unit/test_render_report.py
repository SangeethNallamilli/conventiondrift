"""Unit tests for C11 summary, annotations and ``--format text`` (T-025; D-TL-85, D-TL-86).

Names avoid the ``test_ac_`` prefix. Negative cases are built from the code's
constants (D-TL-25), not from copied literals of those caps.
"""

from __future__ import annotations

from collections.abc import Sequence
from types import MappingProxyType
from typing import get_args

from conventiondrift.core import RunContext
from conventiondrift.model import (
    Case,
    CheckerId,
    CheckerPolicy,
    Conflict,
    Counts,
    InstructionFile,
    InternalError,
    Policy,
    ReportCounts,
    Result,
    Rule,
    RuleMatch,
    RuleResult,
    SideResult,
    SkippedFile,
    Suggestion,
    Thresholds,
    Verdict,
    Window,
)
from conventiondrift.render.annotations import format_run_level_annotation, render_annotations
from conventiondrift.render.context import RenderContext, WindowAnchor
from conventiondrift.render.escape import md, workflow_cmd, workflow_prop
from conventiondrift.render.findings import MAX_FINDING_ANNOTATIONS, is_finding
from conventiondrift.render.strings import (
    FETCH_DEPTH,
    NO_INSTRUCTION_FILES,
    NO_PR_BODY,
    NO_PYTHON_FILES,
    RUN_LEVEL_TITLE,
    conflict_incomplete_note,
    finding_annotation_title,
    not_annotated_line,
    pre_existing_line,
    scan_new_stale_line,
)
from conventiondrift.render.summary import (
    render_error_summary,
    render_fixed_summary,
    render_summary,
)
from conventiondrift.render.text import render_text

SHA = "a" * 40
HEAD_SHA = "b" * 40
ISO = "2026-11-12T15:04:05-05:00"
HOSTILE_PATH = "docs/\n::warning::x.md"
HOSTILE_TEXT = "<img> | ` %0A"
NONE_SUGGESTION = Suggestion("none", None, (), None)


def _policy(
    *,
    after_merge: tuple[str, ...] = (),
    notes: tuple[str, ...] = (),
    disabled: frozenset[str] = frozenset(),
) -> Policy:
    checkers = {cid: CheckerPolicy(cid not in disabled, ()) for cid in get_args(CheckerId)}
    return Policy(
        effective_fail_on="none",
        gated=False,
        source="base",
        history_days=90,
        thresholds=Thresholds(80, 20, 20, 50, 70, 5),
        excludes=(),
        max_file_bytes=1048576,
        checkers=MappingProxyType(checkers),
        ignores=(),
        markers=MappingProxyType({}),
        paths=None,
        comment=True,
        sarif=False,
        after_merge_notes=after_merge,
        notes=notes,
    )


def _ctx(
    *,
    mode: str = "compare",
    head_kind: str | None = None,
    read_only_reason: str | None = None,
    policy_source: str = "base",
    window: bool = True,
    python_files_found: bool = True,
    analyzed_sha: str = HEAD_SHA,
    analyzer_python: str = "3.12.7",
) -> RenderContext:
    return RenderContext(
        mode=mode,  # type: ignore[arg-type]
        analyzed_sha=analyzed_sha,
        head_kind=head_kind,  # type: ignore[arg-type]
        read_only_reason=read_only_reason,  # type: ignore[arg-type]
        analyzer_python=analyzer_python,
        policy_source=policy_source,  # type: ignore[arg-type]
        window_anchor=WindowAnchor(HEAD_SHA, ISO, 90) if window else None,
        python_files_found=python_files_found,
    )


def _side(
    following: int,
    relevant: int,
    *,
    verdict: Verdict = Verdict.STALE,
    recent: Counts | None = None,
    recent_reason: str | None = "no history",
) -> SideResult:
    if recent is not None:
        recent_reason = None
    return SideResult(
        verdict=verdict,
        sites=(),
        overall=Counts(following, relevant - following, relevant),
        recent=recent,
        recent_unavailable_reason=recent_reason,  # type: ignore[arg-type]
    )


def _rule(
    text: str = "Use requests for HTTP calls",
    *,
    file: str = "AGENTS.md",
    line: int = 9,
    checker: CheckerId | None = "http-client",
    ignored: bool = False,
    disabled: bool = False,
    match: bool = True,
) -> Rule:
    return Rule(
        id=f"{file}:{line}",
        file=file,
        line=line,
        also_at=(),
        text=text,
        normalized_text=text.lower(),
        checker=checker,
        match=RuleMatch(frozenset({"requests"}), frozenset(), 1) if match else None,
        scope_dir="",
        ignored=ignored,
        disabled=disabled,
    )


def _item(
    rule: Rule | None = None,
    *,
    case: Case | None = "made-stale-by-code",
    base: SideResult | None = None,
    head: SideResult | None = None,
    omit_base: bool = False,
    omit_head: bool = False,
    conflict_with: tuple[str, ...] = (),
    conflict_total: int = 0,
    conflict_incomplete: bool = False,
) -> RuleResult:
    rule = rule or _rule()
    base_rule = None if omit_base else rule
    head_rule = None if omit_head else rule
    return RuleResult(
        rule_id=rule.id,
        base_rule=base_rule,
        head_rule=head_rule,
        base=base if (base is not None or omit_base) else _side(3, 40),
        head=head if (head is not None or omit_head) else _side(0, 40),
        conflict_with=conflict_with,
        conflict_with_total=conflict_total,
        conflict_incomplete=conflict_incomplete,
        case=case,
        causing_files=(),
        suggestion=NONE_SUGGESTION,
    )


def _result(
    rule_results: Sequence[RuleResult] = (),
    *,
    mode: str = "compare",
    policy: Policy | None = None,
    skipped: tuple[SkippedFile, ...] = (),
    conflicts: tuple[Conflict, ...] = (),
    notes: tuple[str, ...] = (),
    markers: tuple[tuple[str, int], ...] = (),
    errors: tuple[InternalError, ...] = (),
    incomplete: int = 0,
    unlisted: int = 0,
    instructions: bool = True,
    head_only_reason: str | None = None,
) -> Result:
    files = (InstructionFile("AGENTS.md", b"# rules\n", "", False),) if instructions else ()
    return Result(
        mode=mode,  # type: ignore[arg-type]
        base_sha=SHA,
        head_sha=HEAD_SHA,
        head_only_reason=head_only_reason,  # type: ignore[arg-type]
        window=Window(end=None, days=90, available=False, unavailable_reason="no history"),
        policy=policy or _policy(),
        instruction_files=files,
        skipped_files=skipped,
        rule_results=tuple(rule_results),
        conflicts=conflicts,
        unattached_markers=markers,
        internal_errors=errors,
        counts=ReportCounts(
            stale=0,
            new_stale=0,
            rules_changed=0,
            rules_unchanged=0,
            conflicts_unlisted=unlisted,
            conflicts_incomplete=incomplete,
        ),
        notes=notes,
        analyzer_python="3.12.7",
    )


def _findings(count: int, *, start: int = 1, file: str = "AGENTS.md") -> list[RuleResult]:
    return [_item(_rule(f"Use option {i}", file=file, line=start + i)) for i in range(count)]


# --- fixed summaries and error-only policy source --------------------------------------


def test_fixed_summary_for_no_pr() -> None:
    body = render_fixed_summary("no_pr")
    assert body == "# conventiondrift\n\nNo PR to compare.\n"
    assert NO_PR_BODY in body


def test_fixed_summary_names_the_unsupported_trigger() -> None:
    body = render_fixed_summary("pull_request_target")
    assert body.startswith("# conventiondrift: unsupported trigger\n\n")
    assert "`pull_request_target` is not supported." in body
    assert "Nothing was read from the pull request." in body
    assert body.endswith("\n") and not body.endswith("\n\n")


def test_error_policy_source_uses_the_explicit_input() -> None:
    assert (
        render_error_summary(RunContext(explicit_fail_on="new-stale"))
        == "Policy source: new-stale\n"
    )
    assert render_error_summary(RunContext(explicit_fail_on="none")) == "Policy source: none\n"


def test_error_policy_source_when_the_base_config_could_not_be_read() -> None:
    # The error-path fail-on of new-stale is not presented as configured.
    ctx = RunContext(explicit_fail_on=None, config_known_present=True)
    assert render_error_summary(ctx) == "Policy source: base config could not be read\n"


def test_error_policy_source_default_when_nothing_is_known() -> None:
    assert render_error_summary(RunContext()) == "Policy source: default (none)\n"


def test_empty_explicit_fail_on_is_treated_as_unset() -> None:
    ctx = RunContext(explicit_fail_on="", config_known_present=False)
    assert render_error_summary(ctx) == "Policy source: default (none)\n"


# --- summary sections ------------------------------------------------------------------


def test_summary_is_lf_only_with_one_final_newline_and_no_trailing_spaces() -> None:
    body = render_summary(_result([_item()]), _ctx())
    assert "\r" not in body
    assert body.endswith("\n") and not body.endswith("\n\n")
    assert all(line == line.rstrip(" ") for line in body.split("\n"))


def test_compare_summary_has_the_layout_sections() -> None:
    nv = _rule("Always keep functions small", line=12, checker=None, match=False)
    ignored = _rule("Use an ignored rule", line=15, ignored=True)
    removed_rule = _rule("Old rule", line=50)
    recent = Counts(2, 3, 5)
    items = [
        _item(
            _rule(),
            head=_side(0, 40, recent=recent),
            base=_side(4, 40, verdict=Verdict.CONTESTED, recent=recent),
        ),
        _item(
            nv,
            case=None,
            head=_side(
                0,
                0,
                verdict=Verdict.NOT_VERIFIABLE,
                recent_reason="no relevant sites in the window",
            ),
            base=_side(
                0,
                0,
                verdict=Verdict.NOT_VERIFIABLE,
                recent_reason="no relevant sites in the window",
            ),
        ),
        _item(ignored, case="pre-existing-stale", head=_side(1, 10), base=_side(1, 10)),
        _item(
            _rule("Use logging", line=40),
            case="pre-existing-stale",
            head=_side(1, 10),
            base=_side(1, 10),
        ),
        _item(
            removed_rule,
            case="removed",
            omit_head=True,
            base=_side(10, 10, verdict=Verdict.HOLDS, recent=Counts(2, 0, 2)),
        ),
    ]
    result = _result(
        items,
        skipped=(SkippedFile("src/broken.py", "syntax error"),),
        notes=("a cap was hit",),
        markers=(("AGENTS.md", 99),),
        policy=_policy(
            after_merge=(
                "This PR changes thresholds in the config file; "
                "the change takes effect after merge",
            ),
            notes=("unknown key ignored",),
            disabled=frozenset({"money"}),
        ),
        errors=(
            InternalError(
                "core",
                "Exception: this part of the analysis could not finish; details are withheld",
            ),
        ),
        unlisted=1,
        incomplete=3,
    )
    body = render_summary(result, _ctx(read_only_reason="fork"))
    assert body.startswith("# conventiondrift\n\nCompare report.\n")
    assert "## Recent window" in body
    assert f"90 days ending at {ISO} (PR head {md(HEAD_SHA)})." in body
    assert f"Analyzer Python: {md('3.12.7')}" in body
    assert "Policy source: base" in body
    assert "The comment was skipped because the token is read-only (fork pull request)." in body
    assert "## Rules" in body
    assert "## Not verifiable" in body
    assert f"{md('AGENTS.md')} line 12: {md('Always keep functions small')}" in body
    assert "## Skipped files" in body
    assert f"{md('src/broken.py')}: syntax error" in body
    assert pre_existing_line(2) in body
    assert "## Ignored" in body
    assert "## Removed" in body
    assert "— removed; base Holds" in body
    assert "## Notes" in body
    assert md("a cap was hit") in body
    assert md("unknown key ignored") in body
    assert "Unattached ignore marker at" in body
    assert "Checker money is experimental, off by default." in body
    assert "## Unattached markers" not in body
    assert "## Disabled checkers" not in body
    assert "## Takes effect after merge" in body
    assert (
        md("This PR changes thresholds in the config file; the change takes effect after merge")
        in body
    )
    assert "1 conflict not listed" in body
    assert conflict_incomplete_note(3) in body
    assert "## Internal error" in body
    assert "Internal error in" in body
    notes_at = body.index("## Notes")
    after_at = body.index("## Takes effect after merge")
    assert notes_at < after_at
    assert body.index("Unattached ignore marker") > notes_at
    assert body.index("Checker money") > body.index("Unattached ignore marker")


def test_python_files_found_is_not_inferred() -> None:
    result = _result()
    present = render_summary(result, _ctx(python_files_found=True))
    missing = render_summary(result, _ctx(python_files_found=False))
    assert NO_PYTHON_FILES not in present
    assert NO_PYTHON_FILES in missing


def test_no_instruction_files_line_when_the_tuple_is_empty() -> None:
    body = render_summary(_result(instructions=False), _ctx())
    assert NO_INSTRUCTION_FILES in body


def test_head_only_summary_names_the_sha_and_omits_annotations() -> None:
    result = _result(
        [_item(_rule(), case=None, head=_side(4, 40), omit_base=True)],
        mode="head-only",
        head_only_reason="shallow clone",
    )
    ctx = _ctx(mode="head-only", head_kind="pr_head", window=False, policy_source="head")
    body = render_summary(result, ctx)
    assert "Head-only report." in body
    assert "No before/after comparison was made." in body
    assert "This is a shallow clone." in body
    assert f"check out with `{FETCH_DEPTH}`." in body
    assert FETCH_DEPTH in body
    assert f"Analyzed {md(HEAD_SHA)} (PR head)." in body
    assert "Gating was not applied." in body
    assert "## Recent window" not in body
    assert "finding not annotated" not in body
    assert render_annotations(result, ctx) == ()
    text = render_text(result, ctx)
    assert "head-only shallow clone" in text
    assert f"\n{FETCH_DEPTH}\n" in text
    assert f"analyzed {HEAD_SHA} (PR head)" in text
    assert "gating was not applied" in text


def test_head_only_checked_out_commit_wording() -> None:
    result = _result(mode="head-only", head_only_reason="no merge base")
    ctx = _ctx(mode="head-only", head_kind="checkout", window=False, policy_source="head")
    body = render_summary(result, ctx)
    assert "No merge-base exists." in body
    assert f"Analyzed {md(HEAD_SHA)} (checked-out commit)." in body


def test_dependabot_read_only_parenthetical() -> None:
    body = render_summary(_result(), _ctx(read_only_reason="dependabot"))
    assert "The comment was skipped because the token is read-only (Dependabot)." in body


def test_scan_summary_mentions_new_stale_and_head_window() -> None:
    result = _result([_item(_rule(), case=None)], mode="scan")
    ctx = _ctx(mode="scan")
    body = render_summary(result, ctx)
    assert "Scan report." in body
    assert f"90 days ending at {ISO} (HEAD {md(HEAD_SHA)})." in body
    assert "new-stale cannot be met in scan mode because there are no before/after cases." in body
    assert render_annotations(result, ctx) == ()


# --- hostile inputs (SR T-01) ----------------------------------------------------------


def test_summary_escapes_a_hostile_path_and_rule_text() -> None:
    rule = _rule(HOSTILE_TEXT, file=HOSTILE_PATH, line=1)
    body = render_summary(_result([_item(rule)]), _ctx())
    assert md(HOSTILE_PATH) in body
    assert md(HOSTILE_TEXT) in body
    assert "<img>" not in body or md(HOSTILE_TEXT) in body
    assert "\n::warning::" not in body
    assert f"{md(HOSTILE_PATH)} line 1: {md(HOSTILE_TEXT)}" in body


def test_text_hostile_rule_line_matches_the_layout_path_and_drops_the_id() -> None:
    rule = _rule(HOSTILE_TEXT, file=HOSTILE_PATH, line=1)
    line = next(
        row
        for row in render_text(
            _result([_item(rule, head=_side(0, 5), base=_side(0, 5))]), _ctx()
        ).splitlines()
        if row.startswith("rule ")
    )
    assert line.startswith("rule ")
    assert not line.startswith("::")
    assert repr(HOSTILE_PATH) in line
    assert "docs/" in line or "docs/\\n" in line
    # No separate id field: the path appears once as {file}:{line}, not twice.
    assert line.count(repr(HOSTILE_PATH)) == 1
    assert f"{HOSTILE_PATH!r}:1" in line
    assert f'"{HOSTILE_TEXT}"' in line
    assert "\n::warning" not in line


def test_text_never_starts_a_line_with_a_repo_path_or_command() -> None:
    cases = (
        "\n::warning::x",
        "foo%0A",
        "a:,b.md",
        "<img>.md",
        "pipe|.md",
        "tick`file.md",
    )
    for path in cases:
        rule = _rule("a rule", file=path, line=3)
        text = render_text(_result([_item(rule)]), _ctx())
        for row in text.splitlines():
            assert not row.startswith("::"), row
            assert "\n" not in row


def test_finding_annotation_escapes_hostile_path_title_and_message() -> None:
    rule = _rule(HOSTILE_TEXT, file=HOSTILE_PATH, line=1)
    lines = render_annotations(_result([_item(rule)]), _ctx())
    assert len(lines) == 1
    title = finding_annotation_title(rule.id)
    expected = (
        f"::warning file={workflow_prop(HOSTILE_PATH)},line=1,"
        f"title={workflow_prop(title)}::{workflow_cmd(HOSTILE_TEXT)}"
    )
    assert lines[0] == expected
    assert "%3A" in lines[0]
    assert "%250A" in lines[0]
    assert "\n" not in lines[0]


def test_annotation_property_escaping_for_comma_colon_and_percent() -> None:
    path = "a:,b%0A.md"
    rule = _rule("ok", file=path, line=2)
    line = render_annotations(_result([_item(rule)]), _ctx())[0]
    assert workflow_prop(path) in line
    assert "%2C" in line
    assert "%3A" in line
    assert "%250A" in line


def test_run_level_annotation_escapes_a_hostile_message() -> None:
    message = "\n::warning::x %"
    line = format_run_level_annotation(message)
    assert line == (f"::warning title={workflow_prop(RUN_LEVEL_TITLE)}::{workflow_cmd(message)}")
    assert "\n" not in line
    assert line.startswith("::warning title=")
    assert workflow_cmd(message) == "␊::warning::x %25"
    assert line.endswith("␊::warning::x %25")


# --- annotation cap and order (D-TL-86 #6, D-TL-25) ------------------------------------


def test_finding_annotations_follow_rule_results_order_and_stop_at_the_cap() -> None:
    items = _findings(MAX_FINDING_ANNOTATIONS + 2)
    result = _result(items)
    lines = render_annotations(result, _ctx())
    assert len(lines) == MAX_FINDING_ANNOTATIONS
    for index, item in enumerate(items[:MAX_FINDING_ANNOTATIONS]):
        rule = item.head_rule
        assert rule is not None
        assert f"line={rule.line}" in lines[index]
        assert workflow_cmd(rule.text) in lines[index]
    body = render_summary(result, _ctx())
    assert not_annotated_line(2) in body
    assert f"not-annotated {not_annotated_line(2)}" in render_text(result, _ctx())


def test_run_level_conflict_warning_is_extra_and_does_not_take_a_slot() -> None:
    items = _findings(MAX_FINDING_ANNOTATIONS + 2)
    result = _result(items, incomplete=3)
    lines = render_annotations(result, _ctx())
    assert len(lines) == 1 + MAX_FINDING_ANNOTATIONS
    assert lines[0] == format_run_level_annotation(conflict_incomplete_note(3))
    assert lines[0] == (
        f"::warning title={workflow_prop(RUN_LEVEL_TITLE)}::"
        f"{workflow_cmd(conflict_incomplete_note(3))}"
    )
    body = render_summary(result, _ctx())
    assert not_annotated_line(2) in body
    assert not_annotated_line(3) not in body


def test_exactly_the_cap_of_findings_has_no_omitted_line() -> None:
    result = _result(_findings(MAX_FINDING_ANNOTATIONS))
    assert len(render_annotations(result, _ctx())) == MAX_FINDING_ANNOTATIONS
    body = render_summary(result, _ctx())
    assert "not annotated" not in body
    over = _result(_findings(MAX_FINDING_ANNOTATIONS + 1))
    assert not_annotated_line(1) in render_summary(over, _ctx())
    assert not_annotated_line(1) == "1 finding not annotated"


def test_no_annotation_for_doubtful_or_non_stale_rules() -> None:
    nv = _item(
        _rule("Always keep functions small", line=2, checker=None, match=False),
        case=None,
        head=_side(0, 0, verdict=Verdict.NOT_VERIFIABLE),
        base=_side(0, 0, verdict=Verdict.NOT_VERIFIABLE),
    )
    conflict = _item(
        _rule("Use requests", line=3), conflict_total=1, conflict_with=("CLAUDE.md:1",)
    )
    insufficient = _item(
        _rule("Use pytest", line=4, checker="test-framework"),
        case=None,
        head=_side(0, 2, verdict=Verdict.INSUFFICIENT),
        base=_side(0, 2, verdict=Verdict.INSUFFICIENT),
    )
    holds = _item(
        _rule("Use pathlib", line=5, checker="logging"),
        case="fixed",
        head=_side(10, 10, verdict=Verdict.HOLDS),
        base=_side(8, 10, verdict=Verdict.CONTESTED),
    )
    ignored = _item(_rule("Ignored", line=6, ignored=True), case="made-stale-by-code")
    result = _result([nv, conflict, insufficient, holds, ignored])
    assert render_annotations(result, _ctx()) == ()
    assert not any(is_finding(item) for item in result.rule_results)


def test_pre_existing_count_uses_singular_and_plural_from_the_same_formatter() -> None:
    one = _result([_item(_rule(line=9), case="pre-existing-stale")])
    two = _result(
        [
            _item(_rule(line=9), case="pre-existing-stale"),
            _item(_rule("Use httpx", line=10), case="pre-existing-stale"),
        ]
    )
    assert pre_existing_line(1) in render_summary(one, _ctx())
    assert pre_existing_line(1) == "1 pre-existing stale rule"
    assert pre_existing_line(2) in render_summary(two, _ctx())
    assert pre_existing_line(2) == "2 pre-existing stale rules"


def test_conflicting_rules_section_names_both_files_and_verdicts() -> None:
    a = _rule("Use requests for HTTP calls", file="AGENTS.md", line=9)
    b = _rule("Use httpx for HTTP calls", file="CLAUDE.md", line=3)
    items = [
        _item(
            a,
            conflict_with=("CLAUDE.md:3",),
            conflict_total=1,
            head=_side(0, 40),
            base=_side(4, 40, verdict=Verdict.CONTESTED),
        ),
        _item(
            b,
            conflict_with=("AGENTS.md:9",),
            conflict_total=1,
            head=_side(40, 40, verdict=Verdict.HOLDS),
            base=_side(36, 40, verdict=Verdict.HOLDS),
        ),
    ]
    # Conflict.rules must be sorted
    pair = Conflict(("AGENTS.md:9", "CLAUDE.md:3"), "http-client")
    body = render_summary(_result(items, conflicts=(pair,)), _ctx())
    assert "## Conflicting rules" in body
    assert "AGENTS.md" in body and "CLAUDE.md" in body
    assert "head Stale / Holds" in body
    assert "base Contested / Holds" in body
    assert render_annotations(_result(items, conflicts=(pair,)), _ctx()) == ()


def test_notes_from_other_components_are_escaped_but_not_rewritten() -> None:
    note = "see <img> and | and `path`"
    body = render_summary(_result(notes=(note,)), _ctx())
    assert md(note) in body
    assert "see <img>" not in body.replace(md(note), "")


def test_text_report_covers_the_same_sections_as_the_summary() -> None:
    nv = _rule("Always keep functions small", line=12, checker=None, match=False)
    ignored = _rule("Use an ignored rule", line=15, ignored=True)
    removed_rule = _rule("Old rule", line=50)
    recent = Counts(2, 3, 5)
    items = [
        _item(
            _rule(),
            head=_side(0, 40, recent=recent),
            base=_side(4, 40, verdict=Verdict.CONTESTED, recent=recent),
        ),
        _item(
            nv,
            case=None,
            head=_side(
                0,
                0,
                verdict=Verdict.NOT_VERIFIABLE,
                recent_reason="no relevant sites in the window",
            ),
            base=_side(
                0,
                0,
                verdict=Verdict.NOT_VERIFIABLE,
                recent_reason="no relevant sites in the window",
            ),
        ),
        _item(ignored, case="pre-existing-stale", head=_side(1, 10), base=_side(1, 10)),
        _item(
            _rule("Use logging", line=40),
            case="pre-existing-stale",
            head=_side(1, 10),
            base=_side(1, 10),
        ),
        _item(
            removed_rule,
            case="removed",
            omit_head=True,
            base=_side(10, 10, verdict=Verdict.HOLDS, recent=Counts(2, 0, 2)),
        ),
    ]
    result = _result(
        items,
        skipped=(SkippedFile("src/broken.py", "syntax error"),),
        notes=("a cap was hit",),
        markers=(("AGENTS.md", 99),),
        policy=_policy(
            after_merge=(
                "This PR changes thresholds in the config file; "
                "the change takes effect after merge",
            ),
            notes=("unknown key ignored",),
            disabled=frozenset({"money"}),
        ),
        errors=(
            InternalError(
                "core",
                "Exception: this part of the analysis could not finish; details are withheld",
            ),
        ),
        unlisted=1,
        incomplete=3,
        instructions=False,
    )
    text = render_text(result, _ctx(read_only_reason="fork", python_files_found=False))
    assert text.startswith("conventiondrift text 1\nmode compare\n")
    assert f"analyzed {HEAD_SHA}" in text
    assert f"window 90 days ending {ISO} (PR head {HEAD_SHA})" in text
    assert "analyzer-python 3.12.7" in text
    assert "policy-source base" in text
    assert (
        "read-only The comment was skipped because the token is read-only (fork pull request)."
        in text
    )
    assert f"no-python {NO_PYTHON_FILES}" in text
    assert f"no-instruction {NO_INSTRUCTION_FILES}" in text
    assert 'rule AGENTS.md:9 "Use requests for HTTP calls" head Stale' in text
    assert "not-verifiable AGENTS.md:12" in text
    assert "skipped src/broken.py syntax error" in text
    assert f"pre-existing {pre_existing_line(2)}" in text
    assert "ignored AGENTS.md:15" in text
    assert "removed AGENTS.md:50" in text
    assert "note a cap was hit" in text
    assert "note unknown key ignored" in text
    assert "unattached AGENTS.md:99" in text
    assert "disabled money" in text
    assert "after-merge This PR changes thresholds" in text
    assert "the change takes effect after merge" in text
    assert "conflicts-unlisted 1 conflict not listed" in text
    assert f"conflict-incomplete {conflict_incomplete_note(3)}" in text
    assert "internal-error core" in text
    assert all(not row.startswith("::") for row in text.splitlines())
    assert text.endswith("\n") and "\r" not in text


def test_scan_text_uses_the_head_window_label() -> None:
    result = _result([_item(_rule(), case=None)], mode="scan")
    text = render_text(result, _ctx(mode="scan"))
    assert "mode scan" in text
    assert f"window 90 days ending {ISO} (HEAD {HEAD_SHA})" in text
    assert f"scan {scan_new_stale_line()}" in text


def test_summary_and_text_when_the_window_is_unavailable() -> None:
    result = _result()
    ctx = _ctx(window=False)
    body = render_summary(result, ctx)
    assert "## Recent window" in body
    assert "not available (no history)" in body
    text = render_text(result, ctx)
    assert "window not available (no history)" in text


def test_unknown_fixed_summary_kind_is_rejected() -> None:
    try:
        render_fixed_summary("not-a-kind")
    except ValueError as exc:
        assert "unknown fixed summary kind" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_incomplete_conflict_not_in_the_pair_list_uses_at_least() -> None:
    rule = _rule("Use requests for HTTP calls", line=9)
    item = _item(rule, conflict_total=4, conflict_incomplete=True, conflict_with=("CLAUDE.md:3",))
    body = render_summary(_result([item]), _ctx())
    assert "at least 4 partners" in body
    text = render_text(_result([item]), _ctx())
    assert "conflict AGENTS.md:9 head Stale base Stale" in text


def test_text_reprs_paths_that_start_with_command_marker_or_backslash() -> None:
    for path in ("::warning::x.md", r"foo\bar.md"):
        rule = _rule("a rule", file=path, line=3)
        line = next(
            row
            for row in render_text(_result([_item(rule)]), _ctx()).splitlines()
            if row.startswith("rule ")
        )
        assert (
            path not in line.split(" ", 2)[1]
            or line.split()[1].startswith("'")
            or line.split()[1].startswith('"')
        )
        assert path in line or path.encode("unicode_escape").decode() in line or repr(path) in line
        assert line.startswith("rule ")
