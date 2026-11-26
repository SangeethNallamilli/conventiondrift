"""The in-repo I-9 contract text is present, scoped, and pointed at from the code (CON-71).

The two notes are documentation, so nothing else in the suite would notice if the text were
deleted, reworded into something weaker, or the file were mistaken for the whole INTERFACES.md.
These assertions pin the three properties the review asked for: the file exists at the repo root,
it says it is an extract of I-9 only, and the JSON renderer points at it.
"""

from __future__ import annotations

from pathlib import Path

from conventiondrift.render.jsonreport import render_json

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "INTERFACES.md"
JSON_REPORT = ROOT / "src" / "conventiondrift" / "render" / "jsonreport.py"


def test_the_contract_file_exists_at_the_repo_root() -> None:
    assert CONTRACT.is_file(), "INTERFACES.md (I-9 extract) must be versioned with the code"


def test_the_extract_is_scoped_to_i9_and_says_so() -> None:
    text = CONTRACT.read_text(encoding="utf-8")
    assert "in-repo extract" in text
    assert "only the I-9 JSON report" in text
    # It must not pretend to be the whole contract: the other interfaces stay team docs.
    assert "not yet in this repository" in text


def test_both_review_notes_are_present() -> None:
    text = CONTRACT.read_text(encoding="utf-8")
    assert "### I-9.1 Report strings are raw data" in text
    assert "must escape it for that sink" in text
    assert "### I-9.2 Lone surrogates are emitted, not rejected" in text
    assert "not strict I-JSON" in text
    assert "RFC 7493" in text


def test_the_json_renderer_points_at_the_contract() -> None:
    docstring = JSON_REPORT.read_text(encoding="utf-8").split('"""')[1]
    assert "INTERFACES.md" in docstring
    assert "I-9" in docstring


# --- the two notes are load-bearing, not folklore (TE content proofs) ----------------------


def test_report_strings_are_raw_data_for_every_sink() -> None:
    """I-9.1: a value is a JSON string and nothing else - no HTML, shell, Markdown or terminal
    escaping is applied, so a consumer must escape it for its own sink."""
    import json

    from render_support import item, policy, result, rule

    payload = "<script>alert(1)</script> $(touch /tmp/p) `x` %s | ; & > out"
    report = json.loads(
        render_json(
            result(
                [item(rule(payload, file="docs/a&b.html"))],
                the_policy=policy(notes=(payload,)),
                instruction_paths=(payload,),
            )
        )
    )
    assert report["rules"][0]["text"] == payload
    assert report["rules"][0]["file"] == "docs/a&b.html"
    assert report["policy"]["notes"] == [payload]
    assert report["instruction_files"] == [payload]
    text = render_json(result([item(rule(payload))], the_policy=policy(notes=(payload,))))
    assert payload in text, "no sink escaping: the raw characters survive inside the JSON string"


def test_a_lone_surrogate_is_emitted_as_an_escape_not_rejected() -> None:
    """I-9.2: valid JSON, but not strict I-JSON (RFC 7493 2.1) - and never a crash."""
    import json

    from render_support import item, result, rule

    text = render_json(result([item(rule("x\ud800y", file="a\ud800b.md"))]))
    assert text.isascii()
    assert "\\ud800" in text, "the surrogate is written as a \\uXXXX escape, not dropped"
    loaded = json.loads(text)  # the JSON grammar accepts an unpaired escape
    assert loaded["rules"][0]["text"] == "x\ud800y"
    assert loaded["rules"][0]["file"] == "a\ud800b.md"
    # The proof that it is not I-JSON: the parsed value cannot be encoded as UTF-8.
    try:
        loaded["rules"][0]["text"].encode("utf-8")
    except UnicodeEncodeError:
        pass
    else:  # pragma: no cover - would mean the surrogate was silently replaced
        raise AssertionError("a lone surrogate must not be silently repaired")
