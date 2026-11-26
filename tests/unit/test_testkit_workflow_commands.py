"""Unit tests for the workflow-command parser in the testkit (CON-29).

Expected results are written from the real emitter: ``render.escape.workflow_cmd`` escapers, and
the round-trip boundary the Code Reviewer sharpened (a literal Control Picture in the source is
indistinguishable from a mapped one, and ``U+XXXX`` labels are one-way).
"""

from __future__ import annotations

import pytest

from conventiondrift.render.escape import workflow_cmd, workflow_prop
from conventiondrift_testkit.workflow_commands import Command, parse_commands, unescape


def test_a_warning_with_every_property_parses_into_fields() -> None:
    line = (
        f"::warning file={workflow_prop('src/a.py')},line=12,col=3,endLine=14,"
        f"title={workflow_prop('a, b')}::{workflow_cmd('the message')}"
    )
    (command,) = parse_commands(line)
    assert command.kind == "warning"
    assert command.message == "the message"
    assert command.file == "src/a.py"
    assert command.line == 12
    assert command.col == 3
    assert command.end_line == 14
    assert command.title == "a, b"
    assert command.raw == line


def test_unknown_kinds_and_properties_are_kept_not_rejected() -> None:
    (command,) = parse_commands("::future-thing custom=1,line=x::payload")
    assert command.kind == "future-thing"
    assert command.line is None  # "x" is not an integer: reported as absent, kept in properties
    assert command.properties["custom"] == "1"
    assert command.properties["line"] == "x"


def test_properties_are_split_on_raw_commas_then_unescaped() -> None:
    # A path containing a comma is escaped by the emitter as %2C; splitting after unescaping
    # would break it into two properties. This is the order the parser must keep.
    prop = workflow_prop("src/a,b.py")
    assert "%2C" in prop
    (command,) = parse_commands(f"::notice file={prop}::x")
    assert command.file == "src/a,b.py"
    assert "file" in command.properties and command.properties["file"] == "src/a,b.py"


def test_data_unescapes_percent_once_and_leaves_the_rest_literal() -> None:
    assert unescape("100%25 done") == "100% done"
    # The repo's escapers never emit %0A/%0D (controls arrive as pictures), so they stay literal.
    assert unescape("a%0Ab") == "a%0Ab"
    assert unescape("a%0Db") == "a%0Db"
    # One left-to-right pass: "%250A" is the literal text "%0A", not a newline.
    assert unescape("%250A") == "%0A"
    assert unescape("%2C and %3A are not data escapes") == "%2C and %3A are not data escapes"
    assert unescape("a\u240ab") == "a\nb"


def test_property_unescapes_comma_and_colon_before_percent() -> None:
    from conventiondrift_testkit.workflow_commands import unescape_property

    assert unescape_property("a%2Cb") == "a,b"
    assert unescape_property("a%3Ab") == "a:b"
    assert unescape_property("100%25") == "100%"
    # ":%2C" is not a double escape: one pass, so the literal text %2C survives.
    assert unescape_property("%252C") == "%2C"


def test_a_value_that_is_only_escapes_stays_a_property_not_a_second_split() -> None:
    (command,) = parse_commands("::error file=a%2Cb,x::m")
    # The segment with no "=" is dropped; a real property survives.
    assert command.properties == {"file": "a,b"}
    assert command.message == "m"


def test_lines_that_are_not_commands_are_ignored() -> None:
    text = "\n".join(
        [
            "plain output",
            "::not-a-command",  # no second "::"
            "::1bad kind::x",  # kind must start with a letter
            "",
            "::notice::kept",
        ]
    )
    (command,) = parse_commands(text)
    assert command.kind == "notice" and command.message == "kept"


def test_nested_line_records_are_flattened() -> None:
    lines = (("::warning file=a.py,line=1::one", "noise"), ("::error line=2::two",))
    assert [c.kind for c in parse_commands(lines)] == ["warning", "error"]
    assert [c.line for c in parse_commands(lines)] == [1, 2]


def test_a_command_with_no_data_has_an_empty_message() -> None:
    (command,) = parse_commands("::group::")
    assert command.kind == "group" and command.message == ""


def test_properties_are_read_only() -> None:
    (command,) = parse_commands("::notice file=a::x")
    with pytest.raises(TypeError):
        command.properties["file"] = "b"  # type: ignore[index]


def test_round_trip_inverts_the_picture_and_is_ambiguous_only_for_a_literal_picture() -> None:
    """The emitter writes a newline as U+240A; the parser inverts it, so the text round-trips."""
    message = "line1\nline2"
    emitted = workflow_cmd(message)
    assert "\u240a" in emitted and "\n" not in emitted
    (command,) = parse_commands(f"::warning::{emitted}")
    assert command.message == message

    # The documented ambiguity: a source that already contained U+240A looks identical to a
    # mapped newline, so it comes back as a newline. One input is lossy by construction.
    literal = "already \u240a a picture"
    (again,) = parse_commands(f"::warning::{workflow_cmd(literal)}")
    assert again.message == "already \n a picture" != literal


def test_the_label_form_is_not_inverted() -> None:
    """Cf/Zl/Zp/Cs become a one-way "U+XXXX" label; the parser must leave it alone."""
    mapped = workflow_cmd("zero\u200bwidth")
    (command,) = parse_commands(f"::notice::{mapped}")
    assert command.message == "zeroU+200Bwidth"


def test_command_equality_and_defaults() -> None:
    (command,) = parse_commands("::notice::x")
    assert command == Command(
        kind="notice", message="x", properties=command.properties, raw="::notice::x"
    )
    assert command.file is None and command.line is None and command.col is None
