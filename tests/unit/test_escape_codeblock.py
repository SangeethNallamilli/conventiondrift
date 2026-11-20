"""Unit tests for ``md_codeblock``, the seventh escape sink (T-024; INTERFACES I-14 items 1-8).

Names avoid the ``test_ac_`` prefix and ``tests/unit/test_escape.py`` is not touched: both belong
to the Test Engineer. Expected values come from the INTERFACES text, never from the code.
"""

import re

import pytest

from conventiondrift.render.escape import MAX_CODEBLOCK_LINE, md_codeblock

# Every character Python's str.splitlines() treats as a line break (docs, str.splitlines).
SPLITLINES_SEPARATORS = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"
# I-14 item 6: bidi controls, zero-width and BOM characters (category Cf), as U+XXXX text.
CF_CHARS = [*"\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e", "\u2066", "\ufeff"]


def _fence_of(block: str) -> str:
    return block.split("\n", 1)[0].rstrip("abcdefghijklmnopqrstuvwxyz0123456789-")


def test_fixture_block_is_a_plain_fence_around_the_lines() -> None:
    # I-14 item 3: no backtick in any line, so the fence is exactly three backticks.
    assert md_codeblock(["a", "   b", ""]) == "```\na\n   b\n\n```"


def test_empty_sequence_gives_an_empty_block() -> None:
    assert md_codeblock([]) == "```\n\n```"


@pytest.mark.parametrize(
    ("backticks", "fence_len"),
    [(1, 3), (2, 3), (3, 4), (10, 11), (990, 991)],
)
def test_fence_is_one_longer_than_the_longest_run(backticks: int, fence_len: int) -> None:
    block = md_codeblock([f"x {'`' * backticks} y"])
    assert block == f"{'`' * fence_len}\nx {'`' * backticks} y\n{'`' * fence_len}"


def test_fence_follows_the_longest_run_in_any_line() -> None:
    block = md_codeblock(["`", "``", "   ``````", "a"])
    assert block.startswith("```````\n")
    assert block.endswith("\n```````")


@pytest.mark.parametrize("line", ["```", "   ```", "```python", "~~~", "    ```x"])
def test_no_line_can_close_the_fence(line: str) -> None:
    block = md_codeblock(["before", line, "after"])
    fence = _fence_of(block)
    inner = block.split("\n")[1:-1]
    # A closing fence is a line of at least len(fence) backticks and nothing else.
    assert not any(re.fullmatch(rf" {{0,3}}`{{{len(fence)},}}\s*", row) for row in inner)
    assert inner == ["before", line, "after"]


def test_markdown_html_mentions_and_references_stay_as_is() -> None:
    lines = ["@user", "<img src=x onerror=1>", "[x](https://e.example)", "#1", "**b**", "&amp;"]
    assert md_codeblock(lines) == "```\n" + "\n".join(lines) + "\n```"


def test_lf_cr_and_unicode_separators_are_mapped_inside_a_line() -> None:
    block = md_codeblock(["a\nb\rc\u2028d"])
    assert block == "```\na\u240ab\u240dc" + "U+2028" + "d\n```"


def test_every_splitlines_separator_keeps_one_line_per_input_line() -> None:
    lines = [f"x{sep}y" for sep in SPLITLINES_SEPARATORS] + [SPLITLINES_SEPARATORS, ""]
    block = md_codeblock(lines)
    assert len(block.splitlines()) == len(lines) + 2
    assert len(block.split("\n")) == len(lines) + 2


@pytest.mark.parametrize("char", CF_CHARS)
def test_bidi_and_zero_width_characters_become_visible_text(char: str) -> None:
    block = md_codeblock([f"a{char}b"])
    assert f"aU+{ord(char):04X}b" in block
    assert char not in block


def test_u0085_is_shown_as_text_and_c0_as_control_pictures() -> None:
    assert md_codeblock(["\x85\x1b\x7f\x00"]) == "```\nU+0085\u241b\u2421\u2400\n```"


def test_line_of_exactly_the_limit_is_kept_whole() -> None:
    line = "a" * MAX_CODEBLOCK_LINE
    assert md_codeblock([line]) == f"```\n{line}\n```"


def test_line_one_over_the_limit_is_cut_with_a_marker() -> None:
    block = md_codeblock(["a" * (MAX_CODEBLOCK_LINE + 1)])
    assert block == f"```\n{'a' * 1000} [\u20261 more chars]\n```"


def test_cut_counts_mapped_characters() -> None:
    # Each NUL maps to one character, each U+0085 to the 7 characters "U+0085".
    block = md_codeblock(["\x85" * 200])
    assert block == "```\n" + ("U+0085" * 200)[:1000] + " [\u2026200 more chars]\n```"


def test_limit_constant_is_one_thousand() -> None:
    assert MAX_CODEBLOCK_LINE == 1000


def test_a_huge_backtick_line_is_cut_before_the_fence_is_sized() -> None:
    block = md_codeblock(["`" * 60_000])
    fence = "`" * 1001  # 1000 kept backticks, plus one
    assert block.startswith(fence + "\n")
    assert block.endswith("\n" + fence)
    assert "[\u202659000 more chars]" in block
    assert len(block) < 3 * 1001 + 100


def test_only_kept_backticks_count_towards_the_fence() -> None:
    # 1000 kept characters hold no backtick, so the fence stays at three.
    block = md_codeblock(["a" * 1000 + "`" * 500])
    assert block.startswith("```\n")
    assert block.endswith("more chars]\n```")


@pytest.mark.parametrize("info", ["", "diff", "a-b-9", "x" * 32])
def test_valid_info_goes_after_the_fence(info: str) -> None:
    assert md_codeblock(["a"], info) == f"```{info}\na\n```"


@pytest.mark.parametrize("info", ["Diff", "a b", "a\n", "x" * 33, "py`", "é", "a_b", "x\ny"])
def test_bad_info_raises(info: str) -> None:
    with pytest.raises(ValueError, match="info"):
        md_codeblock(["a"], info)


def test_accepts_any_sequence_of_lines() -> None:
    assert md_codeblock(("a", "b")) == md_codeblock(["a", "b"])
