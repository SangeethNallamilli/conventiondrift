"""Unit tests for conventiondrift.policy.ignores: I-7 markers with alone_on_line (T-012).

Expected answers come from INTERFACES I-7 and the I-13 "C6 rulings" item 3.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from conventiondrift.policy.ignores import MARKER, find_markers, markers_by_file

M = "<!-- conventiondrift: ignore -->"  # I-7, verbatim


def test_marker_is_the_i7_text() -> None:
    assert MARKER == M


def test_same_line_and_alone_markers() -> None:
    data = f"# Rules\n- Use httpx {M}\n{M}\n- Use pytest\n".encode()
    assert find_markers(data) == ((2, False), (3, True))


def test_alone_allows_surrounding_whitespace() -> None:
    data = f"  {M}\t\n\t{M}\r\n{M}   \r\n".encode()
    assert find_markers(data) == ((1, True), (2, True), (3, True))


def test_bullet_or_text_beside_the_marker_is_not_alone() -> None:
    data = f"- {M}\n{M} note\n{M}{M}\n".encode()
    assert find_markers(data) == ((1, False), (2, False), (3, False))


def test_case_and_spacing_variants_are_not_markers() -> None:
    variants = [
        M.upper(),
        M.replace("ignore", "Ignore"),
        M.replace(": ", ":"),
        M.replace(" ", "  ", 1),
        "<!--conventiondrift: ignore-->",
        "<!-- conventiondrift : ignore -->",
    ]
    assert find_markers("\n".join(variants).encode()) == ()


def test_only_lf_ends_a_line() -> None:
    # VT, FF and U+2028 don't end a line (git and GitHub line numbers).
    data = f"a\vb\fc\u2028{M}\n{M}".encode()
    assert find_markers(data) == ((1, False), (2, True))


def test_bom_is_stripped_and_bad_bytes_are_tolerated() -> None:
    assert find_markers(b"\xef\xbb\xbf" + M.encode()) == ((1, True),)
    assert find_markers(b"\xff\xfe\n" + M.encode() + b" \xc3") == ((2, False),)


def test_no_markers() -> None:
    assert find_markers(b"") == ()
    assert find_markers(b"- Use httpx\n") == ()


def test_markers_by_file_sorts_and_drops_files_without_markers() -> None:
    files = {
        "z/AGENTS.md": M.encode(),
        "CLAUDE.md": b"- Use httpx\n",
        "AGENTS.md": b"x\n" + M.encode(),
    }
    result = markers_by_file(files)
    assert list(result) == ["AGENTS.md", "z/AGENTS.md"]
    assert result == {"AGENTS.md": ((2, True),), "z/AGENTS.md": ((1, True),)}


_LINE = st.one_of(
    st.just(M),
    st.builds(lambda a, b: f"{a}{M}{b}", st.sampled_from(["", " ", "\t", "- ", "x"]),
              st.sampled_from(["", " ", "\r", " y"])),
    st.text(alphabet="ab -<!>:", max_size=8),
)  # fmt: skip


@settings(derandomize=True, deadline=None, max_examples=300)
@given(st.lists(_LINE, max_size=12))
def test_property_one_sorted_pair_per_marker_line(lines: list[str]) -> None:
    pairs = find_markers("\n".join(lines).encode())
    expected = tuple(
        (i, line.removesuffix("\r").strip() == M)
        for i, line in enumerate(lines, start=1)
        if M in line
    )
    assert pairs == expected
    assert [p[0] for p in pairs] == sorted({p[0] for p in pairs})
