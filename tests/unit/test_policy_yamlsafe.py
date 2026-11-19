"""Unit tests for conventiondrift.policy.yamlsafe: the guarded config loader (T-011).

Expected values come from INTERFACES I-6 ("limited to 64 KiB", "nesting depth <= 10",
"no anchors or aliases"), SECURITY-RULES R1.3 (safe loader only, no Python object
tags) and the YAML 1.1 core types. Parameters are taken from the module's own
constants and category sets, and each test asserts it covers them (D-TL-25).
"""

import ast
import time
from pathlib import Path
from typing import get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import conventiondrift
from conventiondrift import policy
from conventiondrift.policy import yamlsafe
from conventiondrift.policy.yamlsafe import (
    CORE_TAGS,
    MAX_BYTES,
    MAX_DEPTH,
    REJECTION_NOTES,
    CoreLoader,
    Rejection,
    YamlRejected,
    load_yaml,
)

# I-6 / THREAT-MODEL: 64 KiB and depth 10; the seven YAML core schema tags.
SPEC_MAX_BYTES = 64 * 1024
SPEC_MAX_DEPTH = 10
SPEC_CORE_TAGS = {
    f"tag:yaml.org,2002:{t}" for t in ("null", "bool", "int", "float", "str", "seq", "map")
}
CANARY = "CANARY-7f3e"  # repo text that must never appear in a note


def reason_of(data: bytes | str) -> Rejection:
    with pytest.raises(YamlRejected) as caught:
        load_yaml(data)
    return caught.value.reason


@pytest.fixture
def expect_reason():  # type: ignore[no-untyped-def]
    def check(data: bytes | str, reason: Rejection) -> None:
        got = reason_of(data)
        assert got == reason
        with pytest.raises(YamlRejected) as caught:
            load_yaml(data)
        assert caught.value.note == REJECTION_NOTES[reason] == str(caught.value)
        text = data if isinstance(data, str) else data.decode("utf-8", "replace")
        if CANARY in text:
            assert CANARY not in caught.value.note
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None or caught.value.__suppress_context__

    return check


def test_constants_match_spec() -> None:
    assert MAX_BYTES == SPEC_MAX_BYTES
    assert MAX_DEPTH == SPEC_MAX_DEPTH
    assert set(CORE_TAGS) == SPEC_CORE_TAGS
    assert set(REJECTION_NOTES) == set(get_args(Rejection))


def test_load_yaml_is_reexported_from_policy() -> None:
    assert policy.load_yaml is load_yaml


I6_EXAMPLE = """\
version: 1                       # required to be 1
fail-on: none                    # none | new-stale | any-stale (Action input wins)
history-days: 90                 # 1..3650
thresholds:
  holds: 80                      # Holds: overall >= holds; 1..100
  stale:     { overall: 20, recent: 20 }
  migrating: { overall: 50, recent: 70 }
  min-sites: 5                   # 1..1000
exclude:
  - "legacy/**"
limits:
  max-file-bytes: 1048576        # 1024..1048576; may only be lowered (security first)
checkers:                        # ids are fixed (I-10)
  logging:        { enabled: true, script-paths: [
      "**/tests/**", "**/test/**", "**/scripts/**", "**/bin/**",
      "**/test_*.py", "**/*_test.py", "**/conftest.py"] }
  http-client:    { enabled: true }
  test-framework: { enabled: true }
  money:          { enabled: false }
  string-format:  { enabled: true }
  exceptions:     { enabled: true }
  type-hints:     { enabled: true }
  package-manager: { enabled: true }  # I-6 prints "package-manager:{" (no space); see QUESTION
ignore:                          # per-rule ignores
  - { file: "AGENTS.md", line: 9 }
  - { text: "Use requests for HTTP calls" }
"""


def test_i6_example_loads() -> None:
    doc = load_yaml(I6_EXAMPLE.encode())
    assert isinstance(doc, dict)
    assert doc["version"] == 1
    assert doc["thresholds"]["stale"] == {"overall": 20, "recent": 20}
    assert doc["checkers"]["package-manager"] == {"enabled": True}
    assert doc["checkers"]["logging"]["script-paths"][-1] == "**/conftest.py"
    assert doc["ignore"] == [
        {"file": "AGENTS.md", "line": 9},
        {"text": "Use requests for HTTP calls"},
    ]


def test_str_input_is_accepted() -> None:
    # The mutation-job guard (scripts/ci/check_mutation_yaml.py) calls load_yaml with text.
    assert load_yaml("key: value\n") == {"key": "value"}


def test_empty_document_is_none() -> None:
    assert load_yaml(b"") is None
    assert load_yaml(b"# only a comment\n") is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a: ~", None),
        ("a: null", None),
        ("a: true", True),
        ("a: no", False),
        ("a: 12", 12),
        ("a: 0x10", 16),
        ("a: 1.5", 1.5),
        ("a: hello", "hello"),
        # Not core: these stay strings instead of a datetime, a merge or a value marker.
        ("a: 2024-01-01", "2024-01-01"),
        ("a: 2001-12-14t21:59:43.10-05:00", "2001-12-14t21:59:43.10-05:00"),
        ("a: =", "="),
    ],
)
def test_only_core_scalars_resolve(text: str, expected: object) -> None:
    assert load_yaml(text.encode()) == {"a": expected}


def test_merge_key_is_a_plain_key() -> None:
    assert load_yaml(b"<<: {b: 1}\n") == {"<<": {"b": 1}}


def test_core_loader_keeps_only_core_implicit_tags() -> None:
    tags = {tag for entries in CoreLoader.yaml_implicit_resolvers.values() for tag, _ in entries}
    assert tags == {f"tag:yaml.org,2002:{t}" for t in ("null", "bool", "int", "float")}
    assert all(CoreLoader.yaml_implicit_resolvers.values())


# --- size (N-1, N, N+1) ---------------------------------------------------------


def padded(size: int) -> bytes:
    body = b"a: 1\n#"
    return body + b"x" * (size - len(body))


@pytest.mark.parametrize("size", [MAX_BYTES - 1, MAX_BYTES])
def test_size_at_or_under_cap_loads(size: int) -> None:
    data = padded(size)
    assert len(data) == size
    assert load_yaml(data) == {"a": 1}


def test_size_over_cap_rejected(expect_reason) -> None:  # type: ignore[no-untyped-def]
    data = padded(MAX_BYTES + 1)
    assert len(data) == MAX_BYTES + 1
    expect_reason(data, "size")


def test_str_size_counts_utf8_bytes(expect_reason) -> None:  # type: ignore[no-untyped-def]
    # 2-byte characters: MAX_BYTES // 2 + 1 characters is over the byte cap.
    text = "a: " + "\u00e9" * (MAX_BYTES // 2)
    assert len(text) < MAX_BYTES < len(text.encode())
    expect_reason(text, "size")


# --- encoding -------------------------------------------------------------------


def test_utf8_bom_is_dropped() -> None:
    assert load_yaml(b"\xef\xbb\xbfa: 1\n") == {"a": 1}
    assert load_yaml("\ufeffa: 1\n") == {"a": 1}


@pytest.mark.parametrize(
    "data",
    [b"a: \xff\n", b"\xff\xfea\x00:\x00 \x001\x00", "a: 1\n".encode("utf-16"), b"a: \xed\xa0\x80"],
)
def test_not_utf8_rejected(expect_reason, data: bytes) -> None:  # type: ignore[no-untyped-def]
    expect_reason(data, "encoding")


def test_lone_surrogate_text_rejected(expect_reason) -> None:  # type: ignore[no-untyped-def]
    expect_reason("a: \ud800\n", "encoding")


# --- depth (N-1, N, N+1), block and flow ------------------------------------------


def block_nesting(depth: int) -> str:
    lines = [f"{'  ' * level}k{level}:" for level in range(depth)]
    return "\n".join(lines) + " 1\n"


def flow_nesting(depth: int) -> str:
    return "a: " + "[" * (depth - 1) + "1" + "]" * (depth - 1) + "\n"


@pytest.mark.parametrize("build", [block_nesting, flow_nesting])
@pytest.mark.parametrize("depth", [MAX_DEPTH - 1, MAX_DEPTH])
def test_depth_at_or_under_cap_loads(build, depth: int) -> None:  # type: ignore[no-untyped-def]
    doc = load_yaml(build(depth))
    seen = 0
    while isinstance(doc, (dict, list)):
        seen += 1
        doc = next(iter(doc.values())) if isinstance(doc, dict) else doc[0]
    assert seen == depth


@pytest.mark.parametrize("build", [block_nesting, flow_nesting])
def test_depth_over_cap_rejected(expect_reason, build) -> None:  # type: ignore[no-untyped-def]
    expect_reason(build(MAX_DEPTH + 1), "depth")


def test_depth_counts_sequences_and_mappings_together(expect_reason) -> None:  # type: ignore[no-untyped-def]
    # Block mappings, then alternating flow sequences and mappings: depth 11, then 10.
    expect_reason("a:\n  b: [{c: [{d: [{e: [{f: [1]}]}]}]}]\n", "depth")
    assert load_yaml("a:\n  b: [{c: [{d: [{e: [{f: 1}]}]}]}]\n") is not None


def test_very_deep_input_stops_early_without_recursion_error(expect_reason) -> None:  # type: ignore[no-untyped-def]
    text = "[" * (MAX_BYTES - 1)
    start = time.perf_counter()
    expect_reason(text, "depth")
    assert time.perf_counter() - start < 2.0


def test_depth_resets_between_siblings() -> None:
    sibling = "a: " + "[" * (MAX_DEPTH - 1) + "1" + "]" * (MAX_DEPTH - 1)
    text = "\n".join(sibling.replace("a:", f"k{i}:") for i in range(5)) + "\n"
    assert isinstance(load_yaml(text), dict)


def test_depth_is_still_counted_after_an_earlier_sibling_closed(expect_reason) -> None:  # type: ignore[no-untyped-def]
    # Mapping (1) + list (2) + a chain of MAX_DEPTH - 1 lists = MAX_DEPTH + 1 deep, after a
    # short sibling list has already opened and closed in the same parent.
    chain = "[" * (MAX_DEPTH - 1) + "1" + "]" * (MAX_DEPTH - 1)
    expect_reason(f"a: [[1], {chain}]\n", "depth")
    short = "[" * (MAX_DEPTH - 2) + "1" + "]" * (MAX_DEPTH - 2)
    assert isinstance(load_yaml(f"a: [[1], {short}]\n"), dict)


# --- anchors and aliases ----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"a: &x {CANARY}\n",
        "a: &x {b: 1}\n",
        "a: &x [1]\n",
        "&x\na: 1\n",
        "a: &x\n  b: 1\n",
    ],
)
def test_anchor_rejected(expect_reason, text: str) -> None:  # type: ignore[no-untyped-def]
    expect_reason(text, "anchor")


@pytest.mark.parametrize("text", ["a: *x\n", "a: [*x]\n", "*x : 1\n"])
def test_alias_rejected(expect_reason, text: str) -> None:  # type: ignore[no-untyped-def]
    expect_reason(text, "alias")


def test_alias_bomb_rejected_quickly() -> None:
    # "Billion laughs": nine levels of nine aliases. Refused at the first anchor.
    lines = ['a0: &a0 ["lol"]']
    for level in range(1, 10):
        refs = ", ".join([f"*a{level - 1}"] * 9)
        lines.append(f"a{level}: &a{level} [{refs}]")
    start = time.perf_counter()
    assert reason_of("\n".join(lines) + "\n") in {"anchor", "alias"}
    assert time.perf_counter() - start < 1.0


# --- tags -------------------------------------------------------------------------

CORE_TAG_SAMPLES = {
    "tag:yaml.org,2002:null": ("!!null ''", None),
    "tag:yaml.org,2002:bool": ("!!bool true", True),
    "tag:yaml.org,2002:int": ("!!int '7'", 7),
    "tag:yaml.org,2002:float": ("!!float '1.5'", 1.5),
    "tag:yaml.org,2002:str": ("!!str 123", "123"),
    "tag:yaml.org,2002:seq": ("!!seq [1]", [1]),
    "tag:yaml.org,2002:map": ("!!map {b: 1}", {"b": 1}),
}


@pytest.mark.parametrize("tag", sorted(CORE_TAGS))
def test_explicit_core_tags_allowed(tag: str) -> None:
    assert set(CORE_TAG_SAMPLES) == set(CORE_TAGS)
    value, expected = CORE_TAG_SAMPLES[tag]
    assert load_yaml(f"a: {value}\n") == {"a": expected}
    verbatim = value.replace("!!" + tag.rsplit(":", 1)[1], f"!<{tag}>")
    assert load_yaml(f"a: {verbatim}\n") == {"a": expected}


# SEC-T02's five Python tags (TRACEABILITY), the other PyYAML safe-schema extras,
# local and non-specific tags, verbatim and %TAG-defined forms.
NON_CORE_TAGS = [
    "!!python/object:os.system",
    "!!python/object/apply:os.system",
    "!!python/object/new:os.system",
    "!!python/name:os.system",
    "!!python/module:os",
    "!!set",
    "!!omap",
    "!!pairs",
    "!!binary",
    "!!timestamp",
    "!!merge",
    "!!value",
    "!!yaml",
    "!local",
    "!",
    "!<tag:example.com,2000:x>",
    "!<tag:yaml.org,2002:python/object/apply:os.system>",
]


@pytest.mark.parametrize("tag", NON_CORE_TAGS)
@pytest.mark.parametrize("shape", ["scalar", "seq", "map"])
def test_non_core_tag_rejected(expect_reason, tag: str, shape: str) -> None:  # type: ignore[no-untyped-def]
    node = {"scalar": f"'{CANARY}'", "seq": f"[{CANARY}]", "map": f"{{c: {CANARY}}}"}[shape]
    expect_reason(f"a: {tag} {node}\n", "tag")


def test_tag_directive_resolving_outside_core_rejected(expect_reason) -> None:  # type: ignore[no-untyped-def]
    expect_reason("%TAG !e! tag:yaml.org,2002:python/\n---\na: !e!name:os.system x\n", "tag")


def test_tag_directive_resolving_to_core_allowed() -> None:
    assert load_yaml("%TAG !e! tag:yaml.org,2002:\n---\na: !e!str 1\n") == {"a": "1"}


def test_python_object_tag_runs_nothing(tmp_path: Path, expect_reason) -> None:  # type: ignore[no-untyped-def]
    # SEC-T02: the object/apply payload must not run.
    sentinel = tmp_path / "sentinel"
    text = f'a: !!python/object/apply:os.system ["touch {sentinel}"]\n'
    expect_reason(text, "tag")
    assert not sentinel.exists()


# --- documents and syntax ------------------------------------------------------------


def test_single_explicit_document_allowed() -> None:
    assert load_yaml(b"---\na: 1\n...\n") == {"a": 1}


@pytest.mark.parametrize("text", ["a: 1\n---\nb: 2\n", "---\na: 1\n...\n---\n", "--- 1\n--- 2\n"])
def test_more_than_one_document_rejected(expect_reason, text: str) -> None:  # type: ignore[no-untyped-def]
    expect_reason(text, "documents")


@pytest.mark.parametrize(
    "text",
    [
        f"a: [{CANARY}\n",
        "a: b: c\n",
        "\ta: 1\n",
        "a: 1\x00\n",
        f"a: !!int {CANARY}\n",
        "a: !!float x\n",
        "a: !!bool maybe\n",
        "a: !!int\n",
        "a: !!float ''\n",
        "? [1]\n: 2\n",
        "? {b: 1}\n: 2\n",
        "a: " + "1" * 5000 + "\n",
        "a: !!int '" + "1" * 5000 + "'\n",
    ],
)
def test_bad_yaml_rejected_as_syntax(expect_reason, text: str) -> None:  # type: ignore[no-untyped-def]
    expect_reason(text, "syntax")


# One sample per rejection class, so each class is pinned even when tests are selected.
REJECTION_SAMPLES: dict[str, bytes] = {
    "size": padded(MAX_BYTES + 1),
    "encoding": b"a: \xff\n",
    "syntax": b"a: [\n",
    "anchor": b"a: &x 1\n",
    "alias": b"a: *x\n",
    "tag": b"a: !!set {}\n",
    "depth": flow_nesting(MAX_DEPTH + 1).encode(),
    "documents": b"a: 1\n---\nb: 2\n",
}


@pytest.mark.parametrize("reason", sorted(get_args(Rejection)))
def test_every_rejection_class(expect_reason, reason: Rejection) -> None:  # type: ignore[no-untyped-def]
    assert set(REJECTION_SAMPLES) == set(get_args(Rejection))
    expect_reason(REJECTION_SAMPLES[reason], reason)


# --- static: only yamlsafe touches the vendored yaml (R1.3) ---------------------------


def test_only_yamlsafe_imports_vendored_yaml() -> None:
    root = Path(conventiondrift.__file__).parent
    importers = set()
    for path in root.rglob("*.py"):
        if "_vendor" in path.relative_to(root).parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            if any(
                n == "yaml" or n.startswith(("yaml.", "conventiondrift._vendor.yaml"))
                for n in names
            ):
                importers.add(path.relative_to(root).as_posix())
    assert importers == {"policy/yamlsafe.py"}
    assert Path(yamlsafe.__file__).resolve() == (root / "policy" / "yamlsafe.py").resolve()


# --- totality: any input is a value or a YamlRejected, nothing else -------------------

YAML_ALPHABET = st.sampled_from(
    [*"ab1.-_:#&*!%|>'\"[]{}?,=~<@` \t\n0x+e", "\x00", "\u00e9", "\ufeff", "\u2028", "\x85"]
    + [f"!!{name} " for name in ("int", "bool", "float", "null", "str", "seq", "map")]
    + ["? ", "- ", "--- ", "..."]
)


@settings(max_examples=400, deadline=None)
@given(st.lists(YAML_ALPHABET, max_size=60).map("".join))
def test_load_yaml_only_raises_yamlrejected(text: str) -> None:
    try:
        load_yaml(text.encode("utf-8"))
    except YamlRejected:
        pass


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=64))
def test_load_yaml_on_random_bytes(data: bytes) -> None:
    try:
        load_yaml(data)
    except YamlRejected:
        pass
