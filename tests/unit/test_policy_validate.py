"""Unit tests for conventiondrift.policy.validate: I-6 schema to ``SideConfig`` (T-011).

Expected answers are copied from INTERFACES I-6 (keys, ranges, "an unknown key or an
invalid value gets a summary note and that setting's default"), DESIGN §10 S1
(threshold order), AC-F4.10, AC-F9.9, AC-F9.11 and AC-N3.8. Parameters come from the
module's constants, and each test asserts it covers them (D-TL-25).
"""

import dataclasses
from collections.abc import Mapping
from typing import Any, get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conventiondrift.core import FailOn
from conventiondrift.model import CheckerId, CheckerPolicy, IgnoreEntry, Thresholds
from conventiondrift.policy import DEFAULT_CONFIG_PATH, load_yaml
from conventiondrift.policy.config import (
    DEFAULT_CHECKERS,
    DEFAULT_LOGGING_SCRIPT_PATHS,
    HISTORY_DAYS_RANGE,
    THRESHOLD_RANGES,
    SideConfig,
    check_ranges,
)
from conventiondrift.policy.validate import (
    CHECKER_KEYS,
    IGNORE_KEYS,
    LIMIT_KEYS,
    MAX_FILE_BYTES_RANGE,
    NOTE_NOT_MAPPING,
    NOTE_THRESHOLD_ORDER,
    NOTE_VERSION,
    SHOWN_MAX,
    THRESHOLD_KEYS,
    TOP_LEVEL_KEYS,
    UNKNOWN_KEY_NOTES_MAX,
    checked_config_path,
    contained_path,
    parse_side_config,
    validate_document,
)
from conventiondrift.policy.yamlsafe import MAX_BYTES, REJECTION_NOTES

# I-6 text.
SPEC_TOP_LEVEL = {
    "version",
    "fail-on",
    "history-days",
    "thresholds",
    "exclude",
    "limits",
    "checkers",
    "ignore",
}
SPEC_DEFAULT_THRESHOLDS = Thresholds(
    holds=80,
    stale_overall=20,
    stale_recent=20,
    migrating_overall=50,
    migrating_recent=70,
    min_sites=5,
)
SPEC_MAX_FILE_BYTES = (1024, 1048576)
SPEC_HISTORY_DAYS = (1, 3650)


def doc(**settings_: Any) -> dict[str, Any]:
    """A version-1 document with I-6 keys given as Python names (fail_on -> fail-on)."""
    return {"version": 1, **{k.replace("_", "-"): v for k, v in settings_.items()}}


def test_constants_match_spec() -> None:
    assert set(TOP_LEVEL_KEYS) == SPEC_TOP_LEVEL
    assert set(THRESHOLD_KEYS) == {"holds", "stale", "migrating", "min-sites"}
    assert LIMIT_KEYS == ("max-file-bytes",)
    assert set(CHECKER_KEYS) == set(get_args(CheckerId))
    assert CHECKER_KEYS["logging"] == ("enabled", "script-paths")
    assert all(keys == ("enabled",) for cid, keys in CHECKER_KEYS.items() if cid != "logging")
    assert set(IGNORE_KEYS) == {"file", "line", "text"}
    assert MAX_FILE_BYTES_RANGE == SPEC_MAX_FILE_BYTES
    assert HISTORY_DAYS_RANGE == SPEC_HISTORY_DAYS
    assert DEFAULT_CONFIG_PATH == ".conventiondrift.yml"


# --- the I-6 example and the AC configs --------------------------------------------

I6_EXAMPLE = b"""\
version: 1
fail-on: none
history-days: 90
thresholds:
  holds: 80
  stale:     { overall: 20, recent: 20 }
  migrating: { overall: 50, recent: 70 }
  min-sites: 5
exclude:
  - "legacy/**"
limits:
  max-file-bytes: 1048576
checkers:
  logging:        { enabled: true, script-paths: [
      "**/tests/**", "**/test/**", "**/scripts/**", "**/bin/**",
      "**/test_*.py", "**/*_test.py", "**/conftest.py"] }
  http-client:    { enabled: true }
  test-framework: { enabled: true }
  money:          { enabled: false }
  string-format:  { enabled: true }
  exceptions:     { enabled: true }
  type-hints:     { enabled: true }
  package-manager: { enabled: true }
ignore:
  - { file: "AGENTS.md", line: 9 }
  - { text: "Use requests for HTTP calls" }
"""


def test_i6_example_validates_with_no_notes() -> None:
    config = parse_side_config(I6_EXAMPLE)
    assert config == SideConfig(
        fail_on="none",
        history_days=90,
        thresholds=SPEC_DEFAULT_THRESHOLDS,
        exclude=("legacy/**",),
        max_file_bytes=1048576,
        checkers={
            cid: CheckerPolicy(
                enabled=cid != "money",
                script_paths=DEFAULT_LOGGING_SCRIPT_PATHS if cid == "logging" else (),
            )
            for cid in get_args(CheckerId)
        },
        ignores=(
            IgnoreEntry(file="AGENTS.md", line=9, text=None),
            IgnoreEntry(file=None, line=None, text="Use requests for HTTP calls"),
        ),
        notes=(),
    )


def test_i6_example_as_printed_has_a_yaml_typo() -> None:
    # I-6 prints "package-manager:{ enabled: true }" with no space after the colon. YAML
    # reads that as one plain key, so the line becomes an unknown key (QUESTION to the
    # Architect / Technical Writer). The run still works: a note, nothing else.
    printed = I6_EXAMPLE.replace(b"package-manager: {", b"package-manager:{")
    config = parse_side_config(printed)
    assert "package-manager" not in config.checkers
    assert config.notes == ('Unknown config key "checkers.package-manager:{ enabled" was ignored',)


def test_ac_f4_10_config_thresholds_and_window() -> None:
    # AC-F4.10: Holds 90, Stale 30/30, Migrating 60/60, minimum sites 3, window 30 days.
    config = parse_side_config(
        b"version: 1\nhistory-days: 30\nthresholds:\n  holds: 90\n"
        b"  stale: {overall: 30, recent: 30}\n  migrating: {overall: 60, recent: 60}\n"
        b"  min-sites: 3\n"
    )
    assert config.notes == ()
    assert config.history_days == 30
    assert config.thresholds == Thresholds(
        holds=90,
        stale_overall=30,
        stale_recent=30,
        migrating_overall=60,
        migrating_recent=60,
        min_sites=3,
    )


def test_ac_f9_9_settings_take_effect() -> None:
    # AC-F9.9: thresholds, an added exclude, type-hints disabled, one ignore by file+line and
    # one by text.
    config = parse_side_config(
        b"version: 1\nthresholds: {min-sites: 3}\nexclude: [legacy/]\n"
        b"checkers: {type-hints: {enabled: false}}\n"
        b"ignore: [{file: AGENTS.md, line: 4}, {text: Use pytest}]\n"
    )
    assert config.notes == ()
    assert config.thresholds == dataclasses.replace(SPEC_DEFAULT_THRESHOLDS, min_sites=3)
    assert config.exclude == ("legacy/",)
    assert config.checkers == {"type-hints": CheckerPolicy(enabled=False, script_paths=())}
    assert config.ignores == (
        IgnoreEntry(file="AGENTS.md", line=4, text=None),
        IgnoreEntry(file=None, line=None, text="Use pytest"),
    )


def test_ac_f9_11_threshold_of_150() -> None:
    # AC-F9.11: "a threshold of 150": the summary names the setting and the default is used.
    config = parse_side_config(b"version: 1\nthresholds: {holds: 150}\n")
    assert config.thresholds == SPEC_DEFAULT_THRESHOLDS
    assert config.notes == (
        "thresholds.holds must be an integer from 1 to 100; the default 80 is used",
    )


def test_unset_settings_stay_unset() -> None:
    assert validate_document({"version": 1}) == SideConfig()


# --- whole-file rejection ---------------------------------------------------------------


@pytest.mark.parametrize("version", [None, 0, 2, "1", True, 1.0, [1]])
def test_version_other_than_1_ignores_whole_file(version: object) -> None:
    document: dict[str, object] = {"fail-on": "any-stale", "history-days": 7}
    if version is not None:
        document["version"] = version
    assert validate_document(document) == SideConfig(notes=(NOTE_VERSION,))


@pytest.mark.parametrize("document", [[1, 2], "text", 3, 1.5, True])
def test_non_mapping_document_ignores_whole_file(document: object) -> None:
    assert validate_document(document) == SideConfig(notes=(NOTE_NOT_MAPPING,))


def test_empty_file_has_no_version() -> None:
    assert parse_side_config(b"") == SideConfig(notes=(NOTE_VERSION,))


@pytest.mark.parametrize("reason", sorted(REJECTION_NOTES))
def test_refused_yaml_ignores_whole_file(reason: str) -> None:
    samples = {
        "size": b"version: 1\n#" + b"x" * MAX_BYTES,
        "encoding": b"version: 1\nfail-on: \xff\n",
        "syntax": b"version: 1\nfail-on: [\n",
        "anchor": b"version: 1\nfail-on: &a any-stale\n",
        "alias": b"version: 1\nfail-on: *a\n",
        "tag": b"version: 1\nfail-on: !!python/name:os.system any-stale\n",
        "depth": b"version: 1\nexclude: " + b"[" * 10 + b"a" + b"]" * 10 + b"\n",
        "documents": b"version: 1\n---\nversion: 1\n",
    }
    assert set(samples) == set(REJECTION_NOTES)
    config = parse_side_config(samples[reason])
    assert config == SideConfig(notes=(REJECTION_NOTES[reason],))  # type: ignore[index]


# --- unknown keys -----------------------------------------------------------------------

UNKNOWN_KEY_CASES = {
    "": doc(bogus=1),
    "thresholds.": doc(thresholds={"bogus": 1}),
    "thresholds.stale.": doc(thresholds={"stale": {"bogus": 1}}),
    "thresholds.migrating.": doc(thresholds={"migrating": {"bogus": 1}}),
    "limits.": doc(limits={"bogus": 1}),
    "checkers.": doc(checkers={"bogus": {}}),
    **{f"checkers.{cid}.": doc(checkers={cid: {"bogus": 1}}) for cid in get_args(CheckerId)},
    "ignore[1].": doc(ignore=[{"text": "x", "bogus": 1}]),
}


@pytest.mark.parametrize("prefix", sorted(UNKNOWN_KEY_CASES))
def test_unknown_key_is_named_and_ignored(prefix: str) -> None:
    config = validate_document(UNKNOWN_KEY_CASES[prefix])
    assert config.notes == (f'Unknown config key "{prefix}bogus" was ignored',)


@pytest.mark.parametrize("cid", [c for c in get_args(CheckerId) if c != "logging"])
def test_script_paths_is_unknown_except_for_logging(cid: CheckerId) -> None:
    config = validate_document(doc(checkers={cid: {"script-paths": ["x/**"]}}))
    assert config.checkers[cid] == DEFAULT_CHECKERS[cid]
    assert config.notes == (f'Unknown config key "checkers.{cid}.script-paths" was ignored',)


@pytest.mark.parametrize("extra", [0, 1, 5])
def test_unknown_key_notes_are_capped(extra: int) -> None:
    count = UNKNOWN_KEY_NOTES_MAX + extra
    config = validate_document({"version": 1, **{f"k{i:03}": i for i in range(count)}})
    shown = [n for n in config.notes if n.startswith("Unknown config key")]
    assert len(shown) == UNKNOWN_KEY_NOTES_MAX
    assert len(config.notes) == UNKNOWN_KEY_NOTES_MAX + (1 if extra else 0)
    if extra:
        assert config.notes[-1] == f"{extra} more unknown config keys were ignored"


@pytest.mark.parametrize("length", [SHOWN_MAX - 1, SHOWN_MAX, SHOWN_MAX + 1])
def test_long_key_is_cut_in_the_note(length: int) -> None:
    key = "k" * length
    (note,) = validate_document({"version": 1, key: 1}).notes
    shown = key if length <= SHOWN_MAX else "k" * (SHOWN_MAX - 1) + "\u2026"
    assert note == f'Unknown config key "{shown}" was ignored'


@pytest.mark.parametrize(
    ("key", "shown"),
    [(5, "<int key>"), (1.5, "<float key>"), (True, "<bool key>"), (None, "<NoneType key>")],
)
def test_non_string_key_is_named_by_its_type(key: object, shown: str) -> None:
    config = validate_document({"version": 1, key: 1})
    assert config.notes == (f'Unknown config key "{shown}" was ignored',)


# SR M-51-1: int keys too long for repr (int max str digits) at every level that
# names unknown keys; hex and binary build any length, sexagesimal is base 60.
HUGE_INT_KEYS = ["0x" + "f" * 5000, "0b" + "1" * 20000, ":".join(["59"] * 3000)]
HUGE_KEY_PLACES = {
    "": "? {n}\n: 1",
    "thresholds.": "thresholds:\n  ? {n}\n  : 1",
    "thresholds.stale.": "thresholds:\n  stale:\n    ? {n}\n    : 1",
    "limits.": "limits:\n  ? {n}\n  : 1",
    "checkers.": "checkers:\n  ? {n}\n  : {{}}",
    "checkers.logging.": "checkers:\n  logging:\n    ? {n}\n    : 1",
    "ignore[1].": "ignore:\n  - text: x\n    ? {n}\n    : 1",
}


@pytest.mark.parametrize("number", HUGE_INT_KEYS, ids=["hex", "binary", "sexagesimal"])
@pytest.mark.parametrize("prefix", sorted(HUGE_KEY_PLACES))
def test_huge_int_key_is_named_by_its_type(number: str, prefix: str) -> None:
    text = f"version: 1\n{HUGE_KEY_PLACES[prefix].format(n=number)}\n"
    loaded = load_yaml(text.encode())
    assert isinstance(loaded, dict)
    with pytest.raises(ValueError):  # the key really is too long for repr
        repr(next(k for k in _keys(loaded) if not isinstance(k, str)))
    config = validate_document(loaded)
    assert config.notes == (f'Unknown config key "{prefix}<int key>" was ignored',)


def _keys(value: object) -> list[object]:
    if isinstance(value, dict):
        return [k for key, item in value.items() for k in (key, *_keys(item))]
    if isinstance(value, list):
        return [k for item in value for k in _keys(item)]
    return []


def test_huge_int_key_repro_from_the_security_review() -> None:
    loaded = load_yaml(b"version: 1\n? 0x" + b"f" * 5000 + b"\n: 1\n")
    assert isinstance(loaded, dict)
    assert validate_document(loaded).notes == ('Unknown config key "<int key>" was ignored',)


# --- fail-on and history-days -----------------------------------------------------------


@pytest.mark.parametrize("value", get_args(FailOn))
def test_fail_on_valid(value: str) -> None:
    assert validate_document(doc(fail_on=value)) == SideConfig(fail_on=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["None", "NEW-STALE", "any_stale", "", "none ", None, 1, True])
def test_fail_on_invalid_gets_note_and_default(value: object) -> None:
    assert validate_document(doc(fail_on=value)) == SideConfig(
        notes=("fail-on must be none, new-stale or any-stale; the default none is used",)
    )


def boundaries(low: int, high: int) -> list[tuple[int, bool]]:
    return [
        (low - 1, False),
        (low, True),
        (low + 1, True),
        (high - 1, True),
        (high, True),
        (high + 1, False),
    ]


@pytest.mark.parametrize(("value", "valid"), boundaries(*HISTORY_DAYS_RANGE))
def test_history_days_range(value: int, valid: bool) -> None:
    config = validate_document(doc(history_days=value))
    if valid:
        assert config == SideConfig(history_days=value)
    else:
        assert config == SideConfig(
            notes=("history-days must be an integer from 1 to 3650; the default 90 is used",)
        )


@pytest.mark.parametrize("value", [True, "90", 90.0, None, [90]])
def test_history_days_wrong_type(value: object) -> None:
    config = validate_document(doc(history_days=value))
    assert config.history_days is None
    assert config.notes == (
        "history-days must be an integer from 1 to 3650; the default 90 is used",
    )


# --- thresholds ---------------------------------------------------------------------------

THRESHOLD_FIELDS = tuple(THRESHOLD_RANGES)


def thresholds_doc(values: Mapping[str, object]) -> dict[str, Any]:
    """I-6 ``thresholds`` block from ``Thresholds`` field names."""
    block: dict[str, Any] = {}
    for name, value in values.items():
        key = THRESHOLD_RANGES[name][0].removeprefix("thresholds.")
        group, _, leaf = key.partition(".")
        if leaf:
            block.setdefault(group, {})[leaf] = value
        else:
            block[group] = value
    return doc(thresholds=block)


def companions(name: str) -> dict[str, int]:
    """Other thresholds chosen so the S1 order holds for any in-range value of ``name``."""
    base = {"holds": 100, "stale_overall": 0, "stale_recent": 0, "migrating_recent": 100}
    base["migrating_overall"] = 100 if name in ("stale_overall", "migrating_overall") else 0
    if name == "migrating_overall":
        base["migrating_overall"] = 0
    base.pop(name, None)
    return base


def test_threshold_ranges_match_spec() -> None:
    assert dict(THRESHOLD_RANGES) == {
        "holds": ("thresholds.holds", 1, 100),
        "stale_overall": ("thresholds.stale.overall", 0, 100),
        "stale_recent": ("thresholds.stale.recent", 0, 100),
        "migrating_overall": ("thresholds.migrating.overall", 0, 100),
        "migrating_recent": ("thresholds.migrating.recent", 0, 100),
        "min_sites": ("thresholds.min-sites", 1, 1000),
    }


@pytest.mark.parametrize(
    ("name", "value", "valid"),
    [(n, v, ok) for n in THRESHOLD_FIELDS for v, ok in boundaries(*THRESHOLD_RANGES[n][1:])],
)
def test_each_threshold_range(name: str, value: int, valid: bool) -> None:
    key, low, high = THRESHOLD_RANGES[name]
    others = companions(name)
    config = validate_document(thresholds_doc({**others, name: value}))
    default = getattr(SPEC_DEFAULT_THRESHOLDS, name)
    expected = {
        **dataclasses.asdict(SPEC_DEFAULT_THRESHOLDS),
        **others,
        name: value if valid else default,
    }
    assert config.thresholds == Thresholds(**expected)
    if valid:
        assert config.notes == ()
    else:
        assert config.notes == (
            f"{key} must be an integer from {low} to {high}; the default {default} is used",
        )


@pytest.mark.parametrize("name", THRESHOLD_FIELDS)
@pytest.mark.parametrize("value", [True, "50", 50.0, None, {}])
def test_each_threshold_wrong_type(name: str, value: object) -> None:
    key, low, high = THRESHOLD_RANGES[name]
    default = getattr(SPEC_DEFAULT_THRESHOLDS, name)
    config = validate_document(thresholds_doc({name: value}))
    assert config.thresholds == SPEC_DEFAULT_THRESHOLDS
    assert config.notes == (
        f"{key} must be an integer from {low} to {high}; the default {default} is used",
    )


def test_one_bad_threshold_keeps_the_others() -> None:
    config = validate_document(thresholds_doc({"holds": 150, "min_sites": 3}))
    assert config.thresholds == dataclasses.replace(SPEC_DEFAULT_THRESHOLDS, min_sites=3)


@pytest.mark.parametrize(
    "values",
    [
        # DESIGN §10 S1: stale.overall <= migrating.overall <= holds;
        # stale.recent <= migrating.recent
        {"stale_overall": 51},  # stale.overall > migrating.overall (50)
        {"migrating_overall": 81},  # migrating.overall > holds (80)
        {"holds": 49},  # holds < migrating.overall (50)
        {"stale_recent": 71},  # stale.recent > migrating.recent (70)
        {"migrating_recent": 19},  # migrating.recent < stale.recent (20)
    ],
)
def test_threshold_order_violation_resets_whole_block(values: dict[str, int]) -> None:
    config = validate_document(thresholds_doc({"min_sites": 3, **values}))
    assert config.thresholds is None
    assert config.notes == (NOTE_THRESHOLD_ORDER,)


def test_threshold_order_after_a_default_replacement() -> None:
    # holds 150 -> default 80, which is then below migrating.overall 90: order fails.
    config = validate_document(thresholds_doc({"holds": 150, "migrating_overall": 90}))
    assert config.thresholds is None
    assert config.notes == (
        "thresholds.holds must be an integer from 1 to 100; the default 80 is used",
        NOTE_THRESHOLD_ORDER,
    )


def test_threshold_order_allows_equality() -> None:
    values = {
        "stale_overall": 40,
        "migrating_overall": 40,
        "holds": 40,
        "stale_recent": 60,
        "migrating_recent": 60,
    }
    config = validate_document(thresholds_doc(values))
    assert config.notes == ()
    assert config.thresholds == Thresholds(
        **{**dataclasses.asdict(SPEC_DEFAULT_THRESHOLDS), **values}
    )


@pytest.mark.parametrize("value", [[], "80", 80, None, True])
def test_thresholds_not_a_mapping(value: object) -> None:
    assert validate_document(doc(thresholds=value)) == SideConfig(
        notes=("thresholds must be a mapping; the default thresholds are used",)
    )


@pytest.mark.parametrize("group", ["stale", "migrating"])
def test_threshold_group_not_a_mapping(group: str) -> None:
    config = validate_document(doc(thresholds={group: 20, "min-sites": 3}))
    assert config.thresholds == dataclasses.replace(SPEC_DEFAULT_THRESHOLDS, min_sites=3)
    assert config.notes == (f"thresholds.{group} must be a mapping; the defaults are used for it",)


# --- limits.max-file-bytes (I-6 range; may only be lowered) ---------------------------------


@pytest.mark.parametrize(("value", "valid"), boundaries(*MAX_FILE_BYTES_RANGE))
def test_max_file_bytes_range(value: int, valid: bool) -> None:
    config = validate_document(doc(limits={"max-file-bytes": value}))
    low, high = SPEC_MAX_FILE_BYTES
    if valid:
        assert config == SideConfig(max_file_bytes=value)
    elif value > high:
        assert config == SideConfig(
            notes=(
                "limits.max-file-bytes can only be lowered (at most 1048576); "
                "the default 1048576 is used",
            )
        )
    else:
        assert config == SideConfig(
            notes=(
                f"limits.max-file-bytes must be an integer from {low} to {high}; "
                "the default 1048576 is used",
            )
        )


@pytest.mark.parametrize("value", [10**12, -1, 0, 512, True, "1024", 2048.0, None])
def test_max_file_bytes_never_passes_out_of_range(value: object) -> None:
    # SR #35 L1: 10**12, -1, 0 and 512 must never reach a SideConfig.
    config = validate_document(doc(limits={"max-file-bytes": value}))
    assert config.max_file_bytes is None
    assert len(config.notes) == 1
    assert config.notes[0].startswith("limits.max-file-bytes ")


@pytest.mark.parametrize("value", [[], 1024, "x"])
def test_limits_not_a_mapping(value: object) -> None:
    assert validate_document(doc(limits=value)) == SideConfig(
        notes=("limits must be a mapping; the defaults are used",)
    )


def test_limits_without_max_file_bytes() -> None:
    assert validate_document(doc(limits={})) == SideConfig()


# --- containment: exclude, ignore[].file, config ---------------------------------------------

# AC-N3.8's forms plus the other R2.1 classes: absolute, "..", drive, backslash, NUL, empty.
OUTSIDE = [
    "/etc/**",
    "/etc/hostname",
    "../outside.md",
    "../../etc/passwd",
    "a/../../b",
    "a/..",
    "..",
    "..\\outside.yml",
    "C:\\outside.yml",
    "C:/outside.yml",
    "c:x.py",
    "src\\a.py",
    "a.py:stream",
    "a\x00b",
    "",
    ".",
    "./",
    "//",
    "a\ud800b",
    # Windows-only forms that validate_relpath refuses for typed input on every OS (I-13):
    # device names, a trailing dot or space.
    "nul.txt",
    "src/CON",
    "Com1.py",
    "docs./a.md",
    "a.md ",
    "..a/b..",
    # The Architect's I-13 C5 exclude ruling names these exactly; they run on every OS.
    "foo.",
    "foo ",
    "c:x",
]
INSIDE = {
    "AGENTS.md": "AGENTS.md",
    "./AGENTS.md": "AGENTS.md",
    "docs//rules/./x.md": "docs/rules/x.md",
    "legacy/**": "legacy/**",
    "dir/": "dir",
    "..a/..b": "..a/..b",
}


@pytest.mark.parametrize("value", OUTSIDE)
def test_contained_path_rejects(value: str) -> None:
    assert contained_path(value) is None


@pytest.mark.parametrize(("value", "expected"), sorted(INSIDE.items()))
def test_contained_path_accepts(value: str, expected: str) -> None:
    assert contained_path(value) == expected


@pytest.mark.parametrize("value", [v for v in OUTSIDE if v])
def test_exclude_outside_entry_dropped_and_listed(value: str) -> None:
    config = validate_document(doc(exclude=["keep/", value]))
    assert config.exclude == ("keep/",)
    shown = value if len(value) <= SHOWN_MAX else value[: SHOWN_MAX - 1] + "\u2026"
    assert config.notes == (f'exclude entry "{shown}" is outside the repository and was ignored',)


@pytest.mark.parametrize("value", [f"!{v}" for v in OUTSIDE])
def test_negated_exclude_entry_checked_without_the_bang(value: str) -> None:
    config = validate_document(doc(exclude=[value]))
    assert config.exclude == ()
    assert len(config.notes) == 1


def test_exclude_keeps_entries_verbatim_in_order_without_duplicates() -> None:
    # Entries are globs: the original spelling (trailing "/", leading "**/") is kept.
    entries = ["legacy/**", "**/gen/", "migrations/", "legacy/**", "!keep.py"]
    config = validate_document(doc(exclude=entries))
    assert config.exclude == ("legacy/**", "**/gen/", "migrations/", "!keep.py")
    assert config.notes == ()


@pytest.mark.parametrize("value", ["legacy/**", {"a": 1}, 3, None])
def test_exclude_not_a_list(value: object) -> None:
    assert validate_document(doc(exclude=value)) == SideConfig(
        notes=("exclude must be a list of paths; it was ignored",)
    )


@pytest.mark.parametrize("entry", [3, None, True, ["a"], {"a": 1}])
def test_exclude_non_string_entry(entry: object) -> None:
    config = validate_document(doc(exclude=["a/", entry]))
    assert config.exclude == ("a/",)
    assert config.notes == ("exclude entry 2 is not a string and was ignored",)


@pytest.mark.parametrize("value", [v for v in OUTSIDE if v])
def test_ignore_file_outside_dropped_and_listed(value: str) -> None:
    config = validate_document(doc(ignore=[{"file": value, "line": 1}, {"text": "keep"}]))
    assert config.ignores == (IgnoreEntry(file=None, line=None, text="keep"),)
    shown = value if len(value) <= SHOWN_MAX else value[: SHOWN_MAX - 1] + "\u2026"
    assert config.notes == (
        f'ignore entry 1 file "{shown}" is outside the repository; it was ignored',
    )


@pytest.mark.parametrize("value", [v for v in OUTSIDE if v])
def test_config_path_outside_means_defaults(value: str) -> None:
    # AC-N3.8: "A rejected config path means defaults are used"; SR #35 L3.
    path, note = checked_config_path(value)
    assert path is None
    shown = value if len(value) <= SHOWN_MAX else value[: SHOWN_MAX - 1] + "\u2026"
    assert note == f'config path "{shown}" is outside the repository; the defaults are used'


@pytest.mark.parametrize("value", [None, ""])
def test_config_path_unset_is_default(value: str | None) -> None:
    assert checked_config_path(value) == (".conventiondrift.yml", None)


@pytest.mark.parametrize(("value", "expected"), sorted(INSIDE.items()))
def test_config_path_inside_is_normalized(value: str, expected: str) -> None:
    assert checked_config_path(value) == (expected, None)


# --- checkers -------------------------------------------------------------------------------


@pytest.mark.parametrize("cid", get_args(CheckerId))
@pytest.mark.parametrize("enabled", [True, False])
def test_checker_enabled(cid: CheckerId, enabled: bool) -> None:
    config = validate_document(doc(checkers={cid: {"enabled": enabled}}))
    assert config.notes == ()
    assert config.checkers == {cid: dataclasses.replace(DEFAULT_CHECKERS[cid], enabled=enabled)}


@pytest.mark.parametrize("cid", get_args(CheckerId))
@pytest.mark.parametrize("value", ["true", 1, 0, None, []])
def test_checker_enabled_invalid_keeps_that_default(cid: CheckerId, value: object) -> None:
    config = validate_document(doc(checkers={cid: {"enabled": value}}))
    assert config.checkers == {cid: DEFAULT_CHECKERS[cid]}
    default = "false" if cid == "money" else "true"  # I-6: money is off by default
    assert config.notes == (
        f"checkers.{cid}.enabled must be true or false; the default {default} is used",
    )


@pytest.mark.parametrize("cid", get_args(CheckerId))
@pytest.mark.parametrize("value", [True, "x", 1, None, []])
def test_checker_settings_not_a_mapping(cid: CheckerId, value: object) -> None:
    config = validate_document(doc(checkers={cid: value}))
    assert config.checkers == {cid: DEFAULT_CHECKERS[cid]}
    assert config.notes == (f"checkers.{cid} must be a mapping; its defaults are used",)


@pytest.mark.parametrize("paths", [["src/cli/**"], []])
def test_logging_script_paths_replace_default(paths: list[str]) -> None:
    config = validate_document(doc(checkers={"logging": {"script-paths": paths}}))
    assert config.notes == ()
    assert config.checkers == {"logging": CheckerPolicy(enabled=True, script_paths=tuple(paths))}


@pytest.mark.parametrize("value", ["**/bin/**", [1], ["a", None], {"a": 1}, None])
def test_logging_script_paths_invalid(value: object) -> None:
    config = validate_document(doc(checkers={"logging": {"script-paths": value}}))
    assert config.checkers == {"logging": DEFAULT_CHECKERS["logging"]}
    assert config.notes == (
        "checkers.logging.script-paths must be a list of strings; the default list is used",
    )


@pytest.mark.parametrize("value", [[], "x", 3])
def test_checkers_not_a_mapping(value: object) -> None:
    assert validate_document(doc(checkers=value)) == SideConfig(
        notes=("checkers must be a mapping; the defaults are used",)
    )


def test_checkers_only_configured_ones_are_listed() -> None:
    config = validate_document(doc(checkers={"money": {"enabled": True}, "logging": {}}))
    assert dict(config.checkers) == {
        "logging": DEFAULT_CHECKERS["logging"],
        "money": CheckerPolicy(enabled=True, script_paths=()),
    }


# --- ignore -------------------------------------------------------------------------------


def test_ignore_entries_normalized_and_deduplicated() -> None:
    config = validate_document(
        doc(
            ignore=[
                {"file": "./AGENTS.md", "line": 9},
                {"file": "AGENTS.md", "line": 9},
                {"text": "Use X"},
                {"text": "Use X"},
            ]
        )
    )
    assert config.notes == ()
    assert config.ignores == (
        IgnoreEntry(file="AGENTS.md", line=9, text=None),
        IgnoreEntry(file=None, line=None, text="Use X"),
    )


INVALID_IGNORE_ENTRIES = [
    {"file": "AGENTS.md"},
    {"line": 9},
    {"file": "AGENTS.md", "line": 9, "text": "x"},
    {"text": "x", "line": 9},
    {},
    {"file": "AGENTS.md", "line": 0},
    {"file": "AGENTS.md", "line": -1},
    {"file": "AGENTS.md", "line": True},
    {"file": "AGENTS.md", "line": "9"},
    {"file": "AGENTS.md", "line": 9.0},
    {"file": 3, "line": 9},
    {"text": ""},
    {"text": "   "},
    {"text": 3},
    {"text": None},
    "AGENTS.md",
    9,
    None,
    ["AGENTS.md", 9],
]


@pytest.mark.parametrize("entry", INVALID_IGNORE_ENTRIES)
def test_ignore_entry_invalid(entry: object) -> None:
    config = validate_document(doc(ignore=[{"text": "keep"}, entry]))
    assert config.ignores == (IgnoreEntry(file=None, line=None, text="keep"),)
    assert config.notes == ("ignore entry 2 must have file and line, or text; it was ignored",)


def test_ignore_line_has_no_upper_bound() -> None:
    config = validate_document(doc(ignore=[{"file": "A.md", "line": 10**6}]))
    assert config.ignores == (IgnoreEntry(file="A.md", line=10**6, text=None),)


@pytest.mark.parametrize("value", [{"text": "x"}, "x", 3, None])
def test_ignore_not_a_list(value: object) -> None:
    assert validate_document(doc(ignore=value)) == SideConfig(
        notes=("ignore must be a list of entries; it was ignored",)
    )


# --- totality and the T-012 backstop --------------------------------------------------------

JSONISH = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(-(10**13), 10**13)
    | st.floats(allow_nan=False)
    | st.sampled_from(["none", "new-stale", "../x", "/etc", "a/", "AGENTS.md", "", "x"]),
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(
            st.sampled_from(
                [
                    *TOP_LEVEL_KEYS,
                    *THRESHOLD_KEYS,
                    "overall",
                    "recent",
                    *LIMIT_KEYS,
                    *get_args(CheckerId),
                    "enabled",
                    "script-paths",
                    *IGNORE_KEYS,
                    "bogus",
                ]
            ),
            children,
            max_size=6,
        )
    ),
    max_leaves=25,
)


@settings(max_examples=300, deadline=None)
@given(st.dictionaries(st.sampled_from((*TOP_LEVEL_KEYS[1:], "bogus")), JSONISH, max_size=8))
def test_validate_never_raises_and_check_ranges_finds_nothing(document: dict[str, Any]) -> None:
    config = validate_document({"version": 1, **document})
    # T-012's backstop (check_ranges) re-checks I-6 ranges: a T-011 SideConfig passes clean.
    assert check_ranges(config) == (config, ())
    if config.max_file_bytes is not None:
        assert SPEC_MAX_FILE_BYTES[0] <= config.max_file_bytes <= SPEC_MAX_FILE_BYTES[1]
    if config.thresholds is not None:
        t = config.thresholds
        assert t.stale_overall <= t.migrating_overall <= t.holds
        assert t.stale_recent <= t.migrating_recent
    for entry in config.ignores:
        assert entry.file is None or contained_path(entry.file) == entry.file
    for pattern in config.exclude:
        assert contained_path(pattern.removeprefix("!")) is not None
    assert all(isinstance(n, str) and n for n in config.notes)
