"""Unit tests for the C9 verdict engine (T-021; DESIGN §10 S1, I-9, I-10, I-13).

Names deliberately avoid the ``test_ac_`` prefix: the AC-named tests belong to the
Test Engineer. The AC each case exercises is given in a comment instead.
"""

import ast
import inspect
from collections.abc import Collection
from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conventiondrift import verdicts
from conventiondrift.model import Counts, Rule, RuleMatch, SideResult, Site, Thresholds, Verdict
from conventiondrift.verdicts import decide, follows, pct_ge, side_result

DEFAULTS = Thresholds(
    holds=80,
    stale_overall=20,
    stale_recent=20,
    migrating_overall=50,
    migrating_recent=70,
    min_sites=5,
)
HTTP = frozenset({"requests", "httpx", "urllib3"})
USE_HTTPX = RuleMatch(preferred=frozenset({"httpx"}), prohibited=frozenset(), specificity=1)
NO_PRINT = RuleMatch(preferred=frozenset(), prohibited=frozenset({"print"}), specificity=1)
RULE = Rule(
    id="AGENTS.md:3",
    file="AGENTS.md",
    line=3,
    also_at=(),
    text="Use httpx for HTTP calls",
    normalized_text="use httpx for http calls",
    checker="http-client",
    match=USE_HTTPX,
    scope_dir="",
    ignored=False,
    disabled=False,
)

H = Verdict.HOLDS
S = Verdict.STALE
M = Verdict.MIGRATING
C = Verdict.CONTESTED
I = Verdict.INSUFFICIENT  # noqa: E741
NV = Verdict.NOT_VERIFIABLE


def c(following: int, relevant: int) -> Counts:
    return Counts(following=following, contradicting=relevant - following, relevant=relevant)


def v(overall: Counts, recent: Counts | None, t: Thresholds = DEFAULTS) -> Verdict:
    return decide(verifiable=True, overall=overall, recent=recent, thresholds=t)


# --- pct_ge: integer math, f*100 >= t*n -------------------------------------------------


@pytest.mark.parametrize(
    ("f", "n", "t", "expected"),
    [
        (16, 20, 80, True),  # exactly 80%
        (79, 100, 80, False),  # 79%
        (1, 3, 33, True),  # 33.33% >= 33
        (1, 3, 34, False),  # 33.33% < 34
        (2, 3, 67, False),  # 66.67% < 67 (float rounding would say 67)
        (2, 3, 66, True),
        (0, 5, 0, True),  # 0% >= 0
        (0, 5, 1, False),
        (5, 5, 100, True),
        (4, 5, 100, False),
        (0, 0, 50, True),  # empty count: 0 >= 0
        (1, 10_000_000, 0, True),
        (999_999, 1_000_000, 100, False),  # 99.9999% is not 100
    ],
)
def test_pct_ge_integer_math(f: int, n: int, t: int, expected: bool) -> None:
    assert pct_ge(f, n, t) is expected


@given(
    f=st.integers(min_value=0, max_value=10**6),
    extra=st.integers(min_value=0, max_value=10**6),
    t=st.integers(min_value=0, max_value=100),
)
def test_pct_ge_matches_exact_fraction(f: int, extra: int, t: int) -> None:
    from fractions import Fraction

    n = f + extra
    if n:
        assert pct_ge(f, n, t) is (Fraction(f * 100, n) >= t)
    else:
        assert pct_ge(f, n, t) is True


# --- decide: the S1 fixed order ----------------------------------------------------------


@pytest.mark.parametrize(
    ("overall", "recent", "expected"),
    [
        # AC-F4.3: Holds at 80% even with 0% recent; 79% falls through to Contested.
        (c(16, 20), c(0, 5), H),
        (c(79, 100), c(0, 10), C),
        # AC-F4.4: Stale needs both below 20.
        (c(1, 10), c(1, 10), S),
        (c(1, 10), c(2, 10), C),
        (c(2, 10), c(0, 10), C),
        # AC-F4.5: Migrating needs overall < 50 and recent >= 70.
        (c(4, 10), c(7, 10), M),
        (c(5, 10), c(9, 10), C),
        (c(40, 100), c(69, 100), C),
        # AC-F4.6: the fall-through.
        (c(6, 10), c(6, 10), C),
        (c(3, 10), c(4, 10), C),
        # Exact thresholds around every comparison.
        (c(19, 100), c(19, 100), S),
        (c(20, 100), c(19, 100), C),
        (c(19, 100), c(20, 100), C),
        (c(49, 100), c(70, 100), M),
        (c(50, 100), c(70, 100), C),
        (c(49, 100), c(69, 100), C),
        (c(80, 100), c(100, 100), H),
        (c(100, 100), c(0, 1), H),
        # Stale is checked before Migrating: low overall and low recent with Migrating
        # unreachable; and recent high enough for Migrating is never Stale.
        (c(0, 10), c(0, 1), S),
        (c(0, 10), c(1, 1), M),
        # Ties: following == contradicting.
        (c(5, 10), c(5, 10), C),
        (c(3, 6), c(1, 2), C),
    ],
)
def test_decide_with_recent(overall: Counts, recent: Counts, expected: Verdict) -> None:
    assert v(overall, recent) is expected


@pytest.mark.parametrize(
    ("overall", "expected"),
    [
        # AC-F4.12 / F4.13: overall only; never Migrating.
        (c(1, 10), S),
        (c(3, 10), C),
        (c(19, 100), S),
        (c(20, 100), C),
        (c(0, 10), S),
        (c(49, 100), C),  # would need recent for Migrating
        (c(79, 100), C),
        (c(80, 100), H),
    ],
)
@pytest.mark.parametrize("recent", [None, Counts(0, 0, 0)])
def test_decide_without_recent(overall: Counts, recent: Counts | None, expected: Verdict) -> None:
    # A Counts with zero relevant sites is the same as no recent data (S1 step 4).
    assert v(overall, recent) is expected


def test_decide_never_migrating_without_recent_even_when_thresholds_favour_it() -> None:
    t = replace(
        DEFAULTS, stale_overall=0, stale_recent=0, migrating_overall=100, migrating_recent=0
    )
    for f in range(11):
        assert v(c(f, 10), None, t) is not M


def test_decide_min_sites_boundary() -> None:
    # AC-F4.7 / AC-E.19: 4 all-contradicting sites are Insufficient; 5 are Stale.
    assert v(c(0, 4), c(0, 4)) is I
    assert v(c(0, 4), None) is I
    assert v(c(0, 5), c(0, 5)) is S
    assert v(c(0, 5), None) is S


def test_decide_min_sites_beats_holds_and_migrating() -> None:
    assert v(c(4, 4), c(4, 4)) is I
    assert v(c(1, 4), c(3, 3)) is I


def test_decide_zero_sites_is_insufficient() -> None:
    assert v(c(0, 0), None) is I
    assert v(c(0, 0), Counts(0, 0, 0)) is I


@pytest.mark.parametrize("min_sites", [1, 3, 1000])
def test_decide_min_sites_is_configurable(min_sites: int) -> None:
    t = replace(DEFAULTS, min_sites=min_sites)
    assert v(c(0, min_sites - 1), None, t) is I
    assert v(c(0, min_sites), None, t) is S


def test_decide_custom_thresholds() -> None:
    # The AC-F4.10 configuration: Holds 90, Stale 30/30, Migrating 60/60, min 3.
    t = Thresholds(
        holds=90,
        stale_overall=30,
        stale_recent=30,
        migrating_overall=60,
        migrating_recent=60,
        min_sites=3,
    )
    assert v(c(1, 4), c(1, 4), t) is S  # 25% / 25%, 4 sites
    assert v(c(9, 10), None, t) is H
    assert v(c(89, 100), None, t) is C
    assert v(c(5, 10), c(6, 10), t) is M
    assert v(c(0, 2), None, t) is I


def test_decide_stale_thresholds_are_not_interchangeable() -> None:
    t = replace(DEFAULTS, stale_overall=30, stale_recent=10)
    assert v(c(25, 100), c(5, 100), t) is S
    assert v(c(25, 100), c(15, 100), t) is C  # recent 15 is not < 10
    assert v(c(35, 100), c(5, 100), t) is C  # overall 35 is not < 30
    assert v(c(25, 100), None, t) is S  # overall-only uses stale.overall
    assert v(c(15, 100), None, replace(DEFAULTS, stale_overall=10, stale_recent=30)) is C


def test_decide_migrating_thresholds_are_not_interchangeable() -> None:
    t = replace(DEFAULTS, migrating_overall=60, migrating_recent=90)
    assert v(c(55, 100), c(90, 100), t) is M
    assert v(c(55, 100), c(80, 100), t) is C
    assert v(c(65, 100), c(95, 100), t) is C


def test_decide_recent_with_no_following_is_still_available() -> None:
    # Available means >= 1 recent relevant site, even when none of them follows.
    t = replace(DEFAULTS, migrating_recent=0)
    assert v(c(40, 100), c(0, 5), t) is M
    assert v(c(40, 100), None, t) is C


def test_decide_not_verifiable_comes_first() -> None:
    for overall, recent in [(c(0, 0), None), (c(10, 10), c(10, 10)), (c(0, 10), c(0, 10))]:
        got = decide(verifiable=False, overall=overall, recent=recent, thresholds=DEFAULTS)
        assert got is NV


def test_decide_holds_does_not_look_at_recent() -> None:
    assert v(c(8, 10), c(0, 10)) is H
    assert v(c(8, 10), None) is H


def test_decide_zero_min_sites_and_zero_sites_follows_algorithm() -> None:
    # min-sites is validated to 1..1000 by C5; with 0, an empty count passes step 2
    # and 0*100 >= 80*0, so step 3 gives Holds. C9 never raises.
    t = replace(DEFAULTS, min_sites=0)
    assert v(c(0, 0), None, t) is H


VERDICT_ORDER_CASES = st.tuples(
    st.integers(0, 50), st.integers(0, 50), st.integers(0, 50), st.integers(0, 50)
)


@given(VERDICT_ORDER_CASES, st.booleans())
def test_decide_agrees_with_reference(case: tuple[int, int, int, int], has_recent: bool) -> None:
    of, oc, rf, rc = case
    overall = Counts(of, oc, of + oc)
    recent = Counts(rf, rc, rf + rc) if has_recent else None
    got = v(overall, recent)

    def pct(f: int, n: int) -> float:
        return 100 * f / n

    n = of + oc
    if n < 5:
        want = I
    elif pct(of, n) >= 80:
        want = H
    elif recent is not None and recent.relevant >= 1:
        rp = pct(rf, recent.relevant)
        if pct(of, n) < 20 and rp < 20:
            want = S
        elif pct(of, n) < 50 and rp >= 70:
            want = M
        else:
            want = C
    else:
        want = S if pct(of, n) < 20 else C
    assert got is want


# --- follows: I-10 ---------------------------------------------------------------------


def test_follows_preferred() -> None:
    assert follows("httpx", USE_HTTPX) is True
    assert follows("requests", USE_HTTPX) is False


def test_follows_prohibition_only() -> None:
    assert follows("logging", NO_PRINT) is True
    assert follows("print", NO_PRINT) is False


def test_follows_preferred_wins_over_prohibited() -> None:
    both = RuleMatch(
        preferred=frozenset({"logging"}), prohibited=frozenset({"print"}), specificity=1
    )
    assert follows("logging", both) is True
    assert follows("print", both) is False
    # With a non-empty preferred set, an option that is neither preferred nor
    # prohibited contradicts.
    assert follows("warnings", both) is False


def test_follows_empty_match() -> None:
    empty = RuleMatch(preferred=frozenset(), prohibited=frozenset(), specificity=0)
    assert follows("anything", empty) is True


# --- side_result: building SideResult --------------------------------------------------


def site(file: str, line: int, option: str, col: int = 0) -> Site:
    return Site(file=file, line=line, col=col, option=option)


def build(
    sites: list[Site],
    recent_lines: Collection[tuple[str, int]] | None,
    rule: Rule = RULE,
    t: Thresholds = DEFAULTS,
    options: frozenset[str] = HTTP,
) -> SideResult:
    return side_result(rule, sites, options=options, recent_lines=recent_lines, thresholds=t)


FIVE_REQUESTS = [site("src/a.py", i, "requests") for i in range(1, 6)]


def test_side_result_counts_and_flags() -> None:
    sites = [
        site("src/b.py", 2, "httpx"),
        site("src/a.py", 9, "requests"),
        site("src/a.py", 1, "httpx", col=4),
        site("src/a.py", 1, "httpx", col=0),
        site("src/c.py", 5, "urllib3"),
    ]
    recent = frozenset({("src/a.py", 1), ("src/c.py", 5), ("src/zz.py", 1)})
    r = build(sites, recent)
    assert [(s.site.file, s.site.line, s.site.col) for s in r.sites] == [
        ("src/a.py", 1, 0),
        ("src/a.py", 1, 4),
        ("src/a.py", 9, 0),
        ("src/b.py", 2, 0),
        ("src/c.py", 5, 0),
    ]
    assert [s.follows for s in r.sites] == [True, True, False, True, False]
    assert [s.recent for s in r.sites] == [True, True, False, False, True]
    assert r.overall == Counts(following=3, contradicting=2, relevant=5)
    assert r.recent == Counts(following=2, contradicting=1, relevant=3)
    assert r.recent_unavailable_reason is None
    # 60% overall, 67% recent: Contested.
    assert r.verdict is C
    assert len(r.sites) == r.overall.following + r.overall.contradicting


def test_side_result_sorts_by_option_last() -> None:
    sites = [site("a.py", 1, "requests"), site("a.py", 1, "httpx")]
    r = build(sites, None)
    assert [s.site.option for s in r.sites] == ["httpx", "requests"]


def test_side_result_drops_sites_outside_checker_options() -> None:
    sites = [*FIVE_REQUESTS, site("src/x.py", 1, "aiohttp")]
    r = build(sites, None)
    assert r.overall == Counts(0, 5, 5)
    assert all(s.site.option == "requests" for s in r.sites)


def test_side_result_history_unavailable() -> None:
    # AC-F4.12 / I-13: a C8 failure (recent_lines is None) is "no history"
    # per side; overall only, never Migrating, no site marked recent.
    sites = [site("src/a.py", i, "httpx") for i in range(1, 5)] + [
        site("src/b.py", i, "requests") for i in range(1, 7)
    ]
    r = build(sites, None)
    assert r.recent is None
    assert r.recent_unavailable_reason == "no history"
    assert not any(s.recent for s in r.sites)
    assert r.verdict is C  # 40% overall; with recent it could have been Migrating


def test_side_result_history_unavailable_stale() -> None:
    sites = [site("src/a.py", 1, "httpx")] + [site("src/b.py", i, "requests") for i in range(9)]
    r = build(sites, None)
    assert r.verdict is S


def test_side_result_no_relevant_sites_in_window() -> None:
    # AC-F4.13: history exists but no relevant site is recent.
    recent = frozenset({("src/other.py", 1)})
    sites = [site("src/a.py", 1, "httpx")] + [site("src/b.py", i, "requests") for i in range(9)]
    r = build(sites, recent)
    assert r.recent is None
    assert r.recent_unavailable_reason == "no relevant sites in the window"
    assert not any(s.recent for s in r.sites)
    assert r.verdict is S
    sites3 = [site("src/a.py", i, "httpx") for i in range(3)] + [
        site("src/b.py", i, "requests") for i in range(7)
    ]
    assert build(sites3, recent).verdict is C


def test_side_result_empty_recent_set_is_available_history() -> None:
    r = build(FIVE_REQUESTS, frozenset())
    assert r.recent_unavailable_reason == "no relevant sites in the window"


def test_side_result_recent_migrating() -> None:
    old = [site("src/old.py", i, "requests") for i in range(6)]
    new = [site("src/new.py", i, "httpx") for i in range(4)]
    recent = frozenset(("src/new.py", i) for i in range(4))
    r = build(old + new, recent)
    assert r.recent == Counts(4, 0, 4)
    assert r.verdict is M


def test_side_result_recent_all_contradicting_is_available() -> None:
    old = [site("src/old.py", i, "httpx") for i in range(4)]
    new = [site("src/new.py", i, "requests") for i in range(2)]
    r = build(old + new, frozenset(("src/new.py", i) for i in range(2)))
    assert r.recent == Counts(0, 2, 2)
    assert r.recent_unavailable_reason is None


def test_side_result_recent_matches_file_and_line_only() -> None:
    sites = [site("src/a.py", 3, "httpx", col=1), site("src/a.py", 3, "requests", col=9)]
    r = build(sites, frozenset({("src/a.py", 3)}))
    assert all(s.recent for s in r.sites)
    assert build(sites, frozenset({("src/a.py", 4)})).recent is None
    assert build(sites, frozenset({("src/b.py", 3)})).recent is None


class _NoLinearScan(list[tuple[str, int]]):
    """A list that refuses ``in``, so C9 must build its own set (SR F2)."""

    def __contains__(self, item: object) -> bool:
        raise AssertionError("recent_lines was scanned linearly")


def test_side_result_recent_lines_list_is_converted_to_a_set_once() -> None:
    old = [site("src/old.py", i, "requests") for i in range(6)]
    new = [site("src/new.py", i, "httpx") for i in range(4)]
    recent = _NoLinearScan([("src/new.py", i) for i in range(4)] + [("src/new.py", 0)])
    r = build(old + new, recent)
    assert r.recent == Counts(4, 0, 4)
    assert r.verdict is M


def test_side_result_min_sites_boundary() -> None:
    # AC-F4.7 / AC-E.19 through the builder.
    four = build(FIVE_REQUESTS[:4], frozenset(("src/a.py", i) for i in range(1, 6)))
    assert four.verdict is I
    assert four.overall == Counts(0, 4, 4)
    five = build(FIVE_REQUESTS, frozenset(("src/a.py", i) for i in range(1, 6)))
    assert five.verdict is S


def test_side_result_zero_sites() -> None:
    r = build([], frozenset())
    assert r.verdict is I
    assert r.sites == ()
    assert r.overall == Counts(0, 0, 0)
    assert r.recent is None
    assert r.recent_unavailable_reason == "no relevant sites in the window"
    assert build([], None).recent_unavailable_reason == "no history"


@pytest.mark.parametrize(
    "rule",
    [
        replace(RULE, checker=None, match=None),  # no checker (AC-F4.8) or ambiguous
        replace(RULE, checker=None),
        replace(RULE, match=None),
    ],
)
def test_side_result_not_verifiable(rule: Rule) -> None:
    # I-13: recent does not apply, whether or not history is available.
    with_history = build(FIVE_REQUESTS, frozenset({("src/a.py", 1)}), rule=rule)
    assert with_history.verdict is NV
    assert with_history.sites == ()
    assert with_history.overall == Counts(0, 0, 0)
    assert with_history.recent is None
    assert with_history.recent_unavailable_reason is None
    no_history = build(FIVE_REQUESTS, None, rule=rule)
    assert no_history.verdict is NV
    assert no_history.sites == ()
    assert no_history.overall == Counts(0, 0, 0)
    assert no_history.recent is None
    assert no_history.recent_unavailable_reason is None


@pytest.mark.parametrize(
    "rule", [replace(RULE, ignored=True), replace(RULE, disabled=True)], ids=["ignored", "disabled"]
)
def test_side_result_ignored_and_disabled_still_get_a_verdict(rule: Rule) -> None:
    # I-13: an ignored rule gets its normal verdict (fail-on counting is C10).
    # A disabled rule is dropped by T-028 before C9; C9 does not special-case
    # the flag, so a disabled rule that reached it would still get a verdict.
    assert build(FIVE_REQUESTS, None, rule=rule).verdict is S


def test_side_result_prohibition_only_rule() -> None:
    rule = replace(RULE, checker="logging", match=NO_PRINT, text="Never use print()")
    opts = frozenset({"print", "logging"})
    sites = [site("a.py", i, "print") for i in range(5)] + [site("b.py", 1, "logging")]
    r = build(sites, None, rule=rule, options=opts)
    assert r.overall == Counts(1, 5, 6)
    assert r.verdict is S


def test_side_result_accepts_any_iterable() -> None:
    r = side_result(
        RULE,
        iter(FIVE_REQUESTS),
        options=HTTP,
        recent_lines=None,
        thresholds=DEFAULTS,
    )
    assert r.overall.relevant == 5


@given(
    st.lists(
        st.tuples(
            st.sampled_from(["a.py", "b.py", "c.py"]),
            st.integers(1, 30),
            st.integers(0, 3),
            st.sampled_from(["requests", "httpx", "urllib3", "aiohttp"]),
        ),
        max_size=40,
    ),
    st.one_of(
        st.none(),
        st.frozensets(st.tuples(st.sampled_from(["a.py", "b.py"]), st.integers(1, 30))),
    ),
)
def test_side_result_invariants(
    raw: list[tuple[str, int, int, str]], recent: frozenset[tuple[str, int]] | None
) -> None:
    sites = [Site(file=f, line=ln, col=col, option=o) for f, ln, col, o in raw]
    r = build(sites, recent)
    relevant = [s for s in sites if s.option in HTTP]
    assert r.overall.relevant == len(relevant) == len(r.sites)
    assert r.overall.following + r.overall.contradicting == r.overall.relevant
    assert r.overall.following == sum(s.option == "httpx" for s in relevant)
    if r.recent is not None:
        assert r.recent.relevant >= 1
        assert r.recent.following + r.recent.contradicting == r.recent.relevant
        assert r.recent.relevant == sum(s.recent for s in r.sites)
        assert r.recent_unavailable_reason is None
    elif recent is None:
        assert r.recent_unavailable_reason == "no history"
    else:
        assert r.recent_unavailable_reason == "no relevant sites in the window"
        assert not any(s.recent for s in r.sites)
    if recent is None or r.recent is None:
        assert r.verdict is not M
    assert r.verdict is decide(
        verifiable=True, overall=r.overall, recent=r.recent, thresholds=DEFAULTS
    )


# --- purity ----------------------------------------------------------------------------


def test_module_is_pure() -> None:
    tree = ast.parse(inspect.getsource(verdicts))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "collections", "conventiondrift", "typing"}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not names & {"open", "print", "exec", "eval", "compile", "__import__", "float"}
