"""C10 before/after comparison: base vs head rules give cases, causing files and suggestions.

Pure (DESIGN §1, I-11 C10): no I/O, no subprocess, no clock, no globals. The
inputs are each side's rules with their C9 ``SideResult``, the PR's changed
files (I-14 ``ChangedFile``) and each side's C6 conflicts. The output is one
``RuleResult`` per rule identity, sorted as ``Result.rule_results`` requires.

**Rule identity** (D-PM-05 #3, DESIGN §7 step 5): (instruction file after
renames, ``normalized_text``). A base rule's file is mapped through the PR's
``R`` entries before matching, so a renamed instruction file keeps its rules.

**Cases** (brief §7.5, F5, I-9 ``case``, D-PM-05 #3 and #4):

- same rule on both sides: Stale at base and head is ``pre-existing-stale``;
  Stale at base only is ``fixed`` (case 3); Stale at head only is
  ``made-stale-by-code`` (case 1) when it has causing files, else
  ``stale-rule-added`` (I-13 C10 ruling 7); otherwise ``None``.
- head only (new or edited): Stale at head is ``stale-rule-added`` (case 2),
  otherwise ``None``.
- base only (deleted, edited away, or its file deleted): Stale at base with no
  Stale rule replacing it is ``fixed`` (case 3); otherwise ``removed``.
- no base side at all (head-only and scan modes): every case is ``None``.

**causing_files** (I-9, DESIGN §10 B5): per-file site deltas (head minus base)
for files changed in the PR, with base paths mapped through renames, sorted by
|delta| descending and then by path. Only computed when both sides exist.

**suggestion** (I-9, DESIGN §10 B5 and §11 N3, D-PM-05 #20, SC-2.44): the
candidates are the options outside ``preferred`` that have head sites, ranked by
head site count (then option name). ``replace`` swaps option tokens in the rule
text; ``tie`` lists the candidates with no ``new_text``; ``remove-or-rewrite``
is for prohibition-only rules and never builds a new prohibition; ``none``
means no candidate sites (or no checker match).

``compare`` raises ``ValueError`` when one side holds two rules with the same
identity, which C6 never produces (it merges duplicates into ``also_at``).
"""

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Literal, cast, get_args

from conventiondrift.components import ChangedFile
from conventiondrift.model import (
    Alternative,
    Case,
    CausingFile,
    Conflict,
    Rule,
    RuleMatch,
    RuleResult,
    SideResult,
    Suggestion,
    Verdict,
)

__all__ = ["CASES", "SUGGESTION_KINDS", "compare", "suggest"]

SuggestionKind = Literal["replace", "tie", "remove-or-rewrite", "none"]

#: Every ``case`` value (I-9, I-13 ``Case``); ``None`` is the "no case" value.
CASES: tuple[Case, ...] = get_args(Case)
#: Every ``suggestion.kind`` value (I-9, I-13 ``Suggestion.kind``).
SUGGESTION_KINDS: tuple[SuggestionKind, ...] = get_args(SuggestionKind)

#: The ``ChangedFile`` status letter for a rename (I-14, ``diff-tree --name-status -M``).
RENAME_STATUS = "R"

RuleSide = tuple[Rule, SideResult]
_Key = tuple[str, str]
_STALE = Verdict.STALE


def _rename_map(changed_files: Iterable[ChangedFile]) -> dict[str, str]:
    """Old path -> new path for every rename in the PR."""
    return {
        old: new
        for status, old, new in changed_files
        if status == RENAME_STATUS and old is not None
    }


def _changed_paths(changed_files: Iterable[ChangedFile]) -> frozenset[str]:
    """Every path the PR touched, by its head-side name. A rename's old name is not
    needed: base sites are mapped to the new name before they are looked up."""
    return frozenset(new for _status, _old, new in changed_files)


def _index(
    rules: Iterable[RuleSide], renames: Mapping[str, str], side: str
) -> dict[_Key, RuleSide]:
    out: dict[_Key, RuleSide] = {}
    for rule, result in rules:
        key = (renames.get(rule.file, rule.file), rule.normalized_text)
        if key in out:
            raise ValueError(f"two {side} rules share one identity")
        out[key] = (rule, result)
    return out


def _is_stale(side: SideResult | None) -> bool:
    return side is not None and side.verdict is _STALE


def _case(base: SideResult | None, head: SideResult, causing: Sequence[CausingFile]) -> Case | None:
    """Classify a head rule in compare mode; ``base`` is None for a new or edited rule.

    I-13 C10 ruling 7: case 1 needs code. A rule that turns Stale with no causing
    files (for example a moved instruction file changed its scope) was caused by the
    PR's instruction change, so it is ``stale-rule-added``.
    """
    if base is None:
        return "stale-rule-added" if _is_stale(head) else None
    if _is_stale(base):
        return "pre-existing-stale" if _is_stale(head) else "fixed"
    if not _is_stale(head):
        return None
    return "made-stale-by-code" if causing else "stale-rule-added"


def _causing_files(
    base: SideResult, head: SideResult, changed: frozenset[str], renames: Mapping[str, str]
) -> tuple[CausingFile, ...]:
    """Head-minus-base site deltas per changed file; base paths follow renames."""
    following: Counter[str] = Counter()
    contradicting: Counter[str] = Counter()
    for r in head.sites:
        if r.site.file in changed:
            (following if r.follows else contradicting)[r.site.file] += 1
    for r in base.sites:
        path = renames.get(r.site.file, r.site.file)
        if path in changed:
            (following if r.follows else contradicting)[path] -= 1
    files = [
        CausingFile(
            file=path, following_delta=following[path], contradicting_delta=contradicting[path]
        )
        for path in set(following) | set(contradicting)
        if following[path] or contradicting[path]
    ]
    files.sort(key=lambda f: (-(abs(f.following_delta) + abs(f.contradicting_delta)), f.file))
    return tuple(files)


def _swap_text(text: str, match: RuleMatch, top: str, named: str) -> str | None:
    """Replace each preferred option token with ``top``; for a two-option rule whose
    prohibited side names ``top``, also put ``named`` in its place. Tokens match as
    whole words, ignoring case. None when no preferred token appears in ``text``."""
    mapping = dict.fromkeys(match.preferred, top)
    if top in match.prohibited:
        mapping[top] = named
    tokens = sorted(mapping, key=lambda t: (-len(t), t))
    pattern = re.compile(
        r"(?<!\w)(?:" + "|".join(f"({re.escape(t)})" for t in tokens) + r")(?!\w)",
        re.IGNORECASE,
    )
    hit_preferred = False

    def repl(m: re.Match[str]) -> str:
        nonlocal hit_preferred
        # Every alternative is a group, so ``lastindex`` names the token that matched.
        token = tokens[cast(int, m.lastindex) - 1]
        hit_preferred = hit_preferred or token in match.preferred
        return mapping[token]

    new_text = pattern.sub(repl, text)
    return new_text if hit_preferred else None


def suggest(rule: Rule, head: SideResult | None) -> Suggestion:
    """The I-9 ``suggestion`` for ``rule``, from its head sites (``head``)."""
    match = rule.match if rule.checker is not None else None
    if match is None:
        return Suggestion(kind="none", named_option=None, alternatives=(), new_text=None)
    named = min(match.preferred) if match.preferred else None
    counts = Counter(
        r.site.option for r in (head.sites if head else ()) if r.site.option not in match.preferred
    )
    alternatives = tuple(
        Alternative(option=option, sites=n)
        for option, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    )
    if not alternatives:
        return Suggestion(kind="none", named_option=named, alternatives=(), new_text=None)
    if named is None:
        # SC-2.44: prohibition-only. Observed practice with counts; never a new prohibition.
        return Suggestion(
            kind="remove-or-rewrite", named_option=None, alternatives=alternatives, new_text=None
        )
    if len(alternatives) > 1 and alternatives[1].sites == alternatives[0].sites:
        return Suggestion(kind="tie", named_option=named, alternatives=alternatives, new_text=None)
    return Suggestion(
        kind="replace",
        named_option=named,
        alternatives=alternatives,
        new_text=_swap_text(rule.text, match, alternatives[0].option, named),
    )


def _conflict_index(conflicts: Iterable[Conflict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for conflict in conflicts:
        a, b = conflict.rules
        out.setdefault(a, set()).add(b)
        out.setdefault(b, set()).add(a)
    return out


def _sort_key(result: RuleResult) -> tuple[str, int, bool, str]:
    # RuleResult.__post_init__ guarantees at least one of the two rules.
    rule = cast(Rule, result.head_rule or result.base_rule)
    return (rule.file, rule.line, result.head_rule is None, rule.normalized_text)


def compare(
    base: Sequence[RuleSide] | None,
    head: Sequence[RuleSide],
    changed_files: Sequence[ChangedFile],
    *,
    base_conflicts: Sequence[Conflict] = (),
    head_conflicts: Sequence[Conflict] = (),
) -> tuple[RuleResult, ...]:
    """Build one ``RuleResult`` per rule identity (I-11 C10).

    - ``base``: each base rule with its C9 ``SideResult``, or None when there is
      no comparison (head-only and scan modes): then every case is None and
      ``causing_files`` is empty.
    - ``head``: each head rule with its C9 ``SideResult``.
    - ``changed_files``: ``changed_files(base, head)`` from C3 (I-14).
    - ``base_conflicts`` / ``head_conflicts``: each side's C6 conflicts. A result
      takes ``conflict_with`` from the side its ``rule_id`` comes from.

    Disabled rules must already be dropped (I-13, T-028).
    """
    renames = _rename_map(changed_files)
    changed = _changed_paths(changed_files)
    heads = _index(head, {}, "head")
    bases = _index(base or (), renames, "base")
    head_conf = _conflict_index(head_conflicts)
    base_conf = _conflict_index(base_conflicts)

    # D-PM-05 #3: a deleted base-Stale rule is fixed only when no Stale rule replaces
    # it, i.e. no new head rule in the same file (after renames) for the same checker
    # is Stale at head.
    stale_new = {
        (rule.file, rule.checker)
        for key, (rule, side) in heads.items()
        if key not in bases and _is_stale(side)
    }

    results: list[RuleResult] = []
    for key, (rule, side) in heads.items():
        base_pair = bases.get(key)
        base_rule, base_side = base_pair if base_pair else (None, None)
        causing = _causing_files(base_side, side, changed, renames) if base_side is not None else ()
        results.append(
            RuleResult(
                rule_id=rule.id,
                base_rule=base_rule,
                head_rule=rule,
                base=base_side,
                head=side,
                conflict_with=tuple(sorted(head_conf.get(rule.id, ()))),
                case=_case(base_side, side, causing) if base is not None else None,
                causing_files=causing,
                suggestion=suggest(rule, side),
            )
        )
    for key, (rule, side) in bases.items():
        if key in heads:
            continue
        # D-PM-05 #3 and #4: deleted, edited away, or its file deleted.
        replaced = (key[0], rule.checker) in stale_new
        results.append(
            RuleResult(
                rule_id=rule.id,
                base_rule=rule,
                head_rule=None,
                base=side,
                head=None,
                conflict_with=tuple(sorted(base_conf.get(rule.id, ()))),
                case="fixed" if _is_stale(side) and not replaced else "removed",
                causing_files=(),
                suggestion=suggest(rule, None),
            )
        )
    results.sort(key=_sort_key)
    return tuple(results)
