"""Unit tests for the money checker, conventiondrift.checkers.money (T-019a).

Covers AC-F3.5 (I-8 name list and follows/contradicts rule) and the money half of AC-F2.5.
Counts go through the real walk and pool.
"""

import ast
import textwrap

import pytest
from checker_support import assert_linear, counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.money import MoneyChecker
from conventiondrift.checkers.money.match import HINT_WORDS, HYPHENATED, OPTIONS, match_rule
from conventiondrift.checkers.money.sites import (
    MONEY_WORDS,
    is_named_like_money,
    money_sites,
    option_of,
    words_of,
)
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site
from conventiondrift.policy.config import DEFAULT_CHECKERS

STORE_CENTS = match_rule("store money as integer cents.")
CTX = FileContext("a.py", is_test_file=False, is_script=False, main_guard_spans=())

# The I-8 list, pinned so a silent edit of the constant fails (D-TL-25).
_MONEY_WORDS = frozenset(
    {
        "price",
        "prices",
        "amount",
        "amounts",
        "total",
        "totals",
        "subtotal",
        "cost",
        "costs",
        "cents",
        "fee",
        "fees",
        "balance",
        "payment",
        "refund",
        "tax",
        "discount",
        "salary",
        "wage",
        "revenue",
    }
)


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...] = ()) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), len(preferred + prohibited))


INTEGER_CENTS = match(("integer-cents",))
NO_CENTS = match((), ("integer-cents",))


def src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = MoneyChecker()
    assert checker.id == "money"
    assert checker.experimental is True
    assert checker.options == frozenset({"integer-cents", "float"}) == OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert set(checker.ast_handlers()) == {
        ast.Assign,
        ast.AnnAssign,
        ast.AugAssign,
        ast.NamedExpr,
        ast.Call,
    }


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, MoneyChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    sentence = "store money as integer cents."
    assert MoneyChecker().match_rule(sentence) == match_rule(sentence)


def test_money_is_off_by_default() -> None:
    assert DEFAULT_CHECKERS["money"].enabled is False


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "expected"),
    [
        # AC-F2.5 line 4 and the store / keep / represent shape (DESIGN §7 B1).
        ("store money as integer cents.", INTEGER_CENTS),
        ("keep money as integer cents.", INTEGER_CENTS),
        ("represent money as integer cents.", INTEGER_CENTS),
        ("store money as integer cent.", INTEGER_CENTS),
        ("store money as integer-cents.", INTEGER_CENTS),
        ("store money as integer_cents.", INTEGER_CENTS),
        ("never store money as integer cents.", NO_CENTS),
        ("don't store money as integer cents.", NO_CENTS),
        ("STORE MONEY AS INTEGER CENTS.", INTEGER_CENTS),
    ],
)
def test_match_rule_reads_the_polarity_of_each_mention(sentence: str, expected: RuleMatch) -> None:
    assert match_rule(sentence) == expected


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use logging, not print.",
        "use pytest, not unittest.",
        "always use type hints.",
        "use f-strings for string formatting.",
        "store money as floats.",
        "represent prices as decimal.",
        "count the money.",
        "store values as cents.",
        "store money as integer.",  # "integer" with no "cents"
        "store money as integer cents; never store money as integer cents.",
    ],
)
def test_match_rule_does_not_map_what_it_cannot_read(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_a_two_word_mention_spans_both_words() -> None:
    # In a trailing-cue clause the mentions must be one unbroken list (I-10 item 4a):
    # "integer cents or integer cents" is one, so the span covers "cents" too.
    assert match_rule("integer cents or integer cents are banned.") == NO_CENTS
    assert match_rule("integer cents and the integer cents are banned.") is None
    assert match_rule("integer cents the integer cents are banned.") is None
    assert match_rule("integer cents plus integer cents are banned.") is None


def test_the_words_it_reads() -> None:
    assert HINT_WORDS == {"cent", "cents"}
    assert HYPHENATED == {
        "integer-cent",
        "integer-cents",
        "integer_cent",
        "integer_cents",
    }


def test_it_takes_only_line_4_of_the_canonical_sentences_ac_f2_5() -> None:
    sentences = [
        "use logging, not print.",
        "use httpx for http calls.",
        "use pytest, not unittest.",
        "store money as integer cents.",
        "use f-strings for string formatting.",
        "do not use bare except.",
        "always use type hints.",
        "use uv for dependencies.",
    ]
    assert [i for i, s in enumerate(sentences, start=1) if match_rule(s)] == [4]


def test_the_registry_maps_the_money_rule_to_money() -> None:
    # Mapping still happens when the checker is off (default policy, AC-F3.14).
    assert rules_of("Store money as integer cents.") == [(1, "money")]
    assert rules_of("Keep money as integer cents.") == [(1, "money")]


# --- names (I-8 / D-TL-25) ------------------------------------------------------------------


def test_the_money_words_are_the_i8_list() -> None:
    assert MONEY_WORDS == _MONEY_WORDS
    assert MONEY_WORDS >= {"price", "amount", "total", "cost", "cents"}
    assert MONEY_WORDS.isdisjoint({"size", "sizes"})


@pytest.mark.parametrize("word", sorted(_MONEY_WORDS))
def test_each_i8_word_on_its_own_is_named_like_money(word: str) -> None:
    assert is_named_like_money(word)
    sites = sites_of("money", {"src/a.py": f"{word} = 1\n"})
    assert sites == [Site("src/a.py", 1, 0, "integer-cents")]


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        ("price", ("price",)),
        ("total_cents", ("total", "cents")),
        ("unitPrice", ("unit", "price")),
        ("subTotal", ("sub", "total")),
        ("XMLPrice", ("xml", "price")),
        ("_amount", ("amount",)),
        ("already_paid_amount", ("already", "paid", "amount")),
        ("cents2", ("cents", "2")),
    ],
)
def test_identifiers_split_at_underscores_and_camel_case(
    identifier: str, expected: tuple[str, ...]
) -> None:
    assert words_of(identifier) == expected
    assert is_named_like_money(identifier)


@pytest.mark.parametrize(
    "identifier",
    [
        "name",
        "pricing",
        "taxable",
        "balances",  # the list has "balance", not "balances"
        "payments",
        "size",
        "sizes",
        "count",
        "x",
    ],
)
def test_identifiers_without_an_i8_word_are_not_named_like_money(identifier: str) -> None:
    assert not is_named_like_money(identifier)
    assert sites_of("money", {"src/a.py": f"{identifier} = 9.99\n"}) == []


# --- sites: AC-F3.5 -------------------------------------------------------------------------

AC_F3_5 = """
    from decimal import Decimal

    price = 9.99
    total_cents = 999
    amount = Decimal("1.00")
    cost = 5
    name = 1.5
"""


def test_f3_5_three_integer_cents_and_one_float_count_3_and_1() -> None:
    sites = sites_of("money", {"src/mod.py": src(AC_F3_5)})
    assert STORE_CENTS is not None
    assert counts(STORE_CENTS, sites) == (3, 1)
    assert [(s.line, s.option) for s in sites] == [
        (3, "float"),
        (4, "integer-cents"),
        (5, "integer-cents"),
        (6, "integer-cents"),
    ]


def test_a_rule_against_integer_cents_counts_floats_as_following() -> None:
    sites = sites_of("money", {"src/mod.py": src(AC_F3_5)})
    assert counts(NO_CENTS, sites) == (1, 3)


@pytest.mark.parametrize(
    ("code", "option"),
    [
        ("price = 5", "integer-cents"),
        ("price = -5", "integer-cents"),
        ("price = +5", "integer-cents"),
        ("price = 9.99", "float"),
        ("price = -9.99", "float"),
        ("price = 1e2", "float"),
        ("price = Decimal('1.00')", "integer-cents"),
        ("price = decimal.Decimal('1.00')", "integer-cents"),
        ("price = total_cents", "integer-cents"),
        ("price = obj.unit_cents", "integer-cents"),
        ("self.price = 5", "integer-cents"),
        ("price: int = 5", "integer-cents"),
        ("price += 1", "integer-cents"),
        ("price += 0.5", "float"),
        ("(price := 5)", "integer-cents"),
        ("charge(price=5)", "integer-cents"),
        ("charge(price=9.99)", "float"),
        ("charge(name=1, price=5)", "integer-cents"),
        ("charge(**kwargs, price=9.99)", "float"),
    ],
)
def test_recognized_values_on_money_names_are_sites(code: str, option: str) -> None:
    sites = sites_of(
        "money", {"src/a.py": f"import decimal\nfrom decimal import Decimal\n{code}\n"}
    )
    assert [s.option for s in sites] == [option]


@pytest.mark.parametrize(
    "code",
    [
        "name = 9.99",
        "name = 5",
        "price = True",
        "price = False",
        "price = '9.99'",
        "price = None",
        "price = 5 + 1",
        "price = int(5)",
        "price = float(1)",
        "price = get_cents()",
        "price = cents",  # the name "cents" does not end in "_cents"
        "d['price'] = 9.99",
        "price, cost = 1, 2",
        "charge(**{'price': 5})",
        "charge(price=True)",
        "charge(name=5)",
        "price = obj.foo()",
        "price = math.sqrt(1)",
        "price: int",
        "price: int = True",
        "name: int = 5",
        "price += True",
        "(price := True)",
        "(name := 5)",
    ],
)
def test_other_values_and_unnamed_targets_are_not_sites(code: str) -> None:
    assert sites_of("money", {"src/a.py": f"{code}\n"}) == []


def test_option_of_reads_the_i8_value_forms() -> None:
    tree = parse(b"x = 5\ny = 1.5\nz = Decimal('1')\nw = total_cents\n")
    assigns = [n for n in tree.body if isinstance(n, ast.Assign)]
    assert [option_of(a.value) for a in assigns] == [
        "integer-cents",
        "float",
        "integer-cents",
        "integer-cents",
    ]


def test_a_site_is_at_the_target_name() -> None:
    source = "total_cents = 999\n"
    assert sites_of("money", {"src/a.py": source}) == [Site("src/a.py", 1, 0, "integer-cents")]


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": "price = 5\n" for i in range(3)}
    assert len(sites_of("money", files, max_workers=2)) == 3


def test_the_handler_reads_the_node_directly() -> None:
    tree = parse(b"cost = 5\n")
    assert list(money_sites(tree.body[0], CTX)) == [Site("a.py", 1, 0, "integer-cents")]


def test_the_handler_gives_nothing_for_a_node_that_is_not_an_assignment_or_call() -> None:
    assert list(money_sites(ast.Name("price"), CTX)) == []
    assert list(money_sites(parse(b"def f():\n    pass\n"), CTX)) == []


# --- linear time (R2.5) ---------------------------------------------------------------------

HOSTILE_RULES = {
    "no cue": lambda n: "store money as " + "integer cents " * (n // 14),
    "dangling integer": lambda n: "never store money as " + "integer " * (n // 8),
}


@pytest.mark.timing
@pytest.mark.parametrize("kind", HOSTILE_RULES)
def test_match_rule_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    assert_linear(HOSTILE_RULES[kind], match_rule, label=kind)
