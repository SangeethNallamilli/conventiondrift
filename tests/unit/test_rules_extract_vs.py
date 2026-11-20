"""A sentence never ends at the period of a whole-word "vs." or "v." (INTERFACES I-10 6(c))."""

import pytest
from checker_support import assert_linear, extracted

from conventiondrift.rules.extract import segment


def texts(text: str) -> list[str]:
    return [candidate.text for candidate in segment("AGENTS.md", text)]


@pytest.mark.parametrize(
    "text",
    [
        "Use httpx vs. requests.",
        "Use httpx VS. requests.",
        "Use httpx v. requests.",
        "Use httpx V. requests.",
        "Use httpx Vs.\nrequests.",
        "vs. requests is the question.",
    ],
)
def test_the_period_of_vs_or_v_ends_no_sentence(text: str) -> None:
    assert len(texts(text)) == 1


@pytest.mark.parametrize(
    ("text", "count"),
    [
        ("This is vs.", 1),  # the real end of the text
        ("Use canvas. Use httpx.", 2),
        ("Use tvs. Use httpx.", 2),
        ("Use the_vs. Use httpx.", 2),
        ("Use dev. Use httpx.", 2),
        ("Use vs! Use httpx.", 2),  # only the period
        ("Use x vs.. Use httpx.", 2),
    ],
)
def test_other_periods_split_as_before(text: str, count: int) -> None:
    assert len(texts(text)) == count


def test_the_vs_rule_is_one_rule_and_not_verifiable() -> None:
    (rule,) = extracted("Use httpx vs. requests.")
    assert rule.normalized_text == "use httpx vs. requests."
    assert rule.checker is None


@pytest.mark.parametrize("unit", ["a vs. ", "a v. ", "vs. "])
def test_many_vs_periods_are_linear(unit: str) -> None:
    assert_linear(lambda n: "Use " + unit * (n // len(unit)), texts, label=unit)
