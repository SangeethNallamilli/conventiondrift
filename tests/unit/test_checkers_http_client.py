"""Unit tests for the http-client checker, conventiondrift.checkers.http_client (T-017).

Covers AC-F3.3 and the HTTP client half of AC-F2.4 and AC-F2.5. Counts go through the real
walk and pool.
"""

import ast

import pytest
from checker_support import counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.http_client import HttpClientChecker
from conventiondrift.checkers.http_client.match import OPTIONS, WORDS, match_rule
from conventiondrift.checkers.http_client.sites import CALLS, http_sites
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site

USE_HTTPX = match_rule("use httpx for http calls.")


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...] = ()) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), len(preferred + prohibited))


def ctx(path: str = "a.py") -> FileContext:
    return FileContext(path, is_test_file=False, is_script=False, main_guard_spans=())


# --- the checker object (I-10) -------------------------------------------------------------


def test_the_checker_is_described_by_i10() -> None:
    checker = HttpClientChecker()
    assert checker.id == "http-client"
    assert checker.experimental is False
    assert checker.options == frozenset({"requests", "httpx", "aiohttp", "urllib"}) == OPTIONS
    assert checker.inputs == frozenset({"python-ast"})
    assert list(checker.manifest_sites({"pyproject.toml": b"x"})) == []
    assert set(checker.ast_handlers()) == {ast.Call}


def test_the_checker_is_in_the_registry() -> None:
    assert any(isinstance(c, HttpClientChecker) for c in REGISTRY)


def test_the_checker_matches_through_its_module_function() -> None:
    sentence = "use httpx, not requests."
    assert HttpClientChecker().match_rule(sentence) == match_rule(sentence)


def test_every_word_names_one_option() -> None:
    assert set(WORDS.values()) == OPTIONS


# --- match_rule -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "preferred", "prohibited"),
    [
        # AC-F2.5 line 2, AC-F2.4's paragraph, and the other DESIGN §7 shapes.
        ("use httpx for http calls.", ("httpx",), ()),
        ("use httpx, not requests, for those calls.", ("httpx",), ("requests",)),
        ("use httpx, not requests.", ("httpx",), ("requests",)),
        ("use httpx, not requests or aiohttp.", ("httpx",), ("requests", "aiohttp")),
        ("use requests for http calls.", ("requests",), ()),
        ("always use aiohttp.", ("aiohttp",), ()),
        ("use urllib.request for http calls.", ("urllib",), ()),
        ("use urllib for http calls.", ("urllib",), ()),
        ("prefer httpx over requests.", ("httpx",), ("requests",)),
        ("never use requests.", (), ("requests",)),
        ("don't use urllib.request or requests.", (), ("urllib", "requests")),
        ("avoid aiohttp.", (), ("aiohttp",)),
        ("USE HTTPX FOR HTTP CALLS.", ("httpx",), ()),
        # AC-F2.6: the sentence reads as http-client with requests alone.
        ("never use print or requests.", (), ("requests",)),
    ],
)
def test_match_rule_reads_the_libraries_and_their_polarity(
    sentence: str, preferred: tuple[str, ...], prohibited: tuple[str, ...]
) -> None:
    assert match_rule(sentence) == match(preferred, prohibited)


@pytest.mark.parametrize(
    "sentence",
    [
        "",
        "use an async http client.",
        "use httpx2 for http calls.",  # DECISIONS: "Use httpx2" is Not verifiable
        "use urllib.parse for urls.",
        "use urllib3.",
        "use logging, not print.",
        "use pytest, not unittest.",
        "never use requests; always use requests.",  # one option, both polarities
        "never use httpx, requests, aiohttp or urllib.",  # forbids every option
        "use httpx, requests, aiohttp and urllib.",  # prefers every option
        "use requests; never use requests.",
    ],
)
def test_match_rule_does_not_map_what_names_no_library_or_cannot_be_read(sentence: str) -> None:
    assert match_rule(sentence) is None


def test_specificity_is_the_number_of_options_named() -> None:
    one = match_rule("use httpx for http calls.")
    two = match_rule("use httpx, not requests.")
    assert one is not None
    assert two is not None
    assert (one.specificity, two.specificity) == (1, 2)


def test_it_leaves_the_other_canonical_sentences_alone_ac_f2_5() -> None:
    others = [
        "use logging, not print.",
        "use pytest, not unittest.",
        "store money as integer cents.",
        "use f-strings for string formatting.",
        "do not use bare except.",
        "always use type hints.",
        "use uv for dependencies.",
    ]
    assert [s for s in others if match_rule(s)] == []


def test_the_registry_maps_the_rules_ac_f2_4_ac_f2_5_and_ac_f2_6() -> None:
    paragraph = (
        "Our services talk to each other over HTTP. Use httpx, not requests, for those calls."
    )
    assert rules_of(paragraph) == [(1, "http-client")]
    assert rules_of("Use httpx for HTTP calls.") == [(1, "http-client")]
    # Logging and http-client each find one option here, so the rule has no checker.
    assert rules_of("Never use print or requests.") == [(1, None)]


# --- sites: AC-F3.3 -------------------------------------------------------------------------

AC_F3_3 = """
import aiohttp
import httpx
import requests
import urllib.request

requests.get("a")
requests.get("b")
httpx.get("a")
httpx.get("b")
httpx.get("c")
aiohttp.ClientSession()
urllib.request.urlopen("a")
"""


def test_f3_3_two_requests_three_httpx_one_aiohttp_one_urllib_count_3_and_4() -> None:
    sites = sites_of("http-client", {"src/mod.py": AC_F3_3})
    assert USE_HTTPX is not None
    assert counts(USE_HTTPX, sites) == (3, 4)
    assert sorted(s.option for s in sites) == ["aiohttp"] + ["httpx"] * 3 + ["requests"] * 2 + [
        "urllib"
    ]


def test_an_import_is_not_a_site() -> None:
    assert sites_of("http-client", {"a.py": "import requests\nfrom httpx import get\n"}) == []


def test_a_site_is_at_the_call() -> None:
    source = "def f():\n    return requests.get(url).json()\n"
    assert sites_of("http-client", {"src/a.py": source}) == [Site("src/a.py", 2, 11, "requests")]


@pytest.mark.parametrize(
    ("call", "option"),
    [
        ("requests.get(u)", "requests"),
        ("requests.post(u)", "requests"),
        ("requests.put(u)", "requests"),
        ("requests.patch(u)", "requests"),
        ("requests.delete(u)", "requests"),
        ("requests.head(u)", "requests"),
        ("requests.options(u)", "requests"),
        ("requests.request('GET', u)", "requests"),
        ("requests.Session()", "requests"),
        ("requests.session()", "requests"),
        ("httpx.get(u)", "httpx"),
        ("httpx.request('GET', u)", "httpx"),
        ("httpx.stream('GET', u)", "httpx"),
        ("httpx.Client()", "httpx"),
        ("httpx.AsyncClient()", "httpx"),
        ("aiohttp.ClientSession()", "aiohttp"),
        ("aiohttp.request('GET', u)", "aiohttp"),
        ("urllib.request.urlopen(u)", "urllib"),
        ("urllib.request.urlretrieve(u, p)", "urllib"),
    ],
)
def test_each_call_and_client_construction_is_a_site(call: str, option: str) -> None:
    assert [s.option for s in sites_of("http-client", {"src/a.py": call + "\n"})] == [option]


@pytest.mark.parametrize(
    "code",
    [
        "requests.codes.ok",  # not a call
        "requests.exceptions.ConnectionError()",  # builds an error, not a request
        "requests.Request('GET', u)",
        "httpx.URL(u)",
        "httpx.Timeout(5)",
        "aiohttp.ClientTimeout(5)",
        "urllib.parse.quote(u)",
        "urllib.request.Request(u)",
        "urllib.urlopen(u)",  # not the module path
        "request.urlopen(u)",
        "myrequests.get(u)",
        "client.requests.get(u)",
        "session.get(u)",  # a session object: not seen
        "get(u)",
        "requests(u)",
        "requests.get",
        "make().get(u)",
        "requests().get(u)",
        "(a or b).get(u)",
    ],
)
def test_other_code_is_not_a_site(code: str) -> None:
    assert sites_of("http-client", {"src/a.py": code + "\n"}) == []


def test_an_alias_or_a_from_import_is_not_seen() -> None:
    source = "import requests as r\nfrom requests import get\nr.get(u)\nget(u)\n"
    assert sites_of("http-client", {"src/a.py": source}) == []


def test_calls_are_found_inside_nested_code_and_arguments() -> None:
    source = (
        "async def f():\n"
        "    async with aiohttp.ClientSession() as s:\n"
        "        return [httpx.get(requests.get(u).url) for u in urls]\n"
    )
    options = [s.option for s in sites_of("http-client", {"src/a.py": source})]
    assert sorted(options) == ["aiohttp", "httpx", "requests"]


def test_tests_and_scripts_count_like_other_files() -> None:
    source = "requests.get(u)\n"
    sites = sites_of("http-client", {"tests/test_x.py": source, "scripts/run.py": source})
    assert [s.file for s in sites] == ["scripts/run.py", "tests/test_x.py"]


def test_the_call_table_names_every_option() -> None:
    assert {path[0] for path in CALLS} == OPTIONS


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": "requests.get(u)\n" for i in range(3)}
    assert len(sites_of("http-client", files, max_workers=2)) == 3


def test_the_handler_reads_the_node_directly() -> None:
    node = parse(b"httpx.get(u)\n").body[0]
    assert isinstance(node, ast.Expr)
    assert list(http_sites(node.value, ctx())) == [Site("a.py", 1, 0, "httpx")]


def test_the_handler_gives_nothing_for_a_node_that_is_not_a_call() -> None:
    assert list(http_sites(ast.Name("requests"), ctx())) == []
