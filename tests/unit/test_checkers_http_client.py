"""Unit tests for the http-client checker, conventiondrift.checkers.http_client (T-017).

Covers AC-F3.3 and the HTTP client half of AC-F2.4 and AC-F2.5. Counts go through the real
walk and pool.
"""

import ast

import pytest
from checker_support import assert_linear, counts, rules_of, sites_of

from conventiondrift.checkers import REGISTRY
from conventiondrift.checkers.http_client import HttpClientChecker
from conventiondrift.checkers.http_client.match import OPTIONS, WORDS, match_rule
from conventiondrift.checkers.http_client.sites import CALLS, HttpSites
from conventiondrift.checkers.walk import parse
from conventiondrift.model import FileContext, RuleMatch, Site

USE_HTTPX = match_rule("use httpx for http calls.")


def match(preferred: tuple[str, ...], prohibited: tuple[str, ...] = ()) -> RuleMatch:
    return RuleMatch(frozenset(preferred), frozenset(prohibited), len(preferred + prohibited))


def run(source: str, path: str = "src/a.py") -> list[str]:
    """The options of the http-client sites in ``source``, in the walk's order."""
    return [s.option for s in sites_of("http-client", {path: source})]


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
    assert set(checker.ast_handlers()) == {ast.Module, ast.Call}


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
        # I-10 Negation 5(d): after a positive verb, "over" prohibits what follows it, like
        # "rather than" (D-PM-47 #1, AC-F2.3's "Prefer X over Y").
        ("prefer httpx over requests.", ("httpx",), ("requests",)),
        ("prefer httpx over requests and aiohttp.", ("httpx",), ("requests", "aiohttp")),
        ("use httpx rather than requests.", ("httpx",), ("requests",)),
        ("never use requests.", (), ("requests",)),
        ("don't use urllib.request or requests.", (), ("urllib", "requests")),
        ("avoid aiohttp.", (), ("aiohttp",)),
        ("USE HTTPX FOR HTTP CALLS.", ("httpx",), ()),
        # AC-F2.6: the sentence reads as http-client with requests alone.
        ("never use print or requests.", (), ("requests",)),
        # Trailing cues (I-10 4a): an unbroken list before the cue is prohibited.
        ("requests and urllib are banned.", (), ("requests", "urllib")),
        ("requests is forbidden, use httpx.", ("httpx",), ("requests",)),
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
        # I-10 Negation 5(d): a comparison with no positive verb before "than" is not mapped.
        "httpx is better than requests.",
        # I-10 4a guards: comma with mentions on both sides, and a broken list.
        "httpx, requests and urllib are banned.",
        "httpx is fine and requests is forbidden.",
        "use httpx, everything else is forbidden.",
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
    assert run("import requests\nfrom httpx import get\nfrom aiohttp import ClientSession\n") == []


def test_a_site_is_at_the_call() -> None:
    source = "import requests\ndef f():\n    return requests.get(url).json()\n"
    assert sites_of("http-client", {"src/a.py": source}) == [Site("src/a.py", 3, 11, "requests")]


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
    module = call.split("(")[0].rsplit(".", 1)[0]
    assert run(f"import {module}\n{call}\n") == [option]


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
        "myrequests.get(u)",
        "client.requests.get(u)",
        "session.get(u)",  # a method call on a variable
        "get(u)",
        "requests(u)",
        "requests.get",
        "make().get(u)",
        "requests().get(u)",
        "(a or b).get(u)",
    ],
)
def test_other_code_is_not_a_site(code: str) -> None:
    header = "import requests, httpx, aiohttp, urllib.request, urllib.parse\n"
    assert run(header + code + "\n") == []


# --- import resolution (INTERFACES I-10) ---------------------------------------------------


@pytest.mark.parametrize(
    ("imports", "call", "option"),
    [
        ("import requests", "requests.get(u)", "requests"),
        ("import requests as r", "r.get(u)", "requests"),
        ("from requests import get", "get(u)", "requests"),
        ("from requests import get as fetch", "fetch(u)", "requests"),
        ("from requests import Session", "Session()", "requests"),
        ("from httpx import Client as C", "C()", "httpx"),
        ("from httpx import AsyncClient", "AsyncClient()", "httpx"),
        ("import httpx as hx", "hx.AsyncClient()", "httpx"),
        ("from aiohttp import ClientSession", "ClientSession()", "aiohttp"),
        ("import aiohttp as web", "web.ClientSession()", "aiohttp"),
        ("import urllib.request", "urllib.request.urlopen(u)", "urllib"),
        ("import urllib", "urllib.request.urlopen(u)", "urllib"),
        ("import urllib.request as ur", "ur.urlopen(u)", "urllib"),
        ("from urllib import request", "request.urlopen(u)", "urllib"),
        ("from urllib import request as rq", "rq.urlretrieve(u, p)", "urllib"),
        ("from urllib.request import urlopen", "urlopen(u)", "urllib"),
        ("from urllib.request import urlopen as uo", "uo(u)", "urllib"),
        ("import os, requests", "requests.get(u)", "requests"),
        ("import os.path, requests as r", "r.get(u)", "requests"),
    ],
)
def test_calls_through_imports_are_sites(imports: str, call: str, option: str) -> None:
    assert run(f"{imports}\n{call}\n") == [option]


@pytest.mark.parametrize(
    ("imports", "call"),
    [
        ("", "requests.get(u)"),  # never imported
        ("import requests as r", "requests.get(u)"),  # the alias replaces the name
        ("from requests import get", "requests.get(u)"),  # only `get` is bound
        ("from requests import *", "get(u)"),  # star imports are not followed
        ("from requests import *", "requests.get(u)"),
        ("import requests", "r.get(u)"),
        ("from . import requests", "requests.get(u)"),  # relative
        ("from .requests import get", "get(u)"),
        ("from requests import codes", "codes()"),
        ("import urllib3", "urllib3.PoolManager()"),
        ("import urllib3", "urllib3.request('GET', u)"),
        ("import http.client", "http.client.HTTPSConnection(h)"),
        ("from http.client import HTTPSConnection", "HTTPSConnection(h)"),
        ("import requests", "requests.get.__call__"),
        ("from urllib import parse", "parse.quote(u)"),
        ("import foo as requests", "requests.get(u)"),
        ("from os import path as urllib", "urllib.request.urlopen(u)"),
    ],
)
def test_calls_not_resolved_to_a_listed_name_are_not_sites(imports: str, call: str) -> None:
    assert run(f"{imports}\n{call}\n") == []


@pytest.mark.parametrize(
    "source",
    [
        "def f():\n    import requests\n    requests.get(u)\n",
        "async def f():\n    from httpx import Client\n    Client()\n",
        "class A:\n    import requests\n    requests.get(u)\n",
        "g = lambda: __import__('requests').get(u)\n",
        "def f():\n    import requests\nrequests.get(u)\n",
        "def f(requests):\n    session = requests.Session()\n",
    ],
)
def test_imports_inside_a_function_or_class_are_not_followed(source: str) -> None:
    assert run(source) == []


@pytest.mark.parametrize(
    "block",
    [
        "try:\n    import httpx\nexcept ImportError:\n    httpx = None\n",
        "try:\n    pass\nexcept ImportError:\n    import httpx\n",
        "try:\n    pass\nfinally:\n    import httpx\n",
        "try:\n    pass\nexcept* ValueError:\n    import httpx\n",
        "if TYPE_CHECKING:\n    import httpx\n",
        "if a:\n    pass\nelse:\n    import httpx\n",
        "with a:\n    import httpx\n",
        "async def f():\n    pass\nwith a:\n    with b:\n        import httpx\n",
        "for x in y:\n    import httpx\n",
        "else_ = 1\nwhile a:\n    pass\nelse:\n    import httpx\n",
        "match a:\n    case 1:\n        import httpx\n",
    ],
)
def test_imports_under_module_level_blocks_are_followed(block: str) -> None:
    assert run(block + "httpx.get(u)\n") == ["httpx"]


def test_the_last_import_of_a_name_wins() -> None:
    source = "import requests as c\nimport httpx as c\nc.get(u)\n"
    assert run(source) == ["httpx"]
    # A documented v1 limit (TE on #63): a try/except fallback binds the last import too.
    fallback = "try:\n    import httpx as h\nexcept ImportError:\n    import requests as h\n"
    assert run(fallback + "h.get(u)\n") == ["requests"]


def test_a_construction_is_a_site_and_a_call_on_its_variable_is_not() -> None:
    source = "import requests\ns = requests.Session()\ns.get(u)\ns.post(u)\n"
    assert run(source) == ["requests"]


def test_calls_are_found_inside_nested_code_and_arguments() -> None:
    source = (
        "import aiohttp, httpx, requests\n"
        "async def f():\n"
        "    async with aiohttp.ClientSession() as s:\n"
        "        return [httpx.get(requests.get(u).url) for u in urls]\n"
    )
    assert sorted(run(source)) == ["aiohttp", "httpx", "requests"]


def test_tests_and_scripts_count_like_other_files() -> None:
    source = "import requests\nrequests.get(u)\n"
    sites = sites_of("http-client", {"tests/test_x.py": source, "scripts/run.py": source})
    assert [s.file for s in sites] == ["scripts/run.py", "tests/test_x.py"]


def test_the_call_table_names_every_option() -> None:
    assert set(CALLS.values()) == OPTIONS
    assert ("urllib", "request", "urlopen") in CALLS
    assert ("requests", "Session") in CALLS
    assert ("httpx", "Client") in CALLS
    assert ("httpx", "AsyncClient") in CALLS
    assert ("aiohttp", "ClientSession") in CALLS


def test_the_checker_works_in_a_spawn_pool() -> None:
    files = {f"src/m{i}.py": "import requests\nrequests.get(u)\n" for i in range(3)}
    assert len(sites_of("http-client", files, max_workers=2)) == 3


# --- files do not affect each other (INTERFACES I-10, "Per-file handler state") -------------

FILE_A = "import requests as c\nc.get(u)\n"
FILE_B = "import httpx as c\nc.get(u)\nc.get(v)\n"
FILE_C = "c.get(u)\nrequests.get(u)\n"  # imports nothing: must not use A's or B's names


def test_files_give_the_same_sites_alone_and_together_in_either_order() -> None:
    files = {"a.py": FILE_A, "b.py": FILE_B, "c.py": FILE_C}
    alone = [s for name, text in files.items() for s in sites_of("http-client", {name: text})]
    together = sites_of("http-client", files)
    reversed_ = sites_of("http-client", dict(reversed(files.items())))
    assert sorted(together, key=lambda s: s.file) == alone
    assert reversed_ == together
    assert [s.file for s in alone] == ["a.py", "b.py", "b.py"]


def test_handlers_for_a_new_file_do_not_know_the_names_of_the_last_one() -> None:
    module = parse(b"import requests as c\n")
    call = parse(b"c.get(u)\n").body[0]
    assert isinstance(call, ast.Expr)
    handlers = HttpSites()
    assert list(handlers.imports(module, ctx())) == []
    assert [s.option for s in handlers.calls(call.value, ctx())] == ["requests"]
    assert [s.option for s in HttpSites().calls(call.value, ctx())] == []


def test_the_handlers_give_nothing_for_a_node_of_another_kind() -> None:
    handlers = HttpSites()
    assert list(handlers.calls(ast.Name("requests"), ctx())) == []
    assert list(handlers.imports(ast.Name("requests"), ctx())) == []


# --- linear time (R2.5; CR1 B1 and SR L-63-1 on #63) ----------------------------------------

HOSTILE_RULES = {
    "many mentions": lambda n: "use " + "httpx " * (n // 6),
    "cue first": lambda n: "never " + "requests " * (n // 9),
    "trailing-cue list": lambda n: "requests and " * (n // 13) + "httpx are banned",
    "comparatives": lambda n: "prefer httpx over " + "requests or " * (n // 12),
    "than": lambda n: "httpx is better than " + "requests " * (n // 9),
}


@pytest.mark.parametrize("kind", HOSTILE_RULES)
def test_match_rule_is_linear_up_to_the_1_mib_cap(kind: str) -> None:
    assert_linear(HOSTILE_RULES[kind], match_rule, label=kind)


def imports_and_calls(n: int) -> str:
    count = n // 40  # an import of about 22 bytes and a call of about 16 for each
    imports = "".join(f"import m{i} as a{i}\n" for i in range(count))
    # requests is bound last, so a call that searched the table in order would read it all.
    return imports + "import requests\n" + "requests.get(u)\n" * count


def aliases(n: int) -> str:
    count = n // 40
    imports = "".join(f"import requests as r{i}\n" for i in range(count))
    return imports + "".join(f"r{i}.get(u)\n" for i in range(count))


HOSTILE_SOURCES = {
    "many imports and many calls": imports_and_calls,
    "many aliases": aliases,
    # A comment per call keeps the node count per byte near ordinary code (see the
    # string-format tests), so the budget measures the handler and the walk, not the parser.
    "many calls": lambda n: "import httpx\n" + ("httpx.get(u)  # " + "x" * 40 + "\n") * (n // 57),
}


@pytest.mark.parametrize("kind", HOSTILE_SOURCES)
def test_the_site_handlers_are_linear_in_a_run(kind: str) -> None:
    make = HOSTILE_SOURCES[kind]
    assert_linear(make, lambda text: sites_of("http-client", {"src/a.py": text}), label=kind)
