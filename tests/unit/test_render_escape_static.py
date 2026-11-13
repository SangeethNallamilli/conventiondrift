"""T-023 static checks (DESIGN §3a, SECURITY-RULES R3.1-R3.2).

1. Nothing in ``src/`` outside ``render/escape.py`` escapes text.
2. Nothing in ``src/`` (escape.py included), ``entry/`` or ``action.yml`` names
   ``GITHUB_ENV`` or ``GITHUB_PATH``.

The scanner is tested against planted violations so it can never pass by
finding nothing.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "conventiondrift"
ESCAPE = SRC / "render" / "escape.py"
VENDOR = SRC / "_vendor"

# Imports that exist to escape text for an output sink.
BANNED_MODULES = frozenset({"html", "xml.sax.saxutils", "markupsafe", "cgi"})
BANNED_ATTRS = frozenset(
    {
        ("html", "escape"),
        ("saxutils", "escape"),
        ("saxutils", "quoteattr"),
        ("parse", "quote"),
        ("parse", "quote_plus"),
        ("urllib.parse", "quote"),
        ("urllib.parse", "quote_plus"),
    }
)
BANNED_NAMES = frozenset({"quote", "quote_plus", "quoteattr", "escape"})  # from-imports
# String constants that only escaping code needs (sink escape sequences).
ESCAPE_TOKENS = re.compile(r"%25|%0[ADad]|%3[Aa]|%2[Cc]|&(?:lt|gt|amp|quot|#\d+);|ghadelimiter")
ENV_SINKS = re.compile(r"GITHUB_(?:ENV|PATH)\b")


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def escaping_findings(source: str, *, is_escape_module: bool) -> list[str]:
    """Return human-readable findings for one module's source."""
    tree = ast.parse(source)
    docs = _docstring_nodes(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docs:
                continue
            if ENV_SINKS.search(node.value):
                found.append(f"{line}: names GITHUB_ENV/GITHUB_PATH")
            if not is_escape_module and ESCAPE_TOKENS.search(node.value):
                found.append(f"{line}: escape sequence literal {node.value!r}")
        if is_escape_module:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in BANNED_MODULES:
                    found.append(f"{line}: imports {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in BANNED_MODULES:
                found.append(f"{line}: imports from {mod}")
            if mod in {"urllib.parse", "xml.sax.saxutils", "html"} and any(
                a.name in BANNED_NAMES for a in node.names
            ):
                found.append(f"{line}: imports an escape function from {mod}")
        elif isinstance(node, ast.Attribute):
            dotted = _dotted(node.value)
            if dotted and (dotted, node.attr) in BANNED_ATTRS:
                found.append(f"{line}: uses {dotted}.{node.attr}")
            if dotted and (dotted.rsplit(".", 1)[-1], node.attr) in BANNED_ATTRS:
                found.append(f"{line}: uses {dotted}.{node.attr}")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"replace", "translate", "maketrans", "sub"}
            and len(node.args) >= 2
            and isinstance(node.args[-1 if node.func.attr != "sub" else 1], ast.Constant)
        ):
            repl = node.args[-1 if node.func.attr != "sub" else 1]
            assert isinstance(repl, ast.Constant)
            if isinstance(repl.value, str) and re.fullmatch(
                r"\\[!-/:-@\[-`{-~]|\\\\.*|&\w+;|&#\d+;|%[0-9A-Fa-f]{2}", repl.value
            ):
                found.append(f"{line}: ad-hoc escape via .{node.func.attr}()")
    return found


def _src_modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if VENDOR not in p.parents)


def test_escaping_only_in_escape_module() -> None:
    assert ESCAPE.is_file()
    problems = {
        str(p.relative_to(ROOT)): f
        for p in _src_modules()
        if (f := escaping_findings(p.read_text("utf-8"), is_escape_module=p == ESCAPE))
    }
    assert problems == {}


def test_scanner_covers_every_src_module() -> None:
    mods = _src_modules()
    assert ESCAPE in mods
    assert len(mods) >= 5  # guards against an empty or wrong SRC path


def test_nothing_names_github_env_or_path_outside_python() -> None:
    hits = []
    for p in [ROOT / "action.yml", *sorted((ROOT / "entry").rglob("*"))]:
        if p.is_file() and ENV_SINKS.search(p.read_text("utf-8", errors="replace")):
            hits.append(str(p.relative_to(ROOT)))
    assert hits == []


# ---- the scanner itself finds planted violations ----------------------------------


@pytest.mark.parametrize(
    "src",
    [
        "import html\n",
        "import xml.sax.saxutils\n",
        "from html import escape\n",
        "from urllib.parse import quote\n",
        "import html as h\nh.escape('x')\n",
        "import urllib.parse\nurllib.parse.quote('x')\n",
        "from xml.sax import saxutils\nsaxutils.escape('x')\n",
        "s = 'a'.replace('%', '%25')\n",
        "s = t.replace('<', '&lt;')\n",
        "s = t.replace('*', '\\\\*')\n",
        "s = t.replace('\\n', '%0A')\n",
        "import re\ns = re.sub('([*_])', '\\\\\\\\\\\\1', t)\n",
        "d = 'ghadelimiter_x'\n",
        "import os\nos.environ['GITHUB_ENV']\n",
        "p = 'GITHUB_PATH'\n",
    ],
)
def test_scanner_flags_planted_violation(src: str) -> None:
    assert escaping_findings(src, is_escape_module=False)


@pytest.mark.parametrize(
    "src",
    [
        '"""Never writes GITHUB_ENV."""\n',
        "def f():\n    '''Mentions %25 and GITHUB_PATH in prose.'''\n",
        "p = path.replace('\\\\', '/')\n",
        "x = re.escape(word)\n",
        "s = 'GITHUB_STEP_SUMMARY'\n",
        "s = 'GITHUB_OUTPUT'\n",
        "s = t.replace('a', 'b')\n",
    ],
)
def test_scanner_allows_clean_code(src: str) -> None:
    assert escaping_findings(src, is_escape_module=False) == []


def test_escape_module_may_escape_but_never_names_env_sinks() -> None:
    assert escaping_findings("s = t.replace('%', '%25')\n", is_escape_module=True) == []
    assert escaping_findings("s = 'GITHUB_ENV'\n", is_escape_module=True)
