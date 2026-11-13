"""tools/gen_bench_repo.py except-clause census on every OS (CON-11, macOS git grep -E)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from bench import benchlib

SAMPLE = b"""\
try:
    pass
except:
    pass
except Exception:
    pass
except Exception as exc:
    pass
except Exception
except Exceptional:
    pass
except(ValueError):
    pass
except ValueError:
    pass
exceptional = 1
    exceptional = 2
    except_ = 3
"""


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_bench_repo", benchlib.GENERATOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _repo(gen: ModuleType, root: Path) -> Path:
    root.mkdir()
    gen.init_repo(root)
    (root / "m.py").write_bytes(b"class C:\n    def f(self):\n" + SAMPLE.replace(b"\n", b"\n    "))
    (root / "notes.txt").write_bytes(b"    except:\n")  # not *.py: never counted
    gen.git(root, "add", "-A")
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    gen.git(root, *ident, "commit", "-q", "-m", "census")
    return root


def test_census_patterns_are_plain_posix_ere() -> None:
    """No backslash escapes: macOS git compiles -E patterns without REG_ENHANCED."""
    gen = _load_generator()
    for pattern in gen._EXCEPT.values():
        assert "\\" not in pattern, pattern


def test_census_counts_whole_word_except_clauses(tmp_path: Path) -> None:
    """The word-end test matches `except` and `except Exception` but no longer words."""
    gen = _load_generator()
    repo = _repo(gen, tmp_path / "r")
    # Indented except lines in m.py: except:, except Exception: (x2), except Exception,
    # except Exceptional:, except(ValueError):, except ValueError: -> 7 clauses.
    assert gen.exception_census(repo, "main") == {"bare": 1, "Exception": 3, "all": 7}


def test_census_fails_loudly_when_git_grep_errors(tmp_path: Path) -> None:
    """A git error (exit > 1) is not read as zero matches."""
    gen = _load_generator()
    repo = _repo(gen, tmp_path / "r")
    with pytest.raises(RuntimeError, match="git grep -E"):
        gen.exception_census(repo, "no-such-ref")
