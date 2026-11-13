"""Test driver standing in for the CLI in the C-1 launch tests (I-13 C7 ruling 8).

The real CLI (I-4) is still the T-001 placeholder and doesn't call C7, so the
launch tests run this module the ways a user launches the CLI: through a
console-script wrapper (with and without ``-I`` or ``-E``) and as
``python -m``. It analyzes every ``pkg/**/*.py`` under the current folder with
two stand-in checkers and ``max_workers=2``, and prints one JSON object: the
report, the worker count (0 means the batches ran inline) and its own pid.

Usage: ``isolation_driver <record dir> [<repo dir>]``. The repo defaults to the
current folder; it is passed to ``analyze`` as ``repo_root``, as T-028 does.
"""

import json
import os
import sys
from pathlib import Path

from checker_standins import CallChecker, RecordingChecker

from conventiondrift.checkers.pool import analyze
from conventiondrift.model import PyFile


def _never(path: str) -> bool:
    return False


def main() -> int:
    record_dir = sys.argv[1]
    here = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd()
    files = [
        PyFile(p.relative_to(here).as_posix(), p.read_bytes())
        for p in sorted((here / "pkg").rglob("*.py"))
    ]
    checkers = {
        "logging": RecordingChecker(record_dir),
        "http-client": CallChecker("http-client", frozenset({"requests"})),
    }
    result = analyze(files, checkers=checkers, is_script=_never, max_workers=2, repo_root=str(here))
    report = {
        "sites": {
            cid: [[s.file, s.line, s.col, s.option] for s in result.sites(cid)]
            for cid in result.checker_ids()
        },
        "skipped": [[s.path, s.reason] for s in result.skipped],
        "failed": list(result.failed),
        "files_parsed": result.files_parsed,
        "ast_nodes": result.ast_nodes,
    }
    print(json.dumps({"report": report, "workers": result.workers, "pid": os.getpid()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
