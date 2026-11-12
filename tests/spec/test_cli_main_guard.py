"""In-process coverage of ``conventiondrift.cli``'s ``if __name__ == "__main__"`` guard (I-4).

The console-script and ``python -m conventiondrift`` contract tests run in a
subprocess, so they never execute this branch (``python -m conventiondrift``
runs ``conventiondrift.__main__``, not ``cli.py``). An in-process
``runpy.run_module(..., run_name="__main__")`` is measured by coverage.py.

The helper first imports ``conventiondrift.cli`` so the guard's import path is
taken, then drops it from ``sys.modules`` before ``runpy`` re-executes the
module as ``__main__``. That avoids the RuntimeWarning that the module is
already in ``sys.modules``, without a global warnings filter.
"""

from __future__ import annotations

import importlib
import runpy
import sys

import pytest

import conventiondrift


def _run_cli_as_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> tuple[int, str, str]:
    """Re-execute ``conventiondrift.cli`` as ``__main__`` with *argv*.

    The module is imported (guard false) then dropped from ``sys.modules``
    so ``runpy`` can re-execute it as ``__main__`` without a RuntimeWarning.
    """
    importlib.import_module("conventiondrift.cli")
    monkeypatch.delitem(sys.modules, "conventiondrift.cli", raising=False)
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("conventiondrift.cli", run_name="__main__")
    captured = capsys.readouterr()
    code = excinfo.value.code
    assert isinstance(code, int), f"expected integer exit status, got {code!r}"
    return code, captured.out, captured.err


def test_cli_main_guard_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, stdout, stderr = _run_cli_as_main(monkeypatch, capsys, ["conventiondrift", "--version"])
    assert code == 0
    assert stdout == f"conventiondrift {conventiondrift.__version__}\n"
    assert stderr == ""


def test_cli_main_guard_unknown_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, stdout, _stderr = _run_cli_as_main(
        monkeypatch, capsys, ["conventiondrift", "--no-such-flag-cd"]
    )
    assert code == 2
    assert stdout == ""
