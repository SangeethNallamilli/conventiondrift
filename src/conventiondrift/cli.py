"""Console-script entry point placeholder (T-001).

The real CLI (INTERFACES I-4) replaces this module. Until then the command
only answers `--version` and otherwise exits 2, so nobody mistakes the
skeleton for a working tool.
"""

import sys

from conventiondrift import __version__


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--version"]:
        print(f"conventiondrift {__version__}")
        return 0
    print("conventiondrift: not implemented yet (package skeleton)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
