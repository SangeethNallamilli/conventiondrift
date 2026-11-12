"""Allow `python -m conventiondrift`; delegates to the console-script entry point."""

from conventiondrift.cli import main

raise SystemExit(main())
