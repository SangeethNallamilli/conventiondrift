#!/usr/bin/env python3
"""Re-run uv pip compile (universal, 3.11, hashes) and require a match.

The versions pinned in each committed lockfile are passed to uv as == constraints
(names and versions only, never hashes), so a newer upstream release does not
make the check fail. Hashes still come fresh from the index, and a .in change, a
hand-edited pin or a tampered hash still fails. Bumping a pin is a deliberate,
reviewed lockfile change.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UV_CMD = [
    "uv",
    "pip",
    "compile",
    "--universal",
    "--python-version",
    "3.11",
    "--generate-hashes",
]
PAIRS = (
    ("requirements/build.in", "requirements/build.txt"),
    ("requirements/dev.in", "requirements/dev.txt"),
    ("requirements/mutation.in", "requirements/mutation.txt"),
)


PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def pins_of(lockfile: Path) -> list[str]:
    """Return name==version for every top-level pin in a committed lockfile."""
    if not lockfile.is_file():
        return []
    pins = []
    for line in lockfile.read_text(encoding="utf-8").splitlines():
        m = PIN_RE.match(line)
        if m:
            pins.append(f"{m.group(1)}=={m.group(2)}")
    return pins


def strip_pin_annotations(text: str, pins_name: str) -> str:
    """Drop uv's "-c <pins>" via-annotations so output matches a plain compile.

    uv lists a single source inline ("# via x") and several on their own
    "#   x" lines; after removing the constraints entry, re-collapse a lone one.
    """
    marker = f"    #   -c {pins_name}"
    lines = [ln for ln in text.splitlines() if ln != marker]
    out: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln == "    # via":
            j = i + 1
            while j < len(lines) and lines[j].startswith("    #   "):
                j += 1
            group = lines[i + 1 : j]
            if len(group) == 1:
                out.append("    # via " + group[0][len("    #   ") :])
            else:
                out.append(ln)
                out.extend(group)
            i = j
            continue
        out.append(ln)
        i += 1
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def compile_one(work: Path, src_in: str, src_out: str, constraints: Path) -> None:
    # Relative -o paths keep the header and "# via -r" lines identical; the
    # custom compile command keeps the header free of the constraints file.
    header = " ".join([*UV_CMD, src_in, "-o", src_out])
    cmd = [
        *UV_CMD,
        src_in,
        "-o",
        src_out,
        "--constraint",
        str(constraints),
        "--custom-compile-command",
        header,
    ]
    print("running:", " ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, check=True, cwd=work)


def main() -> int:
    if shutil.which("uv") is None:
        print("uv is not on PATH", file=sys.stderr)
        return 2

    # Compile with the same relative -o paths as the committed headers, in a temp tree.
    with tempfile.TemporaryDirectory(prefix="lockcheck-") as tmp:
        tmp_path = Path(tmp)
        for src_in, _src_out in PAIRS:
            in_path = tmp_path / src_in
            in_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / src_in, in_path)
        for src_in, src_out in PAIRS:
            constraints = tmp_path / (Path(src_out).name + ".pins")
            constraints.write_text("\n".join(pins_of(REPO / src_out)) + "\n", encoding="utf-8")
            compile_one(tmp_path, src_in, src_out, constraints)
            generated = tmp_path / src_out
            generated.write_text(
                strip_pin_annotations(generated.read_text(encoding="utf-8"), constraints.name),
                encoding="utf-8",
            )
            expected = (REPO / src_out).read_text(encoding="utf-8")
            actual = (tmp_path / src_out).read_text(encoding="utf-8")
            if expected != actual:
                print(f"lockfile stale: {src_out} does not match a fresh compile", file=sys.stderr)
                subprocess.run(["diff", "-u", str(REPO / src_out), str(tmp_path / src_out)])
                return 1
            print(f"ok: {src_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
