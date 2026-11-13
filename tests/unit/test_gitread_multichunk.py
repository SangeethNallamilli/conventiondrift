"""CR2 S3 (#24 review): multi-chunk stdout comes through byte for byte (T-008).

A fake git writes several MiB in flushes whose sizes sit on each side of the
two chunk sizes the code uses (the reader's ``_CHUNK_BYTES`` and the patches
``PATCH_CHUNK_BYTES``). Through ``_run_bounded`` the bytes must be identical;
through ``patches`` every chunk must be at most 1 MiB and the joined bytes
identical. D-TL-25: a test asserts the write sizes straddle both constants.
"""

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from conventiondrift import gitread
from conventiondrift.gitread import GitReader

MIB = 1024 * 1024
#: Flush sizes, by hand: 64 KiB - 1, 64 KiB, 64 KiB + 1, 1 MiB - 1, 1 MiB, 1 MiB + 1, 1.
WRITES = [65535, 65536, 65537, MIB - 1, MIB, MIB + 1, 1]
TOTAL = 3 * MIB + 3 * 65536 + 1  # sum(WRITES), by hand: 3,342,337


def _expected() -> bytes:
    """Each write is its index letter, repeated: easy to read, and any reordering shows."""
    return b"".join(bytes([ord("a") + i]) * n for i, n in enumerate(WRITES))


def _fake_git() -> list[str]:
    code = (
        "import sys\n"
        f"for i, n in enumerate({WRITES!r}):\n"
        "    sys.stdout.buffer.write(bytes([97 + i]) * n); sys.stdout.buffer.flush()\n"
    )
    return [sys.executable, "-c", code]


def test_write_sizes_straddle_both_chunk_constants() -> None:
    assert sum(WRITES) == TOTAL == len(_expected())
    for size in (gitread._CHUNK_BYTES, gitread.PATCH_CHUNK_BYTES):
        assert {size - 1, size, size + 1} <= set(WRITES)


@pytest.mark.parametrize("cap", [TOTAL, TOTAL + MIB])
def test_runner_assembles_many_chunks_exactly(tmp_path: Path, cap: int) -> None:
    out = gitread._run_bounded(
        _fake_git(), cwd=tmp_path, env=dict(os.environ), label="log", max_stdout=cap, timeout=30.0
    )
    assert out.returncode == 0
    assert len(out.stdout) == TOTAL
    assert out.stdout == _expected()


def test_patches_stream_many_mib_in_chunks_of_at_most_one_mib(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = gitread._start_batch

    def start(_argv: list[str], **kwargs: Any) -> Any:
        return real(_fake_git(), **kwargs)

    monkeypatch.setattr(gitread, "_start_batch", start)
    repo = tmp_path / "repo"
    repo.mkdir()
    chunks = list(GitReader(repo).patches(None, "a" * 40))
    assert len(chunks) >= 4  # 3.2 MiB can't fit in fewer 1 MiB chunks
    assert all(0 < len(c) <= MIB for c in chunks)
    assert b"".join(chunks) == _expected()
