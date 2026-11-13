"""Protocol conformance: GitReader satisfies INTERFACES I-14 GitReaderProtocol (T-008).

The real check is static: ``mypy --strict`` on this file fails if any GitReader
signature drifts from the Protocol in ``components.py`` (D-TL-21). pytest also
runs it, so the module stays imported and exercised.
"""

from collections.abc import Callable, Generator
from pathlib import Path

from conventiondrift.components import Components, GitReaderProtocol
from conventiondrift.gitread import GitReader


def _as_protocol(repo: Path) -> GitReaderProtocol:
    return GitReader(repo)  # mypy --strict fails here on any signature drift


def test_git_reader_is_assignable_to_git_reader_protocol(tmp_path: Path) -> None:
    reader: GitReaderProtocol = _as_protocol(tmp_path)
    assert isinstance(reader, GitReader)


def test_git_reader_class_fits_the_components_factory_slot() -> None:
    factory: Callable[[Path], GitReaderProtocol] = GitReader
    assert Components(git_reader=factory).git_reader is GitReader


class _OneChunk:
    """Just enough of a reader for C8's call pattern."""

    def patches(self, from_sha: str | None, to_sha: str) -> Generator[bytes, None, None]:
        yield b"\x00" + to_sha.encode() + b"\n"


def _c8_reads_one_chunk_then_closes(reader: GitReaderProtocol | _OneChunk) -> bytes:
    stream = reader.patches(None, "a" * 40)
    first = next(stream)
    stream.close()  # I-14 item 9: a Generator, so no cast (mypy --strict checks this)
    return first


def test_c8_can_close_the_patches_stream_without_a_cast() -> None:
    assert _c8_reads_one_chunk_then_closes(_OneChunk()) == b"\x00" + b"a" * 40 + b"\n"
