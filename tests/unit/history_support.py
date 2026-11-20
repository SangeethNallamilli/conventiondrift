"""Stand-ins and patch builders for the C8 history unit tests (T-020).

Test tooling only. ``FakeGit`` serves a first-parent chain, patch text and
tree/blob objects from memory, written against ``GitReaderProtocol``.
"""

from collections.abc import Generator, Mapping, Sequence
from datetime import UTC, datetime, timedelta

from conventiondrift.components import ChangedFile, TreeEntry
from conventiondrift.errors import ComponentError, FileSkipped
from conventiondrift.model import Window

END = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def sha(n: int) -> str:
    return f"{n:040x}"


def when(days_before_end: float) -> datetime:
    return END - timedelta(days=days_before_end)


def window(days: int = 90, end: datetime | None = END) -> Window:
    return Window(end=end, days=days, available=True, unavailable_reason=None)


def marker(commit: str) -> bytes:
    return b"\x00" + commit.encode() + b"\n\n"


def hunk(
    old_start: int, old_count: int, new_start: int, new_count: int, tail: bytes = b""
) -> bytes:
    """One ``-U0`` hunk; counts of 1 are omitted from the header like git does."""

    def span(start: int, count: int) -> bytes:
        return b"%d" % start if count == 1 else b"%d,%d" % (start, count)

    head = b"@@ -" + span(old_start, old_count) + b" +" + span(new_start, new_count) + b" @@"
    body = b"".join(b"-old line\n" for _ in range(old_count))
    body += b"".join(b"+new line\n" for _ in range(new_count))
    return head + tail + b"\n" + body


def file_diff(
    path: bytes,
    *hunks: bytes,
    old: bytes | None = None,
    new: bytes | None = None,
    rename_from: bytes | None = None,
    header: bytes = b"",
) -> bytes:
    """A ``diff --git`` section; ``old`` and ``new`` are the ``---``/``+++`` names."""
    old_name = old if old is not None else path
    new_name = new if new is not None else path
    out = b"diff --git a/" + old_name + b" b/" + new_name + b"\n" + header
    if rename_from is not None:
        out += b"similarity index 90%\nrename from " + rename_from + b"\nrename to " + path + b"\n"
    out += b"index " + b"1" * 40 + b".." + b"2" * 40 + b" 100644\n"
    if hunks:
        out += b"--- " + (b"a/" + old_name if old_name != b"/dev/null" else old_name) + b"\n"
        out += b"+++ " + (b"b/" + new_name if new_name != b"/dev/null" else new_name) + b"\n"
    return out + b"".join(hunks)


class FakeGit:
    """An in-memory C3 reader. Records calls and whether each patch stream was closed."""

    def __init__(
        self,
        chain: Sequence[tuple[str, datetime]] = (),
        patches: Sequence[bytes] = (),
        *,
        tree: Sequence[TreeEntry] = (),
        blobs: Mapping[str, bytes] | None = None,
        head: str | None = None,
        patches_for: Mapping[str, Sequence[bytes]] | None = None,
        chains: Mapping[str, Sequence[tuple[str, datetime]]] | None = None,
    ) -> None:
        self.chain = list(chain)
        self.chunks = list(patches)
        self.entries = list(tree)
        self.blobs = dict(blobs or {})
        self.head = head or sha(1)
        self.patches_for = dict(patches_for or {})
        self.chains = dict(chains or {})
        self.chain_calls: list[tuple[str, int]] = []
        self.patch_calls: list[tuple[str | None, str]] = []
        self.blob_calls: list[tuple[str, int]] = []
        self.tree_calls: list[str] = []
        self.closed = 0
        self.consumed = 0

    def resolve(self, rev: str) -> str:
        assert rev == "HEAD"
        return self.head

    def is_shallow(self) -> bool:
        return False

    def has_object(self, sha: str) -> bool:
        return True

    def merge_base(self, a: str, b: str) -> str | None:
        return None

    def commit_date(self, sha: str) -> datetime:
        return END

    def first_parent_chain(self, sha: str, limit: int) -> Sequence[tuple[str, datetime]]:
        self.chain_calls.append((sha, limit))
        if limit > 10_000:  # the real reader refuses a limit over MAX_COUNT_CAP
            raise ComponentError("gitread", "git --max-count over the cap")
        chain = self.chains.get(sha)
        if chain is None:
            chain = self.chain
            ids = [commit for commit, _ in chain]
            if sha in ids:  # a chain that starts at an older commit, like rev-list would
                chain = chain[ids.index(sha) :]
        return list(chain)[:limit]

    def patches(self, from_sha: str | None, to_sha: str) -> Generator[bytes, None, None]:
        self.patch_calls.append((from_sha, to_sha))
        return self._stream(self.patches_for.get(to_sha, self.chunks))

    def _stream(self, chunks: Sequence[bytes]) -> Generator[bytes, None, None]:
        try:
            for chunk in chunks:
                self.consumed += 1
                yield chunk
        finally:
            self.closed += 1

    def tree(self, sha: str) -> Sequence[TreeEntry]:
        self.tree_calls.append(sha)
        return self.entries

    def blob(self, oid: str, max_bytes: int) -> bytes:
        self.blob_calls.append((oid, max_bytes))
        if len(self.blobs[oid]) > max_bytes:  # the real reader checks the size before the body
            raise FileSkipped("size limit")
        return self.blobs[oid]

    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]:
        return ()

    def close(self) -> None:
        return None
