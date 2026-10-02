"""
The .ngbak container: one encrypted, compressed stream holding every entry of
a backup (database tables, files, the manifest).

Layout on disk
    MAGIC                       8 bytes
    header length               4 bytes, big endian
    header                      JSON, readable without the passphrase (what the
                                UI shows for an uploaded file before unlocking)
    chunk*                      >I ciphertext length, B final flag,
                                12-byte nonce, AES-256-GCM ciphertext

The key comes from the passphrase through scrypt. Every chunk is authenticated
together with a digest of the header, its own index and the final flag, so a
reordered, edited, dropped or appended chunk fails to open, and a file that
ends without its final chunk is reported as cut short rather than read as a
smaller backup.

Inside the encryption the plaintext is one zlib stream of records:
    E <len:H> <name>            start of an entry
    D <len:I> <bytes>           entry data
    Z                           end of the entry
    X                           end of the archive
Nothing is ever written to disk unencrypted: writing and reading both stream.
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import zlib
from typing import BinaryIO, Callable, Dict, Iterator, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"NGBAK\x00\x01\n"
FORMAT = 1
CHUNK = 1 << 20                     # plaintext bytes per encrypted chunk
MAX_CHUNK = CHUNK + 4096            # sanity bound when reading
MAX_HEADER = 1 << 16
SCRYPT = {"n": 1 << 15, "r": 8, "p": 1}
CHECK_LABEL = b"ngcorion-backup-check"


class BackupFormatError(Exception):
    """Not a backup file, damaged, or cut short."""


class WrongPassphrase(Exception):
    pass


def derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=256 * 1024 * 1024, dklen=32)


def _check_value(key: bytes) -> bytes:
    return hmac.new(key, CHECK_LABEL, hashlib.sha256).digest()[:16]


def _aad(header_digest: bytes, index: int, final: bool) -> bytes:
    return header_digest + struct.pack(">QB", index, 1 if final else 0)


# ── writing ───────────────────────────────────────────────────────────────

class Writer:
    """Streams entries into an encrypted container.

    sha256 is the digest of the whole file as written (checked later without
    the passphrase); entries maps every entry name to its size and digest."""

    def __init__(self, out: BinaryIO, passphrase: str, header: dict):
        salt = os.urandom(16)
        key = derive_key(passphrase, salt, **SCRYPT)
        self._aes = AESGCM(key)
        head = dict(header)
        head.update({
            "format": FORMAT,
            "kdf": {"name": "scrypt", "salt": base64.b64encode(salt).decode(), **SCRYPT},
            "cipher": "AES-256-GCM",
            "compression": "zlib",
            "check": base64.b64encode(_check_value(key)).decode(),
        })
        raw = json.dumps(head, sort_keys=True, ensure_ascii=False).encode("utf-8")
        prefix = MAGIC + struct.pack(">I", len(raw)) + raw
        self._digest = hashlib.sha256(prefix).digest()
        self._out = out
        self._file_hash = hashlib.sha256()
        self._emit(prefix)
        self._zip = zlib.compressobj(6)
        self._pending = bytearray()
        self._index = 0
        self._entry: Optional[str] = None
        self._entry_hash = None
        self._entry_size = 0
        self.entries: Dict[str, dict] = {}
        self.size = len(prefix)
        self.closed = False

    def _emit(self, data: bytes) -> None:
        self._out.write(data)
        self._file_hash.update(data)

    def _seal(self, final: bool) -> None:
        while len(self._pending) >= CHUNK or final:
            take = bytes(self._pending[:CHUNK])
            del self._pending[:CHUNK]
            last = final and not self._pending
            nonce = os.urandom(12)
            ct = self._aes.encrypt(nonce, take, _aad(self._digest, self._index, last))
            frame = struct.pack(">IB", len(ct), 1 if last else 0) + nonce + ct
            self._emit(frame)
            self.size += len(frame)
            self._index += 1
            if last:
                return

    def _plain(self, data: bytes) -> None:
        self._pending += self._zip.compress(data)
        if len(self._pending) >= CHUNK:
            self._seal(False)

    def begin(self, name: str) -> None:
        if self._entry is not None:
            raise RuntimeError("entry %s still open" % self._entry)
        if name in self.entries:
            raise ValueError("duplicate entry %s" % name)
        raw = name.encode("utf-8")
        self._plain(b"E" + struct.pack(">H", len(raw)) + raw)
        self._entry, self._entry_hash, self._entry_size = name, hashlib.sha256(), 0

    def write(self, data: bytes) -> None:
        if self._entry is None:
            raise RuntimeError("no open entry")
        view = memoryview(data)
        for start in range(0, len(view), CHUNK):
            part = bytes(view[start:start + CHUNK])
            self._plain(b"D" + struct.pack(">I", len(part)) + part)
            self._entry_hash.update(part)
            self._entry_size += len(part)

    def end(self) -> dict:
        self._plain(b"Z")
        info = {"size": self._entry_size, "sha256": self._entry_hash.hexdigest()}
        self.entries[self._entry] = info
        self._entry = None
        return info

    def add(self, name: str, data: bytes) -> dict:
        self.begin(name)
        self.write(data)
        return self.end()

    def close(self) -> str:
        """Finish the archive; returns the file's sha256."""
        if self._entry is not None:
            raise RuntimeError("entry %s still open" % self._entry)
        self._plain(b"X")
        self._pending += self._zip.flush()
        self._seal(True)
        self._out.flush()
        self.closed = True
        return self._file_hash.hexdigest()


# ── reading ───────────────────────────────────────────────────────────────

def read_header(f: BinaryIO) -> Tuple[dict, bytes]:
    """Header dict and the digest the chunks are bound to. Leaves f after it."""
    magic = f.read(len(MAGIC))
    if magic != MAGIC:
        raise BackupFormatError("not an NGCorion backup file")
    size_raw = f.read(4)
    if len(size_raw) != 4:
        raise BackupFormatError("file is cut short")
    (size,) = struct.unpack(">I", size_raw)
    if size > MAX_HEADER:
        raise BackupFormatError("header is too large")
    raw = f.read(size)
    if len(raw) != size:
        raise BackupFormatError("file is cut short")
    try:
        header = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise BackupFormatError("header is damaged") from exc
    if header.get("format") != FORMAT:
        raise BackupFormatError("unsupported backup format %r" % header.get("format"))
    return header, hashlib.sha256(magic + size_raw + raw).digest()


def unlock(header: dict, passphrase: str) -> bytes:
    kdf = header.get("kdf") or {}
    try:
        salt = base64.b64decode(kdf["salt"])
        key = derive_key(passphrase, salt, int(kdf["n"]), int(kdf["r"]), int(kdf["p"]))
        expected = base64.b64decode(header["check"])
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupFormatError("header is damaged") from exc
    if not hmac.compare_digest(_check_value(key), expected):
        raise WrongPassphrase()
    return key


class Reader:
    """Opens a container and walks its entries in order.

    for name, blocks in reader.entries():
        for data in blocks: ...

    Each entry's blocks must be read (or abandoned) before asking for the
    next entry; an abandoned entry is skipped but still checked."""

    def __init__(self, f: BinaryIO, passphrase: str,
                 progress: Optional[Callable[[int], None]] = None):
        self._f = f
        self.header, self._digest = read_header(f)
        self._aes = AESGCM(unlock(self.header, passphrase))
        self._progress = progress
        self._plain = self._decrypted()
        self._buf = bytearray()
        self._pos = 0
        self.entry_hashes: Dict[str, dict] = {}

    def _decrypted(self) -> Iterator[bytes]:
        unzip = zlib.decompressobj()
        index = 0
        while True:
            head = self._f.read(5)
            if len(head) < 5:
                raise BackupFormatError("file is cut short")
            length, final = struct.unpack(">IB", head)
            if length > MAX_CHUNK or final not in (0, 1):
                raise BackupFormatError("file is damaged")
            nonce = self._f.read(12)
            ct = self._f.read(length)
            if len(nonce) != 12 or len(ct) != length:
                raise BackupFormatError("file is cut short")
            try:
                plain = self._aes.decrypt(nonce, ct, _aad(self._digest, index, bool(final)))
            except InvalidTag as exc:
                raise BackupFormatError("file is damaged (chunk %d failed its check)" % index) from exc
            index += 1
            if self._progress:
                self._progress(self._f.tell())
            out = unzip.decompress(plain)
            if out:
                yield out
            if final:
                tail = unzip.flush()
                if tail:
                    yield tail
                if self._f.read(1):
                    raise BackupFormatError("unexpected data after the end of the backup")
                return

    def _take(self, n: int) -> bytes:
        while len(self._buf) - self._pos < n:
            try:
                more = next(self._plain)
            except StopIteration:
                raise BackupFormatError("archive ends in the middle of an entry")
            if self._pos:
                del self._buf[:self._pos]
                self._pos = 0
            self._buf += more
        out = bytes(self._buf[self._pos:self._pos + n])
        self._pos += n
        return out

    def _blocks(self, name: str) -> Iterator[bytes]:
        h, size = hashlib.sha256(), 0
        while True:
            tag = self._take(1)
            if tag == b"D":
                (n,) = struct.unpack(">I", self._take(4))
                if n > CHUNK:
                    raise BackupFormatError("archive is damaged")
                data = self._take(n)
                h.update(data)
                size += n
                yield data
            elif tag == b"Z":
                self.entry_hashes[name] = {"size": size, "sha256": h.hexdigest()}
                return
            else:
                raise BackupFormatError("archive is damaged")

    def entries(self) -> Iterator[Tuple[str, Iterator[bytes]]]:
        while True:
            tag = self._take(1)
            if tag == b"X":
                if len(self._buf) > self._pos:
                    raise BackupFormatError("unexpected data after the end of the archive")
                # Drain: the final chunk check and the trailing-data check
                # run only when the encrypted stream is read to its end.
                for _ in self._plain:
                    raise BackupFormatError("unexpected data after the end of the archive")
                return
            if tag != b"E":
                raise BackupFormatError("archive is damaged")
            (n,) = struct.unpack(">H", self._take(2))
            name = self._take(n).decode("utf-8")
            blocks = self._blocks(name)
            yield name, blocks
            for _ in blocks:        # whatever the caller did not read
                pass


def read_entry(blocks: Iterator[bytes], limit: int = 64 * 1024 * 1024) -> bytes:
    out = bytearray()
    for data in blocks:
        out += data
        if len(out) > limit:
            raise BackupFormatError("entry is larger than expected")
    return bytes(out)
