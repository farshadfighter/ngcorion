"""
Off-server copies: every finished backup is copied to each enabled SFTP
server or Windows share. Files are written under a temporary name and
renamed once complete, and the size on the far side is compared with ours,
so a destination never holds a half-written file under the real name.

SFTP host keys are pinned on first contact, like device SSH (see
app/core/ssh_host_keys.py): a server that later presents another key is
refused until an admin clears the pin.
"""
import base64
import hashlib
import io
import logging
import posixpath
import socket
from typing import Callable, Optional, Tuple

from app.core.credential_crypto import PURPOSE_SYSTEM_BACKUP, decrypt, encrypt

logger = logging.getLogger(__name__)

TIMEOUT = 20
BLOCK = 1 << 20


class DestinationError(Exception):
    pass


def seal(secret: str) -> str:
    return encrypt(secret, PURPOSE_SYSTEM_BACKUP)


def _secret(dest) -> str:
    if not dest.secret_encrypted:
        return ""
    try:
        return decrypt(dest.secret_encrypted, PURPOSE_SYSTEM_BACKUP)
    except ValueError:
        raise DestinationError("The stored password could not be opened; enter it again")


def fingerprint(host_key: Optional[str]) -> Optional[str]:
    if not host_key or " " not in host_key:
        return None
    raw = base64.b64decode(host_key.split(" ", 1)[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _folder(dest) -> str:
    return (dest.path or "").strip().strip("/\\")


# ── SFTP ──────────────────────────────────────────────────────────────────

def _private_key(text: str):
    import paramiko
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception as exc:        # wrong type: try the next
            errors.append(str(exc))
    raise DestinationError("The private key could not be read (OpenSSH or PEM, without a passphrase)")


class _Sftp:
    def __init__(self, dest):
        import paramiko
        self.dest = dest
        try:
            sock = socket.create_connection((dest.host, dest.port or 22), timeout=TIMEOUT)
        except OSError as exc:
            raise DestinationError(f"Cannot reach {dest.host}:{dest.port or 22} ({exc})")
        self.transport = paramiko.Transport(sock)
        try:
            self.transport.start_client(timeout=TIMEOUT)
            key = self.transport.get_remote_server_key()
            self.host_key = f"{key.get_name()} {key.get_base64()}"
            if dest.host_key and dest.host_key != self.host_key:
                raise DestinationError("The server presented a different host key than the one pinned. "
                                       "If the server was reinstalled, clear the pinned key and test again.")
            secret = _secret(dest)
            if dest.auth == "key":
                self.transport.auth_publickey(dest.username or "", _private_key(secret))
            else:
                self.transport.auth_password(dest.username or "", secret)
            if not self.transport.is_authenticated():
                raise DestinationError("Authentication failed")
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
        except DestinationError:
            self.close()
            raise
        except paramiko.AuthenticationException:
            self.close()
            raise DestinationError("Authentication failed: check the username and password or key")
        except (paramiko.SSHException, OSError, EOFError) as exc:
            self.close()
            raise DestinationError(f"SFTP connection failed: {exc}")

    def close(self):
        try:
            self.transport.close()
        except Exception:
            pass

    def _base(self) -> str:
        raw = (self.dest.path or "").strip().replace("\\", "/").rstrip("/")
        return raw

    def _path(self, name: str) -> str:
        base = self._base()
        return posixpath.join(base, name) if base else name

    def ensure_folder(self):
        base = self._base()
        if not base:
            return
        current = "/" if base.startswith("/") else ""
        for part in [p for p in base.split("/") if p]:
            current = posixpath.join(current, part) if current else part
            try:
                self.sftp.stat(current)
            except IOError:
                self.sftp.mkdir(current)

    def put(self, local: str, name: str, progress: Optional[Callable[[int], None]]) -> int:
        self.ensure_folder()
        final = self._path(name)
        part = final + ".part"
        with open(local, "rb") as src, self.sftp.open(part, "wb") as dst:
            dst.set_pipelined(True)
            sent = 0
            while True:
                block = src.read(BLOCK)
                if not block:
                    break
                dst.write(block)
                sent += len(block)
                if progress:
                    progress(sent)
        size = self.sftp.stat(part).st_size
        try:
            self.sftp.remove(final)
        except IOError:
            pass
        self.sftp.posix_rename(part, final)
        return size

    def remove(self, name: str):
        try:
            self.sftp.remove(self._path(name))
        except IOError:
            pass

    def probe(self):
        self.ensure_folder()
        probe = self._path(".ngcorion-write-test")
        with self.sftp.open(probe, "wb") as f:
            f.write(b"ok")
        self.sftp.remove(probe)


# ── Windows share (SMB) ───────────────────────────────────────────────────

class _Smb:
    def __init__(self, dest):
        import smbclient
        from smbprotocol.exceptions import SMBException
        self.smb = smbclient
        self.dest = dest
        self.host_key = None
        user = dest.username or ""
        if dest.domain and user and "\\" not in user and "@" not in user:
            user = f"{dest.domain}\\{user}"
        # Every smbclient call re-resolves its session from these; without
        # them a later call would quietly go to port 445 with no credentials.
        self.kw = {"username": user or None, "password": _secret(dest) or None, "port": dest.port or 445,
                   "connection_timeout": TIMEOUT}
        try:
            smbclient.register_session(dest.host, **self.kw)
        except (SMBException, OSError, ValueError) as exc:
            text = str(exc)
            if "logon" in text.lower() or "STATUS_LOGON_FAILURE" in text:
                raise DestinationError("Authentication failed: check the username, domain and password")
            if "Failed to connect" in text or isinstance(exc, OSError):
                raise DestinationError(f"Cannot reach {dest.host}:{dest.port or 445} ({text.split(': ', 1)[-1]})")
            raise DestinationError(f"Windows share connection failed: {text}")

    def close(self):
        try:
            self.smb.delete_session(self.dest.host, port=self.dest.port or 445)
        except Exception:
            pass

    def _unc(self, name: str = "") -> str:
        parts = [f"\\\\{self.dest.host}", (self.dest.share or "").strip("\\/")]
        folder = _folder(self.dest).replace("/", "\\")
        if folder:
            parts.append(folder)
        if name:
            parts.append(name)
        return "\\".join(parts)

    def ensure_folder(self):
        if _folder(self.dest):
            self.smb.makedirs(self._unc(), exist_ok=True, **self.kw)

    def put(self, local: str, name: str, progress: Optional[Callable[[int], None]]) -> int:
        from smbprotocol.exceptions import SMBException
        try:
            self.ensure_folder()
            final, part = self._unc(name), self._unc(name + ".part")
            with open(local, "rb") as src, self.smb.open_file(part, mode="wb", **self.kw) as dst:
                sent = 0
                while True:
                    block = src.read(BLOCK)
                    if not block:
                        break
                    dst.write(block)
                    sent += len(block)
                    if progress:
                        progress(sent)
            size = self.smb.stat(part, **self.kw).st_size
            try:
                self.smb.remove(final, **self.kw)
            except (SMBException, OSError):
                pass
            self.smb.rename(part, final, **self.kw)
            return size
        except (SMBException, OSError) as exc:
            raise DestinationError(f"Writing to the share failed: {exc}")

    def remove(self, name: str):
        from smbprotocol.exceptions import SMBException
        try:
            self.smb.remove(self._unc(name), **self.kw)
        except (SMBException, OSError):
            pass

    def probe(self):
        from smbprotocol.exceptions import SMBException
        try:
            self.ensure_folder()
            path = self._unc(".ngcorion-write-test")
            with self.smb.open_file(path, mode="wb", **self.kw) as f:
                f.write(b"ok")
            self.smb.remove(path, **self.kw)
        except (SMBException, OSError) as exc:
            raise DestinationError(f"Cannot write to the share: {exc}")


def _open(dest):
    if dest.type == "sftp":
        return _Sftp(dest)
    if dest.type == "smb":
        return _Smb(dest)
    raise DestinationError(f"Unknown destination type {dest.type}")


def test(dest) -> Tuple[str, Optional[str]]:
    """Connect, write and delete a small file. Returns (host key, fingerprint)
    - the host key to pin when the destination has none yet."""
    conn = _open(dest)
    try:
        conn.probe()
        return conn.host_key, fingerprint(conn.host_key)
    except DestinationError:
        raise
    except Exception as exc:
        raise DestinationError(str(exc))
    finally:
        conn.close()


def upload(dest, local: str, name: str, expected_size: int,
           progress: Optional[Callable[[int], None]] = None) -> Tuple[str, Optional[str]]:
    """Copy one backup file. Returns (remote path, host key seen)."""
    conn = _open(dest)
    try:
        size = conn.put(local, name, progress)
        if size != expected_size:
            conn.remove(name)
            raise DestinationError(f"The copy on the destination has {size} bytes instead of {expected_size}")
        where = conn._unc(name) if dest.type == "smb" else conn._path(name)
        return where, conn.host_key
    except DestinationError:
        raise
    except Exception as exc:
        raise DestinationError(str(exc))
    finally:
        conn.close()


def remove(dest, name: str) -> None:
    conn = _open(dest)
    try:
        conn.remove(name)
    finally:
        conn.close()
