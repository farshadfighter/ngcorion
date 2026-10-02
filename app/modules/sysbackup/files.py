"""
Files the product keeps outside the database: the web certificate and the
pinned SSH host keys. The license activation data is deliberately left out -
it is bound to this server and is re-activated, never copied.
"""
import logging
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Dict, Iterator, Tuple

logger = logging.getLogger(__name__)

MAX_FILE = 16 * 1024 * 1024


def _areas() -> Dict[str, Path]:
    from app.core.ssh_host_keys import resolve_store_path
    from app.modules.system_config.service import CERT_DIR
    return {"certs": CERT_DIR, "known_hosts": resolve_store_path()}


def collect() -> Iterator[Tuple[str, Path, int]]:
    """(entry name, path, mode) for every file to back up."""
    for area, base in _areas().items():
        try:
            if base.is_file():
                yield f"files/{area}", base, stat.S_IMODE(base.stat().st_mode)
            elif base.is_dir():
                for path in sorted(base.rglob("*")):
                    if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_FILE:
                        rel = path.relative_to(base).as_posix()
                        yield f"files/{area}/{rel}", path, stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            logger.warning("[sysbackup] cannot read %s: %s", base, exc)


def target(entry: str) -> Path:
    """Where a files/... entry goes on this server. Refuses anything that
    would land outside its area."""
    parts = PurePosixPath(entry).parts
    if len(parts) < 2 or parts[0] != "files":
        raise ValueError("not a file entry: %s" % entry)
    areas = _areas()
    base = areas.get(parts[1])
    if base is None:
        raise ValueError("unknown file area: %s" % parts[1])
    if len(parts) == 2:
        return base
    rel = PurePosixPath(*parts[2:])
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("unsafe path in backup: %s" % entry)
    path = base.joinpath(*rel.parts)
    if os.path.commonpath([str(base.resolve()), str(path.resolve())]) != str(base.resolve()):
        raise ValueError("unsafe path in backup: %s" % entry)
    return path


def write(entry: str, data: bytes, mode: int) -> Path:
    path = target(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".ngrestore")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode & 0o777 or 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode & 0o777 or 0o600)
    os.replace(tmp, path)
    return path


def after_restore(written: list) -> None:
    """Hand a restored web certificate to the proxy, as an upload would."""
    from app.modules.system_config.service import CERT_DIR, publish_certificate_to_proxy
    if any(str(p).startswith(str(CERT_DIR)) for p in written):
        try:
            publish_certificate_to_proxy()
        except Exception as exc:        # never fail a finished restore on this
            logger.warning("[sysbackup] could not publish the restored certificate: %s", exc)
