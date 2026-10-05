"""
Applying settings to the appliance: the files under /etc and /opt/ngcorion and
the few commands that make them take effect.

Everything goes through System, whose `root` and `runner` tests replace: with
root=<tmpdir> and a recording runner nothing on the real machine is touched.
"""
import hashlib
import json
import os
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from . import APPLIANCE_DIR, STATE_DIR, render
from .settings import ApplianceSettings, Network

NETWORK_FILE = "/etc/systemd/network/10-ngcorion.network"
ENV_FILE = f"{APPLIANCE_DIR}/.env"
CERT_DIR = f"{APPLIANCE_DIR}/traefik/certs"
LICENSE_CA_FILE = f"{CERT_DIR}/license-server.crt"
# Where the backend container sees ./traefik/certs (docker-compose.yml).
LICENSE_CA_IN_CONTAINER = "/app/traefik/certs/license-server.crt"
CONFIGURED_MARK = f"{STATE_DIR}/configured"
VERSION_FILE = f"{APPLIANCE_DIR}/VERSION"

COMPOSE = [
    "docker", "compose", "--project-directory", APPLIANCE_DIR,
    "-f", f"{APPLIANCE_DIR}/docker-compose.yml",
    "-f", f"{APPLIANCE_DIR}/docker-compose.appliance.yml",
]

_SKIP_IFACES = ("lo", "docker", "br-", "veth", "virbr")

# Sets a user's password inside the backend container (console menu, "Reset
# the web administrator's password"). The password arrives on stdin, never on
# a command line; the user must choose a new one at the next login.
_RESET_PASSWORD_PY = r"""
import sys, bcrypt
from app.core.database import SessionLocal
from app.models.user import User
from app.schemas.user import validate_password_strength
password = validate_password_strength(sys.stdin.readline().rstrip("\n"))
db = SessionLocal()
user = db.query(User).filter(User.username == "admin").first()
if user is None:
    sys.exit("There is no user named admin")
user.hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
user.must_change_password = True
user.is_active = True
db.commit()
print("ok")
"""


class CommandFailed(RuntimeError):
    """A system command the appliance needs returned an error."""


class System:
    """The machine being configured. `root` prefixes every path; `runner` runs commands."""

    def __init__(self, root: str = "/", runner: Optional[Callable] = None):
        self.root = Path(root)
        self.runner = runner or subprocess.run

    # ---------- primitives ----------

    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def read(self, p: str) -> Optional[str]:
        try:
            return self.path(p).read_text()
        except FileNotFoundError:
            return None

    def write(self, p: str, content: str, mode: int = 0o644) -> None:
        """Replace a file atomically (temporary file, then rename) with the given mode."""
        target = self.path(p)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "w") as fh:
                fh.write(content)
            os.replace(tmp, target)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def run(self, args: List[str], *, input: Optional[str] = None, check: bool = True,
            timeout: int = 600) -> subprocess.CompletedProcess:
        result = self.runner(args, input=input, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()[-1:] or [""]
            raise CommandFailed(f"{' '.join(args[:4])}...: {detail[0]}")
        return result

    # ---------- what the machine has ----------

    def interfaces(self) -> List[str]:
        """Physical/virtual NICs, in name order (no loopback, Docker or bridge devices)."""
        base = self.path("/sys/class/net")
        if not base.is_dir():
            return []
        return sorted(n for n in os.listdir(base) if not n.startswith(_SKIP_IFACES))

    def addresses(self) -> List[Tuple[str, str]]:
        """(interface, address/prefix) of every IPv4 address on the NICs."""
        out = self.run(["ip", "-4", "-j", "addr", "show"], check=False)
        try:
            data = json.loads(out.stdout or "[]")
        except ValueError:
            return []
        result = []
        for link in data:
            name = link.get("ifname", "")
            if name.startswith(_SKIP_IFACES):
                continue
            for a in link.get("addr_info", []):
                result.append((name, f"{a['local']}/{a['prefixlen']}"))
        return result

    def web_urls(self) -> List[str]:
        return [f"https://{addr.split('/')[0]}/" for _, addr in self.addresses()]

    def version(self) -> str:
        return (self.read(VERSION_FILE) or "").strip() or "unknown"

    def configured(self) -> bool:
        return self.path(CONFIGURED_MARK).exists()

    # ---------- applying settings ----------

    def apply_network(self, network: Network) -> None:
        self.write(NETWORK_FILE, render.networkd(network))
        self.run(["networkctl", "reload"])
        self.run(["networkctl", "reconfigure", network.interface], check=False)

    def apply_hostname(self, name: str) -> None:
        self.write("/etc/hostname", render.hostname_file(name))
        self.write("/etc/hosts", render.hosts(name))
        self.run(["hostname", name])

    def apply_ntp(self, servers: List[str]) -> None:
        self.write("/etc/systemd/timesyncd.conf", render.timesyncd(servers))
        self.run(["systemctl", "restart", "systemd-timesyncd"], check=False)

    def ensure_env(self, settings: ApplianceSettings, ca_in_container: str = "") -> Dict[str, str]:
        """Write /opt/ngcorion/.env. The secrets are made on the first run only: the
        database was initialised with POSTGRES_PASSWORD, so a later run keeps them."""
        existing = render.parse_env(self.read(ENV_FILE) or "")
        keys = render.new_secrets()
        for k in keys:
            if existing.get(k):
                keys[k] = existing[k]
        self.write(ENV_FILE, render.env_file(settings, keys, ca_in_container), mode=0o600)
        return keys

    def ensure_tls_certificate(self, name: str) -> bool:
        """A self-signed certificate for the web interface, made once (the System
        Configuration page can replace it later). Returns True when one was made."""
        crt, key = f"{CERT_DIR}/ngcorion.local.crt", f"{CERT_DIR}/ngcorion.local.key"
        if self.path(crt).exists() and self.path(key).exists():
            return False
        self.path(CERT_DIR).mkdir(parents=True, exist_ok=True)
        san = [f"DNS:{name}", "DNS:ngcorion.local"]
        san += [f"IP:{addr.split('/')[0]}" for _, addr in self.addresses()]
        self.run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-days", "825", "-nodes",
            "-subj", f"/CN={name}", "-addext", "subjectAltName=" + ",".join(san),
            "-keyout", str(self.path(key)), "-out", str(self.path(crt)),
        ])
        os.chmod(self.path(key), 0o600)
        return True

    def trust_license_server_certificate(self, pem: str) -> None:
        self.write(LICENSE_CA_FILE, pem, mode=0o644)

    # ---------- the NGCorion stack ----------

    def start_stack(self) -> None:
        self.run(["systemctl", "enable", "--now", "ngcorion.service"], timeout=900)

    def restart_stack(self) -> None:
        self.run(["systemctl", "restart", "ngcorion.service"], timeout=900)

    def wait_healthy(self, timeout: int = 600, sleep: Callable = time.sleep) -> bool:
        """Wait until the backend container reports healthy (database migrated, app up)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            out = self.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", "backend"], check=False)
            if out.stdout.strip() == "healthy":
                return True
            sleep(5)
        return False

    def create_admin(self, password: str) -> None:
        """The first web administrator (scripts/init_db.py); the password goes in on stdin."""
        self.run(COMPOSE + [
            "exec", "-T", "-u", "10001:10001", "backend", "sh", "-c",
            'IFS= read -r NGCORION_ADMIN_PASSWORD; export NGCORION_ADMIN_PASSWORD; '
            'exec python scripts/init_db.py',
        ], input=password + "\n")

    def reset_admin_password(self, password: str) -> None:
        self.run(COMPOSE + ["exec", "-T", "-u", "10001:10001", "backend", "python", "-c", _RESET_PASSWORD_PY],
                 input=password + "\n")

    def service_status(self) -> List[Tuple[str, str]]:
        """(container, state) for the stack's containers."""
        out = self.run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"], check=False)
        rows = []
        for line in (out.stdout or "").splitlines():
            if "\t" in line:
                name, status = line.split("\t", 1)
                if name in ("backend", "postgres", "redis", "traefik"):
                    rows.append((name, status))
        return rows

    def logs(self, lines: int = 40) -> str:
        return self.run(COMPOSE + ["logs", "--no-color", "--tail", str(lines), "backend"], check=False).stdout

    def mark_configured(self) -> None:
        self.write(CONFIGURED_MARK, time.strftime("%Y-%m-%dT%H:%M:%SZ\n", time.gmtime()))

    def power(self, action: str) -> None:
        assert action in ("reboot", "poweroff")
        self.run(["systemctl", action])


# ---------- the license server's certificate ----------

def license_server_certificate(url: str, timeout: float = 10.0) -> Tuple[bool, Optional[str], str]:
    """Look at the license server's TLS certificate.

    Returns (trusted_by_system_cas, pem, sha256 fingerprint). A certificate the
    system already trusts needs nothing more; a self-signed one can be pinned
    after the operator compares its fingerprint with the license server's.
    """
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        trusted = True
    except ssl.SSLError:
        trusted = False
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    der = ssl.PEM_cert_to_DER_cert(pem)
    fp = hashlib.sha256(der).hexdigest().upper()
    return trusted, pem, ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def verify_pinned(url: str, pem: str, timeout: float = 10.0) -> None:
    """Connect to the license server trusting only `pem`, with host name checking, as
    NGCorion will. Raises ssl.SSLError / OSError when it would fail."""
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    ctx = ssl.create_default_context(cadata=pem)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host):
            pass
