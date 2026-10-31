"""
Applying settings to the appliance: the files under /etc and /opt/ngcorion and
the few commands that make them take effect.

Everything goes through System, whose `root` and `runner` tests replace: with
root=<tmpdir> and a recording runner nothing on the real machine is touched.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import APPLIANCE_DIR, LICENSE_SERVER_HOST, STATE_DIR, render
from . import settings as S
from .settings import Network

NETWORK_FILE = "/etc/systemd/network/10-ngcorion.network"
ENV_FILE = f"{APPLIANCE_DIR}/.env"
CERT_DIR = f"{APPLIANCE_DIR}/traefik/certs"
CONFIGURED_MARK = f"{STATE_DIR}/configured"
VERSION_FILE = f"{APPLIANCE_DIR}/VERSION"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/00-ngcorion.conf"
SSH_STATE = f"{STATE_DIR}/ssh.json"

COMPOSE = [
    "docker", "compose", "--project-directory", APPLIANCE_DIR,
    "-f", f"{APPLIANCE_DIR}/docker-compose.yml",
    "-f", f"{APPLIANCE_DIR}/docker-compose.appliance.yml",
]

_SKIP_IFACES = ("lo", "docker", "br-", "veth", "virbr")

# Sets a user's password inside the backend container (console menu, "Reset
# the web administrator's password"). The password arrives on stdin, never on
# a command line; the user must choose a new one at the next login. Their two-step sign-in is
# cleared too (a lost phone must not lock out the last administrator): they set it up again right
# after signing in, and every open session ends.
_RESET_PASSWORD_PY = r"""
import sys, bcrypt
from datetime import datetime, timezone
from app.core.database import SessionLocal
from app.models.user import User
from app.models.user_mfa import UserMfa
from app.schemas.user import validate_password_strength
password = validate_password_strength(sys.stdin.readline().rstrip("\n"))
db = SessionLocal()
user = db.query(User).filter(User.username == "admin").first()
if user is None:
    # no administrator yet (the first-start setup stopped before making one): make it now
    import os, runpy
    db.close()
    os.environ["NGCORION_ADMIN_PASSWORD"] = password
    runpy.run_path("scripts/init_db.py", run_name="__main__")
    sys.exit(0)
user.hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
user.must_change_password = True
user.is_active = True
mfa = db.query(UserMfa).filter(UserMfa.user_id == user.id).with_for_update().first()
if mfa is not None:
    mfa.enabled, mfa.secret, mfa.pending_secret, mfa.last_used_step = False, None, None, None
    mfa.recovery_codes, mfa.enabled_at = [], None
    mfa.version = (mfa.version or 0) + 1
    mfa.deadline = datetime.now(timezone.utc)
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
        try:
            result = self.runner(args, input=input, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            # A tool that is missing is a failed command, never a crash of the menu.
            result = subprocess.CompletedProcess(args, 127, "", f"{args[0]}: command not found")
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

    def ensure_env(self) -> Dict[str, str]:
        """Write /opt/ngcorion/.env. The secrets are made on the first run only: the
        database was initialised with POSTGRES_PASSWORD, so a later run keeps them."""
        existing = render.parse_env(self.read(ENV_FILE) or "")
        keys = render.new_secrets()
        for k in keys:
            if existing.get(k):
                keys[k] = existing[k]
        self.write(ENV_FILE, render.env_file(keys), mode=0o600)
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

    # ---------- the NGCorion stack ----------

    def start_stack(self) -> None:
        # Separately: `start` of the oneshot unit fails when `docker compose up`
        # does, and that error is what the operator needs to see.
        self.run(["systemctl", "enable", "ngcorion.service"])
        self.run(["systemctl", "start", "ngcorion.service"], timeout=1800)

    def restart_stack(self) -> None:
        self.run(["systemctl", "restart", "ngcorion.service"], timeout=900)

    def wait_healthy(self, timeout: int = 1200, sleep: Callable = time.sleep) -> bool:
        """Wait until the backend container reports healthy (database migrated, app up).
        The first start creates the database and applies every migration, which
        takes minutes on a slow host."""
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
                if name in ("backend", "postgres", "traefik"):
                    rows.append((name, status))
        return rows

    def logs(self, lines: int = 40) -> str:
        """The backend's log; while the backend is not running, also why the stack did not start."""
        out = self.run(COMPOSE + ["logs", "--no-color", "--tail", str(lines), "backend"], check=False).stdout or ""
        if not any(name == "backend" and state.startswith("Up") for name, state in self.service_status()):
            journal = self.run(["journalctl", "-u", "ngcorion.service", "-n", "25", "--no-pager", "-o", "cat"],
                               check=False).stdout or ""
            out = f"{out}\n--- ngcorion.service ---\n{journal}"
        return out

    # ---------- the disk ----------

    def root_partition(self) -> Optional[Tuple[str, str, int, str]]:
        """(partition, disk, partition number, filesystem type) of the root filesystem, e.g.
        ("sda1", "sda", 1, "ext4"); None when / is not on a partition of a disk."""
        out = self.run(["findmnt", "-n", "-o", "SOURCE,FSTYPE", "/"], check=False).stdout.split()
        if len(out) != 2 or not out[0].startswith("/dev/"):
            return None
        source, fstype = out
        name = os.path.basename(source)
        disk = self.run(["lsblk", "-n", "-d", "-o", "PKNAME", source], check=False).stdout.strip()
        number = (self.read(f"/sys/class/block/{name}/partition") or "").strip()
        if not disk or not number.isdigit():
            return None
        return name, disk, int(number), fstype

    def disk_usage(self) -> Optional[Tuple[int, int]]:
        """(used, total) bytes of the root filesystem."""
        try:
            usage = shutil.disk_usage(self.path("/"))
        except OSError:
            return None
        return usage.total - usage.free, usage.total

    def grow_disk(self) -> str:
        """Grow the root partition and its filesystem to the end of the virtual disk, after the
        disk was enlarged in the hypervisor. Run at every boot (ngcorion-growdisk.service) and
        from the console; does nothing when there is no room. Returns what happened."""
        found = self.root_partition()
        if found is None:
            return "The system disk could not be identified; nothing was changed."
        part, disk, number, fstype = found
        # A disk enlarged while the machine runs: have the kernel read its new size first.
        rescan = self.path(f"/sys/class/block/{disk}/device/rescan")
        if rescan.exists():
            try:
                rescan.write_text("1")
            except OSError:
                pass
        grown = self.run(["growpart", f"/dev/{disk}", str(number)], check=False)
        if grown.returncode == 1 and "NOCHANGE" in (grown.stdout or ""):
            return "The disk is already used to its full size."
        if grown.returncode != 0:
            detail = (grown.stderr or grown.stdout or "").strip().splitlines()[-1:] or ["growpart failed"]
            raise CommandFailed(f"growing the partition: {detail[0]}")
        if fstype == "xfs":
            self.run(["xfs_growfs", "/"])
        elif fstype.startswith("ext"):
            self.run(["resize2fs", f"/dev/{part}"])
        else:
            return f"The partition was grown; its {fstype} filesystem must be grown by hand."
        usage = self.disk_usage()
        return "The disk was grown" + (f": {_gib(usage[1])} now." if usage else ".")

    # ---------- SSH access ----------

    def ssh_access(self) -> S.SshAccess:
        """What was chosen (STATE_DIR/ssh.json); off when nothing was."""
        try:
            data = json.loads(self.read(SSH_STATE) or "{}")
            return S.SshAccess(enabled=bool(data.get("enabled")), password=bool(data.get("password")),
                               keys=[str(k) for k in data.get("keys", [])],
                               sources=[str(x) for x in data.get("sources", [])])
        except (ValueError, TypeError, AttributeError):
            return S.SshAccess()

    def apply_ssh(self, access: S.SshAccess, password: Optional[str] = None) -> None:
        """Turn SSH to the console menu on with these settings (or off: disable_ssh). `password`
        sets the account's password (hashed by chpasswd into /etc/shadow, nowhere else); without
        password sign-in the account's password is locked."""
        access.check()
        if not access.enabled:
            self.disable_ssh()
            return
        user = S.SSH_USER
        self.write(render.SSH_AUTHORIZED_KEYS, render.authorized_keys(access.keys), mode=0o644)
        self.write(render.SSH_BANNER, render.ssh_banner(), mode=0o644)
        self.write(SSHD_DROPIN, render.sshd_config(access), mode=0o644)
        if access.password and password:
            self.run(["chpasswd"], input=f"{user}:{password}\n")
            self.run(["usermod", "-U", user], check=False)
        elif not access.password:
            self.run(["usermod", "-L", user], check=False)
        self.run(["ssh-keygen", "-A"])                 # this machine's own host keys, made once
        # sshd -t needs its privilege separation directory, which only exists once ssh.service ran.
        self.path("/run/sshd").mkdir(mode=0o755, parents=True, exist_ok=True)
        self.run(["sshd", "-t"])                       # a configuration sshd refuses never goes live
        self.run(["systemctl", "disable", "--now", "ssh.socket"], check=False)
        self.run(["systemctl", "enable", "ssh.service"])
        self.run(["systemctl", "restart", "ssh.service"])
        self.write(SSH_STATE, json.dumps({"enabled": True, "password": access.password,
                                          "keys": access.keys, "sources": access.sources}) + "\n", mode=0o600)

    def disable_ssh(self) -> None:
        self.run(["systemctl", "disable", "--now", "ssh.service", "ssh.socket"], check=False)
        self.run(["usermod", "-L", S.SSH_USER], check=False)
        current = self.ssh_access()
        self.write(SSH_STATE, json.dumps({"enabled": False, "password": False,
                                          "keys": current.keys, "sources": current.sources}) + "\n", mode=0o600)

    def ssh_running(self) -> bool:
        return self.run(["systemctl", "is-active", "--quiet", "ssh.service"], check=False).returncode == 0

    def ssh_host_fingerprints(self) -> List[str]:
        """SHA256 fingerprints of this machine's SSH host keys, to compare on the first connection."""
        out = []
        for kind in ("ed25519", "ecdsa", "rsa"):
            pub = f"/etc/ssh/ssh_host_{kind}_key.pub"
            if self.path(pub).exists():
                line = self.run(["ssh-keygen", "-l", "-f", str(self.path(pub))], check=False).stdout.strip()
                if line:
                    out.append(line)
        return out

    def mark_configured(self) -> None:
        self.write(CONFIGURED_MARK, time.strftime("%Y-%m-%dT%H:%M:%SZ\n", time.gmtime()))

    def power(self, action: str) -> None:
        assert action in ("reboot", "poweroff")
        self.run(["systemctl", action])


def _gib(size: int) -> str:
    return f"{size / 1024 ** 3:.1f} GiB"


# ---------- the license server ----------

# OpenSSL verify codes meaning "the chain the server sent does not reach a root we know": the
# license server's host sends a Let's Encrypt "Generation Y" certificate without the cross-signed
# root (2026). NGCorion does not check that server's certificate (it checks the signed license
# answers instead; app/core/license_client.py), so this is reported, not treated as a failure.
_INCOMPLETE_CHAIN = {2, 20}          # unable to get issuer certificate / ... local issuer certificate


def check_license_server(host: str = LICENSE_SERVER_HOST, port: int = 443,
                         timeout: float = 10.0, cafile: Optional[str] = None) -> Tuple[bool, str]:
    """Can this machine reach the license server the way NGCorion will: name resolution, a
    connection on port 443 and a TLS handshake? Returns (ok, what happened) - a description the
    operator can act on. The certificate is looked at too, and what it says is part of the
    description: NGCorion trusts the signed license answers, not this certificate, so only a
    server that cannot be reached at all is a failure."""
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"{host} cannot be resolved ({exc}); check the DNS servers"
    try:
        # cafile: tests only (a local server with its own CA); otherwise the system's CAs.
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ssl.create_default_context(cafile=cafile).wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as exc:
        if exc.verify_code in _INCOMPLETE_CHAIN:
            return True, (f"{host} is reachable (its certificate chain is incomplete - the server "
                          "does not send the certificate that links it to a public root; NGCorion "
                          "checks the signed license answers instead)")
        return True, (f"{host} is reachable, but the certificate it presented is not the license "
                      f"server's public one ({exc.verify_message}). Something in the path may be "
                      "intercepting the connection: the license answers are still checked by "
                      "their signature, but the license key sent with the requests could be read")
    except ssl.SSLError as exc:
        return False, (f"{host} answered on port {port}, but no TLS connection could be made "
                       f"({exc.reason or exc}); a proxy or filter may be in the way")
    except OSError as exc:
        return False, f"cannot connect to {host} on port {port} ({exc}); check the gateway and firewall"
    return True, f"{host} is reachable"
