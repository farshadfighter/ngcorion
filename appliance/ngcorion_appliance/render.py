"""
The configuration files the appliance's settings become. Pure functions: text
in, text out, so every file can be checked by tests before it reaches a
machine.
"""
import secrets
from typing import Dict, List

from .settings import Network

HEADER = "# Written by the NGCorion appliance console. Change it there, not here.\n"


def networkd(network: Network) -> str:
    """systemd-networkd unit for the management interface (/etc/systemd/network/10-ngcorion.network)."""
    lines = [HEADER, "[Match]", f"Name={network.interface}", "", "[Network]"]
    if network.dhcp:
        lines.append("DHCP=ipv4")
    else:
        network.check()
        lines.append(f"Address={network.address.with_prefixlen}")
        lines.append(f"Gateway={network.gateway}")
        lines += [f"DNS={d}" for d in network.dns]
    # IPv6 router advertisements are not used for management.
    lines.append("IPv6AcceptRA=no")
    lines += ["LinkLocalAddressing=no", ""]
    if network.dhcp:
        lines += ["[DHCPv4]", "UseDNS=yes", "UseNTP=yes", ""]
    return "\n".join(lines)


def hostname_file(name: str) -> str:
    return name + "\n"


def hosts(name: str) -> str:
    """/etc/hosts: the appliance resolves its own name without DNS."""
    short = name.split(".")[0]
    names = name if short == name else f"{name} {short}"
    return (
        HEADER
        + "127.0.0.1\tlocalhost\n"
        + f"127.0.1.1\t{names}\n"
        + "::1\tlocalhost ip6-localhost ip6-loopback\n"
    )


def timesyncd(ntp: List[str]) -> str:
    """/etc/systemd/timesyncd.conf. Empty NTP: the servers DHCP supplies, then Ubuntu's pool."""
    body = HEADER + "[Time]\n"
    if ntp:
        body += "NTP=" + " ".join(ntp) + "\n"
    return body


def new_secrets() -> Dict[str, str]:
    """The installation's own secrets, made once on first boot and never shipped in the image."""
    return {
        "SECRET_KEY": secrets.token_hex(32),
        # URL-safe and without characters that need quoting in a DSN or a .env file.
        "POSTGRES_PASSWORD": secrets.token_hex(24),
    }


def env_file(keys: Dict[str, str]) -> str:
    """/opt/ngcorion/.env: read by docker compose for interpolation and passed to the backend
    (env_file). Only this installation's secrets: the license server is built into NGCorion."""
    values = {
        "SECRET_KEY": keys["SECRET_KEY"],
        "POSTGRES_PASSWORD": keys["POSTGRES_PASSWORD"],
        "NGCORION_TAG": "latest",
    }
    for k, v in values.items():
        if "\n" in v or '"' in v:
            raise ValueError(f"{k} cannot contain newlines or quotes")
    return HEADER + "".join(f'{k}="{v}"\n' for k, v in values.items())


def parse_env(text: str) -> Dict[str, str]:
    """Read back a file written by env_file (KEY="value" lines)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"')
    return out


def issue_text(version: str, urls: List[str]) -> str:
    """/etc/issue: what the console shows above everything else."""
    lines = [f"NGCorion {version}", ""]
    lines += [f"  Web interface: {u}" for u in urls] or ["  No network address yet"]
    return "\n".join(lines) + "\n\n"


# ---------- SSH access ----------

SSH_CONSOLE = "/usr/local/sbin/ngcorion-ssh-console"
SSH_AUTHORIZED_KEYS = "/etc/ngcorion/ssh/authorized_keys"
SSH_BANNER = "/etc/ngcorion/ssh/banner"


def sshd_config(access) -> str:
    """/etc/ssh/sshd_config.d/00-ngcorion.conf. The first value sshd reads for a keyword wins, and
    this file is read before the image's own drop-ins and the rest of sshd_config.

    One account, and it only ever gets the console menu: ForceCommand also replaces any command,
    shell or subsystem (sftp, scp) the client asks for; nothing can be forwarded or tunnelled."""
    from .settings import SSH_USER
    allow = " ".join(f"{SSH_USER}@{src}" for src in access.sources) or SSH_USER
    lines = [
        "# Written by the NGCorion console (SSH access). Changes here are overwritten.",
        "Port 22",
        "PermitRootLogin no",
        f"AllowUsers {allow}",
        f"PasswordAuthentication {'yes' if access.password else 'no'}",
        "KbdInteractiveAuthentication no",
        "PermitEmptyPasswords no",
        "PubkeyAuthentication yes",
        f"AuthorizedKeysFile {SSH_AUTHORIZED_KEYS}",
        "AuthorizedPrincipalsFile none",
        "HostbasedAuthentication no",
        "GSSAPIAuthentication no",
        "MaxAuthTries 3",
        "LoginGraceTime 30",
        "MaxSessions 2",
        "MaxStartups 3:50:10",
        "ClientAliveInterval 300",
        "ClientAliveCountMax 2",
        "DisableForwarding yes",
        "AllowTcpForwarding no",
        "AllowStreamLocalForwarding no",
        "AllowAgentForwarding no",
        "X11Forwarding no",
        "PermitTunnel no",
        "GatewayPorts no",
        "PermitUserRC no",
        "PermitUserEnvironment no",
        "PermitTTY yes",
        "PrintMotd no",
        f"Banner {SSH_BANNER}",
        "LogLevel VERBOSE",
        f"ForceCommand /usr/bin/sudo -n {SSH_CONSOLE}",
        "",
    ]
    return "\n".join(lines)


def authorized_keys(keys) -> str:
    return "".join(f"{key}\n" for key in keys)


def ssh_banner() -> str:
    return ("NGCorion appliance - authorised use only. Every sign-in and action is recorded.\n"
            "This session offers the appliance console menu only.\n")
