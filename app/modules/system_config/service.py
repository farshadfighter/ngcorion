"""
System Configuration service layer.

Everything that touches the host lives here: subprocess calls, system config
file writes, SMS/SMTP delivery and TLS certificate handling. The router only
does HTTP, DB persistence and audit logging.

All commands run locally on this server (the API process must run as root, or
these calls fail with a permission error that is surfaced verbatim to the
caller). Commands are always passed as an argv list — never through a shell —
so a stored value can't be turned into a second command.
"""
import logging
import os
import smtplib
import subprocess
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)
from cryptography.x509.oid import NameOID

from .schemas import MASK

logger = logging.getLogger(__name__)

# --- Paths / constants -------------------------------------------------
TIMESYNCD_CONF = Path("/etc/systemd/timesyncd.conf")
SNMPD_CONF = Path("/etc/snmp/snmpd.conf")
RSYSLOG_CONF = Path("/etc/rsyslog.d/99-ngcorion.conf")

CERT_DIR = Path("/etc/ngcorion/certs")
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

COMPOSE_FILE = Path("/opt/ngcorion/docker-compose.yml")
COMPOSE_PROXY_SERVICE = "traefik"

COMMAND_TIMEOUT = 30  # seconds, for every subprocess call
HTTP_TIMEOUT = 30     # seconds, for the SMS provider call
SMTP_TIMEOUT = 30     # seconds, for the SMTP test

MANAGED_HEADER = "# Managed by NGCorion — manual edits are overwritten\n"


class SystemConfigError(Exception):
    """A host-level operation failed; the router turns this into HTTP 500."""


# ======================================================================
# Low-level helpers
# ======================================================================

def run_command(command, check: bool = True) -> subprocess.CompletedProcess:
    """Run an argv list with output capture and a hard timeout.

    Raises SystemConfigError carrying stderr (falling back to stdout) so the
    caller can return it to the operator verbatim.
    """
    printable = " ".join(command)
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=COMMAND_TIMEOUT
        )
    except FileNotFoundError:
        raise SystemConfigError(f"Command not found: {command[0]}")
    except subprocess.TimeoutExpired:
        raise SystemConfigError(
            f"Command timed out after {COMMAND_TIMEOUT}s: {printable}"
        )
    except OSError as exc:
        raise SystemConfigError(f"Failed to run '{printable}': {exc}")

    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise SystemConfigError(
            f"Command failed ({printable}, exit {proc.returncode}): "
            f"{detail or 'no output'}"
        )
    return proc


def write_system_file(path: Path, content: str, mode: int = 0o644) -> None:
    """Write a system config file, mapping every OS error to a clear message."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        os.chmod(path, mode)
    except PermissionError:
        raise SystemConfigError(
            f"Permission denied writing {path}. The service must run as root "
            f"(or own that path) to apply this setting."
        )
    except OSError as exc:
        raise SystemConfigError(f"Failed to write {path}: {exc}")


def unmask(new_value: Optional[str], stored_value: Optional[str]) -> Optional[str]:
    """Keep the stored secret when the client echoed back the mask."""
    if new_value == MASK:
        return stored_value
    return new_value


def _masked(value: Optional[str]) -> Optional[str]:
    return MASK if value else None


# ======================================================================
# 1. Time
# ======================================================================

def system_time_status() -> Dict[str, Any]:
    """Live clock state from timedatectl. Never fatal — the GET must still work
    on a host where timedatectl is unavailable."""
    status: Dict[str, Any] = {
        "current_time": datetime.now().astimezone().isoformat(),
        "utc_time": datetime.utcnow().isoformat() + "Z",
        "system_timezone": None,
        "ntp_enabled": None,
        "ntp_synchronized": None,
    }
    try:
        proc = run_command(
            ["timedatectl", "show",
             "--property=Timezone", "--property=NTP",
             "--property=NTPSynchronized"],
        )
    except SystemConfigError as exc:
        logger.debug("timedatectl show unavailable: %s", exc)
        return status

    values = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()

    status["system_timezone"] = values.get("Timezone")
    if "NTP" in values:
        status["ntp_enabled"] = values["NTP"].lower() == "yes"
    if "NTPSynchronized" in values:
        status["ntp_synchronized"] = values["NTPSynchronized"].lower() == "yes"
    return status


def apply_time_config(config: Dict[str, Any]) -> None:
    """Apply the time section to the host."""
    timezone = config["timezone"]
    use_ntp = bool(config.get("use_ntp"))

    if use_ntp:
        run_command(["timedatectl", "set-ntp", "true"])
        run_command(["timedatectl", "set-timezone", timezone])

        ntp_server = (config.get("ntp_server") or "").strip()
        if ntp_server:
            write_system_file(
                TIMESYNCD_CONF,
                f"{MANAGED_HEADER}[Time]\nNTP={ntp_server}\n",
            )
        run_command(["systemctl", "restart", "systemd-timesyncd"])
    else:
        run_command(["timedatectl", "set-ntp", "false"])
        run_command(["timedatectl", "set-timezone", timezone])

        manual_time = config.get("manual_time")
        if not manual_time:
            raise SystemConfigError("manual_time is required when NTP is disabled")
        if isinstance(manual_time, str):
            manual_time = datetime.fromisoformat(manual_time)
        # `date -s` wants a local wall-clock string; the argv form means the
        # value can never be interpreted as shell syntax.
        run_command(["date", "-s", manual_time.strftime("%Y-%m-%d %H:%M:%S")])


# ======================================================================
# 2. SNMP
# ======================================================================

def render_snmpd_conf(config: Dict[str, Any]) -> str:
    lines = [MANAGED_HEADER.rstrip("\n"), ""]
    if config.get("version") == "v2c":
        lines.append(f"rocommunity {config['v2_community']} default")
        lines.append(f"agentAddress udp:{config.get('v2_port', 161)}")
    else:
        lines.append(
            "createUser {username} {auth_proto} {auth_pass} "
            "{priv_proto} {priv_pass}".format(
                username=config["v3_username"],
                auth_proto=config["v3_auth_protocol"],
                auth_pass=config["v3_auth_password"],
                priv_proto=config["v3_priv_protocol"],
                priv_pass=config["v3_priv_password"],
            )
        )
        lines.append(f"rouser {config['v3_username']}")
        lines.append(f"agentAddress udp:{config.get('v3_port', 161)}")
    return "\n".join(lines) + "\n"


def apply_snmp_config(config: Dict[str, Any]) -> None:
    # 0640: the file holds the community string / v3 credentials.
    write_system_file(SNMPD_CONF, render_snmpd_conf(config), mode=0o640)
    run_command(["systemctl", "restart", "snmpd"])


def mask_snmp(config: Dict[str, Any]) -> Dict[str, Any]:
    masked = dict(config)
    masked["v3_auth_password"] = _masked(config.get("v3_auth_password"))
    masked["v3_priv_password"] = _masked(config.get("v3_priv_password"))
    return masked


# ======================================================================
# 3. Syslog
# ======================================================================

def render_rsyslog_conf(config: Dict[str, Any]) -> str:
    target = "@@" if config.get("protocol") == "TCP" else "@"
    return (
        f"{MANAGED_HEADER}"
        f"# facility: {config.get('facility', 'local0')}\n"
        f"*.* {target}{config['server_ip']}:{config.get('port', 514)}\n"
    )


def apply_syslog_config(config: Dict[str, Any]) -> None:
    write_system_file(RSYSLOG_CONF, render_rsyslog_conf(config))
    run_command(["systemctl", "restart", "rsyslog"])


# ======================================================================
# 4. SMS
# ======================================================================

def mask_sms(config: Dict[str, Any]) -> Dict[str, Any]:
    masked = dict(config)
    masked["api_key"] = _masked(config.get("api_key"))
    masked["password"] = _masked(config.get("password"))
    return masked


def _sms_request(
    config: Dict[str, Any], phone: str, message: str
) -> Tuple[str, Dict[str, Any]]:
    """Build (url, requests kwargs) for the configured provider.

    `server_address` is always the provider's base URL. Two common providers get
    their documented path/parameter names; anything else falls back to a generic
    JSON POST straight to `server_address`.
    """
    provider = (config.get("provider") or "").strip().lower()
    base = (config.get("server_address") or "").rstrip("/")
    api_key = config.get("api_key") or ""
    sender = config.get("sender_number")

    if provider == "kavenegar":
        payload = {"receptor": phone, "message": message}
        if sender:
            payload["sender"] = sender
        return f"{base}/v1/{api_key}/sms/send.json", {"data": payload}

    if provider == "ghasedak":
        payload = {"receptor": phone, "message": message}
        if sender:
            payload["linenumber"] = sender
        return (
            f"{base}/v2/sms/send/simple",
            {"data": payload, "headers": {"apikey": api_key}},
        )

    # Generic HTTP provider: everything in one JSON body, key also as a header
    # since providers differ on where they expect it.
    payload = {
        "api_key": api_key,
        "receptor": phone,
        "phone": phone,
        "message": message,
    }
    if sender:
        payload["sender"] = sender
    kwargs: Dict[str, Any] = {
        "json": payload,
        "headers": {"X-API-KEY": api_key},
    }
    if config.get("username") and config.get("password"):
        kwargs["auth"] = (config["username"], config["password"])
    return base, kwargs


def send_test_sms(config: Dict[str, Any], phone: str) -> Dict[str, Any]:
    """Send a test SMS. Provider/transport failures are reported as
    success=False rather than raised — a failed test is a normal result."""
    message = "NGCorion test message. If you received this, SMS is configured."
    url, kwargs = _sms_request(config, phone, message)
    try:
        response = requests.post(url, timeout=HTTP_TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        logger.warning("SMS test to %s failed: %s", phone, exc)
        return {"success": False, "message": f"SMS provider request failed: {exc}"}

    body = (response.text or "").strip()[:300]
    if 200 <= response.status_code < 300:
        return {
            "success": True,
            "message": f"Test SMS sent to {phone} (provider replied {response.status_code}). {body}".strip(),
        }
    return {
        "success": False,
        "message": f"Provider returned HTTP {response.status_code}: {body or 'no body'}",
    }


# ======================================================================
# 5. SMTP
# ======================================================================

def mask_smtp(config: Dict[str, Any]) -> Dict[str, Any]:
    masked = dict(config)
    masked["password"] = _masked(config.get("password"))
    return masked


def send_test_email(config: Dict[str, Any], recipient: str) -> Dict[str, Any]:
    """Send a test email via smtplib. Returns success=False on any SMTP error."""
    message = EmailMessage()
    from_name = config.get("from_name")
    from_email = config["from_email"]
    message["From"] = f"{from_name} <{from_email}>" if from_name else from_email
    message["To"] = recipient
    message["Subject"] = "NGCorion SMTP test"
    message.set_content(
        "This is a test message from NGCorion.\n"
        "If you received it, the SMTP settings are working."
    )

    host = config["host"]
    port = int(config.get("port", 587))
    try:
        if config.get("use_ssl"):
            server = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT)
        else:
            server = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT)
        with server:
            server.ehlo()
            if config.get("use_tls") and not config.get("use_ssl"):
                server.starttls()
                server.ehlo()
            if config.get("username"):
                server.login(config["username"], config.get("password") or "")
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("SMTP test to %s failed: %s", recipient, exc)
        return {"success": False, "message": f"SMTP error: {exc}"}

    return {"success": True, "message": f"Test email sent to {recipient}"}


# ======================================================================
# 6. Certificate
# ======================================================================

def _common_name(name: x509.Name) -> Optional[str]:
    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attributes:
        return str(attributes[0].value)
    rfc = name.rfc4514_string()
    return rfc or None


def _expires_at(certificate: x509.Certificate) -> datetime:
    # cryptography >= 42 deprecates the naive `not_valid_after`.
    return getattr(certificate, "not_valid_after_utc", None) or \
        certificate.not_valid_after


def _load_certificate(data: bytes) -> x509.Certificate:
    """Parse a certificate in either PEM or DER form."""
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        raise SystemConfigError(
            "Unreadable certificate: expected a PEM or DER encoded X.509 file"
        )


def get_certificate_info() -> Dict[str, Any]:
    if not CERT_FILE.is_file():
        return {
            "has_cert": False,
            "expires_at": None,
            "issued_to": None,
            "issued_by": None,
        }
    try:
        data = CERT_FILE.read_bytes()
    except OSError as exc:
        raise SystemConfigError(f"Failed to read {CERT_FILE}: {exc}")

    certificate = _load_certificate(data)
    return {
        "has_cert": True,
        "expires_at": _expires_at(certificate).isoformat(),
        "issued_to": _common_name(certificate.subject),
        "issued_by": _common_name(certificate.issuer),
        "has_key": KEY_FILE.is_file(),
    }


def extract_pfx(data: bytes, password: Optional[str]) -> Tuple[bytes, bytes]:
    """(cert_pem, key_pem) from a PKCS#12 bundle."""
    secret = password.encode() if password else None
    try:
        key, certificate, _chain = load_key_and_certificates(data, secret)
    except ValueError as exc:
        raise SystemConfigError(
            f"Could not open the PFX bundle (wrong password or corrupt file): {exc}"
        )
    if certificate is None:
        raise SystemConfigError("The PFX bundle contains no certificate")
    if key is None:
        raise SystemConfigError("The PFX bundle contains no private key")

    return (
        certificate.public_bytes(Encoding.PEM),
        key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ),
    )


def normalize_certificate(data: bytes) -> bytes:
    """Validate an uploaded .cer/.crt and return it as PEM."""
    return _load_certificate(data).public_bytes(Encoding.PEM)


def validate_private_key(data: bytes) -> bytes:
    """Light sanity check on an uploaded key file (kept byte-identical so an
    encrypted key the proxy can decrypt still works)."""
    if b"PRIVATE KEY" not in data:
        raise SystemConfigError(
            "Unreadable private key: expected a PEM encoded '... PRIVATE KEY' file"
        )
    return data


def save_certificate(cert_pem: bytes, key_pem: Optional[bytes]) -> None:
    try:
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        CERT_FILE.write_bytes(cert_pem)
        os.chmod(CERT_FILE, 0o644)
        if key_pem is not None:
            KEY_FILE.write_bytes(key_pem)
            os.chmod(KEY_FILE, 0o600)
    except PermissionError:
        raise SystemConfigError(
            f"Permission denied writing to {CERT_DIR}. The service must run as "
            f"root (or own that directory) to store certificates."
        )
    except OSError as exc:
        raise SystemConfigError(f"Failed to store the certificate: {exc}")


def delete_certificate() -> bool:
    """Remove both files. Returns False when there was nothing to delete."""
    removed = False
    for path in (CERT_FILE, KEY_FILE):
        try:
            if path.is_file():
                path.unlink()
                removed = True
        except PermissionError:
            raise SystemConfigError(f"Permission denied removing {path}")
        except OSError as exc:
            raise SystemConfigError(f"Failed to remove {path}: {exc}")
    return removed


def reload_reverse_proxy() -> Dict[str, Any]:
    """Restart the traefik container so it picks up the new certificate.

    Best effort by design: a host without the compose stack (dev machine,
    bare-metal nginx) must not fail an otherwise successful upload.
    """
    if not COMPOSE_FILE.is_file():
        return {
            "reloaded": False,
            "message": f"{COMPOSE_FILE} not found; reload the proxy manually",
        }
    try:
        run_command([
            "docker", "compose", "-f", str(COMPOSE_FILE),
            "restart", COMPOSE_PROXY_SERVICE,
        ])
    except SystemConfigError as exc:
        logger.warning("Reverse-proxy reload failed: %s", exc)
        return {"reloaded": False, "message": str(exc)}
    return {"reloaded": True, "message": f"Restarted {COMPOSE_PROXY_SERVICE}"}
