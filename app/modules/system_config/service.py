"""
System Configuration service layer.

Everything that touches the host lives here: subprocess calls, system config
file writes, SMS/SMTP delivery and TLS certificate handling. The router only
does HTTP, DB persistence and audit logging.

All commands run locally on this server (the API process must run as root, or
these calls fail with a permission error that is surfaced verbatim to the
caller). Commands are always passed as an argv list — never through a shell —
so a stored value can't be turned into a second command.

The backend image (python:3.13-slim) ships no systemctl and cannot reach the
host's systemd over D-Bus, so every apply step degrades instead of failing:
systemctl falls back to signalling the daemon (SIGHUP), timedatectl falls back
to `date -s` and the /etc/localtime symlink, and whatever still cannot be done
here comes back as a warning string. The config file is written and stored
either way, so the host picks it up at the next service start.
"""
import ipaddress
import logging
import os
import shutil
import smtplib
import subprocess
from datetime import datetime, timezone as dt_timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

from .schemas import MASK, reject_ssrf_target

logger = logging.getLogger(__name__)

# --- Paths / constants -------------------------------------------------
TIMESYNCD_CONF = Path("/etc/systemd/timesyncd.conf")
SNMPD_CONF = Path("/etc/snmp/snmpd.conf")
RSYSLOG_CONF = Path("/etc/rsyslog.d/99-ngcorion.conf")

CERT_DIR = Path("/etc/ngcorion/certs")
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

# Traefik's certificate directory, bind-mounted into this container as
# ./traefik/certs:/app/traefik/certs. The file names are the ones
# traefik/dynamic/tls.yml actually references — copying to any other name would
# store a certificate that Traefik never serves.
TRAEFIK_CERT_DIR = Path("/app/traefik/certs")
TRAEFIK_CERT_FILE = TRAEFIK_CERT_DIR / "ngcorion.local.crt"
TRAEFIK_KEY_FILE = TRAEFIK_CERT_DIR / "ngcorion.local.key"

# Traefik's file provider watches this directory (--providers.file.directory +
# --providers.file.watch=true), not certs/. Rewriting the dynamic file is what
# produces a change event, so the proxy re-reads its TLS configuration — and
# with it the certificate files — without a restart. Optional: when the
# directory is not mounted the certificate is still published and the operator
# is told to restart Traefik.
TRAEFIK_DYNAMIC_DIR = Path("/app/traefik/dynamic")
TRAEFIK_DYNAMIC_TLS = TRAEFIK_DYNAMIC_DIR / "tls.yml"

ZONEINFO_DIR = Path("/usr/share/zoneinfo")
LOCALTIME_LINK = Path("/etc/localtime")

COMMAND_TIMEOUT = 30  # seconds, for every subprocess call
FALLBACK_TIMEOUT = 10  # seconds, for the signal-based service fallbacks
HTTP_TIMEOUT = 30     # seconds, for the SMS provider call
SMTP_TIMEOUT = 30     # seconds, for the SMTP test

# systemctl is absent from the backend image (python:3.13-slim) and the host's
# systemd is not reachable over D-Bus from the container, so each service gets a
# supervisor-free fallback: SIGHUP makes these daemons re-read their config in
# place. Needs the `procps` package (pkill) in the image to work.
SERVICE_RELOAD_FALLBACKS = {
    "snmpd": ["pkill", "-HUP", "snmpd"],
    "rsyslog": ["pkill", "-HUP", "rsyslogd"],
    "systemd-timesyncd": ["pkill", "-HUP", "ntpd"],
}

MANAGED_HEADER = "# Managed by NGCorion — manual edits are overwritten\n"


class SystemConfigError(Exception):
    """A host-level operation could not be performed at all.

    Only raised where there is no partial result worth keeping (certificate
    storage, unreadable uploads). The time/SNMP/syslog apply steps never raise:
    they return warnings so a saved config is never rejected because the host
    could not be reconfigured.
    """


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


def try_command(
    command, timeout: int = COMMAND_TIMEOUT
) -> Optional[subprocess.CompletedProcess]:
    """Run an argv list without raising.

    Returns None when the command could not run at all (binary missing from the
    image, no permission, timed out) — as opposed to running and failing, which
    comes back as a CompletedProcess with a non-zero returncode.
    """
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        logger.info("Command timed out after %ss: %s", timeout, " ".join(command))
    except OSError as exc:
        logger.info("Command unavailable (%s): %s", " ".join(command), exc)
    return None


def command_error(result: Optional[subprocess.CompletedProcess]) -> str:
    """Human-readable reason a try_command() call did not succeed."""
    if result is None:
        return "command not available in this environment"
    detail = (result.stderr or result.stdout or "").strip()
    return detail or f"exit {result.returncode}"


def restart_service(service_name: str) -> Optional[str]:
    """Restart a host service; returns None on success or a warning string.

    systemctl first, then the signal fallback (SERVICE_RELOAD_FALLBACKS). When
    neither path works nothing is raised: the config file is already on disk, so
    the daemon picks it up the next time it starts, and the caller reports that
    as a warning instead of failing the request.
    """
    result = try_command(["systemctl", "restart", service_name])
    if result is not None and result.returncode == 0:
        return None
    systemctl_reason = command_error(result)

    fallback = SERVICE_RELOAD_FALLBACKS.get(service_name)
    if fallback:
        fallback_result = try_command(fallback, timeout=FALLBACK_TIMEOUT)
        if fallback_result is not None and fallback_result.returncode == 0:
            logger.info(
                "Reloaded %s via %s (systemctl unavailable: %s)",
                service_name, " ".join(fallback), systemctl_reason,
            )
            return None

    logger.warning(
        "Could not restart %s (systemctl: %s)", service_name, systemctl_reason
    )
    return (
        f"'{service_name}' could not be restarted from here "
        f"({systemctl_reason}); the new settings are on disk and take effect "
        f"after 'systemctl restart {service_name}' on the host."
    )


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
        # datetime.utcnow() is deprecated (and returns a *naive* value that the
        # trailing "Z" then mislabels); an aware UTC instant serialises itself.
        "utc_time": datetime.now(dt_timezone.utc).isoformat(),
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


def _set_timezone(timezone: str) -> Optional[str]:
    """timedatectl set-timezone, falling back to the /etc/localtime symlink."""
    result = try_command(["timedatectl", "set-timezone", timezone])
    if result is not None and result.returncode == 0:
        return None
    reason = command_error(result)

    # Fallback for a container without systemd: point /etc/localtime at the
    # zoneinfo file directly. The name is resolved against /usr/share/zoneinfo
    # and must stay inside it, so it can never escape into another path.
    zone_file = (ZONEINFO_DIR / timezone).resolve()
    if not (zone_file.is_file() and ZONEINFO_DIR in zone_file.parents):
        return (
            f"Timezone '{timezone}' could not be applied ({reason}) and is not a "
            f"known zone under {ZONEINFO_DIR}."
        )

    link_result = try_command(
        ["ln", "-sf", str(zone_file), str(LOCALTIME_LINK)], timeout=FALLBACK_TIMEOUT
    )
    if link_result is not None and link_result.returncode == 0:
        logger.info(
            "Set timezone %s via %s symlink (timedatectl unavailable: %s)",
            timezone, LOCALTIME_LINK, reason,
        )
        return None
    return (
        f"Timezone '{timezone}' could not be applied "
        f"(timedatectl: {reason}; symlink: {command_error(link_result)})."
    )


def _set_ntp(enabled: bool) -> Optional[str]:
    """timedatectl set-ntp. No supervisor-free equivalent exists, so a failure
    is reported as a warning rather than worked around."""
    state = "true" if enabled else "false"
    result = try_command(["timedatectl", "set-ntp", state])
    if result is not None and result.returncode == 0:
        return None
    return (
        f"NTP synchronisation could not be turned {'on' if enabled else 'off'} "
        f"({command_error(result)}); run 'timedatectl set-ntp {state}' on the host."
    )


def _set_manual_time(manual_time, tz_name: Optional[str] = None) -> Optional[str]:
    """Set the host clock from the operator's manual time.

    `date -s` reads its argument as a *local wall-clock* string, so an aware
    timestamp has to be converted into the zone the host is being set to before
    it is formatted. The UI sends `new Date(...).toISOString()`, i.e. a UTC
    instant: formatting that directly wrote the UTC wall clock into a host
    running in Asia/Tehran and left it 3.5 hours behind. A naive value is taken
    as already being local wall-clock time, which is what it means.
    """
    if isinstance(manual_time, str):
        manual_time = datetime.fromisoformat(manual_time)

    if manual_time.tzinfo is not None:
        target = None
        if tz_name:
            try:
                target = ZoneInfo(tz_name)
            except (ZoneInfoNotFoundError, ValueError):
                # The schema validates the zone, so this only happens when the
                # host's tz database lacks it. Fall back to the host's own
                # local zone rather than writing a UTC wall clock.
                logger.warning("Unknown timezone %s for manual time", tz_name)
        manual_time = manual_time.astimezone(target) if target else manual_time.astimezone()

    # The argv form means the value can never be interpreted as shell syntax.
    # Needs the SYS_TIME capability.
    stamp = manual_time.strftime("%Y-%m-%d %H:%M:%S")
    result = try_command(["date", "-s", stamp])
    if result is not None and result.returncode == 0:
        return None
    return (
        f"The clock could not be set to {stamp} ({command_error(result)}); "
        f"the container needs the SYS_TIME capability."
    )


def apply_time_config(config: Dict[str, Any]) -> List[str]:
    """Apply the time section to the host.

    Never raises: every step that cannot run here is collected as a warning so
    the saved configuration is still returned to the caller (the router turns
    these into the response's `warning` field).
    """
    warnings: List[str] = []
    timezone = config["timezone"]
    use_ntp = bool(config.get("use_ntp"))

    # Order matters: the timezone goes first so the manual `date -s` below is
    # interpreted against the zone the operator just chose, not the outgoing one.
    for warning in (_set_timezone(timezone), _set_ntp(use_ntp)):
        if warning:
            warnings.append(warning)

    if use_ntp:
        ntp_server = (config.get("ntp_server") or "").strip()
        if ntp_server:
            try:
                write_system_file(
                    TIMESYNCD_CONF,
                    f"{MANAGED_HEADER}[Time]\nNTP={ntp_server}\n",
                )
            except SystemConfigError as exc:
                warnings.append(str(exc))
        warning = restart_service("systemd-timesyncd")
        if warning:
            warnings.append(warning)
    else:
        manual_time = config.get("manual_time")
        if not manual_time:
            warnings.append("manual_time is missing, so the clock was left alone.")
        else:
            warning = _set_manual_time(manual_time, timezone)
            if warning:
                warnings.append(warning)

    return warnings


# ======================================================================
# 2. SNMP
# ======================================================================

def render_agent_address(server_ip: Optional[str], port: int) -> str:
    """The `agentAddress` directive binding snmpd to a specific host IP.

    Format is `udp:<ip>:<port>` for IPv4 and `udp6:[<ip>]:<port>` for IPv6 (the
    brackets are net-snmp's literal syntax for a bracketed IPv6 host). Falls
    back to binding every interface (`udp:<port>`, snmpd's own default) when no
    address is on file — this only happens for a row saved before server_ip
    existed, since the schema requires it on every new write.
    """
    server_ip = (server_ip or "").strip()
    if not server_ip:
        return f"agentAddress udp:{port}"
    try:
        is_v6 = ipaddress.ip_address(server_ip).version == 6
    except ValueError:
        # The schema already validates this on the way in; treat an
        # unparsable legacy value the same as a missing one rather than
        # writing a directive snmpd would refuse to parse.
        return f"agentAddress udp:{port}"
    return f"agentAddress udp6:[{server_ip}]:{port}" if is_v6 else f"agentAddress udp:{server_ip}:{port}"


def render_snmpd_conf(config: Dict[str, Any]) -> str:
    lines = [MANAGED_HEADER.rstrip("\n"), ""]
    server_ip = config.get("server_ip")
    if config.get("version") == "v2c":
        lines.append(f"rocommunity {config['v2_community']} default")
        lines.append(render_agent_address(server_ip, config.get('v2_port', 161)))
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
        lines.append(render_agent_address(server_ip, config.get('v3_port', 161)))
    return "\n".join(lines) + "\n"


def apply_snmp_config(config: Dict[str, Any]) -> List[str]:
    """Write snmpd.conf and restart snmpd. Never raises — see apply_time_config."""
    try:
        # 0640: the file holds the community string / v3 credentials.
        write_system_file(SNMPD_CONF, render_snmpd_conf(config), mode=0o640)
    except SystemConfigError as exc:
        # Nothing changed on disk, so there is nothing for a restart to pick up.
        return [str(exc)]

    warning = restart_service("snmpd")
    return [warning] if warning else []


def mask_snmp(config: Dict[str, Any]) -> Dict[str, Any]:
    masked = dict(config)
    masked["v3_auth_password"] = _masked(config.get("v3_auth_password"))
    masked["v3_priv_password"] = _masked(config.get("v3_priv_password"))
    return masked


# ======================================================================
# 3. Syslog
# ======================================================================

def render_rsyslog_conf(config: Dict[str, Any]) -> str:
    """Render the rsyslog forwarding rule.

    Selector syntax is `<facility>.<priority>  <target><host>:<port>`, where a
    single @ means UDP and @@ means TCP, e.g. `local0.* @@10.0.0.50:514`. The
    configured facility is what selects the messages - an empty/unset facility
    falls back to `*.*` (forward everything).
    """
    protocol = str(config.get("protocol") or "").strip().upper()
    target = "@@" if protocol == "TCP" else "@"

    facility = str(config.get("facility") or "").strip().lower()
    selector = f"{facility}.*" if facility else "*.*"

    server_ip = config["server_ip"]
    port = config.get("port") or 514
    return f"{MANAGED_HEADER}{selector} {target}{server_ip}:{port}\n"


def apply_syslog_config(config: Dict[str, Any]) -> List[str]:
    """Write the rsyslog drop-in and restart rsyslog. Never raises."""
    try:
        write_system_file(RSYSLOG_CONF, render_rsyslog_conf(config))
    except SystemConfigError as exc:
        return [str(exc)]

    warning = restart_service("rsyslog")
    return [warning] if warning else []


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
        # Re-checked here, not just at config-save time in SmsConfig: a
        # server_address that resolved to a public IP when saved could have
        # since been repointed (DNS rebinding) at an internal/metadata
        # address by the time this actually fires.
        reject_ssrf_target(url)
    except ValueError as exc:
        logger.warning("SMS test to %s refused: %s", phone, exc)
        return {"success": False, "message": f"server_address is not allowed: {exc}"}
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
    except ValueError as e:
        logger.debug(f"[SystemConfig] certificate is not PEM, retrying as DER: {e}")
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


def _touch_dynamic_config() -> bool:
    """Rewrite Traefik's dynamic TLS file so its file provider fires a change
    event and re-reads the certificate. Returns False when that isn't possible
    (directory not mounted, read-only, file absent).

    The content is preserved byte-for-byte — only the modification time moves.
    """
    if not TRAEFIK_DYNAMIC_TLS.is_file():
        return False
    try:
        TRAEFIK_DYNAMIC_TLS.write_bytes(TRAEFIK_DYNAMIC_TLS.read_bytes())
    except OSError as exc:
        logger.info("Could not touch %s: %s", TRAEFIK_DYNAMIC_TLS, exc)
        return False
    return True


def publish_certificate_to_proxy() -> Dict[str, Any]:
    """Copy the installed certificate into Traefik's certificate directory.

    Replaces the old `docker compose restart traefik` call: the backend
    container has neither the docker CLI nor the docker socket, so it hands the
    certificate to Traefik through the shared ./traefik/certs bind mount and
    nudges the file provider instead.

    Best effort by design — a dev machine without the mount must not fail an
    otherwise successful upload; the returned message says what is still needed.
    """
    if not TRAEFIK_CERT_DIR.is_dir():
        return {
            "published": False,
            "reloaded": False,
            "message": (
                f"Certificate uploaded. {TRAEFIK_CERT_DIR} is not mounted, so it "
                f"was not handed to Traefik — copy it there and restart Traefik."
            ),
        }
    if not KEY_FILE.is_file():
        return {
            "published": False,
            "reloaded": False,
            "message": (
                "Certificate uploaded, but no private key is installed, so "
                "Traefik cannot serve it. Upload a key file or a PFX bundle."
            ),
        }

    try:
        shutil.copy(CERT_FILE, TRAEFIK_CERT_FILE)
        shutil.copy(KEY_FILE, TRAEFIK_KEY_FILE)
        os.chmod(TRAEFIK_CERT_FILE, 0o644)
        os.chmod(TRAEFIK_KEY_FILE, 0o600)
    except PermissionError:
        return {
            "published": False,
            "reloaded": False,
            "message": (
                f"Certificate uploaded, but {TRAEFIK_CERT_DIR} is not writable "
                f"from this container — copy it there and restart Traefik."
            ),
        }
    except OSError as exc:
        logger.warning("Publishing certificate to Traefik failed: %s", exc)
        return {
            "published": False,
            "reloaded": False,
            "message": f"Certificate uploaded, but copying it to Traefik failed: {exc}",
        }

    reloaded = _touch_dynamic_config()
    logger.info(
        "Published certificate to %s (dynamic config touched: %s)",
        TRAEFIK_CERT_FILE, reloaded,
    )
    if reloaded:
        return {
            "published": True,
            "reloaded": True,
            "message": "Certificate uploaded. Traefik will reload automatically.",
        }
    return {
        "published": True,
        "reloaded": False,
        "message": (
            "Certificate uploaded to Traefik's certificate directory. Traefik "
            "only watches its dynamic/ directory, which is not mounted here, so "
            "run 'docker compose restart traefik' to serve the new certificate."
        ),
    }
