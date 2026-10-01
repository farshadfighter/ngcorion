"""
Outgoing notification channels.

Email, SMS and syslog use the servers already set in System Configuration;
webhooks are configured here. Every sender raises DeliveryError on failure so
the dispatcher can record it and retry.

  email    SMTP section (host, port, TLS/SSL, login, from).
  sms      SMS section (provider, server_address, api_key, sender).
  syslog   Syslog section (server_ip, port, UDP/TCP, facility); alerts are
           sent straight from NGCorion as CEF, which SIEMs (ArcSight, QRadar,
           Splunk, Wazuh) parse without a custom rule.
  webhook  JSON POST signed with HMAC-SHA256 over "<timestamp>.<body>":
             X-NGCorion-Timestamp: 1696153200
             X-NGCorion-Signature: sha256=<hex>
           A receiver recomputes the HMAC with the shared secret and rejects
           old timestamps, so a captured request cannot be replayed later.
"""
import hashlib
import hmac
import ipaddress
import json
import secrets
import smtplib
import socket
import time
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.system_config import SECTION_SMS, SECTION_SMTP, SECTION_SYSLOG, SECTION_TIME

TIMEOUT = 15
SEVERITY_CEF = {"info": 3, "warning": 6, "critical": 9}
SEVERITY_SYSLOG = {"info": 6, "warning": 4, "critical": 2}   # informational / warning / critical
FACILITIES = {f"local{i}": 16 + i for i in range(8)} | {"user": 1, "daemon": 3, "auth": 4, "syslog": 5}


class DeliveryError(Exception):
    pass


def load_section(db: Session, section: str) -> Dict[str, Any]:
    """A System Configuration section with its secrets decrypted ({} if not set)."""
    from app.modules.system_config.router import _load
    return _load(db, section)


def local_timezone(db: Session):
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    name = load_section(db, SECTION_TIME).get("timezone")
    try:
        return ZoneInfo(name) if name else None
    except (ZoneInfoNotFoundError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def send_email(config: Dict[str, Any], to: List[str], subject: str, text_body: str,
               html_body: Optional[str] = None) -> None:
    if not config or not config.get("host"):
        raise DeliveryError("Email is not configured - set SMTP in System Configuration")
    message = EmailMessage()
    from_email = config.get("from_email") or config.get("username") or ""
    message["From"] = formataddr((config.get("from_name") or "NGCorion", from_email))
    message["To"] = ", ".join(to)
    message["Subject"] = subject
    message.set_content(text_body)
    if html_body:
        message.add_alternative(html_body, subtype="html")
    host, port = config["host"], int(config.get("port") or 587)
    try:
        server = (smtplib.SMTP_SSL(host, port, timeout=TIMEOUT) if config.get("use_ssl")
                  else smtplib.SMTP(host, port, timeout=TIMEOUT))
        with server:
            server.ehlo()
            if config.get("use_tls") and not config.get("use_ssl"):
                server.starttls()
                server.ehlo()
            if config.get("username"):
                server.login(config["username"], config.get("password") or "")
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryError(f"SMTP error: {exc}") from exc


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------

def send_sms(config: Dict[str, Any], phone: str, text_body: str) -> None:
    from app.modules.system_config.schemas import reject_ssrf_target
    from app.modules.system_config.service import _sms_request
    if not config or not config.get("provider"):
        raise DeliveryError("SMS is not configured - set it in System Configuration")
    url, kwargs = _sms_request(config, phone, text_body)
    try:
        reject_ssrf_target(url)
    except ValueError as exc:
        raise DeliveryError(f"SMS provider address is not allowed: {exc}") from exc
    try:
        response = requests.post(url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
    except requests.RequestException as exc:
        raise DeliveryError(f"SMS provider request failed: {exc.__class__.__name__}") from exc
    if not 200 <= response.status_code < 300:
        raise DeliveryError(f"SMS provider returned HTTP {response.status_code}")


# ---------------------------------------------------------------------------
# Syslog (CEF)
# ---------------------------------------------------------------------------

def _cef_header(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(value: Any) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", "\\r").replace("\n", "\\n"))


def cef_message(payload: Dict[str, Any]) -> str:
    """CEF:Version|Vendor|Product|Version|Signature ID|Name|Severity|Extension"""
    ext = {
        "rt": payload.get("time_ms"),
        "cat": payload.get("module"),
        "act": payload.get("kind"),
        "msg": payload.get("detail") or payload.get("title"),
        "dvchost": payload.get("asset_name"),
        "dst": payload.get("asset_ip"),
        "cs1Label": "alertId", "cs1": payload.get("alert_id"),
        "cs2Label": "alertStatus", "cs2": payload.get("status"),
    }
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join(_cef_header(v) for v in (
        "CEF:0", "NGCorion", "NGCorion", settings.VERSION, payload.get("event_type", "alert"),
        payload.get("title", "Alert"), SEVERITY_CEF.get(payload.get("severity"), 5)))
    return f"{header}|{extension}"


def send_syslog(config: Dict[str, Any], payload: Dict[str, Any]) -> None:
    if not config or not config.get("server_ip"):
        raise DeliveryError("Syslog is not configured - set the server in System Configuration")
    facility = FACILITIES.get(str(config.get("facility") or "local0").lower(), 16)
    pri = facility * 8 + SEVERITY_SYSLOG.get(payload.get("severity"), 5)
    stamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    host = socket.gethostname()[:255] or "ngcorion"
    # RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG
    line = f"<{pri}>1 {stamp} {host} ngcorion - alert - {cef_message(payload)}"
    data = line.encode("utf-8", "replace")
    port = int(config.get("port") or 514)
    tcp = str(config.get("protocol") or "UDP").upper() == "TCP"
    try:
        if tcp:
            with socket.create_connection((config["server_ip"], port), timeout=TIMEOUT) as sock:
                sock.sendall(f"{len(data)} ".encode() + data)     # RFC 6587 octet counting
        else:
            with socket.socket(socket.AF_INET6 if ":" in config["server_ip"] else socket.AF_INET,
                               socket.SOCK_DGRAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.sendto(data[:8192], (config["server_ip"], port))
    except OSError as exc:
        raise DeliveryError(f"Syslog send failed: {exc.strerror or exc}") from exc


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

def new_secret() -> str:
    return secrets.token_urlsafe(32)


def check_webhook_url(url: str) -> str:
    """Webhooks usually point inside the company (chat, ticketing), so private
    addresses are allowed. Loopback, link-local (cloud metadata), multicast and
    unspecified addresses are not: they would reach NGCorion's own services."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("The URL must start with http:// or https:// and include a host")
    if parsed.username or parsed.password:
        raise ValueError("Put credentials in the signing secret, not in the URL")
    try:
        resolved = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise ValueError(f"The host could not be resolved: {exc.strerror or exc}") from exc
    for *_rest, sockaddr in resolved:
        addr = ipaddress.ip_address(sockaddr[0])
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or \
                (addr.is_reserved and not addr.is_private):
            raise ValueError(f"The host resolves to {addr}, which is not allowed")
    return url


def sign(secret: str, timestamp: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def send_webhook(url: str, secret: str, payload: Dict[str, Any]) -> int:
    try:
        check_webhook_url(url)
    except ValueError as exc:
        raise DeliveryError(str(exc)) from exc
    body = json.dumps(payload, separators=(",", ":"), default=str).encode()
    timestamp = str(int(time.time()))
    headers = {"Content-Type": "application/json", "User-Agent": f"NGCorion/{settings.VERSION}",
               "X-NGCorion-Event": str(payload.get("kind", "alert")),
               "X-NGCorion-Timestamp": timestamp, "X-NGCorion-Signature": sign(secret, timestamp, body)}
    try:
        response = requests.post(url, data=body, headers=headers, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as exc:
        raise DeliveryError(f"Request failed: {exc.__class__.__name__}") from exc
    if not 200 <= response.status_code < 300:
        raise DeliveryError(f"HTTP {response.status_code}")
    return response.status_code
