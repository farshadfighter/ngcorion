"""
Pydantic schemas for the System Configuration module.

These own the shape of every section payload stored in
``system_config_settings.config_json`` (the table itself is generic JSON).

Security note: several of these values are written verbatim into system config
files (/etc/snmp/snmpd.conf, /etc/rsyslog.d/99-ngcorion.conf,
/etc/systemd/timesyncd.conf). ``NoNewlines`` rejects CR/LF so a value can never
inject an extra directive line into those files.
"""
import ipaddress
import re
import socket
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from zoneinfo import available_timezones

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)
from app.models.enums import (
    SnmpAuthProtocolEnum,
    SnmpPrivProtocolEnum,
    SnmpVersionEnum,
    SyslogProtocolEnum,
)

# Returned in place of every stored secret. Sending it back unchanged on a PUT
# keeps the stored value (see service.unmask), so a UI round-trip of a masked
# GET never overwrites a real password with asterisks.
MASK = "********"


def _reject_newlines(value: Optional[str]) -> Optional[str]:
    if value is not None and ("\n" in value or "\r" in value):
        raise ValueError("value must not contain line breaks")
    return value


def reject_ssrf_target(url: str) -> str:
    """Raise unless `url` is http(s) and every address it resolves to is a
    public, routable address.

    This app makes a server-side HTTP request to whatever a SYSTEM_CONFIG
    "write" user configures here (the SMS provider's server_address) - without
    this check, that's a classic SSRF: the same admin action could be pointed
    at the cloud metadata endpoint (169.254.169.254), the license server's
    internal address, or any other host/port this container can otherwise
    only reach over the "app" network. Re-run right before the request is
    actually sent (not only at config-save time) so a DNS record that
    resolved to a public IP when saved can't be repointed at an internal one
    later (DNS rebinding).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("server_address must be an http:// or https:// URL")
    if not parsed.hostname:
        raise ValueError("server_address must include a host")

    try:
        resolved = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"server_address host could not be resolved: {exc}")

    for family, _type, _proto, _canonname, sockaddr in resolved:
        addr = ipaddress.ip_address(sockaddr[0])
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            raise ValueError(
                f"server_address resolves to a non-public address ({addr}); "
                "internal/private targets are not allowed"
            )
    return url


class _ConfigBase(BaseModel):
    """Shared validation: no string field may smuggle in a newline."""

    @field_validator("*")
    @classmethod
    def _no_newlines(cls, value):
        if isinstance(value, str):
            return _reject_newlines(value)
        return value


# ----------------------------------------------------------------------
# 1. Time
# ----------------------------------------------------------------------

class TimeConfig(_ConfigBase):
    timezone: str = Field(..., min_length=1, max_length=100, examples=["Asia/Tehran"])
    use_ntp: bool = True
    ntp_server: Optional[str] = Field(None, max_length=255)
    manual_time: Optional[datetime] = Field(
        None, description="Required when use_ntp is false"
    )

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, value: str) -> str:
        # The timedatectl fallback resolves this against /usr/share/zoneinfo, so
        # keep it to a plain zone name — no traversal, no absolute path.
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*", value):
            raise ValueError(
                "timezone must be a zone name such as 'Asia/Tehran'"
            )
        # Shape alone is not enough: 'Asia/Tehrn' passes the pattern, is stored,
        # and only surfaces later as an apply-time warning — leaving the config
        # claiming a zone the host never adopted. Check it against the real tz
        # database so a typo is a 422 at save time. Offsets are deliberately not
        # accepted: a fixed offset cannot follow a DST change.
        if value not in available_timezones():
            raise ValueError(
                f"unknown timezone '{value}'; use an IANA zone name "
                f"such as 'Asia/Tehran'"
            )
        return value

    @model_validator(mode="after")
    def _check_mode(self):
        if not self.use_ntp and self.manual_time is None:
            raise ValueError("manual_time is required when use_ntp is false")
        return self


# ----------------------------------------------------------------------
# 2. SNMP
# ----------------------------------------------------------------------

class SnmpConfig(_ConfigBase):
    version: SnmpVersionEnum
    # The address snmpd binds to (agentAddress in snmpd.conf) — required so the
    # daemon listens on a known management interface rather than silently
    # falling back to every interface on the host.
    server_ip: str = Field(..., min_length=1, max_length=100, examples=["10.0.0.25"])
    v2_community: Optional[str] = Field(None, max_length=255)
    v2_port: int = Field(161, ge=1, le=65535)
    v3_username: Optional[str] = Field(None, max_length=255)
    v3_auth_protocol: Optional[SnmpAuthProtocolEnum] = None
    v3_auth_password: Optional[str] = Field(None, max_length=255)
    v3_priv_protocol: Optional[SnmpPrivProtocolEnum] = None
    v3_priv_password: Optional[str] = Field(None, max_length=255)
    v3_port: int = Field(161, ge=1, le=65535)

    @field_validator("server_ip")
    @classmethod
    def _check_server_ip(cls, value: str) -> str:
        value = value.strip()
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(
                "server_ip must be a valid IPv4 or IPv6 address, e.g. '10.0.0.25'"
            )
        return value

    @model_validator(mode="after")
    def _check_version_fields(self):
        if self.version == SnmpVersionEnum.V2C:
            if not (self.v2_community or "").strip():
                raise ValueError("v2_community is required for SNMP v2c")
        else:
            missing = [
                name
                for name, value in (
                    ("v3_username", self.v3_username),
                    ("v3_auth_protocol", self.v3_auth_protocol),
                    ("v3_auth_password", self.v3_auth_password),
                    ("v3_priv_protocol", self.v3_priv_protocol),
                    ("v3_priv_password", self.v3_priv_password),
                )
                if value is None or (isinstance(value, str) and not value.strip())
            ]
            if missing:
                raise ValueError(
                    f"required for SNMP v3: {', '.join(missing)}"
                )
        return self


# ----------------------------------------------------------------------
# 3. Syslog
# ----------------------------------------------------------------------

class SyslogConfig(_ConfigBase):
    server_ip: str = Field(..., min_length=1, max_length=255)
    port: int = Field(514, ge=1, le=65535)
    protocol: SyslogProtocolEnum = SyslogProtocolEnum.UDP
    facility: str = Field("local0", min_length=1, max_length=50)

    @field_validator("server_ip", "facility")
    @classmethod
    def _no_whitespace(cls, value: str) -> str:
        value = value.strip()
        if not value or any(char.isspace() for char in value):
            raise ValueError("must be a single token without whitespace")
        return value


# ----------------------------------------------------------------------
# 4. SMS
# ----------------------------------------------------------------------

class SmsConfig(_ConfigBase):
    provider: str = Field(..., min_length=1, max_length=100)
    server_address: str = Field(..., min_length=1, max_length=500)
    api_key: str = Field(..., min_length=1, max_length=500)
    sender_number: Optional[str] = Field(None, max_length=50)
    username: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, max_length=255)

    @field_validator("provider")
    @classmethod
    def _check_provider(cls, value: str) -> str:
        # Stored verbatim and compared case-insensitively against "kavenegar"/
        # "ghasedak" both when routing the test-SMS request (service._sms_request)
        # and when the frontend decides whether to show the known-provider preset
        # or fall back to "Other". Without trimming here, a value saved with
        # stray whitespace (e.g. via a direct API call) sends correctly but the
        # UI can no longer recognise it as the known provider on reload.
        value = value.strip()
        if not value:
            raise ValueError("provider must not be blank")
        return value

    @field_validator("server_address")
    @classmethod
    def _check_server_address(cls, value: str) -> str:
        value = value.strip()
        if not value or any(char.isspace() for char in value):
            raise ValueError("server_address must be a single token without whitespace")
        return reject_ssrf_target(value)

    @field_validator("sender_number", "username")
    @classmethod
    def _strip_optional(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        return value or None


class SmsTestRequest(BaseModel):
    phone: str = Field(..., min_length=3, max_length=32, examples=["09121234567"])

    @field_validator("phone")
    @classmethod
    def _clean(cls, value: str) -> str:
        value = value.strip()
        if not value.replace("+", "").isdigit():
            raise ValueError("phone must contain digits only (optional leading +)")
        return value


# ----------------------------------------------------------------------
# 5. SMTP
# ----------------------------------------------------------------------

class SmtpConfig(_ConfigBase):
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(587, ge=1, le=65535)
    username: str = Field(..., max_length=255)
    password: str = Field(..., max_length=255)
    use_tls: bool = True
    use_ssl: bool = False
    from_email: EmailStr
    from_name: Optional[str] = Field(None, max_length=255)

    @model_validator(mode="after")
    def _check_transport(self):
        if self.use_tls and self.use_ssl:
            raise ValueError(
                "use_tls (STARTTLS) and use_ssl (implicit TLS) are mutually exclusive"
            )
        return self


class SmtpTestRequest(BaseModel):
    to: EmailStr
