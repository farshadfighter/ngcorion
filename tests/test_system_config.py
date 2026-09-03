"""System Configuration: timezone support and the time-apply path.

Tehran is the deployment timezone, so the Time section has to accept
``Asia/Tehran`` as an IANA name (never a fixed offset — that cannot follow a DST
change) and the manual clock has to land on the right wall-clock second in that
zone.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from pydantic import ValidationError

from app.modules.system_config import service
from app.modules.system_config.schemas import SmsConfig, SnmpConfig, TimeConfig

FRONTEND_TIMEZONES = (
    PROJECT_ROOT / "front/src/components/SystemConfig/timezones.js"
)


# ----------------------------------------------------------------------
# Timezone validation
# ----------------------------------------------------------------------

def test_tehran_is_accepted():
    config = TimeConfig(timezone="Asia/Tehran", use_ntp=True)
    assert config.timezone == "Asia/Tehran"


def test_tehran_survives_surrounding_whitespace():
    assert TimeConfig(timezone="  Asia/Tehran  ", use_ntp=True).timezone == "Asia/Tehran"


@pytest.mark.parametrize("zone", [
    "UTC", "Europe/Berlin", "Asia/Dubai", "America/New_York",
])
def test_other_iana_zones_still_work(zone):
    assert TimeConfig(timezone=zone, use_ntp=True).timezone == zone


@pytest.mark.parametrize("bad", [
    "Asia/Tehrn",          # typo — used to be stored and fail only at apply time
    "Iran Standard Time",  # Windows name, not IANA
    "Mars/Olympus",
])
def test_unknown_zone_names_are_rejected(bad):
    with pytest.raises(ValidationError):
        TimeConfig(timezone=bad, use_ntp=True)


@pytest.mark.parametrize("bad", ["+03:30", "UTC+3:30", "../../etc/passwd", "/etc/localtime"])
def test_offsets_and_paths_are_rejected(bad):
    """A fixed offset cannot follow a DST change, and a path would escape the
    zoneinfo directory the apply step resolves against."""
    with pytest.raises(ValidationError):
        TimeConfig(timezone=bad, use_ntp=True)


def test_frontend_offers_tehran():
    source = FRONTEND_TIMEZONES.read_text()
    assert '"Asia/Tehran"' in source
    # No hardcoded UTC offset anywhere in the option list.
    assert "+03:30" not in source


# ----------------------------------------------------------------------
# manual_time
# ----------------------------------------------------------------------

def test_manual_time_required_when_ntp_is_off():
    with pytest.raises(ValidationError):
        TimeConfig(timezone="Asia/Tehran", use_ntp=False)


def _captured_stamp(manual_time, tz_name):
    with mock.patch.object(service, "try_command") as try_command:
        try_command.return_value = mock.Mock(returncode=0)
        warning = service._set_manual_time(manual_time, tz_name)
    assert warning is None
    argv = try_command.call_args[0][0]
    assert argv[:2] == ["date", "-s"]
    return argv[2]


def test_utc_manual_time_is_converted_to_the_target_zone():
    """The UI sends new Date(...).toISOString(), i.e. a UTC instant.

    Formatting that straight into `date -s` — which reads its argument as local
    wall-clock time — left a Tehran host 3.5 hours behind.
    """
    assert _captured_stamp("2026-08-27T06:30:00+00:00", "Asia/Tehran") == "2026-08-27 10:00:00"


def test_offset_manual_time_is_converted_to_the_target_zone():
    assert _captured_stamp("2026-08-27T12:00:00+02:00", "Asia/Tehran") == "2026-08-27 13:30:00"


def test_naive_manual_time_is_taken_as_local_wall_clock():
    """A value with no offset already means "this wall clock" — leave it."""
    assert _captured_stamp("2026-08-27T10:00:00", "Asia/Tehran") == "2026-08-27 10:00:00"


def test_datetime_objects_are_accepted_too():
    stamp = _captured_stamp(
        datetime(2026, 8, 27, 6, 30, tzinfo=timezone.utc), "Asia/Tehran"
    )
    assert stamp == "2026-08-27 10:00:00"


def test_timezone_is_applied_before_the_manual_clock():
    """`date -s` is interpreted against the *current* zone, so the zone has to
    be switched first or the clock lands in the outgoing zone."""
    calls = []
    with mock.patch.object(service, "_set_timezone", side_effect=lambda tz: calls.append("tz")), \
         mock.patch.object(service, "_set_ntp", side_effect=lambda on: calls.append("ntp")), \
         mock.patch.object(service, "_set_manual_time", side_effect=lambda t, tz=None: calls.append("clock")):
        service.apply_time_config({
            "timezone": "Asia/Tehran",
            "use_ntp": False,
            "manual_time": "2026-08-27T06:30:00+00:00",
        })
    assert calls.index("tz") < calls.index("clock")


def test_manual_time_receives_the_configured_zone():
    with mock.patch.object(service, "_set_timezone", return_value=None), \
         mock.patch.object(service, "_set_ntp", return_value=None), \
         mock.patch.object(service, "_set_manual_time", return_value=None) as set_clock:
        service.apply_time_config({
            "timezone": "Asia/Tehran",
            "use_ntp": False,
            "manual_time": "2026-08-27T06:30:00+00:00",
        })
    assert set_clock.call_args[0][1] == "Asia/Tehran"


# ----------------------------------------------------------------------
# Live clock readout
# ----------------------------------------------------------------------

def test_utc_time_is_an_aware_instant():
    """It used to be datetime.utcnow() (naive) with a "Z" glued on, which
    labelled a naive value as UTC."""
    with mock.patch.object(service, "run_command", side_effect=service.SystemConfigError("no timedatectl")):
        status = service.system_time_status()
    parsed = datetime.fromisoformat(status["utc_time"])
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


# ----------------------------------------------------------------------
# SNMP: server_ip
#
# The section had no address field at all — snmpd always bound every
# interface (`agentAddress udp:<port>`), so a submitted IP was silently
# ignored. server_ip is now a required, IP-validated field that flows
# frontend -> schema -> render_snmpd_conf's agentAddress line.
# ----------------------------------------------------------------------

def _v2c_config(**overrides):
    base = {
        "version": "v2c",
        "server_ip": "10.0.0.25",
        "v2_community": "public",
        "v2_port": 161,
    }
    base.update(overrides)
    return base


def _v3_config(**overrides):
    base = {
        "version": "v3",
        "server_ip": "10.0.0.25",
        "v3_username": "monitor",
        "v3_auth_protocol": "SHA",
        "v3_auth_password": "authpass123",
        "v3_priv_protocol": "AES",
        "v3_priv_password": "privpass123",
        "v3_port": 161,
    }
    base.update(overrides)
    return base


def test_snmp_requires_server_ip():
    config = _v2c_config()
    del config["server_ip"]
    with pytest.raises(ValidationError):
        SnmpConfig(**config)


@pytest.mark.parametrize("bad", ["not-an-ip", "10.0.0.999", "10.0.0", "", "   "])
def test_snmp_rejects_invalid_server_ip(bad):
    with pytest.raises(ValidationError):
        SnmpConfig(**_v2c_config(server_ip=bad))


@pytest.mark.parametrize("ip", ["10.0.0.25", "192.168.1.1", "::1", "2001:db8::1"])
def test_snmp_accepts_ipv4_and_ipv6(ip):
    assert SnmpConfig(**_v2c_config(server_ip=ip)).server_ip == ip


def test_snmp_server_ip_survives_surrounding_whitespace():
    assert SnmpConfig(**_v2c_config(server_ip="  10.0.0.25  ")).server_ip == "10.0.0.25"


def test_render_agent_address_ipv4():
    assert service.render_agent_address("10.0.0.25", 161) == "agentAddress udp:10.0.0.25:161"


def test_render_agent_address_ipv6():
    assert service.render_agent_address("::1", 161) == "agentAddress udp6:[::1]:161"


def test_render_agent_address_falls_back_when_missing():
    """A row saved before server_ip existed still renders a valid directive."""
    assert service.render_agent_address(None, 161) == "agentAddress udp:161"
    assert service.render_agent_address("", 161) == "agentAddress udp:161"


def test_render_snmpd_conf_v2c_uses_the_saved_server_ip():
    conf = service.render_snmpd_conf(_v2c_config(server_ip="192.168.10.5", v2_port=1161))
    assert "agentAddress udp:192.168.10.5:1161" in conf.splitlines()
    assert "rocommunity public default" in conf.splitlines()


def test_render_snmpd_conf_v3_uses_the_saved_server_ip():
    conf = service.render_snmpd_conf(_v3_config(server_ip="192.168.10.5", v3_port=1161))
    assert "agentAddress udp:192.168.10.5:1161" in conf.splitlines()
    assert "rouser monitor" in conf.splitlines()


def test_render_snmpd_conf_ignores_an_unparsable_legacy_server_ip():
    """A pre-validation legacy row could hold garbage; don't write it verbatim."""
    conf = service.render_snmpd_conf(_v2c_config(server_ip="not-an-ip"))
    assert "agentAddress udp:161" in conf.splitlines()


# ----------------------------------------------------------------------
# SMS: masking, unmasking and provider normalisation
# ----------------------------------------------------------------------

def _sms_config(**overrides):
    base = {
        "provider": "kavenegar",
        "server_address": "https://api.kavenegar.com",
        "api_key": "real-secret-key",
        "sender_number": "10008663",
        "username": None,
        "password": None,
    }
    base.update(overrides)
    return base


def test_mask_sms_masks_present_secrets():
    from app.modules.system_config.schemas import MASK
    masked = service.mask_sms({**_sms_config(), "password": "hunter2"})
    assert masked["api_key"] == MASK
    assert masked["password"] == MASK


def test_mask_sms_leaves_absent_password_as_none():
    masked = service.mask_sms(_sms_config(password=None))
    assert masked["password"] is None


def test_unmask_keeps_stored_secret_when_mask_is_echoed_back():
    from app.modules.system_config.schemas import MASK
    assert service.unmask(MASK, "the-real-key") == "the-real-key"


def test_unmask_overwrites_when_a_real_value_is_sent():
    assert service.unmask("brand-new-key", "the-real-key") == "brand-new-key"
    assert service.unmask(None, "the-real-key") is None


def test_sms_provider_is_stripped():
    """Stored untrimmed, 'kavenegar ' would send correctly (service._sms_request
    also strips) but silently show as "Other" in the UI on the next load."""
    assert SmsConfig(**_sms_config(provider="  Kavenegar  ")).provider == "Kavenegar"


def test_sms_provider_blank_after_strip_is_rejected():
    with pytest.raises(ValidationError):
        SmsConfig(**_sms_config(provider="   "))


def test_sms_server_address_rejects_embedded_whitespace():
    with pytest.raises(ValidationError):
        SmsConfig(**_sms_config(server_address="https://api.example.com/send now"))


def test_sms_sender_number_and_username_are_stripped_to_none_when_blank():
    config = SmsConfig(**_sms_config(sender_number="   ", username="  "))
    assert config.sender_number is None
    assert config.username is None


def test_sms_sender_number_is_trimmed():
    config = SmsConfig(**_sms_config(sender_number="  10008663  "))
    assert config.sender_number == "10008663"


def test_sms_api_key_is_required():
    with pytest.raises(ValidationError):
        SmsConfig(**_sms_config(api_key=""))


def test_sms_request_kavenegar_builds_documented_url_and_form_body():
    url, kwargs = service._sms_request(
        _sms_config(provider="kavenegar", server_address="https://api.kavenegar.com",
                    api_key="APIKEY123", sender_number="10008663"),
        "09121234567", "hello",
    )
    assert url == "https://api.kavenegar.com/v1/APIKEY123/sms/send.json"
    assert kwargs["data"] == {
        "receptor": "09121234567", "message": "hello", "sender": "10008663",
    }


def test_sms_request_ghasedak_builds_documented_url_and_header():
    url, kwargs = service._sms_request(
        _sms_config(provider="ghasedak", server_address="https://api.ghasedak.me",
                    api_key="APIKEY123", sender_number="10008663"),
        "09121234567", "hello",
    )
    assert url == "https://api.ghasedak.me/v2/sms/send/simple"
    assert kwargs["headers"] == {"apikey": "APIKEY123"}
    assert kwargs["data"] == {"receptor": "09121234567", "message": "hello", "linenumber": "10008663"}


def test_sms_request_generic_provider_posts_json_to_server_address():
    url, kwargs = service._sms_request(
        _sms_config(provider="acme-sms", server_address="https://sms.acme.test/send",
                    api_key="APIKEY123", sender_number=None),
        "09121234567", "hello",
    )
    assert url == "https://sms.acme.test/send"
    assert kwargs["json"]["api_key"] == "APIKEY123"
    assert kwargs["json"]["receptor"] == "09121234567"
    assert kwargs["headers"] == {"X-API-KEY": "APIKEY123"}
    assert "auth" not in kwargs


def test_sms_request_generic_provider_adds_basic_auth_when_username_and_password_set():
    _, kwargs = service._sms_request(
        _sms_config(provider="acme-sms", server_address="https://sms.acme.test/send",
                    api_key="APIKEY123", username="svc", password="secret"),
        "09121234567", "hello",
    )
    assert kwargs["auth"] == ("svc", "secret")
