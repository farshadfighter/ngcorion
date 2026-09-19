"""System Configuration: timezone support and the time-apply path.

Tehran is the deployment timezone, so the Time section has to accept
``Asia/Tehran`` as an IANA name (never a fixed offset — that cannot follow a DST
change) and the manual clock has to land on the right wall-clock second in that
zone.
"""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from pydantic import ValidationError
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import User
from app.models.system_config import SECTION_SMS, SECTION_SNMP, SystemConfigSetting
from app.modules.system_config import service
from app.modules.system_config.router import (
    get_sms_config,
    get_snmp_config,
    update_sms_config,
    update_snmp_config,
)
from app.modules.system_config.schemas import MASK, SmsConfig, SnmpConfig, TimeConfig

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

# SmsConfig.server_address is SSRF-checked with a live DNS lookup (see
# reject_ssrf_target) - unit tests must not depend on real network/DNS access,
# so every hostname used below is stubbed to resolve to a fixed public IP
# (93.184.216.34, IANA's reserved example.com address). Tests that exercise
# the SSRF guard itself use literal loopback/private/link-local IPs instead,
# which resolve locally with no DNS lookup at all.
#
# `schemas.socket` IS the real, process-global `socket` module (import binds
# a name, it doesn't copy it) - patching `.getaddrinfo` as an attribute on it
# patches DNS resolution for the ENTIRE process, including the `db` fixture's
# own psycopg connections below, which then tried to connect to the fake
# 93.184.216.34 and hung until the OS's TCP timeout. Patching the `socket`
# *name* inside schemas' own module namespace instead keeps this scoped to
# calls made through `schemas.reject_ssrf_target`.
@pytest.fixture(autouse=True)
def _stub_public_dns():
    import socket as real_socket_module
    import ipaddress as _ip

    class _StubSocket:
        @staticmethod
        def getaddrinfo(host, *args, **kwargs):
            try:
                _ip.ip_address(host)
                return real_socket_module.getaddrinfo(host, *args, **kwargs)
            except ValueError:
                return [(2, 1, 6, "", ("93.184.216.34", 0))]

        gaierror = real_socket_module.gaierror

    with mock.patch("app.modules.system_config.schemas.socket", _StubSocket):
        yield


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
    masked = service.mask_sms({**_sms_config(), "password": "hunter2"})
    assert masked["api_key"] == MASK
    assert masked["password"] == MASK


def test_mask_sms_leaves_absent_password_as_none():
    masked = service.mask_sms(_sms_config(password=None))
    assert masked["password"] is None


def test_unmask_keeps_stored_secret_when_mask_is_echoed_back():
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


# ----------------------------------------------------------------------
# SMS: server_address SSRF guard (reject_ssrf_target)
# ----------------------------------------------------------------------
# These use literal IPs, not hostnames, so they resolve locally with no DNS
# lookup and need no mocking - covers the exact server-side-request-forgery
# an admin-level SYSTEM_CONFIG write could otherwise use to reach the
# license server's internal address, cloud metadata, or anything else this
# container can reach that an outside caller can't.

@pytest.mark.parametrize("target", [
    "http://127.0.0.1/",          # loopback
    "http://10.0.0.5/",           # RFC1918 private
    "http://192.168.1.1/",        # RFC1918 private
    "http://172.16.0.1/",         # RFC1918 private
    "http://169.254.169.254/",    # link-local / cloud metadata endpoint
    "http://0.0.0.0/",            # unspecified
])
def test_sms_server_address_rejects_internal_targets(target):
    with pytest.raises(ValidationError):
        SmsConfig(**_sms_config(server_address=target))


def test_sms_server_address_rejects_non_http_scheme():
    with pytest.raises(ValidationError):
        SmsConfig(**_sms_config(server_address="file:///etc/passwd"))


def test_sms_server_address_rejects_unresolvable_host():
    with mock.patch(
        "app.modules.system_config.schemas.socket.getaddrinfo",
        side_effect=__import__("socket").gaierror("Name or service not known"),
    ):
        with pytest.raises(ValidationError):
            SmsConfig(**_sms_config(server_address="https://this-host-does-not-exist.invalid/"))


def test_sms_server_address_accepts_a_public_address():
    config = SmsConfig(**_sms_config(server_address="https://api.kavenegar.com"))
    assert config.server_address == "https://api.kavenegar.com"


def test_send_test_sms_refuses_an_internal_server_address_at_send_time():
    """Defence in depth: even if a private address somehow made it into
    storage (a pre-existing row, direct DB write), the request is refused
    again right before it is actually sent."""
    config = _sms_config(server_address="http://127.0.0.1:9999/", provider="acme-sms")
    result = service.send_test_sms(config, "09121234567")
    assert result["success"] is False
    assert "not allowed" in result["message"]


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


# ----------------------------------------------------------------------
# Integration: real router calls against Postgres
#
# The project never substitutes SQLite (see test_risk_module.py), so these run
# against the real database inside a transaction that is rolled back on
# teardown — the same pattern that module uses, since _save/log_action commit
# internally (SAVEPOINTs re-open after each one).
#
# service.apply_snmp_config is stubbed out for the SNMP tests: the real
# implementation writes /etc/snmp/snmpd.conf and restarts snmpd on the host
# running the tests, which must never happen here. It's replaced with a stand-
# in that still calls the real render_snmpd_conf, so the captured content is
# exactly what would have been written.
# ----------------------------------------------------------------------

@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        if transaction.nested and not transaction._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", _restart_savepoint)
        session.close()
        trans.rollback()
        connection.close()


@pytest.fixture
def sc_user(db):
    user = User(
        username=f"sc_test_operator_{uuid.uuid4().hex[:8]}",
        hashed_password="x",
    )
    db.add(user)
    db.flush()
    return user


def _stored_row(db, section):
    return (
        db.query(SystemConfigSetting)
        .filter(SystemConfigSetting.section == section)
        .first()
    )


def test_snmp_server_ip_change_is_persisted_and_rendered(db, sc_user):
    """A PUT lands in the DB, and the saved value is what render_snmpd_conf
    (what apply_snmp_config would have written to disk) actually uses."""
    rendered = {}

    def fake_apply(config):
        rendered["conf"] = service.render_snmpd_conf(config)
        return []

    with mock.patch.object(service, "apply_snmp_config", side_effect=fake_apply):
        update_snmp_config(
            data=SnmpConfig(version="v2c", server_ip="10.0.0.25",
                             v2_community="public", v2_port=161),
            current_user=sc_user, db=db,
        )
    assert _stored_row(db, SECTION_SNMP).config_json["server_ip"] == "10.0.0.25"
    assert "agentAddress udp:10.0.0.25:161" in rendered["conf"].splitlines()

    # Changing server_ip overwrites the same row and the rendered directive.
    with mock.patch.object(service, "apply_snmp_config", side_effect=fake_apply):
        update_snmp_config(
            data=SnmpConfig(version="v2c", server_ip="192.168.50.7",
                             v2_community="public", v2_port=161),
            current_user=sc_user, db=db,
        )
    assert _stored_row(db, SECTION_SNMP).config_json["server_ip"] == "192.168.50.7"
    assert "agentAddress udp:192.168.50.7:161" in rendered["conf"].splitlines()

    fetched = get_snmp_config(_current_user=sc_user, db=db)
    assert fetched["config"]["server_ip"] == "192.168.50.7"


def test_snmp_v3_server_ip_is_persisted_and_rendered(db, sc_user):
    rendered = {}

    def fake_apply(config):
        rendered["conf"] = service.render_snmpd_conf(config)
        return []

    with mock.patch.object(service, "apply_snmp_config", side_effect=fake_apply):
        update_snmp_config(
            data=SnmpConfig(
                version="v3", server_ip="2001:db8::1",
                v3_username="monitor", v3_auth_protocol="SHA",
                v3_auth_password="authpass123", v3_priv_protocol="AES",
                v3_priv_password="privpass123", v3_port=161,
            ),
            current_user=sc_user, db=db,
        )
    assert _stored_row(db, SECTION_SNMP).config_json["server_ip"] == "2001:db8::1"
    assert "agentAddress udp6:[2001:db8::1]:161" in rendered["conf"].splitlines()


def test_snmp_legacy_row_without_server_ip_does_not_break_get_or_rendering(db, sc_user):
    """A row saved before server_ip existed must stay readable and renderable
    — GET must not 500, and rendering falls back to binding every interface
    rather than raising a KeyError."""
    legacy = SystemConfigSetting(
        section=SECTION_SNMP,
        config_json={"version": "v2c", "v2_community": "public", "v2_port": 161},
        updated_by=sc_user.id,
    )
    db.add(legacy)
    db.flush()

    fetched = get_snmp_config(_current_user=sc_user, db=db)
    assert fetched["config"]["v2_community"] == "public"
    assert "server_ip" not in fetched["config"]

    conf = service.render_snmpd_conf(fetched["config"])
    assert "agentAddress udp:161" in conf.splitlines()


def test_sms_masked_secrets_survive_a_round_trip_without_ever_storing_the_mask(db, sc_user):
    update_sms_config(
        data=SmsConfig(
            provider="  Kavenegar  ", server_address="https://api.kavenegar.com",
            api_key="realkey123", password="realpass456", username="svc",
            sender_number="  10008663  ",
        ),
        current_user=sc_user, db=db,
    )
    row = _stored_row(db, SECTION_SMS)
    assert row.config_json["api_key"] == "realkey123"
    assert row.config_json["password"] == "realpass456"
    assert row.config_json["provider"] == "Kavenegar"
    assert row.config_json["sender_number"] == "10008663"

    fetched = get_sms_config(_current_user=sc_user, db=db)
    assert fetched["config"]["api_key"] == MASK
    assert fetched["config"]["password"] == MASK
    assert fetched["config"]["provider"] == "Kavenegar"

    # Echo the mask back for both secrets (what the frontend sends when those
    # fields are left untouched) while changing an unrelated field.
    update_sms_config(
        data=SmsConfig(
            provider=fetched["config"]["provider"],
            server_address=fetched["config"]["server_address"],
            api_key=MASK, password=MASK, username="svc",
            sender_number="10009999",
        ),
        current_user=sc_user, db=db,
    )
    row = _stored_row(db, SECTION_SMS)
    assert row.config_json["api_key"] == "realkey123"
    assert row.config_json["password"] == "realpass456"
    assert row.config_json["api_key"] != MASK
    assert row.config_json["password"] != MASK
    assert row.config_json["sender_number"] == "10009999"
