"""Regression tests for the secure-coding review fixes."""
import base64
import hashlib

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.core import credential_crypto
from app.core.config import settings
from app.core.secret_redaction import REDACTED, redact_commands, redact_text
from app.modules.system_config import service as system_config_service
from app.modules.system_config.schemas import MASK, SnmpConfig, TimeConfig


# --- CWE-532: secrets in stored command history and logs ---------------------

@pytest.mark.parametrize("command, secret", [
    ("enable secret 9 S3cr3tEnable", "S3cr3tEnable"),
    ("username admin privilege 15 secret 0 AdminPw!9", "AdminPw!9"),
    ("snmp-server community Publ1cRO RO", "Publ1cRO"),
    ("snmp-server user mon grp v3 auth sha AuthKey123 priv aes 128 PrivKey456", "AuthKey123"),
    ("snmp-server user mon grp v3 auth sha AuthKey123 priv aes 128 PrivKey456", "PrivKey456"),
    ("tacacs-server host 10.0.0.5 key TacKey77", "TacKey77"),
    ("crypto isakmp key IsaKmpK3y address 1.2.3.4", "IsaKmpK3y"),
    ("set passwd FortiPass1", "FortiPass1"),
    ("set psksecret VpnPsk!23", "VpnPsk!23"),
    ("echo 'root:RootPw99' | chpasswd", "RootPw99"),
    ("db.createUser({user: 'x', pwd: 'MongoPw1'})", "MongoPw1"),
])
def test_known_secret_syntaxes_are_redacted(command, secret):
    redacted = redact_text(command)
    assert secret not in redacted
    assert REDACTED in redacted


def test_secret_parameter_values_are_redacted_wherever_they_appear():
    params = {"SNMP_COMMUNITY": "weird-token-xyz", "HOSTNAME": "core-sw-01"}
    [line] = redact_commands(["some-new-syntax weird-token-xyz on core-sw-01"], params)
    assert "weird-token-xyz" not in line
    assert "core-sw-01" in line


def test_ordinary_commands_are_untouched():
    commands = ["interface Gi0/1", " no shutdown", "set status up", "service password-encryption"]
    assert redact_commands(commands) == commands


# --- CWE-323 key separation / CWE-312 secrets at rest ------------------------

def test_each_purpose_has_its_own_key():
    token = credential_crypto.encrypt("s3cret", credential_crypto.PURPOSE_NOC_SNMP)
    assert credential_crypto.decrypt(token, credential_crypto.PURPOSE_NOC_SNMP) == "s3cret"
    with pytest.raises(ValueError):
        credential_crypto.decrypt(token, credential_crypto.PURPOSE_SCHEDULED_JOBS)


def test_values_encrypted_with_the_legacy_key_still_decrypt():
    legacy = Fernet(base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest()))
    old = legacy.encrypt(b'{"password": "x"}').decode()
    assert credential_crypto.decrypt_json(old) == '{"password": "x"}'


def test_new_values_are_not_encrypted_with_the_legacy_key():
    legacy = Fernet(base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest()))
    new = credential_crypto.encrypt_json("payload")
    with pytest.raises(Exception):
        legacy.decrypt(new.encode())


def test_system_config_secrets_are_sealed_at_rest_and_legacy_rows_still_load():
    from app.modules.system_config.router import _seal, _unseal
    payload = {"host": "smtp.example.com", "password": "SmtpPw!1", "api_key": "k-123"}
    sealed = _seal(payload)
    assert sealed["host"] == "smtp.example.com"
    assert "SmtpPw!1" not in str(sealed) and "k-123" not in str(sealed)
    assert _unseal(sealed) == payload
    assert _seal(sealed) == sealed
    assert _unseal({"password": "legacy-plain"}) == {"password": "legacy-plain"}


def test_snmp_community_is_masked_in_responses():
    masked = system_config_service.mask_snmp({"version": "v2c", "v2_community": "Publ1cRO"})
    assert masked["v2_community"] == MASK


# --- CWE-74: injection into host config files read by root daemons -----------

_SNMP_BASE = {"version": "v2c", "server_ip": "10.0.0.25"}


@pytest.mark.parametrize("community", [
    "public default\nextend pwn /bin/sh -c id",
    "public default",
    'pub"lic',
    "pub#lic",
])
def test_snmp_community_cannot_inject_snmpd_directives(community):
    with pytest.raises(ValidationError):
        SnmpConfig(**_SNMP_BASE, v2_community=community)


def test_snmp_v3_password_cannot_inject_snmpd_directives():
    with pytest.raises(ValidationError):
        SnmpConfig(
            version="v3", server_ip="10.0.0.25", v3_username="mon",
            v3_auth_protocol="SHA", v3_auth_password="Auth\npass /bin/sh",
            v3_priv_protocol="AES", v3_priv_password="PrivPass1",
        )


def test_valid_snmp_values_and_the_mask_are_accepted():
    assert SnmpConfig(**_SNMP_BASE, v2_community="N0c-R3ad.Only!").v2_community == "N0c-R3ad.Only!"
    assert SnmpConfig(**_SNMP_BASE, v2_community=MASK).v2_community == MASK


def test_ntp_server_cannot_inject_timesyncd_directives():
    with pytest.raises(ValidationError):
        TimeConfig(timezone="UTC", use_ntp=True, ntp_server="pool.ntp.org\nFallbackNTP=evil")
    assert TimeConfig(timezone="UTC", ntp_server="0.pool.ntp.org 10.0.0.1").ntp_server == "0.pool.ntp.org 10.0.0.1"
