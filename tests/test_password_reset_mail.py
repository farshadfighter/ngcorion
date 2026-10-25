"""
The password-reset email (app/core/email.py): sent through the mail server of System
Configuration (else the SMTP_* variables of .env), and the code never written to the log.
"""
import logging

from app.core import email as reset_mail
from app.core.config import settings
from app.modules.alerts import channels

CODE = "482913"
SMTP = {"host": "mail.example.org", "port": 587, "use_tls": True, "from_email": "ngcorion@example.org"}


def test_without_a_mail_server_the_code_is_not_logged(caplog):
    caplog.set_level(logging.DEBUG)
    reset_mail.send_password_reset_otp({}, "user@example.org", CODE)
    assert CODE not in caplog.text
    assert "no code was sent" in caplog.text


def test_the_code_goes_through_the_configured_mail_server(monkeypatch, caplog):
    sent = []
    monkeypatch.setattr(channels, "send_email", lambda config, to, subject, text, html=None: sent.append(
        (config, to, subject, text)))
    caplog.set_level(logging.DEBUG)
    reset_mail.send_password_reset_otp(SMTP, "user@example.org", CODE)
    assert len(sent) == 1
    config, to, _subject, text = sent[0]
    assert config is SMTP and to == ["user@example.org"] and CODE in text
    assert CODE not in caplog.text


def test_a_delivery_failure_is_logged_without_the_code(monkeypatch, caplog):
    def fail(*_args, **_kwargs):
        raise channels.DeliveryError("SMTP error: connection refused")
    monkeypatch.setattr(channels, "send_email", fail)
    caplog.set_level(logging.DEBUG)
    reset_mail.send_password_reset_otp(SMTP, "user@example.org", CODE)   # does not raise
    assert "connection refused" in caplog.text
    assert CODE not in caplog.text


def test_system_configuration_comes_first(monkeypatch):
    monkeypatch.setattr(channels, "load_section", lambda db, section: dict(SMTP))
    monkeypatch.setattr(settings, "SMTP_HOST", "old.example.org")
    assert reset_mail.password_reset_mail_config(None)["host"] == "mail.example.org"


def test_env_settings_are_the_fallback(monkeypatch):
    monkeypatch.setattr(channels, "load_section", lambda db, section: {})
    monkeypatch.setattr(settings, "SMTP_HOST", "old.example.org")
    monkeypatch.setattr(settings, "SMTP_USE_TLS", False)
    config = reset_mail.password_reset_mail_config(None)
    assert config["host"] == "old.example.org"
    assert config["use_ssl"] is True and config["use_tls"] is False


def test_no_mail_server_anywhere(monkeypatch):
    monkeypatch.setattr(channels, "load_section", lambda db, section: {})
    monkeypatch.setattr(settings, "SMTP_HOST", "")
    assert reset_mail.password_reset_mail_config(None) == {}


# ── by SMS, as the delivery policy says (System > Notifications > Delivery policy) ──

SMS = {"provider": "smsir", "server_address": "https://api.sms.ir", "api_key": "k", "sender_number": "3000"}


def _sends(monkeypatch, how, phone="09121234567", sms_config=SMS, language="fa"):
    from types import SimpleNamespace

    from app.core import locale
    from app.modules.alerts import policy

    monkeypatch.setattr(policy, "load_policy", lambda db: {**policy.DEFAULTS, "password_reset": {"channel": how}})
    monkeypatch.setattr(channels, "load_section",
                        lambda db, section: dict(sms_config) if section == "sms" else dict(SMTP))
    monkeypatch.setattr(locale, "user_language", lambda db, user: language)
    user = SimpleNamespace(email="user@example.org", phone=phone)
    sends, how_sent = reset_mail.password_reset_sends(None, user, CODE)
    return [(f.__name__, args[1]) for f, args in sends], how_sent


def test_the_policy_picks_email_sms_or_both(monkeypatch):
    assert _sends(monkeypatch, "email") == ([("send_password_reset_otp", "user@example.org")], "email")
    assert _sends(monkeypatch, "sms") == ([("send_password_reset_sms", "09121234567")], "sms")
    assert _sends(monkeypatch, "both") == ([("send_password_reset_sms", "09121234567"),
                                            ("send_password_reset_otp", "user@example.org")], "both")


def test_sms_falls_back_to_email_without_a_number_or_an_sms_server(monkeypatch):
    assert _sends(monkeypatch, "sms", phone=None) == ([("send_password_reset_otp", "user@example.org")], "email")
    assert _sends(monkeypatch, "sms", sms_config={}) == ([("send_password_reset_otp", "user@example.org")], "email")
    assert _sends(monkeypatch, "both", phone="") == ([("send_password_reset_otp", "user@example.org")], "email")


def test_the_sms_is_in_the_account_language_and_the_code_is_not_logged(monkeypatch, caplog):
    sent = []
    monkeypatch.setattr(channels, "send_sms", lambda config, phone, text: sent.append((phone, text)))
    caplog.set_level(logging.DEBUG)
    reset_mail.send_password_reset_sms(SMS, "09121234567", CODE, "fa")
    reset_mail.send_password_reset_sms(SMS, "09121234567", CODE, "en")
    assert sent[0][0] == "09121234567" and CODE in sent[0][1] and "رمز عبور" in sent[0][1]
    assert "password reset code" in sent[1][1]
    assert CODE not in caplog.text

    def fail(*_args):
        raise channels.DeliveryError("sms.ir refused the message: no credit")
    monkeypatch.setattr(channels, "send_sms", fail)
    reset_mail.send_password_reset_sms(SMS, "09121234567", CODE)      # does not raise
    assert "no credit" in caplog.text and CODE not in caplog.text
