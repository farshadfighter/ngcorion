"""
The password-reset code, by email or SMS.

How it is sent is the delivery policy's choice (System > Notifications > Delivery policy):
email (the default), SMS, or both. By SMS it goes to the account's mobile number through the
SMS server of System Configuration; an account without a number, or an installation without an
SMS server, gets it by email instead, so asking for SMS never leaves a person without the code.

Email goes through the mail server set in System Configuration > SMTP (the same one alerts and
reports use). Installations that set the SMTP_* variables in ``.env`` before that page existed
keep working: those are used when the page has no server.

Without any mail server the code is not sent, and it is never written to the log either: a
reset code in a log would let anyone who can read the log take over the account. The log says
only that a reset was requested and could not be delivered.
"""
import logging
from typing import Any, Callable, Dict, List, Tuple

from sqlalchemy.orm import Session

from app.core.config import settings

logger = logging.getLogger(__name__)


def password_reset_mail_config(db: Session) -> Dict[str, Any]:
    """The SMTP settings for the reset email: System Configuration, else the SMTP_* variables of
    ``.env``, else {} (no mail server)."""
    from app.models.system_config import SECTION_SMTP
    from app.modules.alerts.channels import load_section

    config = load_section(db, SECTION_SMTP)
    if config.get("host"):
        return config
    if settings.SMTP_HOST:
        return {
            "host": settings.SMTP_HOST,
            "port": settings.SMTP_PORT,
            "use_tls": settings.SMTP_USE_TLS,
            "use_ssl": not settings.SMTP_USE_TLS,
            "username": settings.SMTP_USERNAME,
            "password": settings.SMTP_PASSWORD,
            "from_email": settings.SMTP_FROM_EMAIL,
            "from_name": settings.SMTP_FROM_NAME,
        }
    return {}


def send_password_reset_otp(config: Dict[str, Any], to_email: str, otp: str) -> None:
    """Send the reset code. Runs as a background task, so it never raises; failures are logged
    without the code."""
    from app.modules.alerts.channels import DeliveryError, send_email

    if not config.get("host"):
        logger.warning("A password reset was requested, but no mail server is set "
                       "(System Configuration > SMTP); no code was sent.")
        return

    expire_minutes = settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    subject = f"{config.get('from_name') or 'NGCorion'} — Password reset code"
    text_body = (
        "We received a request to reset the password for your account.\n\n"
        f"Your password reset code is: {otp}\n\n"
        f"Enter it on the password reset page to choose a new password. This code "
        f"expires in {expire_minutes} minutes and can be used only once.\n\n"
        "If you did not request a password reset, you can safely ignore this email — "
        "your password will not change.\n"
    )
    html_body = (
        f"<p>We received a request to reset the password for your account.</p>"
        f"<p>Your password reset code is:</p>"
        f'<p style="font-size:28px;font-weight:700;letter-spacing:6px;'
        f'font-family:monospace;color:#111827;">{otp}</p>'
        f"<p>Enter it on the password reset page to choose a new password. "
        f"This code expires in {expire_minutes} minutes and can be used only once.</p>"
        f"<p style=\"color:#6B7280;font-size:13px;\">If you did not request a password reset, "
        f"you can safely ignore this email — your password will not change.</p>"
    )
    try:
        send_email(config, [to_email], subject, text_body, html_body)
        logger.info("Sent a password reset code to %s", to_email)
    except DeliveryError as exc:
        logger.error("Could not send a password reset code to %s: %s", to_email, exc)


def send_password_reset_sms(config: Dict[str, Any], phone: str, otp: str, language: str = "en") -> None:
    """Send the reset code by SMS, in the account's language. A background task: never raises, and a
    failure is logged without the code."""
    from app.modules.alerts.channels import DeliveryError, send_sms

    minutes = settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    text = (f"کد بازیابی رمز عبور NGCorion: {otp}\nاین کد {minutes} دقیقه اعتبار دارد."
            if language == "fa" else
            f"NGCorion password reset code: {otp}\nValid for {minutes} minutes.")
    try:
        send_sms(config, phone, text)
        logger.info("Sent a password reset code by SMS to %s", phone)
    except DeliveryError as exc:
        logger.error("Could not send a password reset code by SMS to %s: %s", phone, exc)


def password_reset_sends(db: Session, user, otp: str) -> Tuple[List[Tuple[Callable, tuple]], str]:
    """The sends for a reset code, as (function, args) to run in the background, and how it goes
    ("email", "sms" or "both") for the audit log. The settings are read here, while the
    request's database session is open."""
    from app.core.locale import user_language
    from app.models.system_config import SECTION_SMS
    from app.modules.alerts.channels import load_section
    from app.modules.alerts.policy import load_policy

    how = load_policy(db)["password_reset"]["channel"]
    sms_config = load_section(db, SECTION_SMS) if how in ("sms", "both") else {}
    by_sms = bool(how in ("sms", "both") and user.phone and sms_config.get("provider"))
    by_email = how in ("email", "both") or not by_sms
    if how == "sms" and not by_sms:
        logger.warning("The reset code goes by email: %s", "the account has no mobile number"
                       if not user.phone else "no SMS server is set (System Configuration > SMS)")
    sends: List[Tuple[Callable, tuple]] = []
    if by_sms:
        sends.append((send_password_reset_sms, (sms_config, user.phone, otp, user_language(db, user))))
    if by_email:
        sends.append((send_password_reset_otp, (password_reset_mail_config(db), user.email, otp)))
    return sends, "both" if by_email and by_sms else "sms" if by_sms else "email"
