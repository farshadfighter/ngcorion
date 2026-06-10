"""
Email sending utilities.

Uses the standard-library ``smtplib`` so no extra dependency is required.

If ``settings.SMTP_HOST`` is empty, emails are logged to the console instead of
sent — this lets the password-reset flow work end-to-end in development before a
real mail server is configured. Fill in the SMTP_* settings in ``.env`` to switch
to live sending; no code change is needed.
"""
import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_email(to: str, subject: str, text_body: str, html_body: str | None = None) -> None:
    """
    Send an email, or log it to the console when SMTP is not configured.

    This never raises: failures are logged. It is safe to call from a FastAPI
    BackgroundTask, where an exception would otherwise be swallowed silently.
    """
    from_addr = formataddr((settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL))

    # Development / unconfigured mode: log instead of send.
    if not settings.SMTP_HOST:
        logger.info(
            "[email:console] SMTP not configured — logging email instead of sending.\n"
            "  From:    %s\n  To:      %s\n  Subject: %s\n  Body:\n%s",
            from_addr, to, subject, text_body,
        )
        # Also print so it shows up plainly in the dev server console.
        print(
            f"\n===== DEV EMAIL (SMTP not configured) =====\n"
            f"From: {from_addr}\nTo: {to}\nSubject: {subject}\n\n{text_body}\n"
            f"===========================================\n"
        )
        return

    message = EmailMessage()
    message["From"] = from_addr
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text_body)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    try:
        if settings.SMTP_USE_TLS:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                server.starttls()
                if settings.SMTP_USERNAME:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(message)
        else:
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
                if settings.SMTP_USERNAME:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(message)
        logger.info("Sent email to %s (subject=%r)", to, subject)
    except Exception:
        logger.exception("Failed to send email to %s (subject=%r)", to, subject)


def send_password_reset_otp(to_email: str, otp: str) -> None:
    """Build and send the password-reset OTP email."""
    expire_minutes = settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    subject = f"{settings.SMTP_FROM_NAME} — Password reset code"

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

    send_email(to_email, subject, text_body, html_body)
