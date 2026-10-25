"""
Delivery policy: what may go out by email and SMS, whatever a notification rule says.

Each notification rule picks the channels its alerts go out on. The policy, set once under
System > Notifications > Delivery policy, sits above every rule:

  email.enabled, sms.enabled     a channel off: no rule sends on it (in-app alerts go on)
  email.min_severity,
  sms.min_severity               the least severity a message needs on the channel
                                 (info < warning < critical); e.g. SMS for Critical only
  sms.quiet_start / quiet_end    quiet hours for the rules that set none of their own
  sms.critical_in_quiet_hours    Critical alerts still go out in quiet hours
  sms.daily_limit                at most this many SMS a day, server time (0 = no limit),
                                 so a storm of alerts cannot use up the SMS credit
  password_reset.channel         how the password reset code is sent: email, sms or both.
                                 By SMS it goes to the mobile number of the account; an account
                                 without one, or no SMS server, gets it by email.

A message the policy holds back is still written to the delivery log, as Skipped with the
reason, so "why did I not get an SMS" has an answer. Test messages (a rule's Test, a channel's
Test) are not held back.

The defaults change nothing: both channels on for every severity, no daily limit, Critical
through quiet hours, the reset code by email - as before the policy existed.
"""
import re
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.orm import Session

SECTION_POLICY = "notification_policy"
SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
Severity = Literal["info", "warning", "critical"]
_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class EmailPolicy(BaseModel):
    enabled: bool = True
    min_severity: Severity = "info"


class SmsPolicy(BaseModel):
    enabled: bool = True
    min_severity: Severity = "info"
    quiet_start: Optional[str] = None           # "22:00"; both or neither
    quiet_end: Optional[str] = None             # "07:00"
    critical_in_quiet_hours: bool = True
    daily_limit: int = Field(0, ge=0, le=100000)

    @field_validator("quiet_start", "quiet_end")
    @classmethod
    def _hhmm(cls, v: Optional[str]) -> Optional[str]:
        v = (v or "").strip()
        if not v:
            return None
        if not _HHMM.match(v):
            raise ValueError("quiet hours must be HH:MM (00:00-23:59)")
        return v

    @model_validator(mode="after")
    def _both_or_neither(self) -> "SmsPolicy":
        if bool(self.quiet_start) != bool(self.quiet_end):
            raise ValueError("set both the start and the end of the quiet hours, or neither")
        if self.quiet_start and self.quiet_start == self.quiet_end:
            raise ValueError("the quiet hours must not start and end at the same time")
        return self


class PasswordResetPolicy(BaseModel):
    channel: Literal["email", "sms", "both"] = "email"


class DeliveryPolicy(BaseModel):
    """The delivery policy (body of PUT /api/notifications/policy)."""
    email: EmailPolicy = Field(default_factory=EmailPolicy)
    sms: SmsPolicy = Field(default_factory=SmsPolicy)
    password_reset: PasswordResetPolicy = Field(default_factory=PasswordResetPolicy)


DEFAULTS: Dict[str, Any] = DeliveryPolicy().model_dump()


def load_policy(db: Session) -> Dict[str, Any]:
    """The stored policy over the defaults; a stored value that no longer validates falls back to the
    defaults rather than stopping notifications."""
    from app.modules.alerts.channels import load_section
    stored = load_section(db, SECTION_POLICY) or {}
    try:
        return DeliveryPolicy(**stored).model_dump()
    except ValueError:
        return dict(DEFAULTS)


def save_policy(db: Session, policy: DeliveryPolicy, user) -> None:
    from app.modules.system_config.router import _save
    _save(db, SECTION_POLICY, policy.model_dump(), user)


def channel_block(policy: Dict[str, Any], channel: str, severity: Optional[str]) -> Optional[str]:
    """Why the policy keeps a message of this severity off email or SMS, or None when it may go."""
    part = policy.get(channel)
    if not isinstance(part, dict):
        return None                                         # syslog, webhooks: not governed here
    name = "Email" if channel == "email" else "SMS"
    if not part.get("enabled", True):
        return f"{name} is turned off in the delivery policy"
    least = part.get("min_severity") or "info"
    if SEVERITY_ORDER.get(severity or "info", 0) < SEVERITY_ORDER.get(least, 0):
        return f"{name} is for {least.capitalize()} and above in the delivery policy"
    return None


def quiet_hours(policy: Dict[str, Any], rule_start: Optional[str], rule_end: Optional[str]):
    """The quiet hours that apply to a rule: its own, else the policy's; (None, None) for none."""
    if rule_start and rule_end:
        return rule_start, rule_end
    sms = policy.get("sms") or {}
    return sms.get("quiet_start"), sms.get("quiet_end")


def in_window(start: Optional[str], end: Optional[str], now: datetime, tz) -> bool:
    """Whether `now` (naive UTC) falls in start-end in the server's time zone; the window may span
    midnight (22:00-07:00)."""
    if not start or not end:
        return False
    local = now.replace(tzinfo=timezone.utc).astimezone(tz) if tz else now
    hm = local.strftime("%H:%M")
    return start <= hm < end if start <= end else (hm >= start or hm < end)


def day_start_utc(now: datetime, tz) -> datetime:
    """Midnight of today in the server's time zone, as naive UTC (how deliveries are stored)."""
    if not tz:
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    local = now.replace(tzinfo=timezone.utc).astimezone(tz)
    midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight.astimezone(timezone.utc).replace(tzinfo=None)


def sms_sent_today(db: Session, now: datetime, tz) -> int:
    """SMS queued since midnight (server time), skipped ones and tests not counted."""
    from app.models.notification import CHANNEL_SMS, NotificationDelivery
    db.flush()      # the app's sessions do not autoflush: count what this cycle has queued so far too
    return (db.query(NotificationDelivery)
            .filter(NotificationDelivery.channel == CHANNEL_SMS,
                    NotificationDelivery.created_at >= day_start_utc(now, tz),
                    NotificationDelivery.status != "skipped",
                    NotificationDelivery.kind != "test")
            .count())

