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
from app.modules.system_config.schemas import TimeConfig

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
