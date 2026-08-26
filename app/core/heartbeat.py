"""
Heartbeat Service

Background daemon thread that sends a heartbeat to the license server on a
fixed interval and refreshes the local license state.

Reliability rules this service follows:

* a failed heartbeat is retried with backoff instead of waiting a whole
  interval — one dropped packet must not cost an hour of the offline grace
  window;
* the thread never dies silently: any unexpected error is logged and the
  service marks itself stopped so it can be restarted;
* an explicit rejection from the server (HTTP 400) blocks the product
  immediately — the offline grace window covers outages, not verdicts;
* nothing here ever propagates out of the thread into the app.
"""
import logging
import threading
from typing import Optional

from app.core.config import settings

from .license_client import (
    LicenseNotActivated,
    LicenseRejected,
    LicenseServerError,
    LicenseServerUnreachable,
)
from .license_state import (
    mark_license_rejected,
    mark_license_server_offline,
    refresh_license_state,
    set_license_state,
)

logger = logging.getLogger(__name__)


class HeartbeatService:
    """Background service for automatic heartbeat"""

    def __init__(
        self,
        client,
        interval_seconds: Optional[int] = None,
        retry_seconds: Optional[int] = None,
        max_retry_seconds: Optional[int] = None,
    ):
        """
        Initialize heartbeat service

        Args:
            client: LicenseClient instance
            interval_seconds: Interval between successful heartbeats
            retry_seconds: First delay after a failed heartbeat
            max_retry_seconds: Ceiling for the exponential retry backoff
        """
        self.client = client
        self.interval_seconds = (
            interval_seconds if interval_seconds is not None
            else settings.LICENSE_HEARTBEAT_INTERVAL_SECONDS
        )
        self.retry_seconds = (
            retry_seconds if retry_seconds is not None
            else settings.LICENSE_HEARTBEAT_RETRY_SECONDS
        )
        self.max_retry_seconds = (
            max_retry_seconds if max_retry_seconds is not None
            else settings.LICENSE_HEARTBEAT_MAX_RETRY_SECONDS
        )
        self.running = False
        self.thread: Optional[threading.Thread] = None
        # Set on stop(); also used as the sleep primitive so shutdown is
        # immediate instead of waiting out a 1-second tick, and so an idle
        # heartbeat thread does not wake up 3600 times an hour.
        self._stop_event = threading.Event()
        self._consecutive_failures = 0

    def _run_once(self) -> bool:
        """
        Perform one heartbeat + state refresh.

        Returns True when the license server answered, False when it did not.
        Never raises: this runs on a daemon thread whose death would silently
        stop all license refreshing.
        """
        try:
            result = self.client.heartbeat()
        except LicenseServerError as e:
            # The server is up but broken (5xx/429). Same handling as an
            # outage — it is not a licensing verdict.
            mark_license_server_offline(e)
            logger.warning(
                "[Heartbeat] License server error (attempt %d): %s",
                self._consecutive_failures + 1, e,
            )
            return False
        except LicenseServerUnreachable as e:
            # Connectivity problem, not a licensing verdict: keep the last
            # validated state (the offline grace window in license_state
            # bounds how long that lasts) but flag it, so API responses can
            # say "license server unreachable" instead of "no valid license".
            mark_license_server_offline(e)
            logger.warning(
                "[Heartbeat] License server unreachable (attempt %d): %s",
                self._consecutive_failures + 1, e,
            )
            return False
        except LicenseRejected as e:
            # The server looked this license up and refused it. A verdict, not
            # an outage: block immediately instead of coasting on the offline
            # grace window, which exists to cover unreachable servers only.
            mark_license_rejected(e.detail)
            logger.error(
                "[Heartbeat] License rejected by the license server (HTTP %s): %s. "
                "All licensed requests are now blocked; re-activate a valid "
                "license key to restore service.",
                e.status_code, e.detail,
            )
            # The server answered, so this is not a connectivity failure to back
            # off from — retrying in 60s would not change the verdict.
            return True
        except LicenseNotActivated as e:
            # Steady state, not a transient failure: retrying faster will not
            # help, so report it once per interval at WARNING and move on.
            logger.warning("[Heartbeat] %s", e)
            return True
        except Exception as e:
            logger.error(
                "[Heartbeat] Heartbeat failed (attempt %d): %s: %s",
                self._consecutive_failures + 1, type(e).__name__, e,
                exc_info=True,
            )
            return False

        logger.info("[Heartbeat] Heartbeat successful: %s", result.get("message"))

        # Refresh license state after heartbeat. refresh_license_state handles
        # connectivity failures itself; only a hard rejection escapes it, and
        # that must not kill the loop.
        try:
            refresh_license_state(self.client)
        except Exception as e:
            logger.error(
                "[Heartbeat] Failed to refresh license state after heartbeat: %s", e
            )

        # Check if downgraded
        if result.get("should_downgrade"):
            logger.warning(
                "[Heartbeat] License downgraded to Pilot mode due to connectivity issues"
            )
            # Mark as invalid to force re-validation
            set_license_state({
                "valid": False,
                "message": "License downgraded to Pilot mode",
                "plan_type": "pilot",
                "is_pilot_mode": True
            })

        return True

    def _next_delay(self, succeeded: bool) -> int:
        """
        Seconds to wait before the next attempt.

        After a success: the normal interval. After a failure: an exponential
        backoff starting at retry_seconds and capped at max_retry_seconds (and
        never longer than the normal interval), so an outage is noticed and
        recovered from quickly instead of an hour later.
        """
        if succeeded:
            self._consecutive_failures = 0
            return self.interval_seconds

        self._consecutive_failures += 1
        backoff = self.retry_seconds * (2 ** (self._consecutive_failures - 1))
        return int(min(backoff, self.max_retry_seconds, self.interval_seconds))

    def _heartbeat_loop(self):
        """Background thread loop"""
        try:
            while not self._stop_event.is_set():
                succeeded = self._run_once()
                delay = self._next_delay(succeeded)
                if not succeeded:
                    logger.info("[Heartbeat] Retrying in %ds", delay)
                # Event-based sleep: wakes immediately on stop().
                self._stop_event.wait(delay)
        except BaseException:
            # A thread that dies here stops all license refreshing for the
            # lifetime of the process, and the old code left `running = True`
            # so start_heartbeat() would refuse to bring it back. Log it and
            # let the flags reflect reality.
            logger.exception("[Heartbeat] Heartbeat thread stopped unexpectedly")
            raise
        finally:
            self.running = False

    def is_alive(self) -> bool:
        """True when the worker thread is actually running."""
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        """Start the heartbeat service"""
        if self.running and self.is_alive():
            logger.debug("[Heartbeat] Heartbeat service already running")
            return
        if self.running and not self.is_alive():
            logger.warning(
                "[Heartbeat] Heartbeat thread was marked running but is dead; restarting"
            )

        self._stop_event.clear()
        self._consecutive_failures = 0
        self.running = True
        self.thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="license-heartbeat"
        )
        self.thread.start()
        logger.info(
            "[Heartbeat] Heartbeat service started (interval: %ds, retry: %ds)",
            self.interval_seconds, self.retry_seconds,
        )

    def stop(self):
        """Stop the heartbeat service"""
        if not self.running and not self.is_alive():
            return

        self.running = False
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                logger.warning(
                    "[Heartbeat] Heartbeat thread did not stop within 5s; "
                    "it is a daemon thread and will not block shutdown"
                )
        logger.info("[Heartbeat] Heartbeat service stopped")


# Module-level singleton
_heartbeat: Optional[HeartbeatService] = None
_heartbeat_lock = threading.Lock()


def start_heartbeat(client):
    """
    Start heartbeat service (singleton).

    Restarts the worker when a previous thread died, so a one-off crash in the
    loop does not leave the process without any license refreshing at all.
    """
    global _heartbeat
    with _heartbeat_lock:
        if _heartbeat is None:
            _heartbeat = HeartbeatService(client)
        _heartbeat.client = client
        if not _heartbeat.running or not _heartbeat.is_alive():
            _heartbeat.start()


def stop_heartbeat():
    """Stop heartbeat service"""
    global _heartbeat
    with _heartbeat_lock:
        if _heartbeat is not None:
            _heartbeat.stop()


def get_heartbeat() -> Optional[HeartbeatService]:
    """Current heartbeat service instance, if one was started."""
    return _heartbeat
