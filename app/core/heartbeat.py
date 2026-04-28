"""
Heartbeat Service

Background daemon thread that sends heartbeat to license server every hour
and refreshes local license state.
"""
import threading
import time
import logging
from typing import Optional
from .license_state import refresh_license_state, set_license_state

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HeartbeatService:
    """Background service for automatic heartbeat"""
    
    def __init__(self, client, interval_seconds: int = 3600):
        """
        Initialize heartbeat service
        
        Args:
            client: LicenseClient instance
            interval_seconds: Heartbeat interval in seconds (default: 1 hour)
        """
        self.client = client
        self.interval_seconds = interval_seconds
        self.running = False
        self.thread: Optional[threading.Thread] = None
    
    def _heartbeat_loop(self):
        """Background thread loop"""
        while self.running:
            try:
                result = self.client.heartbeat()
                logger.info(f"Heartbeat successful: {result.get('message')}")
                
                # Refresh license state after heartbeat
                try:
                    refresh_license_state(self.client)
                except Exception as e:
                    logger.error(f"Failed to refresh license state after heartbeat: {e}")
                
                # Check if downgraded
                if result.get('should_downgrade'):
                    logger.warning("License downgraded to Pilot mode due to connectivity issues")
                    # Mark as invalid to force re-validation
                    set_license_state({
                        "valid": False,
                        "message": "License downgraded to Pilot mode",
                        "plan_type": "pilot",
                        "is_pilot_mode": True
                    })
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
            
            # Sleep in small intervals to allow quick shutdown
            for _ in range(self.interval_seconds):
                if not self.running:
                    break
                time.sleep(1)
    
    def start(self):
        """Start the heartbeat service"""
        if self.running:
            logger.warning("Heartbeat service already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.thread.start()
        logger.info(f"Heartbeat service started (interval: {self.interval_seconds}s)")
    
    def stop(self):
        """Stop the heartbeat service"""
        if not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Heartbeat service stopped")


# Module-level singleton
_heartbeat: Optional[HeartbeatService] = None
_heartbeat_lock = threading.Lock()


def start_heartbeat(client):
    """Start heartbeat service (singleton)"""
    global _heartbeat
    with _heartbeat_lock:
        if _heartbeat is None:
            _heartbeat = HeartbeatService(client)
            _heartbeat.start()
        elif not _heartbeat.running:
            _heartbeat.start()


def stop_heartbeat():
    """Stop heartbeat service"""
    global _heartbeat
    with _heartbeat_lock:
        if _heartbeat is not None:
            _heartbeat.stop()
