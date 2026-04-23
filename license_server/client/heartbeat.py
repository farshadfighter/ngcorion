import threading
import time
import logging
from typing import Optional
from .license_client import LicenseClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HeartbeatService:
    """Background service for automatic heartbeat"""
    
    def __init__(self, client: LicenseClient, interval_seconds: int = 3600):
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
                
                if result.get('should_downgrade'):
                    logger.warning("License downgraded to Pilot mode due to connectivity issues")
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
