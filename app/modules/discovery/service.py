"""
NGCORION - Auto Discovery Service
app/modules/discovery/service.py

Uses nmap for network scanning.
Requires: pip install python-nmap
Requires: nmap installed on system (apt install nmap)
"""

import nmap
import uuid
import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor

from .schemas import (
    ScanRequest, ScanResponse, DiscoveredHost, DiscoveredPort
)

logger = logging.getLogger(__name__)

# In-memory store for scans
# In production, consider using Redis or database
_scans: Dict[str, ScanResponse] = {}

# Thread pool for nmap (blocking operation)
_executor = ThreadPoolExecutor(max_workers=3)


# ====================================
# Scan Arguments
# ====================================

def get_scan_arguments(scan_type: str) -> str:
    """
    Get nmap arguments based on scan type
    
    Types:
        basic: Quick scan, top 100 ports (~30 seconds)
        detailed: Service version + OS detection (~2-3 minutes)
        full: All ports + aggressive (~10+ minutes)
    """
    if scan_type == "basic":
        # -sT: TCP connect scan (no root needed)
        # -T4: Aggressive timing
        # --top-ports 100: Common ports only
        return "-sT -T4 --top-ports 100 -Pn"
    
    elif scan_type == "detailed":
        # -sV: Service version detection
        # --top-ports 1000: More ports
        return "-sT -sV -T4 --top-ports 1000 -Pn"
    
    elif scan_type == "full":
        # -A: Aggressive (, version, scripts, traceroute)
        # -p-: All 65535 ports
        return "-sT -sV -A -T4 -p- -Pn"
    
    else:
        return "-sT -T4 --top-ports 100 -Pn"


# ====================================
# OS Detection Helpers
# ====================================

def parse_os_info(host_data: dict) -> tuple:
    """Extract OS information from nmap results"""
    os_name = None
    os_version = None
    os_accuracy = None
    
    if 'osmatch' in host_data and host_data['osmatch']:
        best_match = host_data['osmatch'][0]
        os_name = best_match.get('name', '')
        os_accuracy = int(best_match.get('accuracy', 0))
        
        # Extract version from osclass if available
        if 'osclass' in best_match and best_match['osclass']:
            osclass = best_match['osclass'][0]
            os_version = osclass.get('osgen', '')
    
    return os_name, os_version, os_accuracy


def guess_asset_type(host: DiscoveredHost) -> str:
    """
    Guess asset type based on discovered information
    
    Uses:
        - OS name
        - Vendor (from MAC OUI)
        - Open ports and services
    """
    os_lower = (host.os_name or '').lower()
    vendor_lower = (host.vendor or '').lower()
    
    open_ports = [p.port for p in host.ports if p.state == 'open']
    services = [p.service.lower() if p.service else '' for p in host.ports]
    
    # Network devices
    network_vendors = ['cisco', 'juniper', 'mikrotik', 'fortinet', 'paloalto', 
                       'aruba', 'ubiquiti', 'netgear', 'tp-link']
    
    if any(v in vendor_lower for v in network_vendors):
        # More specific detection
        if any(v in vendor_lower for v in ['fortinet', 'paloalto', 'checkpoint', 'sophos']):
            return 'firewall'
        elif 'switch' in os_lower or any(p in [22, 23] for p in open_ports):
            return 'switch'
        else:
            return 'router'
    
    # Servers
    server_ports = [80, 443, 22, 3306, 5432, 1433, 3389, 21, 25, 110, 143]
    if any(p in open_ports for p in server_ports):
        if 'windows' in os_lower:
            if 'server' in os_lower:
                return 'windows_server'
            return 'workstation'
        elif any(x in os_lower for x in ['linux', 'ubuntu', 'centos', 'debian', 'rhel']):
            return 'linux_server'
        return 'server'
    
    # Printers
    printer_ports = [515, 631, 9100]
    if any(p in open_ports for p in printer_ports) or 'printer' in os_lower:
        return 'printer'
    
    # Workstations
    if 'windows' in os_lower:
        return 'workstation'
    
    return 'unknown'


# ====================================
# Main Scan Logic
# ====================================

def run_nmap_scan(target: str, scan_type: str, scan_id: str) -> ScanResponse:
    """
    Run nmap scan (blocking operation - runs in thread pool)
    
    This function is called by asyncio.run_in_executor()
    """
    scan = _scans.get(scan_id)
    if not scan:
        return None
    
    try:
        logger.info(f"Starting scan {scan_id} on {target} (type: {scan_type})")
        
        nm = nmap.PortScanner()
        arguments = get_scan_arguments(scan_type)
        
        # Execute scan
        nm.scan(hosts=target, arguments=arguments)
        
        discovered_hosts = []
        
        for host_ip in nm.all_hosts():
            host_data = nm[host_ip]
            
            # Hostname
            hostname = None
            if 'hostnames' in host_data and host_data['hostnames']:
                for hn in host_data['hostnames']:
                    if hn.get('name'):
                        hostname = hn['name']
                        break
            
            # MAC Address and Vendor
            mac_address = None
            vendor = None
            if 'addresses' in host_data:
                mac_address = host_data['addresses'].get('mac')
            if 'vendor' in host_data and mac_address:
                vendor = host_data['vendor'].get(mac_address)
            
            # OS Detection
            os_name, os_version, os_accuracy = parse_os_info(host_data)
            
            # Ports
            ports = []
            for proto in ['tcp', 'udp']:
                if proto in host_data:
                    for port, port_data in host_data[proto].items():
                        ports.append(DiscoveredPort(
                            port=port,
                            protocol=proto,
                            state=port_data.get('state', 'unknown'),
                            service=port_data.get('name'),
                            version=port_data.get('version'),
                            product=port_data.get('product')
                        ))
            
            # Create host object
            discovered_host = DiscoveredHost(
                ip_address=host_ip,
                hostname=hostname,
                mac_address=mac_address,
                vendor=vendor,
                os_name=os_name,
                os_version=os_version,
                os_accuracy=os_accuracy,
                ports=ports,
                state=host_data.get('status', {}).get('state', 'up')
            )
            
            # Guess asset type
            discovered_host.suggested_asset_type = guess_asset_type(discovered_host)
            
            discovered_hosts.append(discovered_host)
            logger.info(f"Found host: {host_ip} ({os_name or 'unknown OS'})")
        
        # Update scan result
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.hosts = discovered_hosts
        scan.hosts_up = len([h for h in discovered_hosts if h.state == 'up'])
        scan.hosts_total = len(discovered_hosts)
        
        logger.info(f"Scan {scan_id} completed: {scan.hosts_up} hosts found")
        return scan
        
    except nmap.PortScannerError as e:
        logger.error(f"Nmap error in scan {scan_id}: {str(e)}")
        scan.status = "failed"
        scan.error = f"Nmap error: {str(e)}"
        scan.completed_at = datetime.utcnow()
        return scan
        
    except Exception as e:
        logger.error(f"Error in scan {scan_id}: {str(e)}")
        scan.status = "failed"
        scan.error = f"Scan error: {str(e)}"
        scan.completed_at = datetime.utcnow()
        return scan


# ====================================
# Public Service Functions
# ====================================

async def start_scan(request: ScanRequest) -> ScanResponse:
    """
    Start a new network scan
    
    Returns immediately with scan_id, scan runs in background
    """
    scan_id = str(uuid.uuid4())[:8]
    
    # Create initial response
    scan = ScanResponse(
        scan_id=scan_id,
        target=request.target,
        scan_type=request.scan_type,
        status="running",
        started_at=datetime.utcnow()
    )
    
    _scans[scan_id] = scan
    
    # Run scan in thread pool (non-blocking)
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _executor,
        run_nmap_scan,
        request.target,
        request.scan_type,
        scan_id
    )
    
    logger.info(f"Scan {scan_id} started for target: {request.target}")
    return scan


def get_scan_status(scan_id: str) -> Optional[ScanResponse]:
    """Get current status of a scan"""
    return _scans.get(scan_id)


def get_scan_by_id(scan_id: str) -> Optional[ScanResponse]:
    """Get scan by ID (alias for get_scan_status)"""
    return _scans.get(scan_id)


def get_all_scans() -> List[ScanResponse]:
    """Get all scans (most recent first)"""
    scans = list(_scans.values())
    scans.sort(key=lambda x: x.started_at, reverse=True)
    return scans[:20]  # Last 20 scans


def delete_scan(scan_id: str) -> bool:
    """Delete a scan from history"""
    if scan_id in _scans:
        del _scans[scan_id]
        return True
    return False


def get_discovered_host_by_ip(scan_id: str, ip_address: str) -> Optional[DiscoveredHost]:
    """Get a specific discovered host from a scan"""
    scan = _scans.get(scan_id)
    if not scan:
        return None
    
    for host in scan.hosts:
        if host.ip_address == ip_address:
            return host
    return None