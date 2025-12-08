# Asset Auto Discovery - Complete Redesign

## Overview
This document describes the complete redesign of the Asset Auto Discovery feature, integrating nmap-based network scanning with your existing asset management system.

## Key Features
1. **IP Range Support**: Single IP, CIDR notation, or IP ranges
2. **Port/Protocol Selection**: Customizable port and protocol scanning
3. **Pending Approval Workflow**: Discovered hosts must be reviewed before adding to asset inventory
4. **Non-Destructive**: Never overwrites existing asset data
5. **Visual Indicators**: Orange highlighting for pending discovery results
6. **Real-time Status**: Live scan progress updates

## Database Schema Enhancements

### New Model: `DiscoveredHost`
```python
# Located in: app/models/discovery.py

class DiscoveredHost(Base):
    """Stores discovered hosts awaiting approval"""
    __tablename__ = "discovered_hosts"

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), ForeignKey("discovery_scans.scan_id"))

    # Discovered Information
    ip_address = Column(String(50), nullable=False, index=True)
    mac_address = Column(String(17), nullable=True, index=True)
    hostname = Column(String(255), nullable=True)
    os_info = Column(String(255), nullable=True)
    os_accuracy = Column(Integer, nullable=True)
    open_ports = Column(JSON, nullable=True)  # Array of port objects

    # Approval Workflow
    status = Column(String(20), default="pending")  # pending, approved, rejected, merged
    approved_by_user_id = Column(Integer, ForeignKey("users.id"))
    approved_at = Column(DateTime, nullable=True)
    matched_asset_id = Column(Integer, ForeignKey("asset_inventory.id"))

    # Metadata
    discovery_source = Column(String(50), default="nmap")
    state = Column(String(20), nullable=True)  # up, down, unknown
    additional_info = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

### Enhanced Model: `DiscoveryScan`
Added fields:
```python
ports = Column(String(255), nullable=True,
    comment="Ports to scan (e.g., '80,443,8080' or '1-1000' or 'top1000')")

protocol = Column(String(20), default="TCP",
    comment="Protocol to scan: TCP, UDP, or BOTH")
```

## API Endpoints

### 1. Start New Scan
```http
POST /api/discovery/scan
Authorization: Bearer <token>
Content-Type: application/json

{
    "target": "192.168.1.0/24",
    "scan_type": "detailed",
    "ports": "80,443,8080",
    "protocol": "TCP"
}

Response:
{
    "scan_id": "abc123xy",
    "target": "192.168.1.0/24",
    "status": "running",
    "started_at": "2025-12-08T17:00:00Z"
}
```

### 2. Get Scan Status
```http
GET /api/discovery/scan/{scan_id}/status
Authorization: Bearer <token>

Response:
{
    "scan_id": "abc123xy",
    "status": "completed",
    "progress": 100,
    "hosts_discovered": 15,
    "hosts_up": 12,
    "started_at": "2025-12-08T17:00:00Z",
    "completed_at": "2025-12-08T17:05:30Z"
}
```

### 3. Get Pending Discovered Hosts
```http
GET /api/discovery/pending
Authorization: Bearer <token>

Response:
{
    "total": 12,
    "pending": [
        {
            "id": 1,
            "scan_id": "abc123xy",
            "ip_address": "192.168.1.100",
            "mac_address": "00:11:22:33:44:55",
            "hostname": "server01.local",
            "os_info": "Linux 5.10",
            "os_accuracy": 95,
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.18.0"
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https"
                }
            ],
            "status": "pending",
            "discovered_at": "2025-12-08T17:05:00Z",
            "matched_asset_id": null,
            "highlight": true  // For UI orange highlight
        }
    ]
}
```

### 4. Approve Discovered Host
```http
POST /api/discovery/hosts/{host_id}/approve
Authorization: Bearer <token>
Content-Type: application/json

{
    "action": "create_new",  // or "merge_with_existing"
    "asset_id": null,  // Required if action is "merge_with_existing"
    "asset_data": {
        "asset_name": "Server-01",
        "asset_type_id": 1,
        "location_id": 2
    }
}

Response:
{
    "success": true,
    "asset_id": 45,
    "message": "New asset created from discovered host",
    "fields_applied": ["ip_address", "mac_address", "hostname", "os_name"]
}
```

### 5. Reject Discovered Host
```http
POST /api/discovery/hosts/{host_id}/reject
Authorization: Bearer <token>

Response:
{
    "success": true,
    "message": "Discovered host rejected"
}
```

### 6. Bulk Approve
```http
POST /api/discovery/hosts/bulk-approve
Authorization: Bearer <token>
Content-Type: application/json

{
    "host_ids": [1, 2, 3, 4],
    "default_asset_type_id": 1,
    "default_location_id": 2
}

Response:
{
    "success": true,
    "approved": 4,
    "created_assets": [45, 46, 47, 48],
    "errors": []
}
```

### 7. Check for Matching Assets
```http
POST /api/discovery/hosts/{host_id}/check-match
Authorization: Bearer <token>

Response:
{
    "matches_found": true,
    "matches": [
        {
            "asset_id": 23,
            "asset_name": "Server-Old",
            "match_criteria": "mac_address",
            "match_confidence": "high",
            "current_ip": "192.168.1.50",
            "discovered_ip": "192.168.1.100",
            "empty_fields": ["os_name", "os_version"],
            "conflicting_fields": ["ip_address"]
        }
    ],
    "recommendation": "merge"  // merge, create_new, review
}
```

## UI Workflow

### Step 1: User Clicks "New Scan"
Popup appears with form:
- **Target**: Input field (IP address, CIDR, or range)
- **Ports**: Input field or dropdown (Common ports, Top 1000, Custom)
- **Protocol**: Dropdown (TCP, UDP, Both)
- **Scan Type**: Dropdown (Basic, Detailed, Full)

### Step 2: Scan Starts
- API call to `POST /api/discovery/scan`
- Receives `scan_id`
- Table shows new row with status "Running"

### Step 3: Poll for Updates
- Every 2-3 seconds: `GET /api/discovery/scan/{scan_id}/status`
- Update progress bar and status in table
- When `status == "completed"`, proceed to step 4

### Step 4: Display Results
- Call `GET /api/discovery/pending` to get all pending hosts
- Display in table with **orange highlighting**
- Columns:
  - IP Address
  - Hostname
  - MAC Address
  - OS Info
  - Open Ports (count or list)
  - Status (badge: "Pending Review")
  - Actions (Approve, Reject, View Details)

### Step 5: Review and Approve
User clicks "Approve" on a row:
1. Check for matches: `POST /api/discovery/hosts/{id}/check-match`
2. If matches found:
   - Show dialog: "Found matching asset! Merge or create new?"
   - Options: Merge, Create New, Cancel
3. If no matches or user chooses "Create New":
   - Show form to fill missing data (asset name, type, location)
   - Submit: `POST /api/discovery/hosts/{id}/approve`
4. Row turns green and moves to main asset list

### Step 6: Bulk Operations
- Checkbox column for multi-select
- "Bulk Approve" button
- Applies default values to all selected hosts
- Creates new assets for all

## Backend Service Implementation

### File: `app/modules/discovery/service.py`

Key functions to implement/enhance:

```python
class DiscoveryService:

    @staticmethod
    def start_scan(db: Session, user_id: int, target: str,
                   scan_type: str, ports: str = None, protocol: str = "TCP"):
        """
        Start a new nmap scan
        - Generate scan_id
        - Create DiscoveryScan record
        - Launch background task
        - Return scan info
        """
        pass

    @staticmethod
    def get_scan_status(db: Session, scan_id: str):
        """Get current status of a scan"""
        pass

    @staticmethod
    def get_pending_hosts(db: Session, scan_id: str = None):
        """
        Get all discovered hosts with status='pending'
        Optionally filter by scan_id
        """
        pass

    @staticmethod
    def approve_discovered_host(db: Session, host_id: int, user_id: int,
                                action: str, asset_id: int = None,
                                asset_data: dict = None):
        """
        Approve a discovered host
        Actions:
        - create_new: Create new asset from discovered data
        - merge_with_existing: Update existing asset (non-destructive)
        """
        pass

    @staticmethod
    def reject_discovered_host(db: Session, host_id: int, user_id: int):
        """Mark discovered host as rejected"""
        pass

    @staticmethod
    def check_asset_matches(db: Session, host_id: int):
        """
        Check if discovered host matches existing assets
        Match criteria (in order):
        1. MAC address (exact)
        2. IP address (exact)
        3. Hostname (exact or similar)
        """
        pass

    @staticmethod
    def bulk_approve_hosts(db: Session, host_ids: list, user_id: int,
                          default_type_id: int, default_location_id: int):
        """Approve multiple hosts at once"""
        pass
```

## Nmap Integration

### File: `app/modules/discovery/nmap_scanner.py`

```python
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

class NmapScanner:

    @staticmethod
    def build_nmap_command(target: str, ports: str = None,
                          protocol: str = "TCP", scan_type: str = "basic"):
        """
        Build nmap command based on parameters

        Examples:
        - basic: nmap -sn 192.168.1.0/24
        - detailed: nmap -sV -O 192.168.1.0/24
        - full: nmap -sV -O -A 192.168.1.0/24
        """
        cmd = ["nmap", "-oX", "-"]  # XML output to stdout

        if scan_type == "basic":
            cmd.append("-sn")  # Ping scan only
        elif scan_type == "detailed":
            cmd.extend(["-sV", "-O"])  # Service + OS detection
        elif scan_type == "full":
            cmd.extend(["-sV", "-O", "-A"])  # Aggressive scan

        # Protocol
        if protocol == "TCP":
            cmd.append("-sT" if not is_root() else "-sS")
        elif protocol == "UDP":
            cmd.append("-sU")
        elif protocol == "BOTH":
            cmd.extend(["-sT" if not is_root() else "-sS", "-sU"])

        # Ports
        if ports:
            if ports == "top1000":
                cmd.append("--top-ports=1000")
            elif ports == "all":
                cmd.append("-p-")
            else:
                cmd.extend(["-p", ports])

        cmd.append(target)
        return cmd

    @staticmethod
    def execute_scan(cmd: List[str], timeout: int = 600):
        """Execute nmap command and return XML output"""
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, None, "Scan timeout exceeded"

    @staticmethod
    def parse_nmap_xml(xml_text: str) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output into structured data

        Returns list of hosts with structure:
        {
            "ip": "192.168.1.100",
            "mac": "00:11:22:33:44:55",
            "hostname": "server01.local",
            "state": "up",
            "os": {
                "name": "Linux 5.10",
                "accuracy": 95
            },
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.18.0"
                }
            ]
        }
        """
        root = ET.fromstring(xml_text)
        hosts = []

        for host in root.findall("host"):
            host_data = {
                "ip": None,
                "mac": None,
                "hostname": None,
                "state": None,
                "os": {"name": None, "accuracy": None},
                "ports": []
            }

            # Status
            status = host.find("status")
            if status is not None:
                host_data["state"] = status.get("state")

            # Addresses
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type in ("ipv4", "ipv6"):
                    host_data["ip"] = addr.get("addr")
                elif addr_type == "mac":
                    host_data["mac"] = addr.get("addr")

            # Hostnames
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find("hostname")
                if hostname_elem is not None:
                    host_data["hostname"] = hostname_elem.get("name")

            # OS Detection
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host_data["os"]["name"] = osmatch.get("name")
                    host_data["os"]["accuracy"] = int(osmatch.get("accuracy", 0))

            # Ports
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    port_id = int(port.get("portid"))
                    protocol = port.get("protocol")

                    state_elem = port.find("state")
                    state = state_elem.get("state") if state_elem is not None else None

                    service_elem = port.find("service")
                    service_info = {}
                    if service_elem is not None:
                        service_info = {
                            "service": service_elem.get("name"),
                            "product": service_elem.get("product"),
                            "version": service_elem.get("version")
                        }

                    host_data["ports"].append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        **service_info
                    })

            hosts.append(host_data)

        return hosts

def is_root():
    """Check if running as root (needed for SYN scan)"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
```

## Security Considerations

1. **Authentication**: All endpoints require JWT token
2. **Authorization**:
   - Regular users can view their own scans
   - Managers can approve discoveries
   - Admins have full access
3. **Input Validation**: All scan parameters validated
4. **Rate Limiting**: Limit concurrent scans per user
5. **Audit Trail**: All actions logged in `discovery_audit_logs`
6. **Non-Destructive**: Never overwrites existing asset data without explicit approval

## Migration Script

```python
# File: alembic/versions/xxx_add_discovery_enhancements.py

def upgrade():
    # Add columns to discovery_scans
    op.add_column('discovery_scans', sa.Column('ports', sa.String(255)))
    op.add_column('discovery_scans', sa.Column('protocol', sa.String(20), server_default='TCP'))

    # Create discovered_hosts table
    op.create_table(
        'discovered_hosts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('scan_id', sa.String(50), sa.ForeignKey('discovery_scans.scan_id')),
        sa.Column('ip_address', sa.String(50), nullable=False),
        sa.Column('mac_address', sa.String(17)),
        sa.Column('hostname', sa.String(255)),
        sa.Column('os_info', sa.String(255)),
        sa.Column('os_accuracy', sa.Integer()),
        sa.Column('open_ports', sa.JSON()),
        sa.Column('status', sa.String(20), server_default='pending'),
        sa.Column('approved_by_user_id', sa.Integer(), sa.ForeignKey('users.id')),
        sa.Column('approved_at', sa.DateTime()),
        sa.Column('matched_asset_id', sa.Integer(), sa.ForeignKey('asset_inventory.id')),
        sa.Column('discovery_source', sa.String(50), server_default='nmap'),
        sa.Column('state', sa.String(20)),
        sa.Column('additional_info', sa.JSON()),
        sa.Column('discovered_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now())
    )

    # Create indexes
    op.create_index('ix_discovered_hosts_scan_id', 'discovered_hosts', ['scan_id'])
    op.create_index('ix_discovered_hosts_ip', 'discovered_hosts', ['ip_address'])
    op.create_index('ix_discovered_hosts_status', 'discovered_hosts', ['status'])

def downgrade():
    op.drop_table('discovered_hosts')
    op.drop_column('discovery_scans', 'protocol')
    op.drop_column('discovery_scans', 'ports')
```

## Testing Checklist

- [ ] Single IP scan works
- [ ] CIDR range scan works (e.g., 192.168.1.0/24)
- [ ] IP range scan works (e.g., 192.168.1.1-192.168.1.50)
- [ ] Port specification works (single, range, comma-separated)
- [ ] Protocol selection works (TCP, UDP, BOTH)
- [ ] Scan status updates correctly
- [ ] Pending hosts display with orange highlight
- [ ] Approve creates new asset correctly
- [ ] Approve merges with existing asset (non-destructive)
- [ ] Reject works and marks host as rejected
- [ ] Bulk approve works for multiple hosts
- [ ] Matching algorithm finds duplicates correctly
- [ ] Audit logs record all actions
- [ ] Authentication required for all endpoints
- [ ] Authorization enforced correctly

## Next Steps

1. **Run database migration** to add new tables/columns
2. **Implement nmap scanner utility** (nmap_scanner.py)
3. **Enhance service layer** with new methods
4. **Update router** with new endpoints
5. **Test with real network scans**
6. **Update frontend** to use new API endpoints
7. **Add real-time updates** (WebSocket or SSE optional)
8. **Performance tuning** for large network scans

## Future Enhancements

- **Passive discovery**: Learn from network traffic without active scanning
- **Scheduled scans**: Automatic recurring scans
- **Change detection**: Alert when network topology changes
- **Integration with SIEM**: Export discoveries to security tools
- **Machine learning**: Improve asset matching accuracy
- **Vulnerability scanning**: Integrate with vulnerability databases
- **Network mapping**: Visual network topology from discoveries
