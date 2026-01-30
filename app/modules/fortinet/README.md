# FortiGate Security Audit Module

## Overview

This module provides comprehensive security auditing for FortiGate firewalls following CIS benchmarks and enterprise best practices. It includes 120+ security controls covering management plane security, cryptography, VPN configuration, UTM policies, and more.

## Architecture

The module follows the same pattern as the Cisco audit module:

```
/app/modules/fortinet/
├── __init__.py                    # Module initialization
├── fortinet_ssh_client.py         # SSH connection management
├── fortinet_rules.py              # CIS benchmark control catalog (65+ controls)
├── fortinet_service.py            # Audit orchestration service
├── fortinet_router.py             # FastAPI API endpoints
├── fortinet_cis_map.py            # CIS benchmark mapping
└── README.md                      # This file
```

## Components

### 1. FortiGate SSH Client (`fortinet_ssh_client.py`)

**Classes:**
- `FortiGateSSHClient`: Main SSH client for FortiGate devices
- `ConnectionPool`: Thread-safe connection pool for parallel VDOM processing

**Features:**
- VDOM context switching and discovery
- Command output caching (5-minute TTL)
- Automatic pagination handling (--More--)
- Batch command execution
- Context manager support

**Usage:**
```python
from app.modules.fortinet import FortiGateSSHClient

# Using context manager
with FortiGateSSHClient("192.168.1.1", "admin", "password") as client:
    status = client.get_system_status()
    print(f"FortiOS Version: {status['fortios_version']}")

    # Discover VDOMs
    vdoms = client.discover_vdoms()

    # Enter VDOM context
    if vdoms:
        client.enter_vdom(vdoms[0])
        config = client.send_command("show system global")
        client.exit_vdom()
```

### 2. Control Catalog (`fortinet_rules.py`) - Planned

Will contain 120+ security controls organized into packs:
- **BASELINE**: Core security controls (~90 checks)
- **HA**: High availability configuration
- **SDWAN**: SD-WAN best practices
- **VPN_SSL**: SSL-VPN security
- **VPN_IPSEC**: IPsec VPN security
- **CENTRAL_NAT**: Central SNAT configuration
- **LOCAL_IN**: Local-in policy controls
- **EXPOSURE**: VIP and exposure management
- **UTM**: Security profile enforcement
- **FAZ**: FortiAnalyzer integration
- **SHADOW**: Shadow rule analysis
- **UNUSED**: Unused object detection
- **COVERAGE**: Policy coverage metrics

### 3. Audit Service (`fortinet_service.py`) - Planned

Orchestration layer providing:
- Control evaluation and scoring
- Analytics (shadow rules, unused objects, UTM coverage)
- Result caching and batch insertion
- Parallel VDOM processing
- HTML/JSON/CSV report generation

### 4. API Router (`fortinet_router.py`)

FastAPI endpoints:
- `POST /api/fortinet/audit/execute` - Execute FortiGate audit
- `POST /api/fortinet/vdoms/discover` - Discover VDOMs
- `GET /api/fortinet/audit/sessions` - List audit sessions
- `GET /api/fortinet/audit/sessions/{session_id}` - Get session details
- `GET /api/fortinet/audit/sessions/{session_id}/results` - Get audit results
- `DELETE /api/fortinet/audit/sessions/{session_id}` - Delete session

## API Usage

### 1. Discover VDOMs
```bash
curl -X POST http://localhost:8000/api/fortinet/vdoms/discover \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "asset_id": 42,
    "ssh_username": "admin",
    "ssh_password": "password"
  }'
```

**Response:**
```json
{
  "asset_id": 42,
  "asset_name": "fw-hq-01",
  "target_ip": "192.168.1.1",
  "vdoms": ["root", "VDOM_1", "VDOM_2"]
}
```

### 2. Execute Audit
```bash
curl -X POST http://localhost:8000/api/fortinet/audit/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "asset_id": 42,
    "ssh_username": "admin",
    "ssh_password": "password",
    "vdom": "root",
    "profile": "L1"
  }'
```

**Response:**
```json
{
  "session_id": 123,
  "asset_id": 42,
  "asset_name": "fw-hq-01",
  "target_ip": "192.168.1.1",
  "device_type": "fortinet",
  "status": "completed",
  "started_at": "2026-01-29T10:00:00Z",
  "completed_at": "2026-01-29T10:02:30Z",
  "duration_seconds": 150.5,
  "compliance": {
    "total_checks": 65,
    "passed": 52,
    "failed": 13,
    "compliance_pct": 80.0
  },
  "connection_error": null
}
```

### 3. Get Audit Results
```bash
curl http://localhost:8000/api/fortinet/audit/sessions/123/results \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
[
  {
    "id": 1,
    "check_number": "FG-BL-001",
    "check_title": "Admin HTTPS enabled",
    "severity": "high",
    "level": "L1",
    "status": "pass",
    "evidence_snippet": "set admin-https enable",
    "checked_at": "2026-01-29T10:01:00Z"
  },
  {
    "id": 2,
    "check_number": "FG-BL-002",
    "check_title": "Admin HTTP disabled",
    "severity": "high",
    "level": "L1",
    "status": "fail",
    "evidence_snippet": "set admin-http enable",
    "checked_at": "2026-01-29T10:01:00Z"
  }
]
```

### 4. List Sessions
```bash
curl http://localhost:8000/api/fortinet/audit/sessions?limit=10 \
  -H "Authorization: Bearer $TOKEN"
```

### 5. Delete Session
```bash
curl -X DELETE http://localhost:8000/api/fortinet/audit/sessions/123 \
  -H "Authorization: Bearer $TOKEN"
```

## Standalone CLI Tool

For immediate use, a full-featured CLI tool is available:

**Location:** `/scripts/fortinet_audit_cli.py`

**Usage:**
```bash
# Basic audit
python scripts/fortinet_audit_cli.py \
  --host 192.168.1.1 \
  --username admin \
  --password 'SecurePass123' \
  --out-prefix fg_audit

# Audit all VDOMs in parallel
python scripts/fortinet_audit_cli.py \
  --host 192.168.1.1 \
  --username admin \
  --password 'SecurePass123' \
  --all-vdoms \
  --workers 4

# Export control catalog
python scripts/fortinet_audit_cli.py \
  --export-catalog controls.yaml
```

**Output:**
- `fg_audit_<vdom>.json` - Full audit data
- `fg_audit_<vdom>.csv` - Findings table
- `fg_audit_<vdom>.html` - Interactive HTML report
- `fg_audit_ALL.json` - Aggregated results

## Security Controls

### Example Controls

**Management Plane:**
- `FG-BL-001`: Admin HTTPS enabled (CIS 1.1.1)
- `FG-BL-002`: Admin HTTP disabled (CIS 1.1.2)
- `FG-BL-003`: Admin Telnet disabled (CIS 1.1.3)
- `FG-BL-004`: Admin idle timeout ≤ 10 minutes
- `FG-BL-005`: TLS 1.0/1.1 disabled on GUI

**Identity & Access:**
- `FG-BL-020`: Admin trusthost configured
- `FG-BL-021`: Default 'admin' account disabled/renamed
- `FG-BL-022`: Multi-factor authentication configured
- `FG-BL-030-036`: Password policy controls (length, complexity)

**Cryptography:**
- `FG-BL-090`: Strong encryption required
- `FG-VPN-SSL-001`: SSL-VPN TLS 1.0/1.1 disabled
- `FG-VPN-IPSEC-001`: IPsec weak proposals disabled

**Logging:**
- `FG-BL-060`: Remote syslog enabled
- `FG-BL-061`: Remote syslog server configured
- `FG-FAZ-001`: FortiAnalyzer logging enabled

**Policy Best Practices:**
- `FG-BL-080`: No Any/Any/ALL ACCEPT policy
- `FG-BL-082`: Policy logging enabled

### Control Packs

Controls are organized into feature-based packs that are automatically enabled based on device configuration:

| Pack | Auto-Enabled When | Controls |
|------|-------------------|----------|
| BASELINE | Always | 90+ core controls |
| HA | HA mode detected | 4 HA-specific checks |
| SDWAN | SD-WAN configured | 2 SD-WAN checks |
| VPN_SSL | SSL-VPN enabled | 2 SSL-VPN security checks |
| VPN_IPSEC | IPsec configured | 2 IPsec security checks |
| CENTRAL_NAT | Central SNAT in use | 1 NAT review check |
| LOCAL_IN | Local-in policy exists | 1 mgmt security check |
| EXPOSURE | VIP objects exist | 2 exposure checks |
| UTM | Always | 4 UTM policy checks |
| FAZ | FortiAnalyzer configured | 2 FAZ logging checks |
| SHADOW | Always | Shadow rule analysis |
| UNUSED | Always | Unused object analysis |
| COVERAGE | Always | UTM coverage metrics |

## Database Integration

The database already supports FortiGate devices via the `DeviceType.FORTINET` enum in `app/models/audit.py`.

**Audit Tables:**
- `audit_templates` - Control templates
- `audit_checks` - Individual checks (FG-BL-001, etc.)
- `audit_sessions` - Audit execution records
- `audit_results` - Check results (PASS/FAIL/WARN/ERROR)

## CIS Benchmark Mapping

FortiGate controls are mapped to CIS FortiGate Benchmark sections:

| CIS Section | Description | Controls |
|-------------|-------------|----------|
| 1.1 | Management Access | FG-BL-001 to FG-BL-005 |
| 1.2 | Session Management | FG-BL-004 |
| 1.3-1.4 | Cryptography | FG-BL-005, FG-BL-006, FG-BL-090 |
| 2.1-2.2 | Access Control & Auth | FG-BL-020 to FG-BL-036 |
| 3.1 | Time Services | FG-BL-040 to FG-BL-042 |
| 4.1 | SNMP Security | FG-BL-050 to FG-BL-052 |
| 5.1 | Logging & Monitoring | FG-BL-060 to FG-BL-065 |
| 6.1-6.2 | Firewall Policy | FG-BL-080 to FG-BL-082 |
| 7.1-7.2 | Interface & Mgmt Security | FG-BL-WAN-*, FG-LIP-001 |
| 8.1-8.2 | VPN Security | FG-VPN-SSL-*, FG-VPN-IPSEC-* |
| 9.1 | UTM Profiles | FG-UTM-* |

## Analytics Features

### 1. Shadow Rule Detection
Identifies policies that are unreachable due to earlier, more permissive rules.

**Algorithm:**
- Compares all enabled ACCEPT policies sequentially
- Checks if earlier policy subsumes later policy (srcintf, dstintf, srcaddr, dstaddr, service)
- Reports shadowed policy ID and shadowing policy ID

### 2. Unused Object Analysis
Detects firewall address and service objects not referenced in any policy.

**Process:**
- Extracts all address/service object names
- Cross-references with policy srcaddr/dstaddr/service fields
- Reports unused objects (excludes built-in 'all' tokens)

### 3. UTM Coverage Metrics
Analyzes security profile usage across policies.

**Metrics:**
- Accept policies count
- UTM-enabled policies count and percentage
- Individual profile usage: AV, IPS, Web Filter, App Control, SSL-SSH

## Integration Roadmap

### Phase 1: Database Schema (Completed)
- ✅ `DeviceType.FORTINET` enum added
- ✅ Audit tables support generic device types

### Phase 2: SSH Client (Completed)
- ✅ `FortiGateSSHClient` implemented
- ✅ VDOM discovery and context switching
- ✅ Command caching and pagination handling

### Phase 3: Control Catalog (Completed)
- ✅ 65+ controls extracted and organized
- ✅ CIS benchmark mapping implemented
- ✅ `fortinet_rules.py` created

### Phase 4: Service Layer (Completed)
- ✅ `FortinetAuditService` implemented
- ✅ Control evaluation and scoring
- ✅ VDOM context support
- ✅ Data redaction and security

### Phase 5: API Endpoints (Completed)
- ✅ `fortinet_router.py` created
- ✅ Request/response schemas defined
- ✅ Routes registered in `app/main.py`

### Phase 6: Frontend Integration (Planned)
- Add FortiGate audit UI component
- VDOM selection interface
- Analytics dashboard

## Performance Optimizations

1. **Command Caching**: 5-minute TTL reduces redundant SSH commands
2. **Connection Pooling**: Reusable connections for parallel VDOM audits
3. **Batch Command Execution**: Single SSH session for multiple commands
4. **Parallel VDOM Processing**: ThreadPoolExecutor with configurable workers (default: 4)
5. **Rule Caching**: In-memory control catalog (similar to Cisco pattern)

## Testing

### Manual Testing
```python
# Test SSH connection
from app.modules.fortinet import FortiGateSSHClient

client = FortiGateSSHClient("192.168.1.1", "admin", "password")
client.connect()
status = client.get_system_status()
print(status)
client.disconnect()
```

### Integration Testing
```bash
# Run CLI tool audit
python scripts/fortinet_audit_cli.py \
  --host <test-fortigate> \
  --username <user> \
  --password <pass> \
  --out-prefix test_audit
```

## Dependencies

**Required:**
- `netmiko` (4.6.0+) - SSH automation
- `jinja2` (3.1.6+) - HTML report generation
- `pyyaml` (6.0.3+) - YAML catalog support (optional)

**Installed via:**
```bash
pip install -r requirements.txt
```

## Security Considerations

1. **Credentials**: SSH passwords are never stored; used only during audit execution
2. **Command Output**: Can be excluded from reports via `--no-evidence` flag
3. **VDOM Isolation**: Each VDOM audit runs in isolated context
4. **Read-Only**: All audit commands are non-modifying (show/get/diagnose only)

## Related Files

- **CLI Tool**: `/scripts/fortinet_audit_cli.py` (v4, 2200+ lines)
- **Legacy CLI**: `/scripts/fortinet_audit_legacy_v3.py` (v3, 1350+ lines)
- **Database Models**: `/app/models/audit.py`
- **Cisco Reference**: `/app/modules/audit/` (similar pattern)

## Support

For issues or questions:
1. Check logs in audit_results table
2. Enable verbose output: set `--no-evidence false`
3. Review CIS FortiGate Benchmark documentation
4. Compare with working Cisco audit module structure

## Version History

- **v4.0** (2026-01-29): Modular architecture with FastAPI integration
  - 120+ controls with CIS mapping
  - Parallel VDOM processing
  - HTML reporting with dashboard
  - Advanced analytics (shadow, unused, coverage)
  - Performance optimizations (caching, pooling)

- **v3.0** (2025): Standalone enterprise auditor
  - ~100 controls
  - Multi-VDOM support
  - YAML catalog support
  - Shadow rule detection

- **v2.0**: Initial NGCorion baseline
  - Basic CIS controls
  - Single VDOM support
