# Auto Discovery API Quick Reference Guide

## Authentication

All discovery API requests require authentication using a JWT token.

### Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "123456"}'
```

**Response:**
```json
{
  "access_token": "eyJhbGci...",
  "token_type": "bearer"
}
```

Use the token in subsequent requests:
```bash
Authorization: Bearer <access_token>
```

---

## Core Workflows

### 1. Start a Network Scan

**Endpoint:** `POST /api/discovery/scan`

```bash
curl -X POST http://localhost:8000/api/discovery/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "job_name": "Office Network Scan",
    "target": "192.168.1.0/24",
    "scan_type": "well_known_ports",
    "protocol": "TCP"
  }'
```

**Scan Types:**
- `well_known_ports` - Scans ports 1-1024 (default, balanced)
- `all_ports` - Scans all 65535 ports (slowest, most thorough)
- `custom_ports` - Scans specific ports (requires `ports` parameter)

**Target Formats:**
- Single IP: `192.168.1.1`
- CIDR range: `192.168.1.0/24`
- IP range: `192.168.1.1-254`

**Response:**
```json
{
  "scan_id": "ABC12345",
  "job_name": "Office Network Scan",
  "target": "192.168.1.0/24",
  "status": "running",
  "started_at": "2025-12-30T10:00:00"
}
```

---

### 2. Check Scan Status

**Endpoint:** `GET /api/discovery/scan/{scan_id}`

```bash
curl -X GET http://localhost:8000/api/discovery/scan/ABC12345 \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "scan_id": "ABC12345",
  "status": "completed",
  "hosts_up": 15,
  "hosts_total": 256,
  "hosts": [
    {
      "ip_address": "192.168.1.10",
      "hostname": "workstation-01",
      "mac_address": "00:11:22:33:44:55",
      "os_info": "Linux 5.x",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh"
        }
      ]
    }
  ]
}
```

**Status Values:**
- `pending` - Queued for execution
- `running` - Scan in progress
- `completed` - Scan finished successfully
- `failed` - Scan encountered an error

---

### 3. View Pending Hosts

**Endpoint:** `GET /api/discovery/pending`

```bash
# All pending hosts
curl -X GET http://localhost:8000/api/discovery/pending \
  -H "Authorization: Bearer <token>"

# Filter by scan
curl -X GET "http://localhost:8000/api/discovery/pending?scan_id=ABC12345" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "total": 15,
  "pending": [
    {
      "id": 123,
      "scan_id": "ABC12345",
      "ip_address": "192.168.1.10",
      "hostname": "workstation-01",
      "os_info": "Linux 5.x",
      "open_ports": [...],
      "status": "pending",
      "discovered_at": "2025-12-30T10:05:00"
    }
  ]
}
```

---

### 4. Check for Matching Assets

**Endpoint:** `GET /api/discovery/hosts/{host_id}/check-matches`

```bash
curl -X GET http://localhost:8000/api/discovery/hosts/123/check-matches \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "host_id": 123,
  "discovered_host": {
    "ip_address": "192.168.1.10",
    "hostname": "workstation-01",
    "mac_address": "00:11:22:33:44:55"
  },
  "matches": [
    {
      "asset_id": 456,
      "asset_name": "Employee Workstation",
      "match_type": "ip_address",
      "confidence": "high"
    }
  ],
  "match_count": 1
}
```

**Match Confidence Levels:**
- `high` - IP address match
- `medium` - MAC address match
- `low` - Hostname match

---

### 5. Preview Discovery Application

**Endpoint:** `GET /api/discovery/hosts/{host_id}/preview`

```bash
# Preview without comparison
curl -X GET http://localhost:8000/api/discovery/hosts/123/preview \
  -H "Authorization: Bearer <token>"

# Preview with asset comparison
curl -X GET "http://localhost:8000/api/discovery/hosts/123/preview?asset_id=456" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "host_id": 123,
  "discovered_data": {
    "ip_address": "192.168.1.10",
    "hostname": "workstation-01",
    "mac_address": "00:11:22:33:44:55",
    "os_info": "Linux 5.x"
  },
  "asset_id": 456,
  "asset_name": "Employee Workstation",
  "existing_data": {
    "ip_address": "192.168.1.10",
    "hostname": null,
    "mac_address": null
  },
  "overwrite_changes": {
    "fields_to_replace": [],
    "ports_to_remove": 5,
    "ports_to_add": 3
  },
  "merge_changes": {
    "fields_to_fill": [
      {"field": "hostname", "value": "workstation-01"},
      {"field": "mac_address", "value": "00:11:22:33:44:55"}
    ],
    "ports_to_add": 2
  }
}
```

---

### 6. Apply Discovery Results

**Endpoint:** `POST /api/discovery/hosts/{host_id}/apply`

#### Option A: Create New Asset
```bash
curl -X POST http://localhost:8000/api/discovery/hosts/123/apply \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "create_new",
    "asset_name": "New Workstation",
    "asset_type_id": 1
  }'
```

#### Option B: Merge with Existing Asset (Non-destructive)
```bash
curl -X POST http://localhost:8000/api/discovery/hosts/123/apply \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "merge",
    "asset_id": 456
  }'
```

**Merge Mode:**
- Only fills empty fields
- Adds new ports without removing existing ones
- Safe, non-destructive operation

#### Option C: Overwrite Existing Asset (Destructive)
```bash
curl -X POST http://localhost:8000/api/discovery/hosts/123/apply \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "overwrite",
    "asset_id": 456
  }'
```

**Overwrite Mode:**
- Replaces ALL existing data
- Removes all existing ports and adds discovered ports
- Use with caution!

**Response:**
```json
{
  "success": true,
  "mode": "merge",
  "asset_id": 456,
  "asset_name": "Employee Workstation",
  "message": "Merge applied successfully",
  "fields_updated": ["hostname", "mac_address"],
  "ports_added": 2
}
```

---

### 7. Approve/Skip Host

**Endpoint:** `POST /api/discovery/hosts/{host_id}/approve`

#### Skip (Mark as Reviewed)
```bash
curl -X POST http://localhost:8000/api/discovery/hosts/123/approve \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"action": "skip"}'
```

#### Merge with Existing
```bash
curl -X POST http://localhost:8000/api/discovery/hosts/123/approve \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "merge_with_existing",
    "asset_id": 456
  }'
```

#### Create New Asset
```bash
curl -X POST http://localhost:8000/api/discovery/hosts/123/approve \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "create_new",
    "asset_data": {
      "asset_name": "New Asset",
      "asset_type_id": 1
    }
  }'
```

---

### 8. Reject Host

**Endpoint:** `POST /api/discovery/hosts/{host_id}/reject`

```bash
curl -X POST http://localhost:8000/api/discovery/hosts/123/reject \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "message": "Host 192.168.1.10 rejected",
  "host_id": 123
}
```

---

### 9. Bulk Approve Hosts

**Endpoint:** `POST /api/discovery/bulk-approve`

```bash
curl -X POST http://localhost:8000/api/discovery/bulk-approve \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "host_ids": [123, 124, 125],
    "default_asset_type_id": 1,
    "default_location_id": 5,
    "default_owner_id": 10
  }'
```

**Response:**
```json
{
  "message": "Bulk approved 3 hosts",
  "approved": 3,
  "errors": null,
  "created_assets": [
    {"host_id": 123, "asset_id": 501, "asset_name": "Host-192.168.1.10"},
    {"host_id": 124, "asset_id": 502, "asset_name": "workstation-02"},
    {"host_id": 125, "asset_id": 503, "asset_name": "server-01"}
  ]
}
```

---

### 10. Find Matching Asset by IP

**Endpoint:** `GET /api/discovery/match/{ip_address}`

```bash
curl -X GET http://localhost:8000/api/discovery/match/192.168.1.10 \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "found": true,
  "asset_id": 456,
  "asset_name": "Employee Workstation",
  "empty_fields": ["hostname", "mac_address"],
  "current_values": {
    "hostname": null,
    "mac_address": null,
    "os_name": "Linux"
  }
}
```

---

### 11. Get All Scans

**Endpoint:** `GET /api/discovery/scans`

```bash
curl -X GET http://localhost:8000/api/discovery/scans \
  -H "Authorization: Bearer <token>"
```

Returns last 20 scans.

---

### 12. Delete Scan

**Endpoint:** `DELETE /api/discovery/scan/{scan_id}`

```bash
curl -X DELETE http://localhost:8000/api/discovery/scan/ABC12345 \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "message": "Scan deleted"
}
```

---

## Port Management

### Add Ports to Asset (Non-destructive)

**Endpoint:** `POST /api/discovery/ports/add`

```bash
curl -X POST http://localhost:8000/api/discovery/ports/add \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 456,
    "scan_id": "ABC12345",
    "ports": [
      {
        "port_number": 80,
        "protocol": "TCP",
        "service_name": "http",
        "state": "open"
      }
    ]
  }'
```

### Overwrite Asset Ports (Destructive)

**Endpoint:** `POST /api/discovery/ports/overwrite`

```bash
curl -X POST http://localhost:8000/api/discovery/ports/overwrite \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 456,
    "scan_id": "ABC12345",
    "ports": [...]
  }'
```

### Get Asset Ports

**Endpoint:** `GET /api/discovery/assets/{asset_id}/ports`

```bash
curl -X GET http://localhost:8000/api/discovery/assets/456/ports \
  -H "Authorization: Bearer <token>"
```

### Delete Port

**Endpoint:** `DELETE /api/discovery/ports/{port_id}`

```bash
curl -X DELETE http://localhost:8000/api/discovery/ports/789 \
  -H "Authorization: Bearer <token>"
```

---

## Typical Workflow

1. **Start Scan** → Get `scan_id`
2. **Poll Scan Status** → Wait for `status: completed`
3. **Get Pending Hosts** → Filter by `scan_id`
4. **For Each Host:**
   - **Check Matches** → Find existing assets
   - **Preview Changes** → See what will be updated
   - **Choose Action:**
     - Merge with existing asset (safe)
     - Create new asset
     - Skip/Reject
5. **Apply Discovery** → Update assets with discovered data

---

## Error Handling

### Common HTTP Status Codes

- `200 OK` - Request successful
- `400 Bad Request` - Invalid parameters
- `401 Unauthorized` - Missing/invalid token
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation error
- `500 Internal Server Error` - Server error

### Error Response Format

```json
{
  "detail": "Error message here"
}
```

---

## Permissions Required

All discovery endpoints require permissions on the `asset_auto_discovery` module:

- **Read:** View scans, pending hosts, previews
- **Write:** Start scans, approve hosts, apply discovery
- **Delete:** Delete scans, reject hosts

**Admin users** have all permissions by default.

---

## Tips & Best Practices

1. **Start Small:** Test scans on single IPs before scanning large ranges
2. **Use Preview:** Always preview changes before applying discovery
3. **Merge First:** Use merge mode by default (safer than overwrite)
4. **Filter Pending:** Use `scan_id` parameter to view hosts from specific scans
5. **Bulk Operations:** Use bulk approve for large-scale asset creation
6. **Clean Up:** Regularly delete old scans to keep database clean

---

## Example Python Script

See `test_discovery_api.py` for a complete working example of all endpoints.
