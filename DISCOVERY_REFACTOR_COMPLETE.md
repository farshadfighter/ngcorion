# Auto Discovery System - Complete Refactoring

**Date**: December 9, 2025
**Status**: ✅ **COMPLETE** - Backend & Frontend
**Build Status**: ✅ All tests passed, frontend builds successfully

---

## 🎯 Overview

Complete refactoring of the Auto Discovery system with fundamental changes to scan types, port management, and workflow.

## 📋 Summary of Changes

### **1. Database Schema**

#### New Tables Created:
- **`protocols`** - Stores protocol types (TCP, UDP, SCTP)
  - Seeded with 3 initial protocols
  - Used for port protocol classification

- **`ports`** - Stores discovered ports for each asset
  - Links to assets (CASCADE delete)
  - Links to protocols (RESTRICT delete)
  - Links to discovery scans (SET NULL)
  - Tracks: port_number, service info, state, discovery source

#### Modified Tables:
- **`discovery_scans`** - Added `job_name` column
  - User-friendly scan identification
  - Optional field with default "Scan {scan_id}"

### **2. Scan Type Changes**

#### OLD System:
```
- basic: Quick host discovery (~30s)
- detailed: Service + OS detection (~2-3min)
- full: All ports + aggressive (~10+min)
```

#### NEW System:
```
- well_known_ports: Scans ports 1-1024 (default, balanced)
- all_ports: Scans all 65535 ports (slowest, thorough)
- custom_ports: Scans specific user-defined ports (fastest, targeted)
```

### **3. Nmap Command Changes**

#### Removed:
- ❌ `-O` (OS detection - requires sudo)
- ❌ `-sS` (SYN scan - requires sudo)
- ❌ `-A` (Aggressive scan)
- ❌ Different scan depths based on type

#### Always Used:
- ✅ `-sT` (TCP connect scan - no sudo required)
- ✅ `-sV` (Service version detection)
- ✅ `-Pn` (Skip host discovery)

### **4. New Features**

#### Port Management API:
- `POST /api/discovery/ports/add` - Add new ports (non-destructive)
- `POST /api/discovery/ports/overwrite` - Replace all ports (destructive)
- `GET /api/discovery/assets/{id}/ports` - Get asset ports
- `DELETE /api/discovery/ports/{id}` - Delete specific port

#### Job Names:
- Optional user-friendly names for scans
- Displayed in scan history table
- Default: "Scan {scan_id}"

---

## 🔧 Backend Changes

### Files Modified:

1. **`app/models/port.py`** ⭐ NEW
   - Port and Protocol model definitions
   - Relationships with assets and scans
   - Helper methods for port management

2. **`app/models/discovery.py`**
   - Added `job_name` column
   - Updated `scan_type` comment

3. **`app/models/__init__.py`**
   - Added Port and Protocol exports

4. **`app/modules/discovery/nmap_scanner.py`**
   - Updated `build_nmap_command()` for new scan types
   - Removed -O, -A, -sS flags
   - Always uses -sT, -sV, -Pn
   - Port range logic based on scan type

5. **`app/modules/discovery/service.py`**
   - Updated `create_scan()` to accept job_name
   - Updated `get_scan_status()` to return job_name
   - Updated `start_scan()` to pass job_name

6. **`app/modules/discovery/port_service.py`** ⭐ NEW
   - PortService class for port management
   - add_ports() - non-destructive port addition
   - overwrite_ports() - replace all ports
   - get_asset_ports() - retrieve ports
   - delete_port() - remove specific port
   - **Fixed**: Foreign key validation for scan_id

7. **`app/modules/discovery/router.py`**
   - Added port management endpoints
   - Updated start_scan docstring
   - Added imports for new schemas

8. **`app/modules/discovery/schemas.py`**
   - Updated ScanRequest with job_name
   - Changed scan_type validation
   - Updated ScanResponse with job_name
   - Added PortInfo, AddPortsRequest, OverwritePortsRequest, PortManagementResponse
   - Updated ScanConfigResponse

9. **Migration**: `alembic/versions/a843df816d1c_*.py`
   - Creates protocols and ports tables
   - Adds job_name to discovery_scans
   - Seeds initial protocol data
   - Handles existing tables gracefully

---

## 💻 Frontend Changes

### Files Modified:

1. **`frontend-react/src/pages/AutoDiscovery/AutoDiscovery.jsx`**
   - Added `jobName` state variable
   - Updated default `scanType` to 'well_known_ports'
   - Updated `handleStartScan()`:
     - Added validation for custom_ports
     - Sends job_name in request
     - Resets form after submission
   - Updated `getScanTypeLabel()` function
   - Updated scan history table:
     - Changed columns to: ID, Job Name, Target, Type, Status, Result, Started
     - Shows job_name or fallback
     - Result button shows host count
   - Updated New Scan Modal:
     - Added Job Name input field
     - Updated Scan Type dropdown options
     - Shows Custom Ports field conditionally
     - Updated scan info descriptions
   - Updated current scan progress display

2. **`frontend-react/src/store/slices/discoverySlice.js`**
   - Updated `startScan` async thunk
   - Added job_name parameter
   - Changed default scan_type to 'well_known_ports'

3. **`frontend-react/src/pages/AutoDiscovery/DiscoveryResultModal.jsx`**
   - ✅ No changes needed (doesn't reference scan types)

---

## ✅ Testing Results

### Backend Tests:
```
✓ Schema validation (9/9 tests passed)
  - New scan types validated correctly
  - Old scan types rejected
  - Port management schemas working

✓ Nmap command generation (3/3 tests passed)
  - all_ports: -p-
  - well_known_ports: -p 1-1024
  - custom_ports: -p {custom}
  - Always includes: -sT -sV -Pn
  - Never includes: -O

✓ Port Service (7/7 tests passed)
  - Add ports (non-destructive)
  - Overwrite ports (destructive)
  - Duplicate detection
  - Get asset ports
  - Delete port
  - Foreign key validation fixed

✓ Database Schema
  - protocols table: 3 rows (TCP, UDP, SCTP)
  - ports table: created successfully
  - job_name column: added to discovery_scans
  - All relationships working
```

### Frontend Tests:
```
✓ Build successful (1.76s)
✓ No compilation errors
✓ All components render correctly
✓ Form validation working
```

---

## 🔄 Migration Applied

**Migration ID**: `a843df816d1c`
**Status**: ✅ Applied successfully
**Date**: 2025-12-09

**Changes**:
- Created `protocols` table
- Created `ports` table
- Added `job_name` to `discovery_scans`
- Seeded 3 protocols (TCP, UDP, SCTP)
- Gracefully handles existing tables

---

## 📊 New Workflow

### 1. **User Creates Scan**
```
Frontend Form:
  ├─ Job Name (optional)
  ├─ Target IP/Range
  ├─ Scan Type:
  │    ├─ well_known_ports (1-1024)
  │    ├─ all_ports (1-65535)
  │    └─ custom_ports (user specified)
  ├─ Custom Ports (if custom_ports selected)
  └─ Protocol (TCP/UDP/BOTH)
```

### 2. **Backend Executes Scan**
```
nmap -sT -sV -Pn -p {port_range} {target}
  ├─ No sudo required
  ├─ TCP connect scan
  ├─ Service version detection
  └─ Skip host discovery
```

### 3. **Results Display**
```
Scan History Table:
  ├─ ID: {scan_id}
  ├─ Job Name: {job_name or default}
  ├─ Target: {IP/range}
  ├─ Type: {scan_type label}
  ├─ Status: {running/completed/failed}
  ├─ Result: {host count button}
  └─ Started: {timestamp}
```

### 4. **Port Management**
```
After Scan Completion:
  ├─ View discovered ports
  ├─ Option 1: Add ports (keeps existing)
  └─ Option 2: Overwrite ports (replaces all)
```

---

## 🐛 Issues Fixed

1. **Foreign Key Constraint Error**
   - **Problem**: Port creation failed when scan_id didn't exist
   - **Solution**: Added validation in PortService to check scan existence
   - **Location**: `app/modules/discovery/port_service.py:57-71`

2. **API Documentation Outdated**
   - **Problem**: Router docstring showed old scan types
   - **Solution**: Updated docstring with new scan types and parameters
   - **Location**: `app/modules/discovery/router.py:76-99`

---

## 🚀 Deployment Checklist

- [x] Database migration created
- [x] Database migration applied
- [x] Backend code updated
- [x] Frontend code updated
- [x] Backend tests passed
- [x] Frontend builds successfully
- [x] Documentation created
- [ ] User manual updated (if exists)
- [ ] Team notified of changes

---

## 📝 Breaking Changes

### ⚠️ **API Changes** (Breaking):

1. **Scan Type Values Changed**:
   ```
   OLD: "basic", "detailed", "full"
   NEW: "well_known_ports", "all_ports", "custom_ports"
   ```
   **Impact**: Any external integrations must update scan_type values

2. **Nmap Flags Changed**:
   ```
   OLD: -sS, -O, -A (required sudo)
   NEW: -sT, -sV, -Pn (no sudo)
   ```
   **Impact**: No sudo required, but no OS detection

3. **New Required Field for custom_ports**:
   ```
   When scan_type="custom_ports", ports field is now REQUIRED
   ```

### ✅ **Backward Compatible**:

- Old scans in database still readable
- job_name is optional (defaults provided)
- API version unchanged
- Database schema additions only (no removals)

---

## 📖 API Documentation

### Start New Scan
```http
POST /api/discovery/scan
Content-Type: application/json

{
  "job_name": "Production Network Scan",     // Optional
  "target": "192.168.1.0/24",                // Required
  "scan_type": "well_known_ports",           // Required
  "ports": "80,443,8080",                    // Required if custom_ports
  "protocol": "TCP"                          // Optional, default: TCP
}
```

### Add Ports to Asset
```http
POST /api/discovery/ports/add
Content-Type: application/json

{
  "asset_id": 123,
  "scan_id": "ABC12345",                     // Optional
  "ports": [
    {
      "port_number": 80,
      "protocol": "TCP",
      "service_name": "http",
      "service_product": "nginx",
      "service_version": "1.18.0",
      "state": "open"
    }
  ]
}
```

### Overwrite Asset Ports
```http
POST /api/discovery/ports/overwrite
Content-Type: application/json

{
  "asset_id": 123,
  "scan_id": "ABC12345",                     // Optional
  "ports": [...]                             // Same format as add
}
```

---

## 🎓 Usage Examples

### Example 1: Quick Well-Known Ports Scan
```javascript
const scanData = {
  job_name: "Quick Security Check",
  target: "192.168.1.100",
  scan_type: "well_known_ports",
  protocol: "TCP"
};
```

### Example 2: All Ports Thorough Scan
```javascript
const scanData = {
  job_name: "Complete Port Scan",
  target: "10.0.0.0/24",
  scan_type: "all_ports",
  protocol: "TCP"
};
```

### Example 3: Custom Ports Web Scan
```javascript
const scanData = {
  job_name: "Web Services Scan",
  target: "172.16.0.1-254",
  scan_type: "custom_ports",
  ports: "80,443,8080,8443",
  protocol: "TCP"
};
```

---

## 👥 Credits

**Implemented by**: Claude Code (Anthropic)
**Date**: December 9, 2025
**Testing**: Automated backend + manual validation
**Build**: ✅ Successful (1.76s)

---

## 📞 Support

For questions or issues related to these changes:
1. Check this documentation first
2. Review API documentation in router.py
3. Check migration logs
4. Review test results above

---

**End of Documentation**
