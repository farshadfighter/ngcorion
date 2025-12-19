# Audit Module - Requirements & Design Questions

**Date:** 2025-12-14
**Status:** Planning Phase

---

## **Overview**

The Audit module has two main menus:
1. **Operation & Device** - Windows, Linux, Cisco, Fortinet
2. **Service** - Apache, IIS, Active Directory, SQL Server

---

## **Workflow for Operation & Device**

1. User selects OS/Device type (e.g., "Cisco")
2. User chooses a device from Asset List (must have IP address)
3. User enters SSH credentials (username/password)
4. User selects mode: **inline** or **online**
5. SSH connection established
6. Commands executed based on CIS benchmark
7. Compliance check happens
8. Results displayed as CIS table with green/red indicators

---

## **Critical Questions to Answer**

### **1. Inline vs Online Modes - What's the difference?**
- **Inline**: Does this mean we read a config file that the user uploads (offline analysis)?
- **Online**: Does this mean we connect via SSH in real-time and run commands?

Or does it mean something else?

**Answer:** ✅ **Working on ONLINE mode only** (real-time SSH connections)

---

### **2. Service Menu - Same workflow?**
For services (Apache, IIS, Active Directory, SQL Server):
- Do we also SSH into a server and run commands to check these services?
- Or is this a different type of check?

Example: If user selects "Apache", do we:
- SSH into a Linux server → Run `httpd -V`, check Apache config files?
- Or something different?

**Answer:** ✅ **Service menu is separate with its own auditing logic. NOT working on it now.**

---

### **3. SSH Credentials - Storage?**
- **Option A**: User enters username/password each time (not stored)
- **Option B**: Store credentials encrypted in database for reuse

Which do you prefer?

**Answer:** ✅ **Option A - User enters credentials every time (not stored)**

---

### **4. CIS Templates - Predefined or Customizable?**
- Should we have **built-in CIS benchmarks** (e.g., CIS Cisco IOS Benchmark v4.1.1) that users cannot modify?
- Or should users be able to **create/edit** their own security checks?

**Answer:** ✅ **CIS benchmarks are STANDARD and cannot be customized. CIS audit always performed during scan.**

---

### **5. Audit History - Track Multiple Runs?**
- Should we keep history of audits? (e.g., "Run on Dec 10 - 45 passed, 5 failed", "Run on Dec 14 - 47 passed, 3 failed")
- Or just show the latest result only?

**Answer:** ✅ **CIS history is not important, but audits performed must be permanently stored in database.**

---

### **6. Results Display - What Details?**
When showing the CIS table with green/red indicators, should we show:
- ✅ Check number (e.g., "1.1.1")
- ✅ Check description (e.g., "Ensure password encryption is enabled")
- ✅ Status (Pass/Fail) with green/red color
- ✅ Actual command output (what the device returned)?
- ✅ Expected output (what it should be)?
- ✅ Severity level (Critical/High/Medium/Low)?

Which of these do you want?

**Answer:** ✅ **Only show: Compliant (green checkmark ✓) or Non-Compliant (red cross ✗)**

---

### **7. Real-time Progress?**
When the audit is running (100+ CIS checks might take 5-10 minutes):
- Should the UI show **real-time progress** ("Checking item 45 of 150...")?
- Or just show a loading spinner and display results when done?

**Answer:** ⏳ **[To be decided later]**

---

### **8. Device Selection from Asset List**
You said user must select from Asset List with IP address:
- Should we filter the Asset List to show **only devices of the selected type**?
  - Example: User selects "Cisco" → Only show assets where `asset_type = 'Cisco Router'` or `'Cisco Switch'`
- Or show all assets and let user pick any?

**Answer:** ✅ **No need to filter Asset List - user can select any asset**

---

## **Current State**

### **Database Schema (Exists but Unused):**
- `audit_templates` - CIS benchmark templates
- `audit_checks` - Individual security checks
- `audit_sessions` - Audit execution tracking
- `audit_results` - Check results

### **Models (Defined but No API):**
- `AuditTemplate`, `AuditCheck`, `AuditSession`, `AuditResult`
- Enums: `DeviceType`, `CheckStatus`

### **Frontend:**
- Placeholder page only ("Coming Soon")

---

## **Phase 1 Scope**

✅ **In Scope:**
- Operation & Device menu → Cisco only
- Online mode (real-time SSH)
- CIS Cisco benchmarks (standard, non-customizable)
- Backend implementation only
- Store audit results permanently in database
- Simple compliance display (green ✓ / red ✗)

❌ **Out of Scope (Later):**
- Service menu (Apache, IIS, AD, SQL Server)
- Windows, Linux, Fortinet devices
- Inline mode (config file uploads)
- Frontend UI
- SSH credential storage
- Real-time progress tracking
- Detailed evidence display

---

## **Provided Reference Code Analysis**

### **Script:** `cis_ios_turbo_fixed.py`

**Key Features:**
1. **SSH Connection** - Uses `netmiko` library (ConnectHandler)
2. **Turbo Collection** - Runs targeted commands instead of full `show run`
3. **Rule Engine** - ~50+ predefined CIS rules with check functions
4. **Evidence Redaction** - Masks passwords/secrets in outputs
5. **Compliance Scoring** - Weighted and simple percentage calculations
6. **Multiple Output Formats** - JSON, CSV reports

**Architecture:**
```python
@dataclass
class Rule:
    id: str              # "IOS-L1-001"
    title: str           # "Use enable secret only"
    severity: str        # high/medium/low/info
    level: str           # L1/L2/INFO
    rationale: str
    remediation: str
    check: Callable      # Function that returns True if compliant
    evidence: Callable   # Function that extracts evidence text

# Workflow:
1. collect_turbo() → SSH + run TURBO_COMMANDS → return text blob
2. redact() → mask sensitive data
3. evaluate(text, rules) → run all check() functions → return report
4. print_report() / save_outputs() → display results
```

**Key Insights:**
- Uses ~40 targeted commands (not full config dump)
- Regex-based compliance checks
- Handles enable/privilege mode properly
- Per-device try/except (continues on errors)
- INFO rules excluded from compliance scoring

---

## **Proposed New Architecture**

### **Database Schema Updates Needed:**

**Keep existing tables but modify:**

```sql
-- audit_templates: Store CIS benchmark definitions
--   ✅ Keep: id, name, device_type, version, description, created_at, user_id
--   ➕ Add: is_active (boolean), profile (L1/L2/FULL)

-- audit_checks: Individual CIS check items
--   ✅ Keep: id, template_id, check_number, title, description, severity
--   ❌ Remove: command, expected_output (we'll use Python functions instead)
--   ➕ Add: level (L1/L2/INFO), rationale (text), remediation (text)

-- audit_sessions: Audit execution tracking
--   ✅ Keep: id, template_id, user_id, asset_id, target_ip, device_type,
--          started_at, completed_at, status, total_checks, passed_checks,
--          failed_checks, error_checks
--   ➕ Add: compliance_pct (float), weighted_compliance_pct (float),
--          connection_error (text), turbo_dump (text - raw SSH output)

-- audit_results: Individual check results
--   ✅ Keep: id, session_id, check_id, status, checked_at
--   ❌ Remove: actual_output, error_message (store in turbo_dump instead)
--   ➕ Add: evidence_snippet (text - redacted excerpt)
```

### **Backend Components to Build:**

**1. SSH Connection Module** (`app/modules/audit/ssh_client.py`)
```python
class CiscoSSHClient:
    - connect(ip, username, password) → ConnectHandler
    - run_turbo_commands() → text blob
    - disconnect()
```

**2. CIS Rule Engine** (`app/modules/audit/cisco_rules.py`)
```python
class CiscoCISRule:
    - check(config_text) → bool
    - extract_evidence(config_text) → str

# 50+ predefined Cisco CIS rules (port from Python script)
```

**3. Audit Service** (`app/modules/audit/service.py`)
```python
class AuditService:
    - execute_audit(asset_id, username, password) → AuditSession
    - get_audit_results(session_id) → List[AuditResult]
    - get_audit_history(asset_id) → List[AuditSession]
```

**4. API Endpoints** (`app/modules/audit/router.py`)
```python
POST   /api/audit/cisco/execute        # Start audit
GET    /api/audit/sessions/{id}         # Get session details
GET    /api/audit/sessions/{id}/results # Get all check results
GET    /api/audit/asset/{id}/history    # Get audit history for asset
```

---

## **Implementation Steps**

### **Step 1: Database Migration**
- [ ] Create new migration to update audit schema
- [ ] Add missing columns (profile, level, rationale, etc.)
- [ ] Remove command/expected_output columns
- [ ] Add turbo_dump and connection_error fields

### **Step 2: Port CIS Rules**
- [ ] Create `cisco_rules.py` module
- [ ] Port ~50 rules from Python script to Python functions
- [ ] Add regex patterns and check logic
- [ ] Create evidence extraction functions

### **Step 3: SSH Connection Module**
- [ ] Install netmiko: `pip install netmiko`
- [ ] Create `ssh_client.py` wrapper
- [ ] Implement turbo command collection
- [ ] Add error handling and timeouts

### **Step 4: Audit Service Layer**
- [ ] Create `service.py` with AuditService class
- [ ] Implement execute_audit() workflow
- [ ] Add result storage logic
- [ ] Implement compliance calculation

### **Step 5: API Endpoints**
- [ ] Create router with 4 endpoints
- [ ] Add authentication/authorization
- [ ] Add input validation
- [ ] Add error handling

### **Step 6: Testing**
- [ ] Test SSH connection to Cisco device
- [ ] Test CIS rule evaluation
- [ ] Test full audit workflow
- [ ] Test result storage and retrieval

---

## **Next Steps**

1. ✅ Requirements documented
2. ✅ Reference code analyzed
3. ⏳ Get approval on architecture design
4. 🔜 Start Step 1: Database migration
5. 🔜 Start Step 2: Port CIS rules

---

## **Notes**

- Netmiko dependency required: `pip install netmiko`
- SSH credentials never stored (in-memory only during audit)
- Frontend will be built later (Phase 2)
- Service menu will be built later (Phase 3)
- Real-time progress tracking optional (Phase 4)
