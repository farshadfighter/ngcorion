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

**Answer:** _[Pending]_

---

### **2. Service Menu - Same workflow?**
For services (Apache, IIS, Active Directory, SQL Server):
- Do we also SSH into a server and run commands to check these services?
- Or is this a different type of check?

Example: If user selects "Apache", do we:
- SSH into a Linux server → Run `httpd -V`, check Apache config files?
- Or something different?

**Answer:** _[Pending]_

---

### **3. SSH Credentials - Storage?**
- **Option A**: User enters username/password each time (not stored)
- **Option B**: Store credentials encrypted in database for reuse

Which do you prefer?

**Answer:** _[Pending]_

---

### **4. CIS Templates - Predefined or Customizable?**
- Should we have **built-in CIS benchmarks** (e.g., CIS Cisco IOS Benchmark v4.1.1) that users cannot modify?
- Or should users be able to **create/edit** their own security checks?

**Answer:** _[Pending]_

---

### **5. Audit History - Track Multiple Runs?**
- Should we keep history of audits? (e.g., "Run on Dec 10 - 45 passed, 5 failed", "Run on Dec 14 - 47 passed, 3 failed")
- Or just show the latest result only?

**Answer:** _[Pending]_

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

**Answer:** _[Pending]_

---

### **7. Real-time Progress?**
When the audit is running (100+ CIS checks might take 5-10 minutes):
- Should the UI show **real-time progress** ("Checking item 45 of 150...")?
- Or just show a loading spinner and display results when done?

**Answer:** _[Pending]_

---

### **8. Device Selection from Asset List**
You said user must select from Asset List with IP address:
- Should we filter the Asset List to show **only devices of the selected type**?
  - Example: User selects "Cisco" → Only show assets where `asset_type = 'Cisco Router'` or `'Cisco Switch'`
- Or show all assets and let user pick any?

**Answer:** _[Pending]_

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

## **Next Steps**

1. Get answers to the 8 critical questions above
2. Design the new audit module architecture
3. Decide if we keep/modify/replace existing database schema
4. Implement backend API and SSH connection logic
5. Build frontend UI for the audit workflow
6. Create/import CIS benchmark templates

---

## **Notes**

- The audit module is currently just a skeleton (database tables exist but no functionality)
- 100% safe to redesign completely
- Need to implement SSH connection logic
- Need to create CIS benchmark data for each device/service type
