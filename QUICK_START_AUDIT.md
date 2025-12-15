# 🚀 Quick Start - Cisco CIS Audit

**5-Minute Guide to Your New Audit System**

---

## ✅ What You Can Do Now

Execute automated CIS security compliance audits on Cisco devices via API.

---

## 🔥 Quick Test (3 Steps)

### **1. Login & Get Token**

```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456"}'
```

**Copy the `access_token` from response.**

---

### **2. Execute Audit**

Replace `YOUR_TOKEN`, asset ID, and credentials:

```bash
curl -X POST "http://localhost:8000/api/audit/cisco/execute" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 25,
    "ssh_username": "admin",
    "ssh_password": "cisco",
    "ssh_secret": "enable_secret",
    "profile": "L1"
  }'
```

**Returns:** Compliance score & session ID

---

### **3. View Results**

```bash
curl -X GET "http://localhost:8000/api/audit/sessions/1/results" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Returns:** All CIS checks with PASS/FAIL status

---

## 📝 Prerequisites

1. **Asset with IP address** - Asset must exist in Asset List with IP configured
2. **SSH access** - Device must have SSH enabled
3. **Valid credentials** - Username/password (and enable secret if needed)
4. **Network connectivity** - Backend server can reach device IP

---

## 🎯 What Gets Checked (L1 Profile)

**~30 Security Checks:**
- ✅ Enable secret configured (not enable password)
- ✅ SSH v2 only (telnet disabled)
- ✅ VTY lines secured (access-class, exec-timeout)
- ✅ AAA configured
- ✅ Remote syslog configured
- ✅ SNMP security (v3 or ACL-restricted communities)
- ✅ NTP authentication
- ✅ Service password-encryption
- ✅ Login controls (block-for, logging)
- ✅ And 20+ more...

---

## 📊 Understanding Results

### **Compliance Metrics**

```json
{
  "compliance": {
    "total_checks": 30,
    "passed": 22,           // ✓ Green - Compliant
    "failed": 8,            // ✗ Red - Non-compliant
    "compliance_pct": 73.33,       // Simple percentage
    "weighted_compliance_pct": 68.42  // Severity-weighted
  }
}
```

### **Individual Checks**

```json
{
  "check_number": "IOS-L1-001",
  "check_title": "Use 'enable secret' only",
  "severity": "high",      // high/medium/low/info
  "status": "pass",        // pass = ✓ | fail = ✗
  "evidence_snippet": "enable secret 5 $1$..."
}
```

---

## 🔧 Common Issues

### **"Asset has no IP address"**
→ Add IP address to asset in Asset List

### **"Authentication failed"**
→ Check SSH username/password are correct

### **"Connection timeout"**
→ Verify device IP is reachable from backend server

### **"Permission denied"**
→ Request AUDIT module permissions from admin

---

## 📚 Full Documentation

- **API Reference:** `AUDIT_API_DOCUMENTATION.md`
- **Implementation Details:** `AUDIT_IMPLEMENTATION_SUMMARY.md`
- **Requirements:** `AUDIT_REQUIREMENTS.md`
- **Interactive Docs:** `http://localhost:8000/docs`

---

## 🎯 Next: Build Frontend

The backend is complete. Next phase:

1. Create Auditing page in frontend
2. Add asset selection dropdown
3. Build SSH credential form
4. Display results with ✓/✗ indicators
5. Show compliance charts

---

**Questions?** Check the full documentation files above! 🚀
