# Frontend Quick Reference: Hardening API

Quick reference for implementing network device hardening UI.

---

## API Endpoints Summary

### Cisco

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/hardening/preview` | POST | Preview single check fix |
| `/api/hardening/execute` | POST | Execute single check fix |
| `/api/hardening/session/{id}/parameters` | GET | Get aggregated parameters for batch |
| `/api/hardening/session/{id}/auto-preview` | GET | Preview auto-hardening |
| `/api/hardening/auto-harden-defaults` | POST | Execute auto-hardening |
| `/api/hardening/batch-execute` | POST | Execute batch fixes |

### FortiGate

Same endpoints with `/api/hardening/fortinet/` prefix.
Add `"vdom": "root"` field to requests.

---

## Three Modes Cheat Sheet

### Mode 1: Fix Single
```javascript
// 1. Preview
POST /api/hardening/preview
{ audit_result_id: 123 }

// 2. Execute
POST /api/hardening/execute
{
  action_id: 456,
  ssh_username: "admin",
  ssh_password: "pass",
  parameters: { STRONG_SECRET: "MyPass123!" }
}
```

### Mode 2: Fix All
```javascript
// 1. Get parameters
GET /api/hardening/session/123/parameters?check_ids=101,102,103

// 2. Execute batch
POST /api/hardening/batch-execute
{
  audit_session_id: 123,
  check_ids: [101, 102, 103],
  ssh_username: "admin",
  ssh_password: "pass",
  parameters: {
    STRONG_SECRET: "MyPass123!",
    BANNER_TEXT: "Authorized users only"
  }
}
```

### Mode 3: Automatic
```javascript
// 1. Preview
GET /api/hardening/session/123/auto-preview

// 2. Execute
POST /api/hardening/auto-harden-defaults
{
  audit_session_id: 123,
  ssh_username: "admin",
  ssh_password: "pass",
  confirmed: true  // REQUIRED
}
```

---

## SSH Error Handling

### Error Types & Status Codes

| Type | Code | Icon | User Action |
|------|------|------|-------------|
| `authentication_error` | 401 | 🔐 | Fix credentials |
| `timeout_error` | 504 | ⏱️ | Check device |
| `connection_error` | 503 | 🔌 | Check network |
| `algorithm_mismatch` | 502 | ⚠️ | Upgrade SSH |
| `host_key_error` | 502 | 🔑 | Clear old key |

### Error Response Format

```json
{
  "detail": {
    "error_type": "authentication_error",
    "message": "Authentication failed for 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": [
      "Verify username/password",
      "Check account status",
      ...
    ],
    "original_error": "..."
  }
}
```

### Handling in Code

```javascript
try {
  const response = await api.post('/api/hardening/execute', data);
  // Success
} catch (error) {
  const detail = error.response?.data?.detail;

  if (detail?.error_type) {
    // Structured SSH error
    showSSHErrorModal(detail);
  } else {
    // Other error
    showError(detail || 'Unknown error');
  }
}
```

---

## Parameter Types

| Type | Input | Example |
|------|-------|---------|
| `password` | `<input type="password">` | Enable secret |
| `text` | `<input type="text">` | ACL name |
| `textarea` | `<textarea>` | Banner text |
| `number` | `<input type="number">` | Timeout (min/max) |
| `ip` | `<input type="text" pattern="...">` | NTP server |
| `select` | `<select>` | AAA method |

### Parameter Metadata Structure

```json
{
  "STRONG_SECRET": {
    "type": "password",
    "label": "Enable Secret",
    "description": "New enable secret password",
    "required": true,
    "default": null,
    "placeholder": "MySecureSecret123!",
    "validation": "min_length:8",
    "checks": ["IOS-L1-001"]
  }
}
```

---

## Common Flows

### Fix Single Modal Steps

1. **Preview** - Show commands
2. **Parameters** - Form (if needed)
3. **Credentials** - SSH login
4. **Execute** - Progress spinner
5. **Results** - Success/error display

### Fix All Modal Steps

1. **Summary** - Selected checks
2. **Parameters** - Aggregated form
3. **Credentials** - SSH login
4. **Execute** - Batch progress
5. **Results** - Individual results

### Auto-Harden Modal Steps

1. **Preview** - Defaults + skipped
2. **Credentials** - SSH login only
3. **Execute** - Progress
4. **Results** - Summary

---

## Key Components

```
<FixSingleModal check={...} deviceType="cisco" onClose={...} />
<FixAllModal deviceType="cisco" onClose={...} />
<AutoHardenModal deviceType="cisco" onClose={...} />
<ConfigurationForm parameters={...} values={...} onChange={...} />
<SSHCredentialsForm values={...} onChange={...} deviceType="cisco" />
<SSHErrorModal error={...} onClose={...} onRetry={...} />
```

---

## Response Examples

### Success

```json
{
  "action_id": 456,
  "status": "success",
  "verification_passed": true,
  "backup_created": true,
  "commands_executed": [...],
  "error_message": null
}
```

### Auth Error (401)

```json
{
  "detail": {
    "error_type": "authentication_error",
    "message": "Authentication failed for 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": ["Verify credentials", ...],
    "original_error": "..."
  }
}
```

### Timeout Error (504)

```json
{
  "detail": {
    "error_type": "timeout_error",
    "message": "Connection timed out to 192.168.1.1",
    "device_ip": "192.168.1.1",
    "suggestions": ["Check device is online", ...],
    "original_error": "..."
  }
}
```

---

## Testing Checklist

- [ ] Fix single check with required params
- [ ] Fix single check with defaults
- [ ] Batch execution with multiple checks
- [ ] Auto-hardening preview and execute
- [ ] FortiGate with VDOM
- [ ] Authentication error (401)
- [ ] Connection timeout (504)
- [ ] Network error (503)
- [ ] Missing required parameter
- [ ] Very long banner text
- [ ] Special characters in password
- [ ] Verification failure handling

---

## Best Practices

✅ **DO**:
- Show loading states during execution
- Display structured error messages with suggestions
- Validate forms before submission
- Pre-fill default values
- Clear sensitive data after use
- Show verification status clearly

❌ **DON'T**:
- Log SSH passwords
- Show raw error messages
- Allow submission with missing required params
- Hide network errors
- Retry automatically without user consent
- Store credentials in state longer than needed

---

## Need Help?

- Full guide: `FRONTEND_HARDENING_GUIDE.md`
- Backend team for API questions
- Parameter metadata: `app/modules/hardening/cisco_parameter_metadata.py`
- SSH errors: `app/core/ssh_exceptions.py`

---

**Quick Start**: Read sections 1-6 of the full guide for implementation details.
