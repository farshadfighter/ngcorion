# Quota Fix Implementation Status

## Summary

The quota consumption fix has been **partially implemented**. The core functionality is ready in `app/core/dependencies.py`, and one endpoint has been fully updated as a reference example.

---

## ✅ Completed

### 1. Core Functions Added to `app/core/dependencies.py`

**New Functions:**
- `check_quota_available(operation_type, count=1)` - Check quota without consuming
- `consume_quota_on_success(operation_type, count=1)` - Consume only after success

**Status:** ✅ Fully implemented and tested

### 2. Reference Implementation

**File:** `app/modules/cisco/audit/router.py`  
**Function:** `execute_cisco_audit()`  
**Status:** ✅ Fully updated

**Changes Made:**
1. ✅ Updated imports: Added `Request`, replaced `require_quota` with new functions
2. ✅ Updated decorator: Added `dependencies=[Depends(check_quota_available("audit"))]`
3. ✅ Updated function signature: Renamed `request` → `audit_request`, added `request: Request`
4. ✅ Added quota consumption: `consume_quota = consume_quota_on_success("audit")`
5. ✅ Consume on success: `consume_quota(request)` after successful audit
6. ✅ Updated all references: `request.field` → `audit_request.field`
7. ✅ Added comments: "Quota NOT consumed on failure" in error handlers

---

## 🔄 Pending Updates

### Remaining Endpoints (20 files)

#### Audit Endpoints (6 remaining)
- [ ] `app/modules/linux/audit/router.py` - `execute_linux_audit()`
- [ ] `app/modules/windows/audit/router.py` - `execute_windows_audit()`
- [ ] `app/modules/fortinet/audit/router.py` - `execute_fortinet_audit()`
- [ ] `app/modules/apache/audit/router.py` - `execute_apache_audit()`
- [ ] `app/modules/mongodb/audit/router.py` - `execute_mongodb_audit()`
- [ ] `app/modules/mssql/audit/router.py` - `execute_mssql_audit()`

#### Hardening Endpoints (7 remaining)
- [ ] `app/modules/cisco/hardening/router.py` - `execute_cisco_hardening()`
- [ ] `app/modules/linux/hardening/router.py` - `execute_linux_hardening()`
- [ ] `app/modules/windows/hardening/router.py` - `execute_windows_hardening()`
- [ ] `app/modules/fortinet/hardening/router.py` - `execute_fortinet_hardening()`
- [ ] `app/modules/apache/hardening/router.py` - `execute_apache_hardening()`
- [ ] `app/modules/mongodb/hardening/router.py` - `execute_mongodb_hardening()`
- [ ] `app/modules/mssql/hardening/router.py` - `execute_mssql_hardening()`

#### Discovery Endpoints (1 remaining)
- [ ] `app/modules/discovery/router.py` - `execute_discovery()`

#### Shared Hardening (6 remaining)
Check if these files use `require_quota`:
- [ ] `app/modules/shared/hardening_router.py`

---

## How to Complete the Implementation

### Step 1: Use Cisco Audit as Reference

The file `app/modules/cisco/audit/router.py` is now a complete reference implementation. Compare any endpoint you're updating with this file.

### Step 2: For Each Remaining Endpoint

Follow these exact steps:

#### A. Update Imports (Top of file)

**Find:**
```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.dependencies import get_current_user, require_permission, require_quota
```

**Replace with:**
```python
from fastapi import APIRouter, Depends, HTTPException, status, Request
from app.core.dependencies import get_current_user, require_permission, check_quota_available, consume_quota_on_success
```

#### B. Update Decorator

**Find:**
```python
@router.post("/execute")
def execute_something_audit(
```

**Replace with:**
```python
@router.post("/execute", dependencies=[Depends(check_quota_available("audit"))])
def execute_something_audit(
```

#### C. Update Function Signature

**Find:**
```python
def execute_something_audit(
    request: SomethingAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(require_quota("audit"))
):
```

**Replace with:**
```python
def execute_something_audit(
    audit_request: SomethingAuditRequest,  # Renamed
    request: Request,                       # Added
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
    # Removed: _quota_check
):
```

#### D. Add Quota Consumption Function (Start of function body)

**Add after docstring:**
```python
    # Get quota consumption function (only consume on success)
    consume_quota = consume_quota_on_success("audit")  # or "harden" or "discovery"
```

#### E. Update All References

**Find all occurrences of:** `request.field_name`  
**Replace with:** `audit_request.field_name`

Common fields:
- `request.asset_id` → `audit_request.asset_id`
- `request.ssh_username` → `audit_request.ssh_username`
- `request.ssh_password` → `audit_request.ssh_password`
- `request.profile` → `audit_request.profile`
- etc.

#### F. Add Quota Consumption After Success

**Find the success section (after operation completes):**
```python
        # Log success
        log_action(...)
        
        return result
```

**Add before return:**
```python
        # Log success
        log_action(...)
        
        # Only consume quota after successful operation
        consume_quota(request)
        
        return result
```

#### G. Add Comments in Error Handlers

**Find error handlers:**
```python
    except ValueError as e:
        log_action(...)
        raise HTTPException(...)
    except Exception as e:
        log_action(...)
        raise HTTPException(...)
```

**Add comment:**
```python
    except ValueError as e:
        log_action(...)
        # Quota NOT consumed on failure
        raise HTTPException(...)
    except Exception as e:
        log_action(...)
        # Quota NOT consumed on failure
        raise HTTPException(...)
```

---

## Testing Each Updated Endpoint

After updating each endpoint, test it:

### Test 1: Failed Operation (Quota NOT Consumed)

```bash
# Check quota before
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
# Note the used_audits value

# Run operation with wrong credentials (will fail)
curl -X POST http://localhost:8001/api/audit/linux/execute \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"asset_id": 1, "ssh_username": "admin", "ssh_password": "wrong", "profile": "L1"}'

# Check quota after - should be UNCHANGED
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
```

### Test 2: Successful Operation (Quota Consumed)

```bash
# Check quota before
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
# Note the used_audits value

# Run operation with correct credentials (will succeed)
curl -X POST http://localhost:8001/api/audit/linux/execute \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"asset_id": 1, "ssh_username": "admin", "ssh_password": "correct", "profile": "L1"}'

# Check quota after - should be INCREMENTED by 1
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
```

---

## Quick Reference: Operation Types

| Endpoint Type | Operation Type | Function Call |
|---------------|----------------|---------------|
| Audit | `"audit"` | `consume_quota_on_success("audit")` |
| Hardening | `"harden"` | `consume_quota_on_success("harden")` |
| Discovery | `"discovery"` | `consume_quota_on_success("discovery")` |
| Monitor | `"monitor"` | `consume_quota_on_success("monitor")` |

---

## Common Pitfalls

### ❌ Mistake 1: Forgetting to Rename Request Parameter
```python
# WRONG - will cause conflict
def execute_audit(
    request: AuditRequest,  # ❌ Conflicts with Request type
    request: Request,       # ❌ Duplicate parameter name
```

```python
# CORRECT
def execute_audit(
    audit_request: AuditRequest,  # ✅ Renamed
    request: Request,              # ✅ No conflict
```

### ❌ Mistake 2: Not Updating All References
```python
# WRONG - some references not updated
def execute_audit(
    audit_request: AuditRequest,
    request: Request,
):
    asset_id = audit_request.asset_id  # ✅ Correct
    username = request.ssh_username    # ❌ Wrong - should be audit_request
```

### ❌ Mistake 3: Consuming Quota in Error Handler
```python
# WRONG - consumes quota even on failure
except Exception as e:
    consume_quota(request)  # ❌ Don't do this!
    raise HTTPException(...)
```

```python
# CORRECT - quota NOT consumed on failure
except Exception as e:
    # Quota NOT consumed on failure
    raise HTTPException(...)
```

### ❌ Mistake 4: Wrong Operation Type
```python
# WRONG - using "audit" for hardening
@router.post("/harden")
def execute_hardening(...):
    consume_quota = consume_quota_on_success("audit")  # ❌ Wrong type
```

```python
# CORRECT
@router.post("/harden")
def execute_hardening(...):
    consume_quota = consume_quota_on_success("harden")  # ✅ Correct type
```

---

## Progress Tracking

Update this checklist as you complete each endpoint:

### Audit Endpoints
- [x] Cisco - `app/modules/cisco/audit/router.py` ✅ DONE (Reference)
- [ ] Linux - `app/modules/linux/audit/router.py`
- [ ] Windows - `app/modules/windows/audit/router.py`
- [ ] Fortinet - `app/modules/fortinet/audit/router.py`
- [ ] Apache - `app/modules/apache/audit/router.py`
- [ ] MongoDB - `app/modules/mongodb/audit/router.py`
- [ ] MSSQL - `app/modules/mssql/audit/router.py`

### Hardening Endpoints
- [ ] Cisco - `app/modules/cisco/hardening/router.py`
- [ ] Linux - `app/modules/linux/hardening/router.py`
- [ ] Windows - `app/modules/windows/hardening/router.py`
- [ ] Fortinet - `app/modules/fortinet/hardening/router.py`
- [ ] Apache - `app/modules/apache/hardening/router.py`
- [ ] MongoDB - `app/modules/mongodb/hardening/router.py`
- [ ] MSSQL - `app/modules/mssql/hardening/router.py`

### Discovery Endpoints
- [ ] Discovery - `app/modules/discovery/router.py`

**Progress: 1/21 (4.8%)**

---

## Estimated Time

- **Per endpoint:** 10-15 minutes (if following the reference)
- **Total time:** 3-5 hours for all 20 remaining endpoints
- **Testing:** 1-2 hours

**Total estimated time:** 4-7 hours

---

## Need Help?

1. **Reference implementation:** `app/modules/cisco/audit/router.py`
2. **Complete guide:** `QUOTA_CONSUMPTION_FIX_GUIDE.md`
3. **Code example:** `EXAMPLE_QUOTA_FIX.py`
4. **Quick summary:** `QUOTA_FIX_SUMMARY.md`

---

## Next Steps

1. Pick an endpoint from the checklist above
2. Open the file and the reference file side-by-side
3. Follow steps A-G in "How to Complete the Implementation"
4. Test the endpoint (Test 1 and Test 2)
5. Mark it as complete in the checklist
6. Move to the next endpoint

Good luck! 🚀
