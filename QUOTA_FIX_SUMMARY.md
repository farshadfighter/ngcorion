# Quota Consumption Fix - Summary

## Problem Identified

Currently, license quota is consumed **before** operations run. If an audit or hardening operation fails (SSH error, device unreachable, etc.), the quota is already consumed and cannot be refunded.

**Impact:**
- Users lose quota on failed operations
- Unfair usage tracking
- Poor user experience

---

## Solution Implemented

I've added two new functions to `app/core/dependencies.py`:

### 1. `check_quota_available(operation_type, count=1)`
- **Purpose:** Check if quota is available WITHOUT consuming it
- **Use:** As a FastAPI dependency in the decorator
- **Behavior:** Raises 403 if quota exhausted, otherwise allows request to proceed

### 2. `consume_quota_on_success(operation_type, count=1)`
- **Purpose:** Returns a function to consume quota AFTER successful operation
- **Use:** Call inside the endpoint function after operation succeeds
- **Behavior:** Consumes quota only when explicitly called

---

## How to Update Endpoints

### Quick Reference

**Before:**
```python
from app.core.dependencies import require_quota

@router.post("/execute")
def execute_audit(
    request: AuditRequest,
    _quota_check: None = Depends(require_quota("audit"))  # ❌ Wrong
):
    result = perform_audit(...)
    return result
```

**After:**
```python
from fastapi import Request
from app.core.dependencies import check_quota_available, consume_quota_on_success

@router.post("/execute", dependencies=[Depends(check_quota_available("audit"))])
def execute_audit(
    audit_request: AuditRequest,  # Renamed
    request: Request,              # Added
):
    consume_quota = consume_quota_on_success("audit")
    
    try:
        result = perform_audit(...)
        consume_quota(request)  # ✅ Only consume on success
        return result
    except Exception:
        raise  # Quota NOT consumed
```

---

## Files That Need Updates

### High Priority (Operations that can fail)

**Audit Endpoints:**
1. `app/modules/cisco/audit/router.py` - Line ~89
2. `app/modules/fortinet/audit/router.py`
3. `app/modules/linux/audit/router.py` - Line ~118
4. `app/modules/apache/audit/router.py`
5. `app/modules/mongodb/audit/router.py` - Line ~111
6. `app/modules/mssql/audit/router.py`
7. `app/modules/windows/audit/router.py` - Line ~120

**Hardening Endpoints:**
1. `app/modules/cisco/hardening/router.py` - Line ~579
2. `app/modules/fortinet/hardening/router.py`
3. `app/modules/linux/hardening/router.py` - Line ~204
4. `app/modules/apache/hardening/router.py`
5. `app/modules/mongodb/hardening/router.py` - Line ~190
6. `app/modules/mssql/hardening/router.py`
7. `app/modules/windows/hardening/router.py` - Line ~215

**Discovery Endpoints:**
1. `app/modules/discovery/router.py` - Line ~89

### No Changes Needed

**Asset Creation:**
- Uses `require_asset_quota()` which only checks limits
- Assets are counted, not consumed
- Current implementation is correct

---

## Documentation Created

1. **QUOTA_CONSUMPTION_FIX_GUIDE.md** - Complete migration guide with examples
2. **EXAMPLE_QUOTA_FIX.py** - Side-by-side before/after code comparison
3. **QUOTA_FIX_SUMMARY.md** - This file (quick reference)

---

## Testing Instructions

### Test 1: Failed Operation Should NOT Consume Quota
```bash
# Check current quota
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
# Note: used_audits = 5

# Run audit with wrong credentials (will fail)
curl -X POST http://localhost:8001/api/audit/cisco/execute \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"asset_id": 1, "ssh_username": "admin", "ssh_password": "wrong", "profile": "L1"}'
# Should return error

# Check quota again
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
# Should still show: used_audits = 5 (unchanged) ✅
```

### Test 2: Successful Operation Should Consume Quota
```bash
# Check current quota
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
# Note: used_audits = 5

# Run audit with correct credentials (will succeed)
curl -X POST http://localhost:8001/api/audit/cisco/execute \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"asset_id": 1, "ssh_username": "admin", "ssh_password": "correct", "profile": "L1"}'
# Should return success

# Check quota again
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/license/status
# Should show: used_audits = 6 (incremented) ✅
```

---

## Migration Steps

1. **Read the guide:** `QUOTA_CONSUMPTION_FIX_GUIDE.md`
2. **See example:** `EXAMPLE_QUOTA_FIX.py`
3. **Update endpoints:** Follow the pattern in the example
4. **Test each endpoint:** Verify quota behavior with failing and successful operations
5. **Update frontend:** No changes needed (API behavior is the same)

---

## Benefits

✅ **Fair usage tracking** - Only successful operations consume quota  
✅ **Better user experience** - Users not penalized for connection errors  
✅ **Accurate billing** - Quota reflects actual work performed  
✅ **Backward compatible** - Old `require_quota()` still works for operations that always succeed  

---

## Next Steps

1. Review the documentation files
2. Update audit endpoints (highest priority)
3. Update hardening endpoints
4. Update discovery endpoints
5. Test thoroughly with pilot license (low quotas make testing easier)
6. Deploy to production

---

## Questions?

- See `QUOTA_CONSUMPTION_FIX_GUIDE.md` for detailed implementation guide
- See `EXAMPLE_QUOTA_FIX.py` for complete before/after code example
- Check `app/core/dependencies.py` for the new function implementations
