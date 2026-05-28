# Quota Consumption Fix Guide

## Problem

Currently, the license quota is consumed **before** the operation runs (audit/hardening/discovery). If the operation fails (SSH connection error, device unreachable, etc.), the quota is already consumed and not refunded.

**Current Flow (WRONG):**
```
1. User clicks "Run Audit"
2. Quota consumed (used_audits++)
3. SSH connection fails
4. Error returned to user
5. Quota already consumed ❌
```

**Desired Flow (CORRECT):**
```
1. User clicks "Run Audit"
2. Check if quota available (don't consume yet)
3. SSH connection fails
4. Error returned to user
5. Quota NOT consumed ✅
```

---

## Solution

I've added two new functions to `app/core/dependencies.py`:

### 1. `check_quota_available(operation_type, count=1)`
- **Purpose:** Check if quota is available WITHOUT consuming it
- **Use as:** FastAPI dependency
- **When:** At the start of the endpoint (replaces `require_quota`)

### 2. `consume_quota_on_success(operation_type, count=1)`
- **Purpose:** Returns a function to consume quota AFTER success
- **Use as:** Regular function call
- **When:** After operation completes successfully

---

## How to Update Endpoints

### Before (Current - WRONG)

```python
from app.core.dependencies import require_quota

@router.post("/execute")
def execute_audit(
    request: AuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(require_quota("audit"))  # ❌ Consumes BEFORE operation
):
    try:
        # Perform audit
        result = AuditService.execute_audit(...)
        return result
    except Exception as e:
        # Quota already consumed even though audit failed ❌
        raise HTTPException(400, str(e))
```

### After (Fixed - CORRECT)

```python
from fastapi import Request
from app.core.dependencies import check_quota_available, consume_quota_on_success

@router.post("/execute", dependencies=[Depends(check_quota_available("audit"))])
def execute_audit(
    audit_request: AuditRequest,
    request: Request,  # ✅ Add Request parameter
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    # Get the consume function
    consume_quota = consume_quota_on_success("audit")
    
    try:
        # Perform audit
        result = AuditService.execute_audit(...)
        
        # ✅ Only consume quota if audit succeeded
        consume_quota(request)
        
        return result
    except Exception as e:
        # Quota NOT consumed because consume_quota() was never called ✅
        raise HTTPException(400, str(e))
```

---

## Step-by-Step Migration

### Step 1: Update Imports

**Old:**
```python
from app.core.dependencies import get_current_user, require_permission, require_quota
```

**New:**
```python
from fastapi import Request
from app.core.dependencies import get_current_user, require_permission, check_quota_available, consume_quota_on_success
```

### Step 2: Update Function Signature

**Old:**
```python
@router.post("/execute")
def execute_audit(
    request: AuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(require_quota("audit"))
):
```

**New:**
```python
@router.post("/execute", dependencies=[Depends(check_quota_available("audit"))])
def execute_audit(
    audit_request: AuditRequest,  # Rename to avoid conflict with Request
    request: Request,  # Add this
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
```

### Step 3: Add Quota Consumption After Success

**Add at the beginning of the function:**
```python
consume_quota = consume_quota_on_success("audit")
```

**Add after successful operation (before return):**
```python
# Only consume quota if operation succeeded
consume_quota(request)
```

### Step 4: Ensure Quota NOT Consumed on Failure

Make sure `consume_quota(request)` is **only** called in the success path, not in exception handlers.

---

## Complete Example: Cisco Audit

### Before (Current)

```python
@router.post("/execute", response_model=CiscoAuditSessionResponse)
def execute_cisco_audit(
    request: CiscoAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(require_quota("audit"))  # ❌ Wrong
):
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = AuditService.execute_cisco_audit(
            db=db,
            asset_id=request.asset_id,
            user_id=current_user.id,
            ssh_username=request.ssh_username,
            ssh_password=request.ssh_password,
            ssh_secret=request.ssh_secret,
            profile=request.profile,
            job_name=request.job_name
        )

        summary = AuditService.get_session_summary(db, session.id)
        
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="cisco_cis",
            target_id=request.asset_id,
            ip_address=session.target_ip,
            result="success",
            detail=f"Asset: {asset_name}, Session: {session.id}"
        )

        return summary

    except ValueError as e:
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="cisco_cis",
            target_id=request.asset_id,
            ip_address=target_ip,
            result="failed",
            detail=f"Error: {str(e)}"
        )
        raise HTTPException(status_code=400, detail=str(e))
```

### After (Fixed)

```python
from fastapi import Request
from app.core.dependencies import check_quota_available, consume_quota_on_success

@router.post("/execute", 
             response_model=CiscoAuditSessionResponse,
             dependencies=[Depends(check_quota_available("audit"))])  # ✅ Check only
def execute_cisco_audit(
    audit_request: CiscoAuditRequest,  # Renamed
    request: Request,  # ✅ Added
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
):
    # ✅ Get consume function
    consume_quota = consume_quota_on_success("audit")
    
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == audit_request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        session = AuditService.execute_cisco_audit(
            db=db,
            asset_id=audit_request.asset_id,
            user_id=current_user.id,
            ssh_username=audit_request.ssh_username,
            ssh_password=audit_request.ssh_password,
            ssh_secret=audit_request.ssh_secret,
            profile=audit_request.profile,
            job_name=audit_request.job_name
        )

        summary = AuditService.get_session_summary(db, session.id)
        
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="cisco_cis",
            target_id=audit_request.asset_id,
            ip_address=session.target_ip,
            result="success",
            detail=f"Asset: {asset_name}, Session: {session.id}"
        )

        # ✅ Only consume quota after successful audit
        consume_quota(request)

        return summary

    except ValueError as e:
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="cisco_cis",
            target_id=audit_request.asset_id,
            ip_address=target_ip,
            result="failed",
            detail=f"Error: {str(e)}"
        )
        # ✅ Quota NOT consumed because consume_quota() not called
        raise HTTPException(status_code=400, detail=str(e))
```

---

## Files That Need to Be Updated

### Audit Endpoints (Priority: HIGH)
All these consume quota but might fail:

1. `/home/sina/netease/app/modules/cisco/audit/router.py`
   - `execute_cisco_audit()` - Line ~89

2. `/home/sina/netease/app/modules/fortinet/audit/router.py`
   - `execute_fortinet_audit()`

3. `/home/sina/netease/app/modules/linux/audit/router.py`
   - `execute_linux_audit()` - Line ~118

4. `/home/sina/netease/app/modules/apache/audit/router.py`
   - `execute_apache_audit()`

5. `/home/sina/netease/app/modules/mongodb/audit/router.py`
   - `execute_mongodb_audit()` - Line ~111

6. `/home/sina/netease/app/modules/mssql/audit/router.py`
   - `execute_mssql_audit()`

7. `/home/sina/netease/app/modules/windows/audit/router.py`
   - `execute_windows_audit()` - Line ~120

### Hardening Endpoints (Priority: HIGH)
All these consume quota but might fail:

1. `/home/sina/netease/app/modules/cisco/hardening/router.py`
   - `execute_cisco_hardening()` - Line ~579

2. `/home/sina/netease/app/modules/fortinet/hardening/router.py`
   - `execute_fortinet_hardening()`

3. `/home/sina/netease/app/modules/linux/hardening/router.py`
   - `execute_linux_hardening()` - Line ~204

4. `/home/sina/netease/app/modules/apache/hardening/router.py`
   - `execute_apache_hardening()`

5. `/home/sina/netease/app/modules/mongodb/hardening/router.py`
   - `execute_mongodb_hardening()` - Line ~190

6. `/home/sina/netease/app/modules/mssql/hardening/router.py`
   - `execute_mssql_hardening()`

7. `/home/sina/netease/app/modules/windows/hardening/router.py`
   - `execute_windows_hardening()` - Line ~215

### Discovery Endpoints (Priority: HIGH)

1. `/home/sina/netease/app/modules/discovery/router.py`
   - `execute_discovery()` - Line ~89

---

## Asset Creation (Priority: LOW)

Asset creation uses `require_asset_quota()` which is different - it only **checks** the limit, doesn't consume. Assets are counted, not consumed, so this is OK to keep as-is.

**No changes needed for asset creation.**

---

## Testing the Fix

### Test Case 1: Audit Fails - Quota Should NOT Be Consumed

1. Check current quota: `GET /api/license/status`
   - Note `used_audits` value (e.g., 5)

2. Run audit with wrong credentials (will fail)
   - `POST /api/audit/cisco/execute` with invalid SSH password

3. Audit should fail with error

4. Check quota again: `GET /api/license/status`
   - `used_audits` should still be 5 (unchanged) ✅

### Test Case 2: Audit Succeeds - Quota Should Be Consumed

1. Check current quota: `GET /api/license/status`
   - Note `used_audits` value (e.g., 5)

2. Run audit with correct credentials (will succeed)
   - `POST /api/audit/cisco/execute` with valid SSH credentials

3. Audit should succeed

4. Check quota again: `GET /api/license/status`
   - `used_audits` should be 6 (incremented) ✅

### Test Case 3: Quota Exhausted - Should Fail Before Attempting

1. Use a pilot license (2 audits max)

2. Run 2 successful audits (quota exhausted)

3. Try to run 3rd audit
   - Should fail immediately with: "Audit quota exhausted (2/2)"
   - Should NOT attempt SSH connection
   - Should NOT consume quota (already at max)

---

## Migration Checklist

- [ ] Update `app/modules/cisco/audit/router.py`
- [ ] Update `app/modules/cisco/hardening/router.py`
- [ ] Update `app/modules/fortinet/audit/router.py`
- [ ] Update `app/modules/fortinet/hardening/router.py`
- [ ] Update `app/modules/linux/audit/router.py`
- [ ] Update `app/modules/linux/hardening/router.py`
- [ ] Update `app/modules/apache/audit/router.py`
- [ ] Update `app/modules/apache/hardening/router.py`
- [ ] Update `app/modules/mongodb/audit/router.py`
- [ ] Update `app/modules/mongodb/hardening/router.py`
- [ ] Update `app/modules/mssql/audit/router.py`
- [ ] Update `app/modules/mssql/hardening/router.py`
- [ ] Update `app/modules/windows/audit/router.py`
- [ ] Update `app/modules/windows/hardening/router.py`
- [ ] Update `app/modules/discovery/router.py`
- [ ] Test each endpoint with failing operation
- [ ] Test each endpoint with successful operation
- [ ] Test quota exhaustion behavior

---

## Summary

**Key Changes:**
1. Replace `Depends(require_quota("audit"))` with `dependencies=[Depends(check_quota_available("audit"))]`
2. Add `request: Request` parameter to function
3. Rename first parameter if it's named `request` (e.g., `audit_request`)
4. Add `consume_quota = consume_quota_on_success("audit")` at start
5. Call `consume_quota(request)` only after successful operation

**Benefits:**
- ✅ Quota only consumed on success
- ✅ Failed operations don't waste quota
- ✅ Users not penalized for connection errors
- ✅ Fair usage tracking

**Backward Compatibility:**
- Old `require_quota()` still works (for operations that always succeed)
- New functions are additions, not replacements
- Can migrate endpoints one at a time
