"""
Example: How to Fix Quota Consumption for Audit/Hardening Endpoints

This file shows the BEFORE and AFTER for fixing quota consumption.
"""

# ============================================================================
# BEFORE (WRONG - Quota consumed even if operation fails)
# ============================================================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.dependencies import get_current_user, require_permission, require_quota

router = APIRouter(prefix="/api/audit/cisco", tags=["Audit - Cisco CIS"])

@router.post("/execute")
def execute_cisco_audit_BEFORE(
    request: CiscoAuditRequest,
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(require_quota("audit"))  # ❌ WRONG: Consumes BEFORE operation
):
    """
    PROBLEM: require_quota() runs as a dependency BEFORE the function body.
    If the audit fails (SSH error, device unreachable, etc.), the quota is already consumed.
    """
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        # Perform the audit
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
        
        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary"
            )

        # Log success
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="cisco_cis",
            target_id=request.asset_id,
            ip_address=session.target_ip,
            result="success",
            detail=f"Asset: {asset_name}, Session: {session.id}, Profile: {request.profile}"
        )

        return summary

    except ValueError as e:
        # ❌ PROBLEM: Quota already consumed even though audit failed
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

    except Exception as e:
        # ❌ PROBLEM: Quota already consumed even though audit failed
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
        raise HTTPException(status_code=500, detail=f"Audit execution failed: {str(e)}")


# ============================================================================
# AFTER (CORRECT - Quota consumed only on success)
# ============================================================================

from fastapi import APIRouter, Depends, HTTPException, status, Request  # ✅ Add Request
from sqlalchemy.orm import Session
from app.core.dependencies import (
    get_current_user, 
    require_permission, 
    check_quota_available,      # ✅ New: Check only
    consume_quota_on_success    # ✅ New: Consume after success
)

router = APIRouter(prefix="/api/audit/cisco", tags=["Audit - Cisco CIS"])

@router.post("/execute", dependencies=[Depends(check_quota_available("audit"))])  # ✅ Check only
def execute_cisco_audit_AFTER(
    audit_request: CiscoAuditRequest,  # ✅ Renamed to avoid conflict with Request
    request: Request,                   # ✅ Added Request parameter
    current_user: User = Depends(require_permission("AUDIT", "write")),
    db: Session = Depends(get_db)
    # ✅ Removed: _quota_check: None = Depends(require_quota("audit"))
):
    """
    SOLUTION: 
    1. check_quota_available() only checks if quota is available (doesn't consume)
    2. consume_quota_on_success() returns a function to consume quota
    3. We call that function ONLY after successful audit
    4. If audit fails, quota is NOT consumed
    """
    # ✅ Get the consume function (doesn't consume yet)
    consume_quota = consume_quota_on_success("audit")
    
    from app.models import Asset
    asset = db.query(Asset).filter(Asset.id == audit_request.asset_id).first()
    asset_name = asset.asset_name if asset else None
    target_ip = asset.ip_address if asset else None

    try:
        # Perform the audit
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
        
        if not summary:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve audit summary"
            )

        # Log success
        log_action(
            db=db,
            user_id=current_user.id,
            action="audit_executed",
            module="cisco_cis",
            target_id=audit_request.asset_id,
            ip_address=session.target_ip,
            result="success",
            detail=f"Asset: {asset_name}, Session: {session.id}, Profile: {audit_request.profile}"
        )

        # ✅ ONLY consume quota after successful audit
        consume_quota(request)

        return summary

    except ValueError as e:
        # ✅ SOLUTION: Quota NOT consumed because consume_quota() was never called
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
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        # ✅ SOLUTION: Quota NOT consumed because consume_quota() was never called
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
        raise HTTPException(status_code=500, detail=f"Audit execution failed: {str(e)}")


# ============================================================================
# SUMMARY OF CHANGES
# ============================================================================

"""
1. IMPORTS:
   - Add: from fastapi import Request
   - Add: from app.core.dependencies import check_quota_available, consume_quota_on_success
   - Remove: require_quota (no longer used)

2. DECORATOR:
   - Add: dependencies=[Depends(check_quota_available("audit"))]

3. FUNCTION SIGNATURE:
   - Rename: request → audit_request (to avoid conflict)
   - Add: request: Request (new parameter)
   - Remove: _quota_check: None = Depends(require_quota("audit"))

4. FUNCTION BODY:
   - Add at start: consume_quota = consume_quota_on_success("audit")
   - Add after success: consume_quota(request)
   - Update all references: request.field → audit_request.field

5. ERROR HANDLERS:
   - No changes needed (quota automatically NOT consumed)
   - Can add comment: # Quota NOT consumed on failure
"""


# ============================================================================
# TESTING
# ============================================================================

"""
Test Case 1: Audit Fails - Quota Should NOT Be Consumed
--------------------------------------------------------
1. Check quota: GET /api/license/status → used_audits = 5
2. Run audit with wrong password (will fail)
3. Audit fails with error
4. Check quota: GET /api/license/status → used_audits = 5 (unchanged) ✅

Test Case 2: Audit Succeeds - Quota Should Be Consumed
-------------------------------------------------------
1. Check quota: GET /api/license/status → used_audits = 5
2. Run audit with correct credentials (will succeed)
3. Audit succeeds
4. Check quota: GET /api/license/status → used_audits = 6 (incremented) ✅

Test Case 3: Quota Exhausted - Should Fail Before Attempting
-------------------------------------------------------------
1. Use pilot license (2 audits max)
2. Run 2 successful audits
3. Try 3rd audit → Should fail immediately with "Audit quota exhausted (2/2)"
4. Should NOT attempt SSH connection ✅
"""
