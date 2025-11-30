"""
Enums Router - Returns enum values for dropdowns
"""
from fastapi import APIRouter, Depends
from app.core.dependencies import get_current_user
from app.models.enums import (
    StatusEnum,
    ConfidentialityLevelEnum,
    RiskLevelEnum,
    RelationTypeEnum
)

enums_router = APIRouter(prefix="/api/enums", tags=["Enums"])


@enums_router.get("/status")
def get_status_values(current_user=Depends(get_current_user)):
    """Get status enum values"""
    return [{"value": e.value, "label": e.value.title()} for e in StatusEnum]


@enums_router.get("/confidentiality")
def get_confidentiality_values(current_user=Depends(get_current_user)):
    """Get confidentiality level values"""
    return [{"value": e.value, "label": e.value.title()} for e in ConfidentialityLevelEnum]


@enums_router.get("/risk")
def get_risk_values(current_user=Depends(get_current_user)):
    """Get risk level values"""
    return [{"value": e.value, "label": e.value.title()} for e in RiskLevelEnum]


@enums_router.get("/relation-types")
def get_relation_types(current_user=Depends(get_current_user)):
    """Get relation type values"""
    return [{"value": e.value, "label": e.value.replace("_", " ").title()} for e in RelationTypeEnum]


@enums_router.get("/all")
def get_all_enums(current_user=Depends(get_current_user)):
    """Get all enum values at once"""
    return {
        "status": [{"value": e.value, "label": e.value.title()} for e in StatusEnum],
        "confidentiality": [{"value": e.value, "label": e.value.title()} for e in ConfidentialityLevelEnum],
        "risk": [{"value": e.value, "label": e.value.title()} for e in RiskLevelEnum],
        "relation_types": [{"value": e.value, "label": e.value.replace("_", " ").title()} for e in RelationTypeEnum]
    }