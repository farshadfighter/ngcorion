"""Pydantic schemas for the CVE API."""
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class CveFinding(BaseModel):
    asset_id: int
    asset_name: Optional[str] = None
    asset_icon: Optional[str] = None
    ip_address: Optional[str] = None
    product: str
    vendor: str
    product_key: str
    installed: Optional[str] = None
    identity_source: str
    fixed_in: Optional[str] = None
    cve_id: str
    description: str
    severity: Optional[str] = None
    cvss: Optional[float] = None
    cvss_version: Optional[str] = None
    kev: bool = False
    kev_due: Optional[date] = None
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    published: Optional[datetime] = None
    priority: int
    # nvd: a version range in NVD; advisory: the distribution's own advisory
    source: str = "nvd"
    advisories: List[str] = []
    package: Optional[str] = None
    binaries: List[str] = []
    availability: Optional[str] = None       # standard | pro (Ubuntu Pro only)
    release: Optional[str] = None
    reboot: bool = False                     # the fix is installed, the running kernel is older


class AssetProduct(BaseModel):
    vendor: str
    product: str
    version: Optional[str] = None
    label: str
    source: str
    software_id: Optional[int] = None


class AssetFindings(BaseModel):
    asset_id: int
    asset_name: Optional[str] = None
    asset_icon: Optional[str] = None
    ip_address: Optional[str] = None
    findings: int
    products: List[AssetProduct]
    platform: Optional[str] = None
    advisory_status: Optional[str] = None
    reboot_required: bool = False


class FindingsSummary(BaseModel):
    total: int
    fix_now: int
    affected_assets: int
    critical: int
    high: int
    medium: int
    low: int
    from_advisories: int = 0
    from_nvd: int = 0
    reboot_assets: int = 0


class FindingsResponse(BaseModel):
    summary: FindingsSummary
    findings: List[CveFinding]
    assets: List[AssetFindings]
    database_loaded: bool
    advisories_loaded: bool = False


class CveEntryDetail(BaseModel):
    cve_id: str
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    status: Optional[str] = None
    description: str
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    references: List[str] = []
    kev: bool = False
    kev_added: Optional[date] = None
    kev_due: Optional[date] = None
    kev_ransomware: Optional[str] = None
    kev_action: Optional[str] = None
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    products: List[Dict[str, Any]] = []

    model_config = {"from_attributes": True}


class ProductSuggestion(BaseModel):
    vendor: str
    product: str
    cves: int


class SoftwareCreate(BaseModel):
    vendor: str = Field(..., min_length=1, max_length=120)
    product: str = Field(..., min_length=1, max_length=160)
    version: str = Field(..., min_length=1, max_length=80)

    @field_validator("vendor", "product", "version")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        if any(c in v for c in ":*?\n\r\t"):
            raise ValueError("must not contain ':', '*', '?' or control characters")
        return v

    @field_validator("vendor", "product")
    @classmethod
    def _cpe_name(cls, v: str) -> str:
        # CPE names are lower case with underscores (e.g. "http_server").
        return v.lower().replace(" ", "_")


class SoftwareOut(BaseModel):
    id: int
    asset_id: int
    vendor: str
    product: str
    version: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class JobOut(BaseModel):
    id: int
    kind: str
    trigger: str
    status: str
    progress: Optional[Dict[str, Any]] = None
    stats: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    file_name: Optional[str] = None
    requested_by: Optional[int] = None
    requested_by_name: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AutoUpdate(BaseModel):
    enabled: bool
    time: str


class DbStatus(BaseModel):
    loaded: bool
    cves: int
    with_cpe: int
    kev: int
    epss: int
    watermark: Optional[datetime] = None
    kev_released: Optional[str] = None
    epss_date: Optional[str] = None
    size_bytes: int
    api_key_configured: bool
    auto_update: AutoUpdate
    bundle_available: bool
    active_job: Optional[JobOut] = None
    last_job: Optional[JobOut] = None
    sources: Dict[str, str]
    is_admin: bool


class DbSettingsUpdate(BaseModel):
    nvd_api_key: Optional[str] = Field(None, max_length=64)
    clear_api_key: bool = False
    auto_update_enabled: Optional[bool] = None
    auto_update_time: Optional[str] = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")


class ConnectionCheck(BaseModel):
    name: str
    ok: bool
    detail: str


class ConnectionResult(BaseModel):
    ok: bool
    checks: List[ConnectionCheck]


class UpdateRequest(BaseModel):
    full: bool = False


class ExportRequest(BaseModel):
    kind: str = Field("delta", pattern="^(full|delta)$")
    since: Optional[datetime] = None


class PackageCheck(BaseModel):
    name: str
    status: str
    detail: str


class PackageVerified(BaseModel):
    token: Optional[str] = None
    file_name: str
    size: int
    importable: bool
    signer: Optional[str] = None
    manifest: Optional[Dict[str, Any]] = None
    checks: List[PackageCheck]


class TrustedKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    public_key: str = Field(..., min_length=40, max_length=100)


class TrustedKeyOut(BaseModel):
    id: Optional[int] = None
    name: str
    public_key: str
    fingerprint: str
    builtin: bool
