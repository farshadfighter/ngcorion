"""Pydantic schemas for the CVE API."""
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ActionLink(BaseModel):
    """A page to read: the vendor's or the distribution's advisory."""
    url: str
    label: str


class EolNote(BaseModel):
    """The operating system or firmware past its end of life."""
    title: str
    until: Optional[str] = None
    latest: Optional[str] = None


class RecommendedAction(BaseModel):
    """What to do about a finding (app/modules/cve/recommend.py)."""
    # package | reboot | windows | version | after | advisory
    kind: str
    text: str
    product: Optional[str] = None
    target: Optional[str] = None
    pro: bool = False                        # the fix is in Ubuntu Pro (ESM) only
    commands: List[str] = []
    link: Optional[ActionLink] = None
    check_vendor: bool = False               # a version from NVD's ranges: check the vendor's advisory
    kev_action: Optional[str] = None         # CISA's required action, for a CVE known to be exploited
    kev_due: Optional[date] = None
    eol: Optional[EolNote] = None


class PlanStep(BaseModel):
    """One step of an asset's upgrade plan and the findings it closes."""
    asset_id: int
    asset_name: Optional[str] = None
    kind: str
    text: Optional[str] = None
    product: Optional[str] = None
    target: Optional[str] = None
    pro: bool = False
    commands: List[str] = []
    link: Optional[ActionLink] = None
    check_vendor: bool = False
    eol: Optional[EolNote] = None
    findings: int
    critical: int = 0
    kev: bool = False
    priority: int
    cves: List[str]


class CveFinding(BaseModel):
    """One CVE affecting one product of one asset, with its scores, priority and fix version."""
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
    action: Optional[RecommendedAction] = None


class AssetProduct(BaseModel):
    """A product an asset is matched on and where it came from."""
    vendor: str
    product: str
    version: Optional[str] = None
    label: str
    source: str
    software_id: Optional[int] = None


class AssetFindings(BaseModel):
    """An asset's finding count and products, for the by-asset view."""
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
    """Counts at the top of the CVE page."""
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
    """The CVE page's data: summary, findings, assets, and whether the databases are loaded."""
    summary: FindingsSummary
    findings: List[CveFinding]
    assets: List[AssetFindings]
    plan: Dict[int, List[PlanStep]] = {}     # per asset: what to do, and what each step closes
    database_loaded: bool
    advisories_loaded: bool = False


class CveEntryDetail(BaseModel):
    """One CVE as the detail drawer shows it."""
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
    """A vendor/product known to the CVE database, suggested while typing."""
    vendor: str
    product: str
    cves: int


class SoftwareCreate(BaseModel):
    """Body of adding a product to an asset. Values are trimmed and may not contain CPE separators
    or wildcards (':', '*', '?'); vendor and product are normalised like CPE names.
    """
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
    """A manually added product of an asset."""
    id: int
    asset_id: int
    vendor: str
    product: str
    version: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class JobOut(BaseModel):
    """A database job: kind, trigger, status, progress and statistics."""
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
    """Automatic update setting: on/off and the daily time."""
    enabled: bool
    time: str


class DbStatus(BaseModel):
    """State of the CVE database for the database page."""
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
    """Body of the database settings: NVD API key and automatic update."""
    nvd_api_key: Optional[str] = Field(None, max_length=64)
    clear_api_key: bool = False
    auto_update_enabled: Optional[bool] = None
    auto_update_time: Optional[str] = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")


class ConnectionCheck(BaseModel):
    """Reachability of one feed."""
    name: str
    ok: bool
    detail: str


class ConnectionResult(BaseModel):
    """Reachability of every feed."""
    ok: bool
    checks: List[ConnectionCheck]


class UpdateRequest(BaseModel):
    """Body of an online update: full or incremental."""
    full: bool = False


class ExportRequest(BaseModel):
    """Body of an export: full package, or the changes since a date."""
    kind: str = Field("delta", pattern="^(full|delta)$")
    since: Optional[datetime] = None


class PackageCheck(BaseModel):
    """One verification check of an uploaded package."""
    name: str
    status: str
    detail: str


class PackageVerified(BaseModel):
    """An uploaded package's verification result and the token to import it with."""
    token: Optional[str] = None
    file_name: str
    size: int
    importable: bool
    signer: Optional[str] = None
    manifest: Optional[Dict[str, Any]] = None
    checks: List[PackageCheck]


class TrustedKeyCreate(BaseModel):
    """Body of trusting a public key: a name and the base64 Ed25519 key."""
    name: str = Field(..., min_length=1, max_length=120)
    public_key: str = Field(..., min_length=40, max_length=100)


class TrustedKeyOut(BaseModel):
    """A trusted public key (built-in release key or added by an admin)."""
    id: Optional[int] = None
    name: str
    public_key: str
    fingerprint: str
    builtin: bool
