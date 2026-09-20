"""
NVD Sync

Fetches CVE records from the NVD REST API v2.0 (services.nvd.nist.gov) for a
given product keyword and upserts them into CveRecord rows.

Split into a pure parser (parse_nvd_response) and a network-calling function
(fetch_nvd_cves) so the parser can be unit-tested against a captured sample
response with no live network access required - the NVD API is not always
reachable from every deployment network (see the module docstring in
app/models/cve.py), so this is a manually-triggered admin action, never an
automatic background job like NOC's poller.
"""
import logging
from datetime import datetime
from typing import Optional

import requests
from sqlalchemy.orm import Session

from app.models.cve import CveRecord

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Product keywords are matched as a case-insensitive substring against
# Asset.os_name (see matcher.asset_matches_cve), so each keyword here is kept
# distinctive enough not to collide with another tracked product - e.g.
# "cisco ios" rather than bare "ios", which would also match "FortiOS".
# Covers the vendors/technologies this app already has audit/hardening
# modules for, so "Sync all" is useful platform-wide, not just for Fortinet.
TRACKED_PRODUCTS = [
    ("Cisco", "Cisco IOS", "cisco ios"),
    ("Fortinet", "FortiOS", "fortios"),
    ("Apache Software Foundation", "Apache HTTP Server", "apache"),
    ("MongoDB Inc.", "MongoDB Server", "mongodb"),
    ("Microsoft", "SQL Server", "sql server"),
    ("Microsoft", "Windows Server", "windows server"),
    ("Linux", "Linux Kernel", "linux"),
]


def _english_description(cve_data: dict) -> str:
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _severity_and_score(cve_data: dict) -> tuple[Optional[str], Optional[float]]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            if severity:
                severity = severity.lower()
            return severity, score
    return None, None


def _reference_url(cve_data: dict) -> Optional[str]:
    refs = cve_data.get("references", [])
    return refs[0]["url"] if refs and "url" in refs[0] else None


def _published_date(cve_data: dict) -> Optional[datetime]:
    raw = cve_data.get("published")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _version_bounds(cpe_match: dict) -> tuple[Optional[str], Optional[str]]:
    """NVD carries inclusive/exclusive bounds separately; this app's matcher
    only supports inclusive bounds (app/modules/cve/matcher.py), so the
    *Excluding fields are used as-is - a documented approximation that can be
    off by one version right at a range boundary."""
    min_v = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
    max_v = cpe_match.get("versionEndExcluding") or cpe_match.get("versionEndIncluding")
    return min_v, max_v


def parse_nvd_response(payload: dict, product_keyword: str, vendor: str, product: str) -> list[dict]:
    """Pure parse: NVD API v2.0 JSON -> a list of CveRecord-shaped dicts, one
    per affected version branch (mirrors the seed data's one-row-per-branch
    design - see app/models/cve.py). Entries with no version-range data are
    skipped: an unbounded range would match every installed version of the
    product, which is worse than not reporting that CVE at all."""
    records: list[dict] = []
    for entry in payload.get("vulnerabilities", []):
        cve_data = entry.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            continue

        severity, cvss_score = _severity_and_score(cve_data)
        summary = _english_description(cve_data)
        reference_url = _reference_url(cve_data)
        published_date = _published_date(cve_data)

        branches_found = False
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable"):
                        continue
                    min_v, max_v = _version_bounds(cpe_match)
                    if min_v is None and max_v is None:
                        continue
                    branches_found = True
                    records.append({
                        "cve_id": cve_id,
                        "vendor": vendor,
                        "product": product,
                        "product_keyword": product_keyword,
                        "affected_version_min": min_v,
                        "affected_version_max": max_v,
                        "fixed_version": max_v,
                        "severity": severity or "medium",
                        "cvss_score": cvss_score,
                        "summary": summary,
                        "recommendation": (
                            f"Upgrade {product} to version {max_v} or later." if max_v
                            else "Review the vendor advisory for a remediation path."
                        ),
                        "reference_url": reference_url,
                        "published_date": published_date,
                    })

        if not branches_found:
            logger.info("NVD sync: skipped %s (%s) - no version range data", cve_id, product_keyword)

    return records


def fetch_nvd_cves(product_keyword: str, timeout: float = 15.0) -> dict:
    """Live network call to the NVD REST API. Raises requests.RequestException
    on failure - callers decide how to surface that (see
    CveService.sync_from_nvd)."""
    response = requests.get(
        NVD_API_URL,
        params={"keywordSearch": product_keyword, "resultsPerPage": 100},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def sync_product_from_nvd(db: Session, product_keyword: str, vendor: str, product: str) -> dict:
    """Fetch + parse + upsert one product's CVEs from NVD. Idempotent via the
    same composite key as the seed data (cve_id, product_keyword,
    affected_version_min, affected_version_max) - a re-sync updates existing
    rows in place rather than duplicating them."""
    payload = fetch_nvd_cves(product_keyword)
    records = parse_nvd_response(payload, product_keyword, vendor, product)

    added = 0
    updated = 0
    for record in records:
        existing = (
            db.query(CveRecord)
            .filter(
                CveRecord.cve_id == record["cve_id"],
                CveRecord.product_keyword == record["product_keyword"],
                CveRecord.affected_version_min == record["affected_version_min"],
                CveRecord.affected_version_max == record["affected_version_max"],
            )
            .first()
        )
        if existing:
            for key, value in record.items():
                setattr(existing, key, value)
            existing.source = "nvd_sync"
            updated += 1
        else:
            db.add(CveRecord(**record, source="nvd_sync"))
            added += 1

    db.commit()
    return {"records_added": added, "records_updated": updated}


def sync_all_tracked_products(db: Session) -> dict:
    """Sync every product in TRACKED_PRODUCTS. One product's failure (e.g. the
    NVD API being unreachable from this deployment's network) is logged and
    skipped rather than aborting the rest of the batch."""
    added = 0
    updated = 0
    failures: list[str] = []
    for vendor, product, product_keyword in TRACKED_PRODUCTS:
        try:
            result = sync_product_from_nvd(db, product_keyword, vendor, product)
            added += result["records_added"]
            updated += result["records_updated"]
        except requests.RequestException as exc:
            logger.warning("NVD sync failed for %s: %s", product_keyword, exc)
            failures.append(product)

    return {"records_added": added, "records_updated": updated, "failures": failures}
