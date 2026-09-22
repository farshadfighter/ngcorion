"""Tests for the CVE vulnerability module: version matcher, seed data,
NVD parser, findings service, and router behaviour.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_drift.py / test_topology.py / test_deployment.py).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import requests
from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.cve import CveRecord
from app.models.user import User
from app.modules.cve.matcher import parse_version, version_in_range, asset_matches_cve
from app.modules.cve.seed_data import SEED_RECORDS
from app.modules.cve.seed import seed_cve_defaults
from app.modules.cve.nvd_sync import parse_nvd_response, TRACKED_PRODUCTS
from app.modules.cve.service import CveService


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        if transaction.nested and not transaction._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", _restart_savepoint)
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _next() -> int:
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def user(db) -> User:
    row = User(username=f"cve_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, os_name="FortiOS", os_version="7.0.5", manufacturer="Fortinet"):
    asset_type = AssetType(type_name=f"Firewall_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(
        asset_name=f"cve-asset-{_next()}",
        asset_type_id=asset_type.id,
        manufacturer=manufacturer,
        os_name=os_name,
        os_version=os_version,
    )
    db.add(row)
    db.flush()
    return row


def _make_cve(db, cve_id="CVE-2099-00001", product_keyword="fortios",
              affected_version_min="7.0.0", affected_version_max="7.0.6",
              severity="critical"):
    row = CveRecord(
        cve_id=cve_id, vendor="Fortinet", product="FortiOS",
        product_keyword=product_keyword,
        affected_version_min=affected_version_min, affected_version_max=affected_version_max,
        fixed_version=affected_version_max, severity=severity, cvss_score=9.0,
        summary="test summary", source="seed",
    )
    db.add(row)
    db.flush()
    return row


# ======================================================================
# matcher: parse_version
# ======================================================================

def test_parse_version_semver():
    assert parse_version("7.0.5") == (7, 0, 5)


def test_parse_version_cisco_train_style_falls_back_to_leading_numerics():
    assert parse_version("15.2(4)M3") == (15, 2)


def test_parse_version_none_and_empty():
    assert parse_version(None) is None
    assert parse_version("") is None


def test_parse_version_unparseable_returns_none():
    assert parse_version("not-a-version-at-all") is None


# ======================================================================
# matcher: version_in_range
# ======================================================================

def test_version_in_range_within_bounds():
    assert version_in_range("7.0.5", "7.0.0", "7.0.6") is True


def test_version_in_range_below_min():
    assert version_in_range("6.9.9", "7.0.0", "7.0.6") is False


def test_version_in_range_above_max():
    assert version_in_range("7.0.7", "7.0.0", "7.0.6") is False


def test_version_in_range_open_ended_min():
    assert version_in_range("1.0.0", None, "7.0.6") is True


def test_version_in_range_open_ended_max():
    assert version_in_range("99.0.0", "7.0.0", None) is True


def test_version_in_range_unparseable_version_never_matches():
    assert version_in_range("garbage", "7.0.0", "7.0.6") is False


# ======================================================================
# matcher: asset_matches_cve
# ======================================================================

def test_asset_matches_cve_true_when_keyword_and_version_match(db):
    asset = _make_asset(db, os_name="FortiOS", os_version="7.0.5")
    cve = _make_cve(db)
    assert asset_matches_cve(asset, cve) is True


def test_asset_matches_cve_false_when_keyword_absent(db):
    asset = _make_asset(db, os_name="Cisco IOS", os_version="15.2")
    cve = _make_cve(db)
    assert asset_matches_cve(asset, cve) is False


def test_asset_matches_cve_false_when_version_out_of_range(db):
    asset = _make_asset(db, os_name="FortiOS", os_version="6.4.0")
    cve = _make_cve(db)
    assert asset_matches_cve(asset, cve) is False


def test_asset_matches_cve_false_when_asset_has_no_os_version(db):
    asset = _make_asset(db, os_name="FortiOS", os_version=None)
    cve = _make_cve(db)
    assert asset_matches_cve(asset, cve) is False


def test_asset_matches_cve_case_insensitive(db):
    asset = _make_asset(db, os_name="fortios", os_version="7.0.5")
    cve = _make_cve(db, product_keyword="FortiOS")
    assert asset_matches_cve(asset, cve) is True


# ======================================================================
# seed data sanity
# ======================================================================

def test_seed_records_have_required_fields():
    required = ("cve_id", "vendor", "product", "product_keyword", "severity", "summary")
    for record in SEED_RECORDS:
        for field in required:
            assert record.get(field), f"{record.get('cve_id')} missing {field}"


def test_seed_records_composite_key_is_unique():
    keys = set()
    for record in SEED_RECORDS:
        key = (
            record["cve_id"], record["product_keyword"],
            record.get("affected_version_min"), record.get("affected_version_max"),
        )
        assert key not in keys, f"duplicate branch key {key}"
        keys.add(key)


def test_seed_records_severity_is_a_known_level():
    for record in SEED_RECORDS:
        assert record["severity"] in ("critical", "high", "medium", "low")


def test_seed_cve_defaults_is_idempotent(db):
    first = seed_cve_defaults(db)
    assert first["records_added"] == len(SEED_RECORDS)
    second = seed_cve_defaults(db)
    assert second["records_added"] == 0


# ======================================================================
# NVD parser (pure function, no live network access needed)
# ======================================================================

def _nvd_payload(vulnerable_branches=None, descriptions=None, metrics=None, references=None):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2022-42475",
                    "published": "2022-12-13T00:00:00.000",
                    "descriptions": descriptions if descriptions is not None else [
                        {"lang": "en", "value": "English summary"},
                        {"lang": "fr", "value": "Resume francais"},
                    ],
                    "metrics": metrics if metrics is not None else {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "references": references if references is not None else [
                        {"url": "https://www.fortiguard.com/psirt/FG-IR-22-398"}
                    ],
                    "configurations": [
                        {"nodes": [{"cpeMatch": vulnerable_branches if vulnerable_branches is not None else [
                            {"vulnerable": True, "versionStartIncluding": "7.0.0", "versionEndExcluding": "7.0.7"},
                        ]}]}
                    ],
                }
            }
        ]
    }


def test_parse_nvd_response_extracts_one_row_per_branch():
    payload = _nvd_payload(vulnerable_branches=[
        {"vulnerable": True, "versionStartIncluding": "7.0.0", "versionEndExcluding": "7.0.7"},
        {"vulnerable": True, "versionStartIncluding": "7.2.0", "versionEndExcluding": "7.2.2"},
    ])
    records = parse_nvd_response(payload, "fortios", "Fortinet", "FortiOS")
    assert len(records) == 2
    assert {r["affected_version_min"] for r in records} == {"7.0.0", "7.2.0"}


def test_parse_nvd_response_skips_non_vulnerable_entries():
    payload = _nvd_payload(vulnerable_branches=[
        {"vulnerable": False, "versionStartIncluding": "6.0.0", "versionEndExcluding": "6.0.5"},
    ])
    records = parse_nvd_response(payload, "fortios", "Fortinet", "FortiOS")
    assert records == []


def test_parse_nvd_response_skips_entries_with_no_version_data():
    payload = _nvd_payload(vulnerable_branches=[{"vulnerable": True}])
    records = parse_nvd_response(payload, "fortios", "Fortinet", "FortiOS")
    assert records == []


def test_parse_nvd_response_picks_english_description():
    payload = _nvd_payload(descriptions=[{"lang": "fr", "value": "seulement francais"}])
    records = parse_nvd_response(payload, "fortios", "Fortinet", "FortiOS")
    assert records[0]["summary"] == ""


def test_parse_nvd_response_extracts_severity_and_score():
    records = parse_nvd_response(_nvd_payload(), "fortios", "Fortinet", "FortiOS")
    assert records[0]["severity"] == "critical"
    assert records[0]["cvss_score"] == 9.3


def test_parse_nvd_response_missing_cve_id_is_skipped():
    payload = {"vulnerabilities": [{"cve": {}}]}
    assert parse_nvd_response(payload, "fortios", "Fortinet", "FortiOS") == []


def test_tracked_products_keywords_are_distinctive():
    """Regression guard: a short/generic keyword (e.g. bare 'ios') would
    substring-match unrelated products (FortiOS contains 'ios')."""
    keywords = [p[2] for p in TRACKED_PRODUCTS]
    for keyword in keywords:
        others = [k for k in keywords if k != keyword]
        assert not any(keyword in other or other in keyword for other in others)


# ======================================================================
# CveService
# ======================================================================

def test_get_findings_matches_vulnerable_asset(db):
    asset = _make_asset(db, os_name="FortiOS", os_version="7.0.5")
    _make_cve(db, cve_id="CVE-2099-00001")
    result = CveService.get_findings(db, asset_id=asset.id)
    assert result["summary"]["total"] == 1
    assert result["summary"]["critical"] == 1
    assert result["findings"][0]["cve"].cve_id == "CVE-2099-00001"


def test_get_findings_excludes_unaffected_asset(db):
    asset = _make_asset(db, os_name="Windows Server", os_version="2019")
    _make_cve(db, cve_id="CVE-2099-00002")
    result = CveService.get_findings(db, asset_id=asset.id)
    assert result["summary"]["total"] == 0
    assert result["findings"] == []


def test_get_findings_all_assets_aggregates_across_assets(db):
    vulnerable = _make_asset(db, os_name="FortiOS", os_version="7.0.5")
    safe = _make_asset(db, os_name="FortiOS", os_version="7.4.0")
    _make_cve(db, cve_id="CVE-2099-00003")
    result = CveService.get_findings(db)
    matched_asset_ids = {f["asset_id"] for f in result["findings"]}
    assert vulnerable.id in matched_asset_ids
    assert safe.id not in matched_asset_ids


def test_get_findings_sorts_critical_before_low(db):
    asset = _make_asset(db, os_name="FortiOS", os_version="7.0.5")
    _make_cve(db, cve_id="CVE-2099-00005", severity="low",
              affected_version_min="7.0.0", affected_version_max="7.0.6")
    _make_cve(db, cve_id="CVE-2099-00006", severity="critical",
              affected_version_min="7.0.0", affected_version_max="7.0.6")
    result = CveService.get_findings(db, asset_id=asset.id)
    severities = [f["cve"].severity for f in result["findings"]]
    assert severities[0] == "critical"
    assert severities[-1] == "low"


def test_sync_from_nvd_single_product_success(db):
    with patch(
        "app.modules.cve.nvd_sync.fetch_nvd_cves",
        return_value=_nvd_payload(),
    ):
        result = CveService.sync_from_nvd(db, product_keyword="fortios")
    assert result["records_added"] == 1
    assert result["source"] == "nvd"
    assert db.query(CveRecord).filter(CveRecord.source == "nvd_sync").count() == 1


def test_sync_from_nvd_is_idempotent_on_reupsert(db):
    with patch(
        "app.modules.cve.nvd_sync.fetch_nvd_cves",
        return_value=_nvd_payload(),
    ):
        CveService.sync_from_nvd(db, product_keyword="fortios")
        second = CveService.sync_from_nvd(db, product_keyword="fortios")
    assert second["records_added"] == 0
    assert second["records_updated"] == 1


def test_sync_from_nvd_all_products_continues_after_one_failure(db):
    def flaky_fetch(product_keyword, timeout=15.0):
        if product_keyword == "fortios":
            raise requests.RequestException("network unreachable")
        return _nvd_payload()

    with patch("app.modules.cve.nvd_sync.fetch_nvd_cves", side_effect=flaky_fetch):
        result = CveService.sync_from_nvd(db)

    assert "FortiOS" in result["failures"]
    assert result["records_added"] > 0  # other tracked products still synced


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_asset_findings_404s_for_missing_asset(db, user):
    from app.modules.cve.router import get_asset_findings as route

    with pytest.raises(HTTPException) as exc_info:
        route(asset_id=2_000_000_000, current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_sync_returns_502_when_nvd_unreachable(db, user):
    from app.modules.cve.router import sync_from_nvd as route
    from app.modules.cve.schemas import CveSyncRequest

    with patch(
        "app.modules.cve.nvd_sync.fetch_nvd_cves",
        side_effect=requests.RequestException("connection refused"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            route(request=CveSyncRequest(product_keyword="fortios"), current_user=user, db=db)
    assert exc_info.value.status_code == 502


def test_route_findings_returns_service_result(db, user):
    from app.modules.cve.router import get_all_findings as route

    result = route(current_user=user, db=db)
    assert "summary" in result
    assert "findings" in result


def test_route_list_records_returns_all_records(db, user):
    from app.modules.cve.router import list_records as route

    _make_cve(db, cve_id="CVE-2099-00004")
    records = route(current_user=user, db=db)
    assert any(r.cve_id == "CVE-2099-00004" for r in records)
