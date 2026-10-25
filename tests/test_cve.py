"""
Local CVE database: version ranges, product identities, the NVD / KEV / EPSS
parsers (on responses in the feeds' real formats), writing to the database,
findings and priority, signed offline packages, update jobs and the API's
access rules.

The feeds themselves are never contacted: NVD, CISA and EPSS answers are
captured here and fed through fakes.
"""
import base64
import copy
import gzip
import importlib
import io
import json
import os
import zipfile
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, engine
from app.core.dependencies import require_admin
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.cve import AssetSoftware, CveCpeMatch, CveEntry, CveSetting, CveTrustedKey, CveUpdateJob
from app.models.user import User, UserRole
from app.modules.cve import cpe, feeds, findings, jobs, keys, package, settings, store, versions

router_mod = importlib.import_module("app.modules.cve.router")


# ── captured feed answers (real formats, trimmed) ────────────────────────

def _nvd_cve(cve_id, *, status="Analyzed", score=9.8, version="cvssMetricV31", severity="CRITICAL",
             matches=(), modified="2026-09-20T10:00:00.000", description="Test vulnerability"):
    metric_data = {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                   "baseScore": score, "baseSeverity": severity}
    metric = {"source": "nvd@nist.gov", "type": "Primary", "cvssData": metric_data}
    if version == "cvssMetricV2":
        metric = {"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": severity,
                  "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": score}}
    return {"cve": {
        "id": cve_id, "sourceIdentifier": "psirt@example.com", "published": "2024-02-09T09:15:08.087",
        "lastModified": modified, "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": description}, {"lang": "es", "value": "Vulnerabilidad"}],
        "metrics": {version: [metric]},
        "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-787"}]}],
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": list(matches)}]}],
        "references": [{"url": "https://example.com/blog", "source": "x"},
                       {"url": "https://example.com/advisory", "source": "x", "tags": ["Vendor Advisory"]}],
    }}


def _match(criteria, vulnerable=True, **ranges):
    m = {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "00000000-0000-0000-0000-000000000000"}
    keymap = {"start_incl": "versionStartIncluding", "start_excl": "versionStartExcluding",
              "end_incl": "versionEndIncluding", "end_excl": "versionEndExcluding"}
    m.update({keymap[k]: v for k, v in ranges.items()})
    return m


FORTI = _nvd_cve("CVE-2024-21762", matches=[
    _match("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", start_incl="7.2.0", end_excl="7.2.7"),
    _match("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", start_incl="7.0.0", end_excl="7.0.14"),
    _match("cpe:2.3:h:fortinet:fortigate-60f:-:*:*:*:*:*:*:*", vulnerable=False),
])
IOSXE = _nvd_cve("CVE-2023-20198", score=10.0, matches=[
    _match("cpe:2.3:o:cisco:ios_xe:17.9.1:*:*:*:*:*:*:*"),
    _match("cpe:2.3:o:cisco:ios_xe:17.9.2:*:*:*:*:*:*:*"),
])
APACHE = _nvd_cve("CVE-2021-41773", score=7.5, severity="HIGH", matches=[
    _match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
])
OLD = _nvd_cve("CVE-2014-0160", score=5.0, severity="MEDIUM", version="cvssMetricV2", matches=[
    _match("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", start_incl="1.0.1", end_incl="1.0.1f"),
])
REJECTED = {"cve": {"id": "CVE-2023-99999", "vulnStatus": "Rejected", "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2026-09-21T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "** REJECT ** Duplicate."}]}}


def nvd_page(*items, total=None, start=0):
    return {"resultsPerPage": len(items), "startIndex": start, "totalResults": total or len(items),
            "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-09-30T12:00:00.000",
            "vulnerabilities": list(items)}


KEV_FEED = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.09.30",
    "dateReleased": "2026-09-30T17:01:12.0000Z", "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2024-21762", "vendorProject": "Fortinet", "product": "FortiOS",
         "vulnerabilityName": "Fortinet FortiOS Out-of-Bound Write", "dateAdded": "2024-02-09",
         "shortDescription": "...", "requiredAction": "Apply mitigations per vendor instructions.",
         "dueDate": "2024-02-16", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-787"]},
        {"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server",
         "dateAdded": "2021-11-03", "requiredAction": "Apply updates per vendor instructions.",
         "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Unknown"},
    ],
}
EPSS_CSV = ("#model_version:v2025.03.14,score_date:2026-09-30T12:55:00Z\n"
            "cve,epss,percentile\n"
            "CVE-2024-21762,0.94321,0.99912\n"
            "CVE-2023-20198,0.93800,0.99850\n"
            "CVE-2021-41773,0.94400,0.99950\n"
            "CVE-2014-0160,0.04000,0.88000\n"
            "CVE-1999-0001,0.01000,0.50000\n")


# ── fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    # Commits and rollbacks inside the code under test act on savepoints; the
    # whole test is rolled back at the end.
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _n() -> int:
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def admin(db) -> User:
    row = User(username=f"cve_admin_{_n()}", hashed_password="x", role=UserRole.ADMIN)
    db.add(row)
    db.flush()
    return row


def _asset(db, *, os_name=None, os_version=None, model=None, manufacturer=None, type_name="Firewall"):
    t = AssetType(type_name=f"{type_name}_{_n()}", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"cve-asset-{_n()}", asset_type_id=t.id, os_name=os_name, os_version=os_version,
              model=model, manufacturer=manufacturer, ip_address=f"10.9.{_n() % 250}.{_n() % 250}")
    db.add(a)
    db.flush()
    return a


def _load(db, *items):
    records = feeds.parse_nvd_page(nvd_page(*items))
    return store.apply_cves(db, records)


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_DATA_DIR", str(tmp_path / "cve"))
    return tmp_path


# ── versions ─────────────────────────────────────────────────────────────

class TestVersions:
    @pytest.mark.parametrize("a,b,expected", [
        ("7.2.8", "7.2.10", -1), ("17.9.4a", "17.9.4", 1), ("9", "9.0", 0), ("1.0rc1", "1.0", -1),
        ("1.0", "1.0.1", -1), ("1:8.9p1-3ubuntu0.10", "8.9p1-3ubuntu0.10", 0),
        ("10.0.20348.2527", "10.0.20348.2340", 1), ("15.2(4)M3", "15.2(4)M10", -1), ("2.4.49", "2.4.49", 0),
    ])
    def test_compare(self, a, b, expected):
        assert versions.compare(a, b) == expected

    def test_ranges(self):
        assert versions.matches("7.2.5", start_incl="7.2.0", end_excl="7.2.7")
        assert not versions.matches("7.2.7", start_incl="7.2.0", end_excl="7.2.7")
        assert versions.matches("1.0.1f", start_incl="1.0.1", end_incl="1.0.1f")
        assert not versions.matches("1.0.1g", start_incl="1.0.1", end_incl="1.0.1f")
        assert not versions.matches("2.0", start_excl="2.0")

    def test_exact_and_any(self):
        assert versions.matches("17.9.1", exact="17.9.1")
        assert not versions.matches("17.9.3", exact="17.9.1")
        assert versions.matches(None, exact="*")          # no version, no range: every version
        assert versions.matches("1.0", exact="-")

    def test_unknown_asset_version_never_matches_a_versioned_criterion(self):
        assert not versions.matches(None, start_incl="7.0.0", end_excl="7.0.14")
        assert not versions.matches(None, exact="17.9.1")


# ── product identities ───────────────────────────────────────────────────

def _fake(**kw):
    base = {"os_name": None, "os_version": None, "model": None}
    base.update(kw)
    return SimpleNamespace(**base)


class TestIdentities:
    def test_parse_cpe23_keeps_escaped_colons(self):
        p = cpe.parse_cpe23(r"cpe:2.3:a:vendor:prod\:x:1.2:*:*:*:*:*:*:*")
        assert p["product"] == r"prod\:x" and p["version"] == "1.2"
        assert cpe.parse_cpe23("cpe:/o:old:format") is None

    @pytest.mark.parametrize("asset,expected", [
        (_fake(os_name="FortiOS", os_version="v7.2.5,build1517"), ("fortinet", "fortios", "7.2.5")),
        (_fake(os_name="Cisco IOS XE Software", os_version="17.9.1"), ("cisco", "ios_xe", "17.9.1")),
        (_fake(os_name="Cisco IOS", os_version="15.2(4)M3"), ("cisco", "ios", "15.2(4)M3")),
        (_fake(os_name="Ubuntu 22.04.4 LTS"), ("canonical", "ubuntu_linux", "22.04")),
        (_fake(os_name="Red Hat Enterprise Linux", os_version="9.3"), ("redhat", "enterprise_linux", "9.0")),
        (_fake(os_name="Microsoft Windows Server 2022 Datacenter", os_version="10.0.20348.2527"),
         ("microsoft", "windows_server_2022", "10.0.20348.2527")),
        (_fake(os_name="Apache httpd", os_version="2.4.49"), ("apache", "http_server", "2.4.49")),
    ])
    def test_inferred(self, asset, expected):
        ids = cpe.infer_identities(asset)
        assert ids and (ids[0].vendor, ids[0].product, ids[0].version) == expected
        assert ids[0].source == "inferred"

    def test_nothing_recognisable_infers_nothing(self):
        assert cpe.infer_identities(_fake(os_name="Custom appliance", os_version="3.1")) == []

    def test_manual_rows_are_merged_without_duplicates(self):
        asset = _fake(os_name="FortiOS", os_version="7.2.5")
        rows = [SimpleNamespace(id=1, vendor="fortinet", product="fortios", version="7.2.5"),
                SimpleNamespace(id=2, vendor="openbsd", product="openssh", version="9.6")]
        ids = cpe.identities_for(asset, rows)
        assert [(i.product, i.source) for i in ids] == [("fortios", "inferred"), ("openssh", "manual")]
        assert ids[1].software_id == 2


# ── feed parsers ─────────────────────────────────────────────────────────

class TestParsers:
    def test_nvd_record(self):
        r = feeds.normalize_nvd_cve(FORTI["cve"])
        assert r["id"] == "CVE-2024-21762" and r["modified"] == "2026-09-20T10:00:00"
        assert r["cvss"] == {"score": 9.8, "version": "3.1", "severity": "critical",
                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        assert r["description"] == "Test vulnerability" and r["cwe"] == "CWE-787"
        assert r["refs"][0] == "https://example.com/advisory"     # advisories first
        assert len(r["cpes"]) == 2                                   # the non-vulnerable hardware row is dropped
        assert r["cpes"][0]["start_incl"] == "7.2.0" and r["cpes"][0]["end_excl"] == "7.2.7"

    def test_cvss_v2_fallback_and_rejected(self):
        r = feeds.normalize_nvd_cve(OLD["cve"])
        assert r["cvss"]["version"] == "2.0" and r["cvss"]["severity"] == "medium"
        assert feeds.normalize_nvd_cve(REJECTED["cve"]) == {"id": "CVE-2023-99999", "rejected": True}

    def test_kev(self):
        kev = feeds.parse_kev(KEV_FEED)
        assert kev["version"] == "2026.09.30" and len(kev["items"]) == 2
        assert kev["items"][0] == {"id": "CVE-2024-21762", "added": "2024-02-09", "due": "2024-02-16",
                                   "ransomware": "Known", "action": "Apply mitigations per vendor instructions."}

    def test_epss(self):
        e = feeds.parse_epss_csv(EPSS_CSV)
        assert e["date"] == "2026-09-30" and len(e["rows"]) == 5
        assert e["rows"][0] == ("CVE-2024-21762", 0.94321, 0.99912)

    def test_nvd_client_pages_and_windows(self):
        calls = []

        class FakeResp:
            def __init__(self, payload):
                self.status_code, self._p = 200, payload

            def json(self):
                return self._p

        class FakeSession:
            def get(self, url, params=None, headers=None, timeout=None):
                calls.append(dict(params))
                if params["startIndex"] == 0:
                    return FakeResp(nvd_page(FORTI, total=2))
                return FakeResp(nvd_page(IOSXE, total=2, start=1))

        sleeps = []
        client = feeds.NvdClient("key-123", session=FakeSession(), sleep=sleeps.append)
        pages = list(client.pages(None, datetime(2026, 9, 30)))
        assert [r["id"] for p in pages for r in p] == ["CVE-2024-21762", "CVE-2023-20198"]
        assert "lastModStartDate" not in calls[0] and sleeps == [0.7]

        calls.clear()
        list(client.pages(datetime(2026, 1, 1), datetime(2026, 9, 30)))
        windows = {(c["lastModStartDate"], c["lastModEndDate"]) for c in calls}
        assert len(windows) == 3     # 272 days in <= 120-day windows

    def test_nvd_client_retries_rate_limit_then_reports(self):
        class Resp:
            status_code = 503

        class S:
            n = 0

            def get(self, *a, **k):
                S.n += 1
                return Resp()

        client = feeds.NvdClient(None, session=S(), sleep=lambda s: None)
        with pytest.raises(feeds.FeedError, match="HTTP 503"):
            client.ping()
        assert S.n == 5


# ── store ────────────────────────────────────────────────────────────────

class TestStore:
    def test_insert_update_reject(self, db):
        assert _load(db, FORTI, IOSXE) == {"new": 2, "changed": 0, "removed": 0}
        assert db.query(CveCpeMatch).filter_by(cve_id="CVE-2024-21762").count() == 2
        newer = _nvd_cve("CVE-2024-21762", score=9.6, modified="2026-09-25T00:00:00.000", matches=[
            _match("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", start_incl="7.4.0", end_excl="7.4.3")])
        gone = {"cve": dict(REJECTED["cve"], id="CVE-2023-20198")}
        assert _load(db, newer, gone) == {"new": 0, "changed": 1, "removed": 1}
        db.expire_all()
        assert db.get(CveEntry, "CVE-2024-21762").cvss_score == 9.6
        assert [m.start_incl for m in db.query(CveCpeMatch).filter_by(cve_id="CVE-2024-21762")] == ["7.4.0"]
        assert db.get(CveEntry, "CVE-2023-20198") is None

    def test_older_copy_never_overwrites_newer(self, db):
        _load(db, _nvd_cve("CVE-2024-21762", score=9.6, modified="2026-09-25T00:00:00.000"))
        _load(db, FORTI)       # modified 2026-09-20
        db.expire_all()
        assert db.get(CveEntry, "CVE-2024-21762").cvss_score == 9.6

    def test_kev_and_epss_survive_an_nvd_update(self, db):
        _load(db, FORTI, IOSXE, APACHE)
        assert store.apply_kev(db, feeds.parse_kev(KEV_FEED)) == 2
        assert store.apply_epss(db, feeds.parse_epss_csv(EPSS_CSV)["rows"]) == 3
        _load(db, _nvd_cve("CVE-2024-21762", modified="2026-09-29T00:00:00.000"))
        db.expire_all()
        e = db.get(CveEntry, "CVE-2024-21762")
        assert e.kev and e.kev_ransomware == "Known" and e.epss == pytest.approx(0.94321)
        # A later KEV list without it clears the flag.
        store.apply_kev(db, {"items": []})
        db.expire_all()
        assert not db.get(CveEntry, "CVE-2024-21762").kev


# ── findings ─────────────────────────────────────────────────────────────

class TestFindings:
    def test_priority(self):
        P = SimpleNamespace
        assert findings.priority(P(kev=True, cvss_score=3.0, epss=0.0)) == 1
        assert findings.priority(P(kev=False, cvss_score=9.1, epss=None)) == 2
        assert findings.priority(P(kev=False, cvss_score=5.0, epss=0.6)) == 2
        assert findings.priority(P(kev=False, cvss_score=7.0, epss=None)) == 3
        assert findings.priority(P(kev=False, cvss_score=5.0, epss=0.01)) == 4

    def test_asset_findings(self, db, admin):
        _load(db, FORTI, IOSXE, APACHE, OLD)
        store.apply_kev(db, feeds.parse_kev(KEV_FEED))
        fw = _asset(db, os_name="FortiOS", os_version="7.2.5")
        patched = _asset(db, os_name="FortiOS", os_version="7.2.8")
        router = _asset(db, os_name="Cisco IOS XE Software", os_version="17.9.1", type_name="Router")
        web = _asset(db, os_name="Ubuntu 22.04", type_name="Server")
        db.add(AssetSoftware(asset_id=web.id, vendor="apache", product="http_server", version="2.4.49"))
        db.flush()

        r = findings.compute(db, fw.id)
        assert [f["cve_id"] for f in r["findings"]] == ["CVE-2024-21762"]
        f = r["findings"][0]
        assert f["priority"] == 1 and f["kev"] and f["fixed_in"] == "7.2.7" and f["installed"] == "7.2.5"
        assert r["summary"]["fix_now"] == 1 and r["summary"]["critical"] == 1

        assert findings.compute(db, patched.id)["findings"] == []
        assert [f["cve_id"] for f in findings.compute(db, router.id)["findings"]] == ["CVE-2023-20198"]
        w = findings.compute(db, web.id)
        assert [f["cve_id"] for f in w["findings"]] == ["CVE-2021-41773"]
        assert w["findings"][0]["identity_source"] == "manual"
        assert {p["product"] for p in w["assets"][0]["products"]} == {"ubuntu_linux", "http_server"}


# ── packages ─────────────────────────────────────────────────────────────

def _loaded_db(db, watermark="2026-09-30T00:00:00"):
    _load(db, FORTI, IOSXE, APACHE)
    store.apply_kev(db, feeds.parse_kev(KEV_FEED))
    store.apply_epss(db, feeds.parse_epss_csv(EPSS_CSV)["rows"])
    settings.put(db, settings.WATERMARK, watermark)
    settings.put(db, settings.KEV_INFO, {"version": "2026.09.30", "released": KEV_FEED["dateReleased"]})
    settings.put(db, settings.EPSS_DATE, "2026-09-30")
    db.flush()


def _clear(db):
    db.query(CveEntry).delete()
    for key in (settings.WATERMARK, settings.KEV_INFO, settings.EPSS_DATE):
        settings.put(db, key, None)
    db.flush()


class TestPackages:
    def test_round_trip(self, db, tmp_path):
        _loaded_db(db)
        path = str(tmp_path / "full.ngcve")
        manifest = package.build(db, path, "full")
        assert manifest["counts"] == {"cves": 3, "kev": 2, "epss": 3}
        with zipfile.ZipFile(path) as zf:
            assert sorted(zf.namelist()) == sorted(package.MEMBERS)

        _clear(db)
        v = package.verify(db, path)
        assert v.importable and v.signer == "This NGCorion"
        assert [c.name for c in v.checks] == ["signature", "integrity", "format", "freshness"]
        records = list(package.read_cves(path))
        assert {r["id"] for r in records} == {"CVE-2024-21762", "CVE-2023-20198", "CVE-2021-41773"}
        assert store.apply_cves(db, records)["new"] == 3
        assert len(package.read_kev(path)["items"]) == 2
        assert package.read_epss(path)["date"] == "2026-09-30"

    def _rewrite(self, src, dst, member, data):
        with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
            for name in zin.namelist():
                zout.writestr(name, data if name == member else zin.read(name))

    def test_tampered_contents_fail_integrity(self, db, tmp_path):
        _loaded_db(db)
        src, dst = str(tmp_path / "a.ngcve"), str(tmp_path / "b.ngcve")
        package.build(db, src, "full")
        evil = gzip.compress(b'{"id":"CVE-2024-0001","cvss":{},"cpes":[]}\n')
        self._rewrite(src, dst, "cves.jsonl.gz", evil)
        v = package.verify(db, dst)
        assert not v.importable and next(c for c in v.checks if c.name == "integrity").status == "fail"

    def test_tampered_manifest_fails_signature(self, db, tmp_path):
        _loaded_db(db)
        src, dst = str(tmp_path / "a.ngcve"), str(tmp_path / "b.ngcve")
        package.build(db, src, "full")
        with zipfile.ZipFile(src) as zf:
            m = json.loads(zf.read("manifest.json"))
        m["until"] = "2099-01-01T00:00:00"
        self._rewrite(src, dst, "manifest.json", json.dumps(m, indent=2, sort_keys=True).encode())
        v = package.verify(db, dst)
        assert not v.importable and [c.name for c in v.checks] == ["signature"]

    def test_untrusted_key_then_trusted(self, db, tmp_path, monkeypatch):
        _loaded_db(db)
        other = Ed25519PrivateKey.generate()
        raw = other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub = base64.b64encode(raw).decode()
        monkeypatch.setattr(keys, "_private", lambda _db: other)
        path = str(tmp_path / "hq.ngcve")
        package.build(db, path, "full")
        monkeypatch.undo()
        assert not package.verify(db, path).importable
        db.add(CveTrustedKey(name="HQ", public_key=pub, fingerprint=keys.fingerprint(pub)))
        db.flush()
        v = package.verify(db, path)
        assert v.importable and v.signer == "HQ"

    def test_release_key_from_environment(self, db, monkeypatch):
        k = Ed25519PrivateKey.generate()
        pub = base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        monkeypatch.setenv("CVE_RELEASE_PUBLIC_KEY", pub)
        names = [t["name"] for t in keys.trusted(db)]
        assert names[:2] == ["This NGCorion", "NGCorion release"]
        sig = base64.b64encode(k.sign(b"data")).decode()
        assert keys.verify(db, b"data", sig, keys.fingerprint(pub)) == "NGCorion release"
        assert keys.verify(db, b"other", sig, keys.fingerprint(pub)) is None

    def test_freshness(self, db, tmp_path):
        _loaded_db(db, watermark="2026-09-30T00:00:00")
        delta = str(tmp_path / "d.ngcve")
        package.build(db, delta, "delta", since=datetime(2026, 9, 1))
        status = lambda p: next(c for c in package.verify(db, p).checks if c.name == "freshness").status  # noqa: E731

        assert status(delta) == "warn"                     # not newer than this database
        settings.put(db, settings.WATERMARK, "2026-08-01T00:00:00")
        db.flush()
        assert status(delta) == "fail"                     # gap: Aug 1 .. Sep 1 would be missed
        settings.put(db, settings.WATERMARK, "2026-09-15T00:00:00")
        db.flush()
        assert status(delta) == "ok"
        settings.put(db, settings.WATERMARK, None)
        db.flush()
        assert status(delta) == "fail"                     # partial update into an empty database

    def test_not_a_package(self, db, tmp_path):
        p = tmp_path / "x.ngcve"
        p.write_bytes(b"hello")
        with pytest.raises(package.PackageError):
            package.verify(db, str(p))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("evil.txt", "x")
        p.write_bytes(buf.getvalue())
        with pytest.raises(package.PackageError, match="unexpected contents"):
            package.verify(db, str(p))


# ── jobs (committed data; skipped when this database already holds CVE data) ──

_CVE_TABLES = "cve_cpe_matches, cve_entries, cve_update_jobs, cve_settings, cve_trusted_keys"


@pytest.fixture
def clean(data_dir):
    s = SessionLocal()
    try:
        if s.execute(text("SELECT (SELECT count(*) FROM cve_entries) + (SELECT count(*) FROM cve_settings) "
                          "+ (SELECT count(*) FROM cve_update_jobs)")).scalar():
            pytest.skip("this database holds CVE data; job tests need empty CVE tables")
        user = User(username=f"cve_job_user_{_n()}_{os.getpid()}", hashed_password="x", role=UserRole.ADMIN)
        s.add(user)
        s.commit()
        uid = user.id
    finally:
        s.close()
    yield uid
    s = SessionLocal()
    try:
        s.execute(text(f"TRUNCATE {_CVE_TABLES}"))
        # audit_logs is append-only; test clean-up declares maintenance like the restore engine does.
        s.execute(text("SET LOCAL ngcorion.audit_maintenance = 'on'"))
        s.execute(text("DELETE FROM audit_logs WHERE module = 'cve' AND user_id = :u"), {"u": uid})
        s.execute(text("DELETE FROM users WHERE id = :u"), {"u": uid})
        s.commit()
    finally:
        s.close()


class FakeClient:
    def __init__(self, pages, fail_after=None, on_page=None):
        self._pages, self.fail_after, self.calls, self.hook = pages, fail_after, [], on_page

    def pages(self, start, end, on_page=None, cancelled=lambda: False):
        self.calls.append((start, end))
        for n, p in enumerate(self._pages):
            if self.fail_after is not None and n >= self.fail_after:
                raise feeds.FeedError("NVD answered HTTP 503")
            if self.hook:
                self.hook(n)
            records = feeds.parse_nvd_page(p)
            if on_page:
                on_page(len(records), 0)
            yield records

    def ping(self):
        pass


def _feeds(monkeypatch, client, kev=KEV_FEED, epss=EPSS_CSV):
    monkeypatch.setattr(jobs, "make_client", lambda api_key: client)
    # Recalculating every asset's risk would write to this database's other assets.
    client.risk_refreshes = 0

    def refresh(db):
        client.risk_refreshes += 1
    monkeypatch.setattr(jobs, "refresh_risk_scores", refresh)
    monkeypatch.setattr(feeds, "fetch_kev", lambda: feeds.parse_kev(kev))
    monkeypatch.setattr(feeds, "fetch_epss", lambda: feeds.parse_epss_csv(epss))


def _job(kind, uid):
    s = SessionLocal()
    try:
        return jobs.create_job(s, kind, uid).id
    finally:
        s.close()


def _get(model, key):
    s = SessionLocal()
    try:
        row = s.get(model, key)
        if row is not None:
            s.expunge(row)
        return row
    finally:
        s.close()


class TestJobs:
    def test_first_online_update_is_a_full_download_then_incremental(self, clean, monkeypatch):
        client = FakeClient([nvd_page(FORTI, IOSXE), nvd_page(APACHE, REJECTED)])
        _feeds(monkeypatch, client)
        job_id = _job("online", clean)
        jobs.run_online(job_id)
        job = _get(CveUpdateJob, job_id)
        assert job.status == "succeeded", job.error
        assert job.stats["new"] == 3 and job.stats["kev"] == 2 and job.stats["epss"] == 3
        assert job.stats["mode"] == "full" and client.calls[0][0] is None
        assert job.progress["step"] == "done"
        assert client.risk_refreshes == 1                       # risk scores follow the new data
        assert _get(CveEntry, "CVE-2024-21762").kev
        s = SessionLocal()
        try:
            watermark = settings.get(s, settings.WATERMARK)
            assert watermark and settings.get(s, settings.EPSS_DATE) == "2026-09-30"
            audit = s.execute(text("SELECT action, result FROM audit_logs WHERE module='cve' AND target_id=:j"),
                              {"j": job_id}).all()
            assert audit == [("cve.online", "success")]
        finally:
            s.close()

        client2 = FakeClient([nvd_page(_nvd_cve("CVE-2024-21762", score=9.6, modified="2026-09-29T00:00:00"))])
        _feeds(monkeypatch, client2)
        job2 = _job("online", clean)
        jobs.run_online(job2)
        j2 = _get(CveUpdateJob, job2)
        assert j2.status == "succeeded" and j2.stats["mode"] == "incremental"
        assert client2.calls[0][0] == datetime.fromisoformat(watermark)
        assert j2.stats["changed"] == 1 and j2.stats["new"] == 0

    def test_failure_mid_download_changes_nothing(self, clean, monkeypatch):
        _feeds(monkeypatch, FakeClient([nvd_page(FORTI), nvd_page(IOSXE)], fail_after=1))
        job_id = _job("online", clean)
        jobs.run_online(job_id)
        job = _get(CveUpdateJob, job_id)
        assert job.status == "failed" and "503" in job.error
        assert _get(CveEntry, "CVE-2024-21762") is None
        assert _get(CveSetting, settings.WATERMARK) is None

    def test_cancel_changes_nothing(self, clean, monkeypatch):
        holder = {}
        client = FakeClient([nvd_page(FORTI), nvd_page(IOSXE)],
                            on_page=lambda n: n == 1 and jobs._cancel[holder["id"]].set())
        _feeds(monkeypatch, client)
        holder["id"] = _job("online", clean)
        jobs.run_online(holder["id"])
        job = _get(CveUpdateJob, holder["id"])
        assert job.status == "cancelled"
        assert _get(CveEntry, "CVE-2024-21762") is None

    def test_kev_outage_is_a_warning_not_a_failure(self, clean, monkeypatch):
        _feeds(monkeypatch, FakeClient([nvd_page(FORTI)]))

        def down():
            raise feeds.FeedError("CISA KEV is not reachable: ConnectTimeout")
        monkeypatch.setattr(feeds, "fetch_kev", down)
        job_id = _job("online", clean)
        jobs.run_online(job_id)
        job = _get(CveUpdateJob, job_id)
        assert job.status == "succeeded" and "previous KEV list was kept" in job.stats["warnings"][0]

    def test_only_one_job_at_a_time(self, clean):
        job_id = _job("online", clean)
        with pytest.raises(jobs.JobBusy):
            _job("offline", clean)
        s = SessionLocal()
        try:
            # Still owned by a live process (this one): a worker starting up leaves it alone.
            assert jobs.fail_interrupted_cve_jobs(s) == 0
            s.get(CveUpdateJob, job_id).runner = "old-host:1:1|999999"     # a server run that is gone
            s.commit()
            assert jobs.fail_interrupted_cve_jobs(s) == 1
        finally:
            s.close()
        _job("export", clean)   # free again

    def test_cancel_reaches_a_job_in_another_process(self, clean, monkeypatch):
        """Cancel is stored on the job row; the running job reads it there."""
        monkeypatch.setattr(jobs, "CANCEL_CHECK_SECONDS", 0)
        holder = {}

        def cancel_from_elsewhere(n):
            if n == 1:
                s = SessionLocal()
                try:
                    jobs._cancel.pop(holder["id"], None)       # no in-process flag to set
                    assert jobs.request_cancel(s, s.get(CveUpdateJob, holder["id"]))
                finally:
                    s.close()
        _feeds(monkeypatch, FakeClient([nvd_page(FORTI), nvd_page(IOSXE)], on_page=cancel_from_elsewhere))
        holder["id"] = _job("online", clean)
        jobs.run_online(holder["id"])
        assert _get(CveUpdateJob, holder["id"]).status == "cancelled"
        assert _get(CveEntry, "CVE-2024-21762") is None

    def test_export_then_import_on_an_empty_database(self, clean, monkeypatch):
        _feeds(monkeypatch, FakeClient([nvd_page(FORTI, IOSXE, APACHE)]))
        jobs.run_online(_job("online", clean))
        export_id = _job("export", clean)
        jobs.run_export(export_id, "full", None)
        ex = _get(CveUpdateJob, export_id)
        assert ex.status == "succeeded", ex.error
        path = jobs.export_file(ex)
        assert path and ex.stats["cves"] == 3

        # Wipe the data (the signing key stays: this instance trusts its own packages).
        s = SessionLocal()
        try:
            s.execute(text("TRUNCATE cve_cpe_matches, cve_entries"))
            for key in (settings.WATERMARK, settings.KEV_INFO, settings.EPSS_DATE):
                settings.put(s, key, None)
            s.commit()
        finally:
            s.close()

        copy = path + ".copy"
        with open(path, "rb") as a, open(copy, "wb") as b:
            b.write(a.read())
        import_id = _job("offline", clean)
        jobs.run_import(import_id, copy)
        im = _get(CveUpdateJob, import_id)
        assert im.status == "succeeded", im.error
        assert im.stats["new"] == 3 and im.stats["kev"] == 2 and im.stats["signer"] == "This NGCorion"
        assert not os.path.exists(copy)
        assert _get(CveEntry, "CVE-2024-21762").epss == pytest.approx(0.94321)

    def test_auto_update_due(self, clean):
        s = SessionLocal()
        try:
            now = datetime(2026, 10, 1, 3, 0)
            settings.put(s, settings.AUTO_UPDATE, {"enabled": True, "time": "02:00"})
            s.commit()
            assert not jobs.auto_update_due(s, now)          # database not loaded yet
            settings.put(s, settings.WATERMARK, "2026-09-30T00:00:00")
            s.commit()
            assert jobs.auto_update_due(s, now)
            assert not jobs.auto_update_due(s, now.replace(hour=1))
            settings.put(s, settings.LAST_AUTO_RUN, "2026-10-01")
            s.commit()
            assert not jobs.auto_update_due(s, now)          # once a day
            assert jobs.auto_update_due(s, now + timedelta(days=1))
        finally:
            s.close()


# ── API ──────────────────────────────────────────────────────────────────

ADMIN_ONLY = {
    ("PUT", "/api/cve/db/settings"), ("POST", "/api/cve/db/test-connection"), ("POST", "/api/cve/db/update"),
    ("POST", "/api/cve/db/bundle/load"), ("POST", "/api/cve/db/packages"),
    ("POST", "/api/cve/db/packages/{token}/import"), ("POST", "/api/cve/db/export"),
    ("GET", "/api/cve/db/export/{job_id}/file"), ("POST", "/api/cve/db/jobs/{job_id}/cancel"),
    ("GET", "/api/cve/db/keys"), ("POST", "/api/cve/db/keys"), ("DELETE", "/api/cve/db/keys/{key_id}"),
    ("PUT", "/api/cve/advisories/settings"), ("POST", "/api/cve/advisories/update"),
    ("POST", "/api/cve/advisories/import"), ("DELETE", "/api/cve/advisories/releases/{release}"),
}


def _deps(route):
    out, stack = set(), [route.dependant]
    while stack:
        d = stack.pop()
        if d.call is not None:
            out.add(d.call)
        stack.extend(d.dependencies)
    return out


class TestApi:
    def test_every_route_is_authenticated_and_changes_are_admin_only(self):
        seen = set()
        for route in router_mod.router.routes:
            deps = _deps(route)
            for method in route.methods:
                key = (method, route.path)
                seen.add(key)
                if key in ADMIN_ONLY:
                    assert require_admin in deps, key
                else:
                    assert router_mod._read in deps or router_mod._write in deps, key
        assert ADMIN_ONLY <= seen

    def test_findings_for_missing_asset_404(self, db, admin):
        with pytest.raises(HTTPException) as exc:
            router_mod.get_findings(asset_id=2_000_000_000, current_user=admin, db=db)
        assert exc.value.status_code == 404

    def test_software_add_and_remove(self, db, admin):
        from app.modules.cve.schemas import SoftwareCreate
        asset = _asset(db, os_name="Ubuntu 22.04")
        row = router_mod.add_software(asset.id, SoftwareCreate(vendor="Apache", product="HTTP Server",
                                                               version="2.4.49"), admin, db)
        assert (row.vendor, row.product) == ("apache", "http_server")
        with pytest.raises(HTTPException) as exc:
            router_mod.add_software(asset.id, SoftwareCreate(vendor="apache", product="http_server",
                                                             version="2.4.49"), admin, db)
        assert exc.value.status_code == 409
        router_mod.remove_software(asset.id, row.id, admin, db)
        assert db.get(AssetSoftware, row.id) is None

    def test_software_rejects_cpe_wildcards(self):
        from pydantic import ValidationError
        from app.modules.cve.schemas import SoftwareCreate
        with pytest.raises(ValidationError):
            SoftwareCreate(vendor="apache", product="*", version="2.4")

    def test_status_and_settings(self, db, admin):
        from app.modules.cve.schemas import DbSettingsUpdate
        st = router_mod.db_status(admin, db)
        assert st.is_admin and not st.api_key_configured
        st = router_mod.update_settings(DbSettingsUpdate(nvd_api_key="abcd-1234", auto_update_enabled=True,
                                                         auto_update_time="03:30"), admin, db)
        assert st.api_key_configured and st.auto_update.enabled and st.auto_update.time == "03:30"
        raw = db.get(CveSetting, settings.NVD_API_KEY).value
        assert "abcd-1234" not in raw                      # encrypted at rest
        assert settings.api_key(db) == "abcd-1234"
        with pytest.raises(HTTPException):
            router_mod.update_settings(DbSettingsUpdate(nvd_api_key="bad key; rm"), admin, db)
        st = router_mod.update_settings(DbSettingsUpdate(clear_api_key=True), admin, db)
        assert not st.api_key_configured

    def test_trusted_keys(self, db, admin):
        from app.modules.cve.schemas import TrustedKeyCreate
        pub = base64.b64encode(Ed25519PrivateKey.generate().public_key()
                               .public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        out = router_mod.add_key(TrustedKeyCreate(name="HQ", public_key=pub), admin, db)
        assert not out.builtin and len(out.fingerprint) == 64
        with pytest.raises(HTTPException) as exc:
            router_mod.add_key(TrustedKeyCreate(name="HQ again", public_key=pub), admin, db)
        assert exc.value.status_code == 409
        with pytest.raises(HTTPException) as exc:
            router_mod.add_key(TrustedKeyCreate(name="bad", public_key="A" * 44), admin, db)
        assert exc.value.status_code == 422
        own = keys.trusted(db)[0]["public_key"]
        with pytest.raises(HTTPException):
            router_mod.add_key(TrustedKeyCreate(name="me", public_key=own), admin, db)
        router_mod.remove_key(out.id, admin, db)

    def test_upload_tokens_cannot_escape_the_upload_folder(self, data_dir):
        for token in ("../../etc/passwd", "a" * 31, "Z" * 32, ""):
            with pytest.raises(package.PackageError):
                jobs.upload_path(token)

    def test_package_upload_checks_before_anything_is_imported(self, db, admin, data_dir, tmp_path):
        import asyncio
        from starlette.requests import Request
        _loaded_db(db)
        path = tmp_path / "p.ngcve"
        package.build(db, str(path), "full")

        def upload(raw, name="p.ngcve", declared=None):
            chunks = [raw[i:i + 65536] for i in range(0, len(raw), 65536)] or [b""]
            msgs = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]

            async def receive():
                return msgs.pop(0) if msgs else {"type": "http.disconnect"}
            length = str(declared if declared is not None else len(raw)).encode()
            req = Request({"type": "http", "method": "POST", "headers": [(b"content-length", length)]}, receive)
            return asyncio.run(router_mod.upload_package(req, file_name=name, current_user=admin, db=db))

        ok = upload(path.read_bytes())
        assert ok.importable and ok.token and ok.signer == "This NGCorion"
        assert os.path.isfile(jobs.upload_path(ok.token))
        assert db.query(CveUpdateJob).count() == 0          # verified only, nothing imported

        with pytest.raises(HTTPException) as exc:
            upload(b"not a zip")
        assert exc.value.status_code == 422
        uploads = sorted(os.listdir(jobs.data_dir("uploads")))
        assert uploads == [ok.token + ".ngcve", ok.token + ".ngcve.json"]   # the rejected file is gone

    def test_package_upload_size_limit(self, db, admin, data_dir, monkeypatch):
        import asyncio
        from starlette.requests import Request
        monkeypatch.setattr(package, "MAX_PACKAGE_BYTES", 1000)

        def upload(raw, declared):
            msgs = [{"type": "http.request", "body": raw, "more_body": False}]

            async def receive():
                return msgs.pop(0) if msgs else {"type": "http.disconnect"}
            req = Request({"type": "http", "method": "POST", "headers": [(b"content-length", declared)]}, receive)
            return asyncio.run(router_mod.upload_package(req, file_name="big.ngcve", current_user=admin, db=db))

        for raw, declared in ((b"x" * 10, b"5000"), (b"x" * 5000, b"10")):   # refused up front / while streaming
            with pytest.raises(HTTPException) as exc:
                upload(raw, declared)
            assert exc.value.status_code == 413
        assert os.listdir(jobs.data_dir("uploads")) == []


def test_package_records_cannot_smuggle_script_links(db):
    """A package is signed, but its references still pass the same filter."""
    rec = {"id": "CVE-2099-0001", "modified": "2026-01-01T00:00:00", "description": "x", "cvss": {},
           "refs": ["javascript:alert(document.cookie)", "https://ok.example/advisory"], "cpes": []}
    store.apply_cves(db, [rec])
    db.expire_all()
    assert db.get(CveEntry, "CVE-2099-0001").references == ["https://ok.example/advisory"]


def test_package_upload_over_http(db, admin, data_dir, tmp_path):
    """Through FastAPI's routing (ASGI, no HTTP client needed): the raw body is
    accepted from an admin, and without credentials the request is refused
    before any of its body is read."""
    import asyncio
    from fastapi import FastAPI
    from app.core.database import get_db

    _loaded_db(db)
    path = tmp_path / "p.ngcve"
    package.build(db, str(path), "full")
    raw = path.read_bytes()
    app = FastAPI()
    app.include_router(router_mod.router)
    app.dependency_overrides[get_db] = lambda: db

    def post(query):
        reads, sent = [], []
        msgs = [{"type": "http.request", "body": raw, "more_body": False}]

        async def receive():
            reads.append(1)
            return msgs.pop(0) if msgs else {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)
        scope = {"type": "http", "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/api/cve/db/packages",
                 "raw_path": b"/api/cve/db/packages", "query_string": query, "root_path": "",
                 "headers": [(b"content-type", b"application/octet-stream"), (b"content-length", str(len(raw)).encode())],
                 "client": ("127.0.0.1", 1), "server": ("test", 80)}
        asyncio.run(app(scope, receive, send))
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return status, json.loads(body), reads

    status, _, reads = post(b"file_name=p.ngcve")
    assert status in (401, 403) and reads == []

    app.dependency_overrides[require_admin] = lambda: admin
    status, out, reads = post(b"file_name=..%2F..%2Fp.ngcve")
    assert status == 200, out
    assert out["importable"] and out["file_name"] == "p.ngcve" and reads


class TestRiskAndDashboard:
    """Known vulnerabilities feed the asset risk score (factor CV) and the
    organisation security score (Vulnerability sub-score)."""

    def test_risk_factor(self, db):
        from app.modules.risk.service import risk_calculation_service
        _loaded_db(db)
        vulnerable = _asset(db, os_name="FortiOS", os_version="7.2.5")    # KEV CVE-2024-21762
        patched = _asset(db, os_name="FortiOS", os_version="7.2.8")
        a = risk_calculation_service.calculate(asset_id=vulnerable.id, db=db, trigger_type="test")
        b = risk_calculation_service.calculate(asset_id=patched.id, db=db, trigger_type="test")
        assert float(a.vulnerability_score) == 100 and a.cve_kev_count == 1 and a.cve_findings_count == 1
        assert float(a.vulnerability_contribution) == float(a.vulnerability_weight)   # 100% of its share
        assert b.cve_findings_count == 0 and b.cve_kev_count == 0
        # FortiOS 7.2 left vendor support on 2026-09-30: the factor of the patched asset is the
        # end-of-life score (app/modules/eol), still below a known exploited vulnerability
        from app.modules.eol.service import RISK_SCORE
        assert float(b.vulnerability_score) == RISK_SCORE["unsupported"]
        assert float(a.final_risk_score) > float(b.final_risk_score)

    def test_risk_factor_is_zero_before_the_database_is_loaded(self, db):
        from app.modules.risk.service import risk_calculation_service
        _load(db, FORTI)                                   # records, but no watermark: not loaded
        asset = _asset(db, os_name="FortiOS", os_version="7.2.5")
        score = risk_calculation_service.calculate(asset_id=asset.id, db=db, trigger_type="test")
        assert score.cve_findings_count == 0 and score.cve_kev_count == 0
        # no CVE part; what remains is the end of support of FortiOS 7.2 (app/modules/eol)
        from app.modules.eol.service import RISK_SCORE
        assert float(score.vulnerability_score) == RISK_SCORE["unsupported"]

    def test_dashboard_sub_score(self, db):
        from app.modules.dashboard.security_score_router import _vulnerability
        score, reason, detail = _vulnerability(db)
        assert detail.get("source") != "cve"               # not loaded yet: manual data or unknown
        _loaded_db(db)
        _asset(db, os_name="FortiOS", os_version="7.2.5")
        score, reason, detail = _vulnerability(db)
        assert detail["source"] == "cve" and reason is None
        assert detail["vulnerable_assets"] >= 1 and detail["exploited_in_the_wild"] >= 1
        assert 0 <= score < 100

    def test_software_change_recalculates_the_asset(self, db, admin):
        from app.models.risk import AssetRiskScore
        from app.modules.cve.schemas import SoftwareCreate
        _loaded_db(db)
        web = _asset(db, os_name="Ubuntu 22.04", type_name="Server")
        router_mod.add_software(web.id, SoftwareCreate(vendor="apache", product="http_server", version="2.4.49"), admin, db)
        score = db.query(AssetRiskScore).filter_by(asset_id=web.id).one()
        assert score.cve_kev_count == 1 and float(score.vulnerability_score) == 100


def test_feed_values_postgres_would_refuse(db):
    """A CPE field is unbounded in the CPE 2.3 standard (long firmware versions, product names) and a
    NUL character cannot be stored in PostgreSQL text: either used to fail the whole update with a
    DataError. Long CPE fields are kept whole; NUL characters are dropped."""
    long_version = "5.0.0.1234-build-" + "x" * 120
    long_product = "very_long_product_name_" + "p" * 200
    nul = _nvd_cve("CVE-2099-90001", description="Overflow\u0000 in the parser", matches=[
        _match(f"cpe:2.3:o:acme:{long_product}:{long_version}:*:*:*:*:*:*:*"),
        _match("cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*", start_incl="1.0" + "\u0000", end_excl="9." + "9" * 150),
    ])
    assert _load(db, nul)["new"] == 1
    entry = db.get(CveEntry, "CVE-2099-90001")
    assert entry.description == "Overflow in the parser"
    rows = db.query(CveCpeMatch).filter_by(cve_id="CVE-2099-90001").all()
    assert {r.product for r in rows} == {long_product, "tool"}
    assert any(r.version == long_version for r in rows)
    tool = next(r for r in rows if r.product == "tool")
    assert tool.start_incl == "1.0" and tool.end_excl == "9." + "9" * 150

    kev = {"items": [{"id": "CVE-2099-90001", "added": "2099-01-02", "due": None,
                      "ransomware": "Known, under investigation by several vendors", "action": "Patch\u0000 now"}]}
    assert store.apply_kev(db, kev) == 1
    db.refresh(entry)
    assert entry.kev and entry.kev_action == "Patch now" and len(entry.kev_ransomware) <= 16


def test_a_failed_job_names_the_database_reason():
    from sqlalchemy.exc import DataError
    exc = DataError("INSERT ...", {}, Exception("value too long for type character varying(80)\nDETAIL: x"))
    assert jobs._reason(exc) == "DataError (value too long for type character varying(80))"
    assert jobs._reason(ValueError("secret detail")) == "ValueError"


# ── recommended action and upgrade plan (app/modules/cve/recommend.py) ────

def _with_refs(item, *urls):
    item = copy.deepcopy(item)
    item["cve"]["references"] = [{"url": u, "source": "x", "tags": ["Vendor Advisory"]} for u in urls]
    return item


WINDOWS = _nvd_cve("CVE-2024-38063", matches=[
    _match("cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", end_excl="10.0.20348.2655"),
])
FORTI_NEXT = _nvd_cve("CVE-2024-23113", matches=[
    _match("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", start_incl="7.2.0", end_excl="7.2.9"),
    _match("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", start_incl="7.0.0", end_excl="7.0.16"),
])


class TestRecommendedAction:
    def test_nvd_version_in_the_installed_branch_with_the_vendor_advisory(self, db):
        _load(db, _with_refs(FORTI, "https://example.com/blog", "https://fortiguard.com/psirt/FG-IR-24-015"),
              FORTI_NEXT)
        store.apply_kev(db, feeds.parse_kev(KEV_FEED))
        fw = _asset(db, os_name="FortiOS", os_version="7.2.5")
        old_branch = _asset(db, os_name="FortiOS", os_version="7.0.12")
        r = findings.compute(db, fw.id)
        by_id = {f["cve_id"]: f["action"] for f in r["findings"]}
        a = by_id["CVE-2024-21762"]
        assert a["kind"] == "version" and a["target"] == "7.2.7" and a["check_vendor"]
        assert a["text"] == "Upgrade Fortinet FortiOS to 7.2.7 or later"
        assert a["link"] == {"url": "https://fortiguard.com/psirt/FG-IR-24-015", "label": "fortiguard.com"}
        assert a["kev_action"] == "Apply mitigations per vendor instructions." and a["kev_due"] == "2024-02-16"
        assert by_id["CVE-2024-23113"]["kev_action"] is None          # not known to be exploited
        # the 7.0 branch is told its own fix, not 7.2's
        assert {f["action"]["target"] for f in findings.compute(db, old_branch.id)["findings"]} == {"7.0.14", "7.0.16"}

        # one upgrade closes both: to the highest version either needs
        [step] = r["plan"][fw.id]
        assert step["findings"] == 2 and step["target"] == "7.2.9" and step["kev"] and step["priority"] == 1
        assert step["text"] == "Upgrade Fortinet FortiOS to 7.2.9 or later"
        assert step["cves"] == ["CVE-2024-21762", "CVE-2024-23113"]

    def test_no_fixed_version_points_to_the_vendor_advisory(self, db):
        _load(db, _with_refs(IOSXE, "https://example.com/x",
                             "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"),
              OLD)
        router = _asset(db, os_name="Cisco IOS XE Software", os_version="17.9.1", type_name="Router")
        [f] = findings.compute(db, router.id)["findings"]
        a = f["action"]
        assert a["kind"] == "advisory" and a["target"] is None and not a["check_vendor"]
        assert a["text"] == "No fixed version is known here: follow the vendor's advisory"
        assert a["link"]["label"] == "sec.cloudapps.cisco.com"

        # only the last vulnerable version known: "later than"
        web = _asset(db, os_name="Ubuntu 22.04", type_name="Server")
        db.add(AssetSoftware(asset_id=web.id, vendor="openssl", product="openssl", version="1.0.1e"))
        db.flush()
        [f] = findings.compute(db, web.id)["findings"]
        assert f["action"]["kind"] == "after" and f["action"]["text"] == "Upgrade Openssl to a version later than 1.0.1f"

    def test_windows_cumulative_update_and_the_update_guide(self, db):
        _load(db, WINDOWS)
        srv = _asset(db, os_name="Microsoft Windows Server 2022 Standard", os_version="10.0.20348.2340",
                     type_name="Server")
        r = findings.compute(db, srv.id)
        [f] = r["findings"]
        a = f["action"]
        assert a["kind"] == "windows" and a["target"] == "10.0.20348.2655"
        assert a["text"].startswith("Install the latest cumulative update for ") and "10.0.20348.2655 or later" in a["text"]
        # no Microsoft link among the references: the CVE's page in the Security Update Guide
        assert a["link"]["url"] == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063"
        assert r["plan"][srv.id][0]["kind"] == "windows"

    def test_end_of_life_operating_system_is_said(self, db, monkeypatch):
        from app.modules.cve import recommend
        _load(db, FORTI)
        fw = _asset(db, os_name="FortiOS", os_version="7.2.5")
        monkeypatch.setattr(recommend, "_eol_os", lambda db, ids: {fw.id: {"title": "FortiOS 7.2", "until": "2026-09-28",
                                                                          "latest": "7.2.11"}})
        [f] = findings.compute(db, fw.id)["findings"]
        assert f["action"]["eol"] == {"title": "FortiOS 7.2", "until": "2026-09-28", "latest": "7.2.11"}

    def test_the_findings_api_carries_the_action_and_the_plan(self, db):
        from app.modules.cve.schemas import FindingsResponse
        _load(db, FORTI)
        fw = _asset(db, os_name="FortiOS", os_version="7.2.5")
        r = findings.compute(db, fw.id)
        out = FindingsResponse(**r, database_loaded=True).model_dump()
        assert out["findings"][0]["action"]["kind"] == "version"
        assert out["plan"][fw.id][0]["target"] == "7.2.7"


class TestActionForDistributionPackages:
    """Distribution findings (app/modules/advisories): the fixed package, its commands, Ubuntu Pro, kernels."""

    @staticmethod
    def _f(**kw):
        base = {"source": "advisory", "asset_id": 1, "cve_id": "CVE-2024-6387", "product": "openssh",
                "product_key": "openssh", "package": "openssh", "binaries": ["openssh-server", "openssh-client"],
                "fixed_in": "1:9.6p1-3ubuntu13.3", "availability": "standard", "advisories": ["USN-6859-1"],
                "reboot": False, "kev": False, "release": "ubuntu:24.04"}
        base.update(kw)
        return base

    def test_standard_fix(self):
        from app.modules.cve.recommend import action_for
        a = action_for(self._f(), family="deb")
        assert a["kind"] == "package" and a["text"] == "Upgrade openssh to 1:9.6p1-3ubuntu13.3 or later"
        assert a["commands"] == ["sudo apt-get update",
                                 "sudo apt-get install --only-upgrade openssh-client openssh-server"]
        assert a["link"] == {"url": "https://ubuntu.com/security/notices/USN-6859-1", "label": "USN-6859-1"}
        assert not a["pro"]

    def test_ubuntu_pro_only(self):
        from app.modules.cve.recommend import action_for
        a = action_for(self._f(availability="pro", fixed_in="1:8.2p1-4ubuntu0.11+esm1"), family="deb")
        assert a["pro"] and a["commands"][0] == "sudo pro attach <your-token>"

    def test_kernel(self):
        from app.modules.cve.recommend import action_for
        kernel = dict(package="linux", product="linux", product_key="linux", binaries=["linux-image-6.8.0-45-generic"],
                      fixed_in="6.8.0-45.45")
        a = action_for(self._f(**kernel), family="deb")
        assert a["commands"] == ["sudo apt-get update", "sudo apt-get full-upgrade", "sudo reboot"]
        a = action_for(self._f(**kernel, reboot=True), family="deb")
        assert a["kind"] == "reboot" and a["commands"] == ["sudo reboot"]
        assert a["text"] == "Restart the machine: the fixed kernel 6.8.0-45.45 is installed but not running"

    def test_rpm_and_other_advisory_pages(self):
        from app.modules.cve.recommend import action_for, advisory_page
        a = action_for(self._f(binaries=["openssh-server"], advisories=["RHSA-2024:4312"], release="rhel:9"),
                       family="rpm")
        assert a["commands"] == ["sudo dnf upgrade openssh-server"]
        assert a["link"]["url"] == "https://access.redhat.com/errata/RHSA-2024:4312"
        assert advisory_page("DSA-5724-1") == "https://security-tracker.debian.org/tracker/DSA-5724-1"
        assert advisory_page("RLSA-2024:4312") == "https://osv.dev/vulnerability/RLSA-2024:4312"

    def test_the_plan_takes_the_highest_fixed_version_of_a_package(self):
        from app.modules.cve.recommend import action_for, plan
        rows = []
        for cve, fixed, prio in (("CVE-1", "1:9.6p1-3ubuntu13.3", 3), ("CVE-2", "1:9.6p1-3ubuntu13.5", 2)):
            f = self._f(cve_id=cve, fixed_in=fixed, priority=prio, severity="high")
            f["action"] = action_for(f, family="deb")
            rows.append(f)
        [step] = plan(rows)[1]
        assert step["target"] == "1:9.6p1-3ubuntu13.5" and step["findings"] == 2 and step["priority"] == 2


class TestActionInAlertEmails:
    def test_email_lines_and_the_alert_body(self, db):
        from app.models.notification import Alert, NotificationRule
        from app.modules.alerts import engine as alert_engine
        from app.modules.cve.recommend import email_lines
        _load(db, _with_refs(FORTI, "https://fortiguard.com/psirt/FG-IR-24-015"))
        store.apply_kev(db, feeds.parse_kev(KEV_FEED))
        fw = _asset(db, os_name="FortiOS", os_version="7.2.5")
        lines = email_lines(db, [fw.id], {fw.id: "FW-HQ"})
        assert lines[:3] == ["What to do on FW-HQ:", "  - Upgrade Fortinet FortiOS to 7.2.7 or later",
                             "      https://fortiguard.com/psirt/FG-IR-24-015"]

        rule = NotificationRule(event_type="cve.kev_finding", name="Exploited vulnerability", enabled=True,
                                severity="critical", params={}, asset_scope="all", asset_filter={},
                                recipients={"emails": ["soc@example.com"]}, channels=["email"], repeat_minutes=0,
                                notify_resolved=False, group_minutes=0, builtin=False)
        db.add(rule)
        db.flush()
        alert = Alert(rule_id=rule.id, event_type="cve.kev_finding", module="cve", severity="critical",
                      fingerprint=f"{rule.id}:kev:{fw.id}", title="Exploited vulnerability on an asset",
                      detail="CVE-2024-21762", asset_id=fw.id, source_label="FW-HQ · 10.0.0.1", status="active")
        db.add(alert)
        db.flush()
        [d] = alert_engine.queue_message(db, rule, "raised", [alert], datetime.utcnow())
        assert "What to do on FW-HQ:" in d.body and "Upgrade Fortinet FortiOS to 7.2.7 or later" in d.body
