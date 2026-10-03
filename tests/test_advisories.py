"""
Distribution security advisories (app/modules/advisories): version order as
dpkg and rpm decide it, OSV records to rows, releases, the collection of the
release and running kernel, matching (source versions, kernels, Ubuntu Pro,
no fix yet), the findings every page reads, loading and updating (archive
import, incremental online update), signed packages and the daily update.

Everything runs inside a rolled-back transaction.
"""
import io
import json
import sys
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset
from app.models.advisory import DistroFeed, DistroVuln
from app.models.asset_types import AssetType
from app.modules.advisories import jobs as adv_jobs
from app.modules.advisories import match, osv, releases, service, store
from app.modules.advisories.versions import deb_compare, rpm_compare
from app.modules.cve import findings
from app.modules.cve import jobs as cve_jobs
from app.modules.cve import package
from app.modules.cve import settings as cve_settings
from app.modules.software import collect
from app.modules.software import store as sw_store

sys.path.insert(0, str(Path(__file__).parent))
from test_cve import _loaded_db  # noqa: E402


@pytest.fixture
def db():
    connection = db_engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    match._cache.clear()
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()
        match._cache.clear()


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


def _asset(db):
    t = AssetType(type_name=f"Linux {_n()}", category="server")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"adv-asset-{_n()}", asset_type_id=t.id, ip_address=f"10.77.{_n() % 250}.{_n() % 250}")
    db.add(a)
    db.flush()
    return a


def _deb(name, version, src, src_version=None):
    return {"name": name, "version": version, "arch": "amd64", "source": "distro", "origin": "Ubuntu",
            "publisher": None, "kind": "package", "source_package": src, "vkind": "deb", "source_version": src_version}


def _os(release_id="ubuntu", version="22.04", kernel="5.15.0-91-generic", reboot=False):
    return {"name": "Ubuntu", "version": version, "arch": None, "source": "distro", "origin": "jammy",
            "publisher": None, "kind": "os", "source_package": None, "vkind": None,
            "platform": {"id": release_id, "version_id": version, "codename": "jammy", "pretty": "Ubuntu 22.04.4 LTS",
                         "kernel": kernel, "reboot_required": reboot, "reboot_packages": []}}


def _vuln(release, package, cve, fixed=None, kind="cve", record=None, stream="Ubuntu:22.04:LTS",
          availability="standard", severity="high", introduced=None, last=None):
    return DistroVuln(release=release, stream=stream, package=package, record_id=record or f"UBUNTU-{cve}",
                      kind=kind, introduced=introduced, fixed=fixed, last_affected=last, cves=[cve], severity=severity,
                      availability=availability, title=f"{package} issue", modified=datetime(2026, 9, 1))


def _feed(db, release, when=datetime(2026, 9, 1)):
    db.add(DistroFeed(release=release, rows=1, records=1, watermark=when, updated_at=datetime.utcnow(),
                      source="online"))
    db.flush()


# ── version order ─────────────────────────────────────────────────────────

def test_dpkg_order():
    for a, b, want in (("1.0~rc1", "1.0", -1), ("1:1.0", "2.0", 1), ("1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10", -1),
                       ("1.0+b1", "1.0", 1), ("1.0~~", "1.0~", -1), ("0:1.0", "1.0", 0),
                       ("5.15.0-91.101", "5.15.0-105.115", -1), ("1.2.3", "1.2.3-0", 0)):
        assert deb_compare(a, b) == want, (a, b)


def test_rpm_order():
    for a, b, want in (("1.0~rc1", "1.0", -1), ("1.0^", "1.0", 1), ("1.0^git1", "1.0.1", -1), ("2.0a", "2.0", 1),
                       ("0:115.6.0-1.el8_9", "115.6.0-1.el8_8", 1), ("1:1.0-1", "2.0-1", 1),
                       ("8.7p1-34.el9", "8.7p1-38.el9_4.1", -1), ("1.0010", "1.9", 1), ("1.05", "1.5", 0),
                       ("1.0-1", "1.0", 0), ("2a", "2.0", -1)):
        assert rpm_compare(a, b) == want, (a, b)


def test_cvss3_base_score():
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H") == 9.9
    assert osv.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert osv.cvss3_score("garbage") is None


# ── OSV records ───────────────────────────────────────────────────────────

def _affected(eco, name, events, **es):
    a = {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
    if es:
        a["ecosystem_specific"] = es
    return a


def test_ubuntu_records_to_rows():
    rec = {"id": "UBUNTU-CVE-2024-6387", "modified": "2024-07-01T00:00:00Z", "summary": "",
           "details": "A security regression in sshd.\nmore", "affected": [
               _affected("Ubuntu:22.04:LTS", "openssh", [{"introduced": "0"}, {"fixed": "1:8.9p1-3ubuntu0.10"}],
                         ubuntu_priority="high"),
               _affected("Ubuntu:Pro:18.04:LTS", "openssh", [{"introduced": "0"}, {"fixed": "1:7.6p1-4ubuntu0.7+esm1"}]),
               _affected("Ubuntu:24.04:LTS", "openssh", [{"introduced": "0"}]),
               _affected("Ubuntu:22.04:LTS", "linux-aws", [{"introduced": "0"}]),        # kernel, no fix: dropped
               _affected("Ubuntu:22.04:LTS", "linux", [{"introduced": "0"}, {"fixed": "5.15.0-105.115"}]),
               _affected("Alpine:v3.19", "openssh", [{"introduced": "0"}, {"fixed": "9.6"}]),
           ]}
    rows = osv.rows_from(rec)
    by = {(r["release"], r["package"]): r for r in rows}
    assert set(by) == {("ubuntu:22.04", "openssh"), ("ubuntu:18.04", "openssh"), ("ubuntu:24.04", "openssh"),
                       ("ubuntu:22.04", "linux")}
    jammy = by[("ubuntu:22.04", "openssh")]
    assert jammy["kind"] == "cve" and jammy["cves"] == ["CVE-2024-6387"] and jammy["severity"] == "high"
    assert jammy["fixed"] == "1:8.9p1-3ubuntu0.10" and jammy["title"] == "A security regression in sshd."
    assert by[("ubuntu:18.04", "openssh")]["availability"] == "pro"
    assert by[("ubuntu:24.04", "openssh")]["fixed"] is None
    assert [r["release"] for r in osv.rows_from(rec, {"ubuntu:24.04"})] == ["ubuntu:24.04"]


def test_rpm_advisories_to_rows():
    rhsa = {"id": "RHSA-2024:0001", "summary": "Red Hat Security Advisory: thunderbird security update",
            "upstream": ["CVE-2023-6856", "CVE-2023-50761"],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}],
            "affected": [_affected("Red Hat:enterprise_linux:9::appstream", "thunderbird",
                                   [{"introduced": "0"}, {"fixed": "0:115.6.0-1.el9_3"}]),
                         _affected("Red Hat:enterprise_linux:9::appstream", "thunderbird-debuginfo",
                                   [{"introduced": "0"}, {"fixed": "0:115.6.0-1.el9_3"}]),
                         _affected("Red Hat:rhel_eus:9.2::appstream", "thunderbird",
                                   [{"introduced": "0"}, {"fixed": "0:115.6.0-1.el9_2"}])]}
    rows = osv.rows_from(rhsa)
    assert [(r["release"], r["package"]) for r in rows] == [("rhel:9", "thunderbird")]
    assert rows[0]["kind"] == "advisory" and rows[0]["cves"] == ["CVE-2023-50761", "CVE-2023-6856"]
    assert rows[0]["severity"] == "high"                                   # from the CVSS vector (8.8)
    rlsa = {"id": "RLSA-2024:0003", "summary": "Important: thunderbird security update", "upstream": ["CVE-2023-6856"],
            "affected": [_affected("Rocky Linux:8", "thunderbird", [{"introduced": "0"}, {"fixed": "0:115.6.0-1.el8_9"}])]}
    assert osv.rows_from(rlsa)[0]["severity"] == "high"
    bugfix = {"id": "RHBA-2024:0100", "affected": rlsa["affected"]}
    assert osv.rows_from(bugfix) == []                                     # not security, no CVE
    assert osv.rows_from({**rlsa, "withdrawn": "2024-01-02T00:00:00Z"}) == []


def test_releases():
    assert releases.from_platform({"id": "ubuntu", "version_id": "22.04"}) == ("ubuntu:22.04", "ok")
    assert releases.from_platform({"id": "rocky", "version_id": "9.4"}) == ("rocky:9", "ok")
    assert releases.from_platform({"id": "almalinux", "version_id": "8.10"}) == ("alma:8", "ok")
    assert releases.from_platform({"id": "rhel", "version_id": "9.4"}) == ("rhel:9", "ok")
    assert releases.from_platform({"id": "centos", "version_id": "7"}) == (None, "unsupported")
    assert releases.from_platform({}) == (None, "unknown")
    assert releases.label("ubuntu:22.04") == "Ubuntu 22.04 LTS" and releases.label("ubuntu:23.10") == "Ubuntu 23.10"
    assert releases.label("rhel:9") == "Red Hat Enterprise Linux 9"
    assert releases.from_ecosystem("Ubuntu:Pro:FIPS-updates:22.04:LTS") is None
    assert releases.bundles("ubuntu:22.04") == ["Ubuntu"]       # the per-release archives stopped in 2024
    assert releases.valid("debian:12") and not releases.valid("debian:x") and not releases.valid("windows:11")


# ── collection ────────────────────────────────────────────────────────────

def test_collection_reads_release_kernel_and_source_versions():
    outputs = {
        "deb_packages": "libldb2:amd64\t2:2.4.4+samba4.15.13+dfsg-0ubuntu1.6\tamd64\tsamba\tii \t"
                        "2:4.15.13+dfsg-0ubuntu1.6\nopenssl\t3.0.2-0ubuntu1.15\tamd64\topenssl\tii \t3.0.2-0ubuntu1.15\n",
        "deb_sources": "", "deb_repos": "",
        "os_release": 'NAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\nID=ubuntu\n'
                      'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n',
        "kernel": "5.15.0-91-generic\n", "reboot": "linux-base\n__REBOOT_REQUIRED__\n",
    }
    items = collect.parse_linux("debian", outputs)
    pk = {i["name"]: i for i in items if i["kind"] == "package"}
    assert pk["libldb2"]["source_version"] == "2:4.15.13+dfsg-0ubuntu1.6"
    assert pk["openssl"]["source_version"] is None                          # same as the binary
    os_item = next(i for i in items if i["kind"] == "os")
    assert os_item["platform"] == {"id": "ubuntu", "version_id": "22.04", "codename": "jammy",
                                   "pretty": "Ubuntu 22.04.4 LTS", "kernel": "5.15.0-91-generic",
                                   "reboot_required": True, "reboot_packages": ["linux-base"]}
    rpm = collect._dedupe([{"name": "kernel", "arch": "x86_64", "version": v, "vkind": "rpm"}
                           for v in ("5.14.0-1.el9", "5.14.0-2.el9")])
    assert len(rpm) == 2                                                    # every installed kernel is kept


# ── matching ──────────────────────────────────────────────────────────────

def _jammy_host(db, kernel="5.15.0-91-generic"):
    a = _asset(db)
    sw_store.save(db, a.id, "linux", [
        _deb("openssh-server", "1:8.9p1-3ubuntu0.6", "openssh"),
        _deb("openssh-client", "1:8.9p1-3ubuntu0.6", "openssh"),
        _deb("libldb2", "2:2.4.4+samba4.15.13+dfsg-0ubuntu1.6", "samba", "2:4.15.13+dfsg-0ubuntu1.6"),
        _deb("linux-libc-dev", "5.15.0-91.101", "linux"),
        _deb("linux-image-5.15.0-91-generic", "5.15.0-91.101", "linux-signed"),
        _deb("linux-image-5.15.0-105-generic", "5.15.0-105.115", "linux-signed"),
        _deb("linux-image-generic", "5.15.0.105.105", "linux-meta"),
        _deb("vim", "2:8.2.3995-1ubuntu2.17", "vim"),
        _os(kernel=kernel),
    ])
    return a


def _jammy_advisories(db):
    _feed(db, "ubuntu:22.04")
    db.add_all([
        _vuln("ubuntu:22.04", "openssh", "CVE-2024-6387", "1:8.9p1-3ubuntu0.10"),
        _vuln("ubuntu:22.04", "openssh", "CVE-2024-6387", "1:8.9p1-3ubuntu0.10", kind="advisory", record="USN-6859-1"),
        _vuln("ubuntu:22.04", "openssh", "CVE-2023-1111", "1:8.9p1-3ubuntu0.4"),          # already fixed
        _vuln("ubuntu:22.04", "openssh", "CVE-2025-9999", None, severity="medium"),        # no fix yet
        _vuln("ubuntu:22.04", "samba", "CVE-2022-0001", "2:4.15.9+dfsg-0ubuntu0.2"),      # source is newer
        _vuln("ubuntu:22.04", "samba", "CVE-2024-0002", "2:4.15.13+dfsg-0ubuntu1.7"),
        _vuln("ubuntu:22.04", "linux", "CVE-2024-0003", "5.15.0-105.115"),
        _vuln("ubuntu:22.04", "vim", "CVE-2024-0004", "2:8.2.3995-1ubuntu2.18+esm1", stream="Ubuntu:Pro:22.04:LTS",
              availability="pro", severity="medium"),
    ])
    db.flush()


def test_matching_by_source_with_kernels_pro_and_unfixed(db):
    a = _jammy_host(db)
    _jammy_advisories(db)
    res = match.analyse(db, [a.id])[a.id]
    assert res.status == "ok" and res.release == "ubuntu:22.04" and res.label == "Ubuntu 22.04 LTS"
    found = {f["cve_id"]: f for f in res.findings}
    assert set(found) == {"CVE-2024-6387", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"}
    ssh = found["CVE-2024-6387"]
    assert ssh["package"] == "openssh" and ssh["binaries"] == ["openssh-client", "openssh-server"]
    assert ssh["advisories"] == ["USN-6859-1"] and ssh["fixed_in"] == "1:8.9p1-3ubuntu0.10"
    assert found["CVE-2024-0002"]["installed"] == "2:4.15.13+dfsg-0ubuntu1.6"   # compared by the source version
    kernel = found["CVE-2024-0003"]
    # only the running kernel counts (not linux-libc-dev, not the newer image), and the fix is installed
    assert kernel["binaries"] == ["linux-image-5.15.0-91-generic"] and kernel["kernel"] and kernel["reboot"]
    assert res.reboot_required and res.newest_kernel == "5.15.0-105"
    assert found["CVE-2024-0004"]["availability"] == "pro"
    assert [u["cve_id"] for u in res.unfixed] == ["CVE-2025-9999"]


def test_kernel_after_the_reboot_and_a_foreign_kernel(db):
    a = _jammy_host(db, kernel="5.15.0-105-generic")
    _jammy_advisories(db)
    res = match.analyse(db, [a.id])[a.id]
    assert "CVE-2024-0003" not in {f["cve_id"] for f in res.findings} and not res.reboot_required
    b = _jammy_host(db, kernel="6.18.44-fc-v64")                         # a container on another host's kernel
    assert "CVE-2024-0003" not in {f["cve_id"] for f in match.analyse(db, [b.id])[b.id].findings}


def test_status_without_loaded_or_supported_release(db):
    a = _jammy_host(db)
    assert match.analyse(db, [a.id])[a.id].status == "not_loaded"
    c = _asset(db)
    sw_store.save(db, c.id, "linux", [_deb("bash", "5.1", "bash"),
                                      {**_os(), "platform": {"id": "centos", "version_id": "7", "pretty": "CentOS 7"}}])
    res = match.analyse(db, [c.id])[c.id]
    assert res.status == "unsupported" and res.label == "CentOS 7"


def test_findings_every_page_reads(db):
    a = _jammy_host(db)
    _jammy_advisories(db)
    out = findings.compute(db, a.id)
    rows = {f["cve_id"]: f for f in out["findings"]}
    ssh = rows["CVE-2024-6387"]
    assert ssh["source"] == "advisory" and ssh["vendor"] == "Ubuntu 22.04 LTS" and ssh["product"] == "openssh"
    assert ssh["priority"] == 3 and ssh["severity"] == "high"         # no NVD entry: the distribution's priority
    assert out["summary"]["from_advisories"] == 4 and out["summary"]["reboot_assets"] == 1
    assert out["assets"][0]["advisory_status"] == "ok" and out["assets"][0]["reboot_required"]
    assert cve_settings.vulnerability_data_loaded(db)

    upd = service.security_updates(db, a.id)
    assert upd["status"] == "ok" and upd["summary"]["packages"] == 4 and upd["summary"]["unfixed"] == 1
    groups = {u["package"]: u for u in upd["updates"]}
    assert groups["linux"]["reboot"] and groups["vim"]["availability"] == "pro"
    assert upd["commands"] == ["sudo apt-get update",
                               "sudo apt-get install --only-upgrade libldb2 openssh-client openssh-server",
                               "sudo reboot"]                     # vim needs Ubuntu Pro: left out


# ── loading and updating ──────────────────────────────────────────────────

class _Job:
    id = 0

    def __init__(self):
        self.stats = {}

    def progress(self, *a, **k):
        pass

    def check(self):
        pass

    def cancelled(self):
        return False


def _zip(path, records):
    with zipfile.ZipFile(path, "w") as zf:
        for r in records:
            zf.writestr(f"{r['id']}.json", json.dumps(r))
    return str(path)


def _ucve(cve, eco_fixed):
    return {"id": f"UBUNTU-{cve}", "modified": "2026-09-30T10:00:00Z",
            "affected": [_affected(eco, "openssl", [{"introduced": "0"}, {"fixed": fx}]) for eco, fx in eco_fixed]}


def test_archive_import_takes_only_the_release_it_is_about(db, tmp_path):
    # a per-release archive (every record names 22.04) also names 24.04 in some records
    path = _zip(tmp_path / "jammy.zip", [_ucve(f"CVE-2026-{i:04d}", [("Ubuntu:22.04:LTS", "3.0.2-0ubuntu1.20")]
                                               + ([("Ubuntu:24.04:LTS", "3.0.13-0ubuntu3.9")] if i % 3 == 0 else []))
                                         for i in range(30)])
    j = _Job()
    adv_jobs.import_zip(j, db, path)
    assert j.stats["loaded"] == ["ubuntu:22.04"] and j.stats["rows"] == 30 and len(j.stats["sha256"]) == 64
    feed = db.query(DistroFeed).filter_by(release="ubuntu:22.04").one()
    assert feed.records == 30 and feed.source == "osv_zip" and feed.watermark == datetime(2026, 9, 30, 10)
    # a distribution-wide archive: no release dominates, every release in it is complete; the ones this
    # instance keeps are taken (24.04 is neither in use nor asked for)
    path = _zip(tmp_path / "all.zip", [_ucve("CVE-2026-1000", [("Ubuntu:22.04:LTS", "1")]),
                                        _ucve("CVE-2026-1001", [("Ubuntu:24.04:LTS", "1")])])
    j = _Job()
    adv_jobs.import_zip(j, db, path)
    assert j.stats["loaded"] == ["ubuntu:22.04"]
    assert db.query(DistroFeed).filter_by(release="ubuntu:22.04").one().records == 1      # replaced
    # a file of releases this instance keeps none of: all of them (an explicit import)
    deb = {"id": "CVE-2026-2000", "modified": "2026-09-30T10:00:00Z", "affected": [
        _affected("Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u1"}]),
        _affected("Debian:11", "openssl", [{"introduced": "0"}, {"fixed": "1.1.1w-0+deb11u2"}])]}
    j = _Job()
    adv_jobs.import_zip(j, db, _zip(tmp_path / "debian.zip", [deb]))
    assert sorted(j.stats["loaded"]) == ["debian:11", "debian:12"]
    with pytest.raises(osv.FeedError):
        adv_jobs.import_zip(_Job(), db, _zip(tmp_path / "none.zip", [{"id": "GHSA-1", "affected": []}]))


class _FakeOsv:
    def __init__(self, archive, changed, records):
        self.archive, self.changed, self.records_ = archive, changed, records
        self.downloads = []

    def download(self, ecosystem, dest, on_progress=None, cancelled=None):
        self.downloads.append(ecosystem)
        Path(dest).write_bytes(Path(self.archive).read_bytes())
        return True

    def changed_since(self, ecosystem, since, limit):
        return [(w, i) for w, i in self.changed if w > since]

    def records(self, ecosystem, ids, cancelled=None, on_progress=None):
        for i in ids:
            yield i, self.records_.get(i)


def test_online_full_then_incremental(db, tmp_path, monkeypatch):
    a = _jammy_host(db)
    archive = _zip(tmp_path / "Ubuntu.zip", [_ucve("CVE-2026-0001", [("Ubuntu:22.04:LTS", "1:8.9p1-3ubuntu0.10")])])
    changed_rec = {"id": "UBUNTU-CVE-2026-0001", "modified": "2026-10-02T08:00:00Z",
                   "affected": [_affected("Ubuntu:22.04:LTS", "openssl", [{"introduced": "0"},
                                                                         {"fixed": "3.0.2-0ubuntu1.21"}])]}
    fake = _FakeOsv(archive, [(datetime(2026, 10, 2, 8), "UBUNTU-CVE-2026-0001")], {"UBUNTU-CVE-2026-0001": changed_rec})
    monkeypatch.setattr(adv_jobs, "make_client", lambda: fake)
    j = _Job()
    adv_jobs.online(j, db, str(tmp_path))
    assert fake.downloads == ["Ubuntu"] and j.stats["loaded"] == ["ubuntu:22.04"]
    assert store.in_use(db) == {"ubuntu:22.04": [a.id]}
    j = _Job()
    adv_jobs.online(j, db, str(tmp_path))                                    # now incremental
    assert j.stats["updated"] == ["ubuntu:22.04"] and j.stats["records"] == 1
    rows = db.query(DistroVuln).filter_by(record_id="UBUNTU-CVE-2026-0001").all()
    assert [r.fixed for r in rows] == ["3.0.2-0ubuntu1.21"]                  # replaced, not added
    assert db.query(DistroFeed).filter_by(release="ubuntu:22.04").one().watermark == datetime(2026, 10, 2, 8)


def test_signed_package_carries_the_advisories(db, tmp_path):
    _loaded_db(db)
    _jammy_advisories(db)
    path = str(tmp_path / "full.ngcve")
    manifest = package.build(db, path, "full")
    assert manifest["advisories"]["ubuntu:22.04"]["rows"] == 1                # the feed row's own count
    assert package.verify(db, path).importable
    rows = list(package.read_advisories(path))
    assert len(rows) == 8 and {r["release"] for r in rows} == {"ubuntu:22.04"}
    db.query(DistroVuln).delete()
    db.query(DistroFeed).delete()
    taken = adv_jobs.apply_package(db, manifest["advisories"], iter(rows), lambda: None)
    assert taken == ["ubuntu:22.04"] and db.query(DistroVuln).count() == 8
    assert adv_jobs.apply_package(db, manifest["advisories"], iter(rows), lambda: None) == []   # not newer


def test_daily_update_and_first_load(db):
    cve_settings.put(db, store.AUTO, {"enabled": True})
    cve_settings.put(db, cve_settings.AUTO_UPDATE, {"enabled": False, "time": "02:00"})
    db.flush()
    _jammy_host(db)
    # a release in use and never loaded: due at once, then not again within the hour
    assert cve_jobs.advisories_due(db, datetime(2026, 10, 3, 1, 0))
    cve_settings.put(db, store.LAST_ATTEMPT, datetime(2026, 10, 3, 1, 0).isoformat())
    assert not cve_jobs.advisories_due(db, datetime(2026, 10, 3, 1, 30))
    _feed(db, "ubuntu:22.04")
    assert not cve_jobs.advisories_due(db, datetime(2026, 10, 3, 1, 59))     # loaded: waits for 02:00
    assert cve_jobs.advisories_due(db, datetime(2026, 10, 3, 2, 5))
    cve_settings.put(db, store.LAST_AUTO_RUN, "2026-10-03")
    assert not cve_jobs.advisories_due(db, datetime(2026, 10, 3, 9, 0))
    cve_settings.put(db, store.AUTO, {"enabled": False})
    assert not cve_jobs.advisories_due(db, datetime(2026, 10, 4, 9, 0))


def test_settings_and_removing_a_release(db):
    service.set_settings(db, True, ["debian:12", "debian:12"])
    assert store.extra(db) == ["debian:12"] and "debian:12" in store.tracked(db)
    with pytest.raises(ValueError):
        service.set_settings(db, None, ["windows:11"])
    _jammy_host(db)
    _feed(db, "ubuntu:22.04")
    assert not service.remove_release(db, "ubuntu:22.04")                   # in use
    assert service.remove_release(db, "debian:12") and "debian:12" not in store.tracked(db)
    st = service.status(db)
    assert [r["release"] for r in st["releases"]] == ["ubuntu:22.04"] and st["releases"][0]["assets"] == 1
