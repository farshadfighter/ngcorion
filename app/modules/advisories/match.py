"""
Matching installed distribution packages against the advisories.

For every Linux asset with a known, loaded release: each package from the
distribution's own repositories (SoftwareItem.source "distro") is looked up
by the name the distribution publishes under - the source package on
Debian/Ubuntu, the binary package on RHEL/Rocky/Alma - and its installed
version is compared with every affected range, by dpkg or rpm rules.

  finding   installed < fixed version: the CVE is open and an update fixes it
  unfixed   affected, and the distribution has no fix yet (shown for
            information; not a finding - there is nothing to install)

Kernels: several stay installed, one runs. Only the running kernel's
packages count (when the running kernel is not known, the newest installed);
a fix that is installed but not yet running is reported as "reboot needed".

Evaluations are cached per (release, package, version) for the life of the
loaded data, so the per-asset calls of the risk engine stay cheap.
"""
import re
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import func, tuple_
from sqlalchemy.orm import Session

from app.models.advisory import AVAILABILITY_PRO, AVAILABILITY_STANDARD, KIND_ADVISORY, DistroFeed, DistroVuln
from app.models.software import SoftwareItem
from app.modules.advisories import releases, store
from app.modules.advisories.versions import compare

# Ubuntu builds the kernel image from linux-signed[-flavour] and the
# metapackages from linux-meta[-flavour]; advisories name linux[-flavour].
_DEB_SIGNED = re.compile(r"^linux-signed(-.+)?$")
_DEB_META = re.compile(r"^linux-meta(-.+)?$")
_DEB_SIGNED_DEBIAN = re.compile(r"^linux-signed-(amd64|arm64|i386|armhf|ppc64el|s390x)$")
# Kernel packages of one ABI: linux-image-5.15.0-91-generic, linux-modules-5.15.0-91-generic, ...
_DEB_KERNEL_ABI = re.compile(r"^linux-(?:image(?:-unsigned)?|modules(?:-extra)?|headers|tools|cloud-tools|buildinfo|"
                             r"objects|signatures|modules-nvidia[\w.-]*)-(\d+\.\d+\.\d+-\d+)")
# Packages built from a kernel source that are not a kernel (headers for
# userspace, tools, documentation): kernel CVEs do not apply to them.
_DEB_KERNEL_HELPER = re.compile(r"^linux-(libc-dev|tools-common|cloud-tools-common|doc|source(-[\d.]+)?|tools-host|"
                                r"bpf-dev|perf)$")
_RPM_KERNEL = re.compile(r"^kernel(-(core|modules|modules-core|modules-extra|devel|uek|uek-core|uek-modules|rt|"
                         r"rt-core|rt-modules|debug|debug-core|debug-modules))?$")
_ARCH = re.compile(r"\.(x86_64|aarch64|ppc64le|s390x|i686|noarch)(\+\w+)?$")
_SEV_PRIORITY = {"critical": 2, "high": 3, "medium": 4, "low": 4}

_cache_lock = threading.Lock()
_cache: Dict[Tuple[str, str, str], tuple] = {}
_cache_stamp: Optional[tuple] = None
MAX_CACHE = 400_000


@dataclass
class Hit:
    cve: str
    package: str              # the published name (source package / rpm name)
    fixed: Optional[str]      # None: no fix yet
    availability: str
    severity: Optional[str]
    advisories: Set[str] = field(default_factory=set)
    title: Optional[str] = None


@dataclass
class AssetAdvisories:
    asset_id: int
    platform: dict
    release: Optional[str]
    status: str               # ok | not_loaded | unsupported | unknown
    label: Optional[str]
    running_kernel: Optional[str] = None
    newest_kernel: Optional[str] = None
    reboot_required: bool = False
    findings: List[dict] = field(default_factory=list)
    unfixed: List[dict] = field(default_factory=list)


def _deb_key(item) -> Optional[str]:
    src = (item.source_package or item.name or "").split(" ")[0]
    if _DEB_META.match(src):
        return None                       # metapackages carry no code
    if _DEB_SIGNED_DEBIAN.match(src):
        return "linux"
    m = _DEB_SIGNED.match(src)
    if m:
        return "linux" + (m.group(1) or "")
    return src


def _affected(family: str, version: str, introduced, fixed, last) -> bool:
    if introduced and compare(family, version, introduced) < 0:
        return False
    if fixed:
        return compare(family, version, fixed) < 0
    if last:
        return compare(family, version, last) <= 0
    return True


def _stamp(db: Session) -> tuple:
    return tuple(db.query(func.count(DistroFeed.id), func.max(DistroFeed.updated_at)).one())


def _evaluate(db: Session, needed: Set[Tuple[str, str, str]]) -> Dict[Tuple[str, str, str], tuple]:
    """(release, package, version) -> tuple of (cve, kind, record_id, fixed,
    availability, severity, title, state); state: open | unfixed | fixed."""
    global _cache_stamp
    stamp = _stamp(db)
    with _cache_lock:
        if stamp != _cache_stamp or len(_cache) > MAX_CACHE:
            _cache.clear()
            _cache_stamp = stamp
        out = {k: _cache[k] for k in needed if k in _cache}
    missing = needed - set(out)
    if not missing:
        return out
    pairs = sorted({(r, p) for r, p, _ in missing})
    rows: Dict[Tuple[str, str], list] = defaultdict(list)
    cols = (DistroVuln.release, DistroVuln.package, DistroVuln.cves, DistroVuln.kind, DistroVuln.record_id,
            DistroVuln.introduced, DistroVuln.fixed, DistroVuln.last_affected, DistroVuln.availability,
            DistroVuln.severity, DistroVuln.title)
    for k in range(0, len(pairs), 500):
        for r in db.query(*cols).filter(tuple_(DistroVuln.release, DistroVuln.package).in_(pairs[k:k + 500])):
            rows[(r[0], r[1])].append(r)
    fresh = {}
    for release, package, version in missing:
        fam = releases.family(release)
        res = []
        for r in rows.get((release, package), ()):
            _, _, cves, kind, rid, introduced, fixed, last, avail, sev, title = r
            if introduced and compare(fam, version, introduced) < 0:
                continue
            if fixed:
                state = "open" if compare(fam, version, fixed) < 0 else "fixed"
            elif last:
                if compare(fam, version, last) > 0:
                    continue
                state = "unfixed"
            else:
                state = "unfixed"
            for cve in cves or ():
                res.append((cve, kind, rid, fixed, avail, sev, title, state))
        fresh[(release, package, version)] = tuple(res)
    with _cache_lock:
        if _cache_stamp == stamp:
            _cache.update(fresh)
    out.update(fresh)
    return out


def _kernel_filter(family: str, items: list, running: Optional[str]):
    """(items that count, newest kernel version, running kernel version)."""
    if family == "deb":
        abis = {}
        for it in items:
            m = _DEB_KERNEL_ABI.match(it.name)
            if m:
                abis[it] = m.group(1)
        if not abis:
            return items, None, None
        newest = max(set(abis.values()), key=_AbiKey)
        run = None
        if running:
            m = re.match(r"^(\d+\.\d+\.\d+-\d+)", running)
            run = m.group(1) if m else "foreign"
        # Unknown running kernel: the newest counts. A running kernel that is
        # not one of these (removed, or not the distribution's): none does.
        keep_abi = newest if run is None else (run if run in set(abis.values()) else None)
        kept = [it for it in items if it not in abis or abis[it] == keep_abi]
        return kept, newest, (None if run == "foreign" else run)
    kernels = [it for it in items if _RPM_KERNEL.match(it.name)]
    if not kernels:
        return items, None, None
    versions = {re.sub(r"^0:", "", it.version or "") for it in kernels}
    newest = max(versions, key=_RpmKey)
    run = _ARCH.sub("", running) if running else None
    keep = run if run in versions else (newest if not run else None)
    kept = [it for it in items if it not in kernels or re.sub(r"^0:", "", it.version or "") == keep]
    return kept, newest, run


class _AbiKey:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return compare("deb", self.v, other.v) < 0


class _RpmKey:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return compare("rpm", self.v, other.v) < 0


def analyse(db: Session, asset_ids: Optional[Iterable[int]] = None) -> Dict[int, AssetAdvisories]:
    plats = store.platforms(db, asset_ids)
    if not plats:
        return {}
    loaded = {r for (r,) in db.query(DistroFeed.release).filter(DistroFeed.watermark.isnot(None))}
    results: Dict[int, AssetAdvisories] = {}
    for aid, platform in plats.items():
        release, status = releases.from_platform(platform)
        if status == "ok" and release not in loaded:
            status = "not_loaded"
        results[aid] = AssetAdvisories(aid, platform, release, status,
                                       releases.label(release) if release else releases.platform_label(platform),
                                       running_kernel=platform.get("kernel"),
                                       reboot_required=bool(platform.get("reboot_required")))
    active = [aid for aid, r in results.items() if r.status == "ok"]
    if not active:
        return results

    items = defaultdict(list)
    for it in (db.query(SoftwareItem)
               .filter(SoftwareItem.asset_id.in_(active), SoftwareItem.collector == "linux",
                       SoftwareItem.kind == "package", SoftwareItem.source == "distro",
                       SoftwareItem.version.isnot(None))):
        items[it.asset_id].append(it)

    per_asset = {}
    needed = set()
    for aid in active:
        res = results[aid]
        fam = releases.family(res.release)
        kept, newest, run = _kernel_filter(fam, items[aid], res.running_kernel)
        res.newest_kernel = newest
        if newest and run and compare(fam, run, newest) < 0:
            res.reboot_required = True
        keyed = []
        for it in kept:
            if fam == "deb":
                if _DEB_KERNEL_HELPER.match(it.name):
                    continue
                key, version = _deb_key(it), it.source_version or it.version
            else:
                key, version = it.name, it.version
            if key:
                keyed.append((key, version, it))
                needed.add((res.release, key, version))
        per_asset[aid] = (keyed, items[aid])
    evaluated = _evaluate(db, needed)

    for aid in active:
        res = results[aid]
        fam = releases.family(res.release)
        keyed, all_items = per_asset[aid]
        # per (package, cve): what applies
        opened: Dict[Tuple[str, str], dict] = {}
        resolved: Set[Tuple[str, str]] = set()
        unfixed: Dict[Tuple[str, str], dict] = {}
        for key, version, it in keyed:
            for cve, kind, rid, fixed, avail, sev, title, state in evaluated.get((res.release, key, version), ()):
                k = (key, cve)
                if state == "fixed":
                    resolved.add(k)
                    continue
                if state == "unfixed":
                    u = unfixed.setdefault(k, {"cve_id": cve, "package": key, "binaries": set(),
                                               "installed": version, "severity": None,
                                               "availability": avail})
                    u["binaries"].add(it.name)
                    u["severity"] = u["severity"] or sev
                    continue
                f = opened.setdefault(k, {"cve_id": cve, "package": key, "binaries": set(), "installed": version,
                                          "fixed": {}, "advisories": set(), "severity": None, "title": None})
                f["binaries"].add(it.name)
                if compare(fam, version, f["installed"]) < 0:
                    f["installed"] = version
                prev = f["fixed"].get(avail)
                if prev is None or compare(fam, fixed, prev) > 0:
                    f["fixed"][avail] = fixed
                if kind == KIND_ADVISORY:
                    f["advisories"].add(rid)
                    f["title"] = f["title"] or title
                f["severity"] = f["severity"] or sev
        for k, f in opened.items():
            if AVAILABILITY_STANDARD in f["fixed"]:
                fixed, avail = f["fixed"][AVAILABILITY_STANDARD], AVAILABILITY_STANDARD
            else:
                fixed, avail = f["fixed"].get(AVAILABILITY_PRO), AVAILABILITY_PRO
            kernel = any(_DEB_KERNEL_ABI.match(b) or _RPM_KERNEL.match(b) for b in f["binaries"])
            reboot = False
            if kernel and res.newest_kernel:
                newest_item = next((i for i in all_items if (i.name in f["binaries"] or _RPM_KERNEL.match(i.name))
                                    and i.version and compare(fam, i.version, fixed) >= 0), None)
                if newest_item is not None or (fam == "deb" and _abi_fixed(res.newest_kernel, fixed)):
                    reboot = True
            res.findings.append({
                "cve_id": f["cve_id"], "package": f["package"], "binaries": sorted(f["binaries"]),
                "installed": f["installed"], "fixed_in": fixed, "availability": avail,
                "advisories": sorted(f["advisories"]), "vendor_severity": f["severity"], "title": f["title"],
                "kernel": kernel, "reboot": reboot,
            })
        for k, u in unfixed.items():
            if k in opened or k in resolved:
                continue
            u["binaries"] = sorted(u["binaries"])
            res.unfixed.append(u)
        res.findings.sort(key=lambda f: (f["package"], f["cve_id"]))
        res.unfixed.sort(key=lambda u: (u["package"], u["cve_id"]))
    return results


def _abi_fixed(newest_abi: str, fixed: str) -> bool:
    """Whether the newest installed kernel ABI (5.15.0-105) reaches a fixed
    kernel version (5.15.0-105.115): the version starts with the ABI."""
    m = re.match(r"^(\d+\.\d+\.\d+)-(\d+)", fixed or "")
    n = re.match(r"^(\d+\.\d+\.\d+)-(\d+)", newest_abi or "")
    if not m or not n:
        return False
    return compare("deb", f"{n.group(1)}-{n.group(2)}", f"{m.group(1)}-{m.group(2)}") >= 0


def priority_from_severity(sev: Optional[str]) -> int:
    return _SEV_PRIORITY.get(sev or "", 4)
