"""
What to do about a CVE finding: the recommended action, and per asset the upgrade plan.

The finding already knows where the fix is (app/modules/cve/findings.py): the fixed package version
from the distribution's advisory, or the end of the vulnerable range NVD gives for the product. This
turns that into one action, said the same way everywhere (CVE page, remediation, Asset 360, reports):

  package   a Linux package from the distribution: "Upgrade age to 1.1.1-1ubuntu0.24.04.3 or later",
            with the commands (apt-get / dnf). A fix published only in Ubuntu Pro (ESM) says so and
            starts with "pro attach".
  reboot    the fixed kernel is installed but not running: restart.
  windows   Windows: "Install the latest cumulative update (build 10.0.20348.2700 or later)", with
            the CVE's page in Microsoft's Security Update Guide, which names the KB.
  version   another product with a known fixed version, in the branch installed ("FortiOS 7.2.9 or
            later" for 7.2.x): NVD's range, so marked to check against the vendor's advisory.
  after     only the last vulnerable version is known: "a version later than 7.2.8".
  advisory  no fixed version known (Cisco lists vulnerable releases, not fixed ones): the vendor's
            advisory, found among the CVE's references by the vendor's domain.

Besides the action: CISA's required action and due date for a CVE known to be exploited (KEV), and
for an operating system or firmware past its end of life (app/modules/eol) the note that it gets no
more fixes.

The sentences are English; the UI translates them (front/src/i18n/backendText.js).
"""
from collections import defaultdict
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse

from app.modules.cve import versions

PRO = "pro"
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{}"
MSRC_PAGE = "https://msrc.microsoft.com/update-guide/vulnerability/{}"

# Where each vendor publishes its advisories, to pick the vendor's own page among a CVE's references.
VENDOR_DOMAINS = {
    "cisco": ("sec.cloudapps.cisco.com", "tools.cisco.com", "cisco.com"),
    "fortinet": ("fortiguard.com", "fortinet.com"),
    "microsoft": ("msrc.microsoft.com", "portal.msrc.microsoft.com", "microsoft.com"),
    "vmware": ("vmware.com", "broadcom.com"),
    "broadcom": ("broadcom.com", "vmware.com"),
    "sophos": ("sophos.com",),
    "paloaltonetworks": ("security.paloaltonetworks.com", "paloaltonetworks.com"),
    "juniper": ("supportportal.juniper.net", "juniper.net"),
    "mikrotik": ("mikrotik.com",),
    "f5": ("my.f5.com", "f5.com"),
    "citrix": ("support.citrix.com", "citrix.com"),
    "oracle": ("oracle.com",),
    "apache": ("apache.org",),
    "openssl": ("openssl.org",),
    "openbsd": ("openssh.com", "openbsd.org"),
    "nginx": ("nginx.org", "f5.com"),
    "mongodb": ("mongodb.com",),
    "postgresql": ("postgresql.org",),
}

# A distribution advisory ID -> its page.
ADVISORY_PAGES = (
    ("USN-", "https://ubuntu.com/security/notices/{}"),
    ("DSA-", "https://security-tracker.debian.org/tracker/{}"),
    ("DLA-", "https://security-tracker.debian.org/tracker/{}"),
    ("RHSA-", "https://access.redhat.com/errata/{}"),
)


def advisory_page(advisory_id: str) -> str:
    for prefix, page in ADVISORY_PAGES:
        if advisory_id.startswith(prefix):
            return page.format(advisory_id)
    return f"https://osv.dev/vulnerability/{advisory_id}"


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def vendor_link(cve_id: str, vendor: Optional[str], references: Optional[Iterable[str]]) -> Dict[str, str]:
    """The vendor's advisory for a CVE: a reference on the vendor's domain, Microsoft's Update Guide
    for Microsoft, else the first reference (advisories come first), else the NVD page."""
    refs = [u for u in (references or []) if isinstance(u, str) and u.lower().startswith(("https://", "http://"))]
    domains = VENDOR_DOMAINS.get((vendor or "").lower(), ())
    for domain in domains:
        for url in refs:
            host = _host(url)
            if host == domain or host.endswith("." + domain):
                return {"url": url, "label": host}
    if (vendor or "").lower() == "microsoft":
        return {"url": MSRC_PAGE.format(cve_id), "label": "msrc.microsoft.com"}
    if refs:
        return {"url": refs[0], "label": _host(refs[0])}
    return {"url": NVD_PAGE.format(cve_id), "label": "nvd.nist.gov"}


def _iso(value) -> Optional[str]:
    """A date as text: actions are stored in remediation items as JSON."""
    return value.isoformat() if hasattr(value, "isoformat") else value


def _is_kernel(finding: Dict) -> bool:
    return (finding.get("package") or "").startswith(("linux", "kernel")) and any(
        b.startswith(("linux-image", "linux-modules", "kernel")) for b in finding.get("binaries") or ())


def _commands(family: Optional[str], finding: Dict, pro: bool) -> List[str]:
    """The commands that install this fix on the machine."""
    binaries = sorted(finding.get("binaries") or [finding.get("package")])
    kernel = _is_kernel(finding)
    lines = ["sudo pro attach <your-token>"] if pro else []
    if family == "deb":
        lines.append("sudo apt-get update")
        lines.append("sudo apt-get full-upgrade" if kernel else "sudo apt-get install --only-upgrade " + " ".join(binaries))
    elif family == "rpm":
        lines.append("sudo dnf upgrade kernel" if kernel else "sudo dnf upgrade " + " ".join(binaries))
    else:
        return []
    if kernel:
        lines.append("sudo reboot")
    return lines


def action_for(finding: Dict, *, references=None, kev_action: Optional[str] = None, family: Optional[str] = None,
               end_incl: Optional[str] = None, eol: Optional[Dict] = None) -> Dict:
    """The recommended action of one finding (see the module docstring for the kinds)."""
    product = finding.get("product") or finding.get("product_key") or ""
    vendor = (finding.get("vendor") or "").lower()
    out = {"kind": "advisory", "text": "No fixed version is known here: follow the vendor's advisory",
           "product": product, "target": None, "pro": False, "commands": [], "link": None,
           "check_vendor": False, "kev_action": kev_action if finding.get("kev") else None,
           "kev_due": _iso(finding.get("kev_due")) if finding.get("kev") else None, "eol": eol}

    if finding.get("source") == "advisory":
        fixed = finding.get("fixed_in")
        pro = finding.get("availability") == PRO
        ids = finding.get("advisories") or []
        if ids:
            out["link"] = {"url": advisory_page(ids[0]), "label": ids[0]}
        if fixed and finding.get("reboot") and _is_kernel(finding):
            out.update(kind="reboot", target=fixed, commands=["sudo reboot"],
                       text="Restart the machine: the fixed kernel {version} is installed but not running"
                       .format(version=fixed))
        elif fixed:
            out.update(kind="package", target=fixed, pro=pro, commands=_commands(family, finding, pro),
                       text=f"Upgrade {product} to {fixed} or later")
        return out

    fixed = finding.get("fixed_in")
    link = vendor_link(finding.get("cve_id") or "", vendor, references)
    out["link"] = link
    windows = vendor == "microsoft" and (finding.get("product_key") or "").startswith("windows")
    if windows:
        out.update(kind="windows", target=fixed, check_vendor=bool(fixed),
                   text=(f"Install the latest cumulative update for {product} (build {fixed} or later)" if fixed
                         else f"Install the latest cumulative update for {product}"))
    elif fixed and not fixed.startswith("after "):
        out.update(kind="version", target=fixed, check_vendor=True, text=f"Upgrade {product} to {fixed} or later")
    elif end_incl:
        out.update(kind="after", target=end_incl, check_vendor=True,
                   text=f"Upgrade {product} to a version later than {end_incl}")
    return out


def annotate(db, findings: List[Dict], entries: Dict, nvd_info: Dict) -> None:
    """Give every finding its "action". `entries` are the CVE entries by ID, `nvd_info` the NVD match
    of each NVD finding by (asset_id, cve_id): {"part", "end_incl"}."""
    from app.modules.advisories import releases
    eol_by_asset = _eol_os(db, {f["asset_id"] for f in findings})
    for f in findings:
        e = entries.get(f["cve_id"])
        info = nvd_info.get((f["asset_id"], f["cve_id"]), {}) if f["source"] == "nvd" else {}
        os_level = f["source"] == "advisory" or info.get("part") == "o"
        f["action"] = action_for(
            f, references=e.references if e is not None else None,
            kev_action=e.kev_action if e is not None else None,
            family=releases.family(f["release"]) if f.get("release") else None,
            end_incl=info.get("end_incl"),
            eol=eol_by_asset.get(f["asset_id"]) if os_level else None)


def _eol_os(db, asset_ids) -> Dict[int, Dict]:
    """Per asset: its operating system or firmware past its end of life, if any."""
    if not asset_ids:
        return {}
    try:
        from app.modules.eol import service as eol
        comps = eol.components(db, asset_ids)
    except Exception:       # the end-of-life catalog is advice here; a problem there must not hide findings
        return {}
    out = {}
    for c in comps:
        if c.kind in ("os", "firmware") and c.status == "unsupported":
            out.setdefault(c.asset_id, {"title": c.title, "until": c.until, "latest": c.latest})
    return out


def email_lines(db, asset_ids: Iterable[int], names: Dict[int, str], top: int = 3) -> List[str]:
    """For a CVE alert email: the first steps of each asset's plan ("What to do on web-01: ...")."""
    from app.modules.cve import findings as cve_findings
    lines: List[str] = []
    for aid in sorted(set(asset_ids)):
        steps = plan(cve_findings.compute(db, aid)["findings"]).get(aid, [])
        if not steps:
            continue
        lines.append(f"What to do on {names.get(aid) or aid}:")
        for s in steps[:top]:
            closes = f" (closes {s['findings']} findings)" if s["findings"] > 1 else ""
            lines.append(f"  - {s['text']}{closes}")
            for c in s["commands"]:
                lines.append(f"      {c}")
            if s.get("link"):
                lines.append(f"      {s['link']['url']}")
        if len(steps) > top:
            lines.append(f"  - and {len(steps) - top} more on the asset's page in NGCorion")
        lines.append("")
    return lines


def _later(family: Optional[str], kind: str, a: Optional[str], b: Optional[str]) -> bool:
    """Whether target a is later than b (a version or a package version)."""
    if not b:
        return bool(a)
    if not a:
        return False
    if kind in ("package", "reboot") and family:
        from app.modules.advisories.versions import compare
        return compare(family, a, b) > 0
    return versions.compare(a, b) > 0


def plan(findings: List[Dict]) -> Dict[int, List[Dict]]:
    """Per asset, its actions with what each closes, most urgent first. The findings of one product
    are closed by one upgrade, to the highest version any of them needs ("Upgrade FortiOS to 7.2.9 or
    later" closes 12 findings); Windows by one cumulative update; a finding with no known fix stays
    alone, with its vendor advisory."""
    from app.modules.advisories import releases
    groups: Dict[tuple, Dict] = {}
    for f in findings:
        a = f.get("action") or {}
        kind = a.get("kind") or "advisory"
        family = releases.family(f["release"]) if f.get("release") else None
        key = (f["asset_id"], "windows" if kind == "windows" else "advisory" if kind == "advisory" else "upgrade",
               f.get("product_key") or f.get("product"), f["cve_id"] if kind == "advisory" else None)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"asset_id": f["asset_id"], "asset_name": f.get("asset_name"),
                               "product": a.get("product") or f.get("product"), "findings": 0, "cves": [],
                               "kev": False, "priority": 9, "critical": 0, "pro": False, "_best": a,
                               "_family": family}
        elif _later(family, kind, a.get("target"), g["_best"].get("target")):
            g["_best"] = a
        g["pro"] = g["pro"] or bool(a.get("pro"))
        g["findings"] += 1
        g["cves"].append(f["cve_id"])
        g["kev"] = g["kev"] or bool(f.get("kev"))
        g["priority"] = min(g["priority"], f.get("priority") or 9)
        g["critical"] += f.get("severity") == "critical"
    out: Dict[int, List[Dict]] = defaultdict(list)
    for g in groups.values():
        best = g.pop("_best")
        g.pop("_family")
        g.update(kind=best.get("kind") or "advisory", text=best.get("text"), target=best.get("target"),
                 commands=best.get("commands") or [], link=best.get("link"),
                 check_vendor=bool(best.get("check_vendor")), eol=best.get("eol"))
        g["cves"] = sorted(set(g["cves"]))
        out[g["asset_id"]].append(g)
    for rows in out.values():
        rows.sort(key=lambda g: (g["priority"], not g["kev"], -g["findings"], g["product"] or ""))
    return dict(out)
