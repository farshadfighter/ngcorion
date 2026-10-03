"""
Collecting what is installed, and parsing it into items.

An item is one installed thing: {name, version, arch, source, origin,
publisher, kind}. source says where it came from, which decides whether it
is matched against NVD:
  distro      the distribution's own repositories (Ubuntu, Debian, RHEL,
              Rocky, ...): fixes are backported into the same version
              number, so NVD version ranges do not apply - phase 2 matches
              these against USN / OVAL advisories instead
  third_party another vendor's repository (download.docker.com, a PPA,
              EPEL, repo.mongodb.org, ...)
  manual      installed from a file, in no repository
  windows     a Windows program (from the registry)
  service     the version a service reports about itself (Apache, MongoDB,
              SQL Server), read by that service's audit
  firmware    a network device's firmware (Cisco, Fortinet)
kind: package | program | hotfix | service | firmware.

Every command here only reads, and needs no root.
"""
import re
from typing import Dict, List, Optional

# ── Debian / Ubuntu ──────────────────────────────────────────────────────

DEB_PACKAGES = ("dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\t${source:Package}"
                "\\t${db:Status-Abbrev}\\n' 2>/dev/null")
# For every installed package: where its installed version comes from (I),
# and where other versions of it are offered (C) - an installed version the
# archive has moved past is still the distribution's package.
DEB_SOURCES = ("dpkg-query -W -f='${binary:Package}\\n' 2>/dev/null | xargs -r apt-cache policy 2>/dev/null"
               " | awk '/^[^ ].*:$/{p=substr($0,1,length($0)-1);i=\"\";next} /^ \\*\\*\\* /{i=\"I\";next}"
               " /^     [^ ]/{i=\"C\";next} i!=\"\"&&/^ +[0-9]+ /{sub(/^ +[0-9]+ /,\"\");"
               "if($0!=\"/var/lib/dpkg/status\")print p\"\\t\"i\"\\t\"$0}' | sort -u")
# The repositories with their Release origin (o=Ubuntu, o=Docker, LP-PPA-...),
# so a local mirror of the Ubuntu archive still counts as Ubuntu.
DEB_REPOS = "apt-cache policy 2>/dev/null | grep -E '^ +[0-9]+ |^ +release |^ +origin '"

# ── RHEL / Rocky / Alma / CentOS ─────────────────────────────────────────

RPM_PACKAGES = ("rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\t%{SOURCERPM}\\n'"
                " 2>/dev/null")
# The repository each package came from, from dnf's own database; -C keeps
# dnf off the network.
RPM_REPOS = ("(dnf -C repoquery --installed --qf '%{name}\\t%{arch}\\t%{from_repo}\\n' 2>/dev/null"
             " || yum list installed -C 2>/dev/null | awk 'NF==3{print $1\"\\t\\t\"$3}') | head -20000")

LINUX_COMMANDS = {
    "debian": [("deb_packages", DEB_PACKAGES, 90), ("deb_sources", DEB_SOURCES, 120), ("deb_repos", DEB_REPOS, 60)],
    "rhel": [("rpm_packages", RPM_PACKAGES, 90), ("rpm_repos", RPM_REPOS, 120)],
}

_DISTRO_ORIGINS = {"ubuntu", "debian", "ubuntuesm", "ubuntuesmapps", "ubuntu-security", "debian backports",
                   "canonical"}
_DISTRO_VENDORS = re.compile(r"red hat|rocky enterprise|centos|almalinux|cloudlinux|oracle america|"
                             r"scientific linux|fedora project(?! .*epel)", re.I)
_DISTRO_RPM_REPOS = re.compile(r"^(@?)(anaconda|baseos|appstream|extras|crb|powertools|devel|ha|"
                               r"resilientstorage|nfv|rt|sap|sap_hana|plus|centosplus|base|updates|"
                               r"rhel-[\w.-]+|ubi-[\w.-]+|ol\d+_[\w]+|rocky-[\w-]+|almalinux-[\w-]+)$", re.I)


def linux_family(distro_id: str) -> str:
    return "debian" if (distro_id or "").lower() in ("ubuntu", "debian", "linuxmint", "pop", "kali") else "rhel"


def _deb_repo_origins(text: str) -> Dict[str, str]:
    """'URL suite/comp arch Packages' -> origin (o= of its Release file)."""
    out, current = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"^ +\d+ (\S.*)$", line)
        if m and not line.strip().startswith(("release", "origin")):
            current = m.group(1).strip()
            out.setdefault(current, "")
            continue
        m = re.match(r"^ +release (.*)$", line)
        if m and current:
            fields = dict(p.split("=", 1) for p in m.group(1).split(",") if "=" in p)
            out[current] = fields.get("o") or fields.get("l") or ""
    return out


def _host(source_line: str) -> str:
    m = re.match(r"^[a-z+]+://([^/\s]+)", source_line)
    return m.group(1) if m else source_line.split()[0]


def parse_debian(outputs: Dict[str, str]) -> List[dict]:
    origins = _deb_repo_origins(outputs.get("deb_repos", ""))
    installed_src: Dict[str, List[str]] = {}
    other_src: Dict[str, List[str]] = {}
    for line in (outputs.get("deb_sources") or "").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        name, which, src = parts
        (installed_src if which == "I" else other_src).setdefault(name, []).append(src.strip())

    def classify(name: str):
        """(source, origin) for a package name."""
        for table, outdated in ((installed_src, False), (other_src, True)):
            srcs = table.get(name) or table.get(name.split(":")[0])
            if not srcs:
                continue
            named = [(origins.get(s, ""), s) for s in srcs]
            for o, s in named:
                if o.lower() in _DISTRO_ORIGINS:
                    return "distro", o
            o, s = named[0]
            # A PPA is named after its owner; any other repository after its host
            # (download.docker.com tells more than "Docker").
            return "third_party", ("PPA " + o[len("LP-PPA-"):]) if o.startswith("LP-PPA-") else _host(s)
        return "manual", None

    items = []
    for line in (outputs.get("deb_packages") or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        name, version, arch, src_pkg, status = parts[:5]
        if len(status) < 2 or status[1] != "i":          # only packages actually installed
            continue
        source, origin = classify(name)
        items.append({"name": re.sub(r":[a-z0-9_]+$", "", name), "version": version, "arch": arch,
                      "source": source, "origin": origin, "publisher": None, "kind": "package",
                      "source_package": src_pkg or None, "vkind": "deb"})
    return _dedupe(items)


def parse_rhel(outputs: Dict[str, str]) -> List[dict]:
    repos = {}
    for line in (outputs.get("rpm_repos") or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            repos[(parts[0], parts[1])] = parts[2]
            repos.setdefault((parts[0], ""), parts[2])
    items = []
    for line in (outputs.get("rpm_packages") or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or parts[0].startswith("gpg-pubkey"):
            continue
        name, version, arch, vendor = parts[:4]
        version = re.sub(r"^0:", "", version)
        repo = (repos.get((name, arch)) or repos.get((name, "")) or "").lstrip("@")
        vendor = "" if vendor == "(none)" else vendor
        if repo in ("System", "commandline", "@commandline") or repo == "" and not vendor:
            source, origin = "manual", None
        elif repo.lower().startswith("epel"):
            source, origin = "third_party", "EPEL"
        elif _DISTRO_RPM_REPOS.match(repo or "") or (not repo and _DISTRO_VENDORS.search(vendor)):
            source, origin = "distro", vendor or repo
        elif repo:
            source, origin = "third_party", repo
        else:
            source, origin = ("distro", vendor) if _DISTRO_VENDORS.search(vendor) else ("third_party", vendor)
        srpm = parts[4] if len(parts) > 4 else ""
        src_name = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", srpm) if srpm.endswith(".src.rpm") else None
        items.append({"name": name, "version": version, "arch": arch, "source": source, "origin": origin,
                      "publisher": vendor or None, "kind": "package", "source_package": src_name, "vkind": "rpm"})
    return _dedupe(items)


def _dedupe(items: List[dict]) -> List[dict]:
    seen, out = set(), []
    for it in items:
        key = (it["name"], it.get("arch") or "")
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def parse_linux(family: str, outputs: Dict[str, str]) -> List[dict]:
    return parse_debian(outputs) if family == "debian" else parse_rhel(outputs)


# ── Windows ──────────────────────────────────────────────────────────────

# Programs from both registry views, the installed updates, and the exact build.
WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  ForEach-Object { "P`t$($_.DisplayName)`t$($_.DisplayVersion)`t$($_.Publisher)`t$($_.InstallDate)`t$(if ($_.PSPath -like '*WOW6432Node*') {'x86'} else {'x64'})" }
Get-HotFix | ForEach-Object { "H`t$($_.HotFixID)`t$($_.Description)`t$(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyyMMdd') })" }
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"B`t$($cv.ProductName)`t10.0.$($cv.CurrentBuild).$($cv.UBR)`t$($cv.DisplayVersion)"
"""


def parse_windows(output: str) -> List[dict]:
    items = []
    for line in (output or "").splitlines():
        parts = [p.strip() for p in line.rstrip("\r").split("\t")]
        at = lambda i: (parts[i] or None) if len(parts) > i else None  # noqa: E731
        tag = parts[0]
        if tag == "P" and at(1):
            items.append({"name": at(1), "version": at(2), "arch": at(5), "source": "windows", "origin": None,
                          "publisher": at(3), "kind": "program", "source_package": None, "vkind": "win"})
        elif tag == "H" and at(1):
            items.append({"name": at(1), "version": None, "arch": None, "source": "windows", "origin": at(2),
                          "publisher": "Microsoft", "kind": "hotfix", "source_package": None, "vkind": "win"})
        elif tag == "B" and at(2):
            items.append({"name": at(1) or "Windows", "version": at(2), "arch": None, "source": "windows",
                          "origin": "Microsoft", "publisher": "Microsoft Corporation", "kind": "os",
                          "source_package": None, "vkind": "win"})
    return _dedupe_windows(items)


def _dedupe_windows(items):
    seen, out = set(), []
    for it in items:
        key = (it["kind"], it["name"], it.get("version"), it.get("arch"))
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


# ── versions services and devices report about themselves ────────────────

_DISTRO_BUILD = re.compile(r"\((ubuntu|debian|red hat|rocky|centos|almalinux|fedora|oracle)[^)]*\)", re.I)


def apache_item(version_output: str) -> Optional[dict]:
    """'Server version: Apache/2.4.52 (Ubuntu)'. A distribution build is left
    to the distribution's advisories, like its package."""
    m = re.search(r"Apache/(\d+\.\d+\.\d+)\s*(\([^)]*\))?", version_output or "")
    if not m:
        return None
    distro = bool(m.group(2) and _DISTRO_BUILD.match(m.group(2)))
    return {"name": "Apache HTTP Server", "version": m.group(1), "arch": None,
            "source": "distro" if distro else "service", "origin": (m.group(2) or "").strip("()") or None,
            "publisher": "Apache Software Foundation", "kind": "service", "source_package": None, "vkind": "svc"}


def mongodb_item(dump: str) -> Optional[dict]:
    m = re.search(r"(?:db version v|\"version\"\s*:\s*\"|^version[:=]\s*)(\d+\.\d+\.\d+)", dump or "", re.M)
    if not m:
        m = re.search(r"\b(\d+\.\d+\.\d+)\b", (dump or "").split("buildInfo", 1)[-1][:200])
    if not m:
        return None
    return {"name": "MongoDB Server", "version": m.group(1), "arch": None, "source": "service", "origin": None,
            "publisher": "MongoDB, Inc.", "kind": "service", "source_package": None, "vkind": "svc"}


def mssql_item(dump: str) -> Optional[dict]:
    """'Microsoft SQL Server 2019 (RTM-CU22) ... - 15.0.4322.2 (X64)'."""
    m = re.search(r"Microsoft SQL Server (20\d\d)[^\n]*?-\s*(\d+\.\d+\.\d+\.\d+)", dump or "")
    if not m:
        return None
    return {"name": f"Microsoft SQL Server {m.group(1)}", "version": m.group(2), "arch": None, "source": "service",
            "origin": None, "publisher": "Microsoft Corporation", "kind": "service", "source_package": None,
            "vkind": "svc"}


_CISCO_VERSION = re.compile(r"Cisco (IOS[ -]XE|IOS|NX-OS|Adaptive Security Appliance)[^\n]*?Version\s+([\w.()]+)",
                            re.I)


def cisco_item(dump: str) -> Optional[dict]:
    m = _CISCO_VERSION.search(dump or "")
    if not m:
        return None
    family = "IOS XE" if re.search(r"IOS[ -]?XE", dump or "", re.I) else m.group(1).upper().replace("-", " ")
    name = {"IOS XE": "Cisco IOS XE", "IOS": "Cisco IOS", "NX OS": "Cisco NX-OS",
            "ADAPTIVE SECURITY APPLIANCE": "Cisco ASA"}.get(family, f"Cisco {m.group(1)}")
    return {"name": name, "version": m.group(2).rstrip(","), "arch": None, "source": "firmware", "origin": None,
            "publisher": "Cisco", "kind": "firmware", "source_package": None, "vkind": "fw"}


def fortinet_item(status: dict) -> Optional[dict]:
    version = (status or {}).get("fortios_version")
    if not version or version == "0.0.0":
        return None
    return {"name": "Fortinet FortiOS", "version": version, "arch": (status or {}).get("model"),
            "source": "firmware", "origin": None, "publisher": "Fortinet", "kind": "firmware",
            "source_package": None, "vkind": "fw", "build": (status or {}).get("build")}
