"""
Apache HTTP Server CIS Benchmark Rules

CIS security compliance rules for Apache HTTP Server 2.4.x
Based on CIS Apache HTTP Server 2.4 Benchmark v2.0.0 — all 12 sections.

Each rule includes:
- Unique ID (e.g., APACHE-L1-2.3)
- Title, rationale and remediation guidance
- Severity level (high/medium/low/info)
- Level (L1/L2)
- Check function (returns True if compliant)
- Evidence extraction function
- distros: distro families the rule applies to (11.x RHEL only, 12.x Debian only)
- manual: True for controls that cannot be evaluated automatically; these are
  reported as SKIPPED (never scored) with guidance on what to verify by hand.
"""

import re
from typing import List, Dict, Any, Callable
from dataclasses import dataclass, field

@dataclass
class ApacheCISRule:
    """Represents a single Apache CIS compliance check."""

    id: str                          # "APACHE-L1-2.3"
    cis_section: str                 # "2.3" - CIS Benchmark section
    title: str                       # Short description
    severity: str                    # high/medium/low/info
    level: str                       # L1/L2
    rationale: str                   # Why this matters
    remediation: str                 # How to fix
    check: Callable[[Dict[str, str], str], bool]  # Function: returns True if compliant
    evidence: Callable[[Dict[str, str], str], str]  # Function: returns evidence text
    distros: List[str] = field(default_factory=lambda: ["all"])  # Supported distros
    manual: bool = False             # Manual controls are reported SKIPPED, never scored




SEVERITY_WEIGHT = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}




def _get_output(data: Dict[str, str], key: str) -> str:
    """Get command output from data dict, handling errors."""
    output = data.get(key, "")
    if output.startswith("<<ERROR:"):
        return ""
    return output


def _not_configured(output: str) -> bool:
    lower = output.lower()
    return (
        not output.strip()
        or "not configured" in lower
        or "not found" in lower
    )


def _check_module_enabled(data: Dict[str, str], module: str) -> bool:
    """Check if an Apache module is enabled/loaded."""
    output = _get_output(data, "apache_modules")
    if not output:
        return False
    return module.lower() in output.lower()


def _check_module_disabled(data: Dict[str, str], module: str) -> bool:
    """Check if an Apache module is disabled/not loaded."""
    output = _get_output(data, "apache_modules")
    if not output or "cannot list modules" in output.lower():
        # Could not enumerate modules — inability to verify is not compliance.
        return False
    return module.lower() not in output.lower()


def _scan_clean(data: Dict[str, str], key: str) -> bool:
    """Evaluate a find-based ownership/permission scan.

    The command prints offending paths followed by SCAN_COMPLETE, so
    compliance means the marker is present and nothing else was printed.
    """
    output = _get_output(data, key)
    if "SCAN_COMPLETE" not in output:
        return False
    offenders = [
        line for line in output.splitlines()
        if line.strip() and "SCAN_COMPLETE" not in line
    ]
    return not offenders


def _check_apache_running_non_root(data: Dict[str, str]) -> bool:
    """Check that Apache worker processes run as a non-root user."""
    output = _get_output(data, "apache_user_group")
    if output and "not configured" not in output.lower():
        if re.search(r'User\s+root\b', output, re.IGNORECASE):
            return False

    proc_output = _get_output(data, "apache_process")
    if proc_output:
        workers = [
            line for line in proc_output.split('\n')
            if 'grep' not in line and ('apache2' in line or 'httpd' in line)
        ]
        if workers:
            # The parent runs as root; at least one worker must not.
            non_root = [w for w in workers if w.split() and w.split()[0] != 'root']
            return bool(non_root)
    return True


def _check_trace_disabled(data: Dict[str, str]) -> bool:
    """Check that HTTP TRACE method is disabled."""
    output = _get_output(data, "trace_enable")
    if not output or "not configured" in output.lower():
        return False
    return "traceenable off" in output.lower()


def _options_tokens(line: str) -> List[str]:
    m = re.search(r'Options\s+(.*)$', line, re.IGNORECASE)
    if not m:
        return []
    return m.group(1).split()


def _options_restricted(output: str, forbidden: set) -> bool:
    """True when no Options line grants a forbidden feature un-negated."""
    if _not_configured(output):
        return False
    for line in output.splitlines():
        for token in _options_tokens(line):
            if token in forbidden:  # bare token, no leading '-'
                return False
    return True


def _root_options_none(data: Dict[str, str]) -> bool:
    """CIS 5.1 — <Directory /> must carry 'Options None'."""
    block = _get_output(data, "root_directory_block")
    if _not_configured(block):
        return False
    return bool(re.search(r'^\s*Options\s+None\s*$', block, re.IGNORECASE | re.MULTILINE))


def _docroot_options_minimized(data: Dict[str, str]) -> bool:
    """CIS 5.2 — web root Options must not enable risky features."""
    block = _get_output(data, "docroot_directory_block")
    if _not_configured(block):
        return False
    if not re.search(r'Options', block, re.IGNORECASE):
        # No Options in the block means the (safe) inherited default applies
        # only if the root directory is already restricted; require explicit.
        return False
    return _options_restricted(block, {"Indexes", "Includes", "ExecCGI", "All"})


def _num_values(output: str, directive: str) -> List[int]:
    """Extract all integer values for a directive from grep output."""
    return [
        int(m) for m in
        re.findall(rf'{directive}\s+(\d+)', output, re.IGNORECASE)
    ]


def _directive_max_ok(data: Dict[str, str], key: str, directive: str,
                      maximum: int, absent_ok: bool = False) -> bool:
    """Directive value(s) must all be <= maximum; absence per absent_ok."""
    output = _get_output(data, key)
    values = _num_values(output, directive)
    if not values:
        return absent_ok
    return all(v <= maximum for v in values)


def _directive_min_ok(data: Dict[str, str], key: str, directive: str,
                      minimum: int, absent_ok: bool = False) -> bool:
    output = _get_output(data, key)
    values = _num_values(output, directive)
    if not values:
        return absent_ok
    return all(v >= minimum for v in values)


def _check_ssl_protocol_secure(data: Dict[str, str]) -> bool:
    """CIS 7.4 — SSLv3/TLSv1.0/TLSv1.1 must be disabled."""
    output = _get_output(data, "ssl_protocol")
    if _not_configured(output):
        return False
    lower = output.lower()
    # Explicit modern-only form: "TLSv1.2" / "TLSv1.3" without older versions
    if re.search(r'sslprotocol[^\n]*tlsv1\.[23]', lower):
        stripped = re.sub(r'-\s*(sslv3|tlsv1\.1|tlsv1(?!\.))', '', lower)
        if not re.search(r'(?<![-.\w])(sslv3|tlsv1(?!\.[23]))', stripped):
            return True
    # Subtractive form: "all -SSLv3 -TLSv1 -TLSv1.1"
    if "all" in lower and "-sslv3" in lower and "-tlsv1" in lower:
        return True
    return False


_WEAK_CIPHER_TOKENS = ("null", "rc4", "des", "export", "adh")
_MEDIUM_CIPHER_TOKENS = ("3des", "idea")


def _ciphers_exclude(data: Dict[str, str], tokens) -> bool:
    """SSLCipherSuite must be configured and not enable any listed family."""
    output = _get_output(data, "ssl_ciphers")
    if _not_configured(output):
        return False
    for line in output.splitlines():
        m = re.search(r'SSLCipherSuite\s+(\S+)', line, re.IGNORECASE)
        if not m:
            continue
        for part in m.group(1).split(':'):
            bare = part.lower().lstrip('+')
            if bare.startswith('!') or bare.startswith('-'):
                continue  # explicitly excluded
            for token in tokens:
                # "des" must not match "3des" exclusions handled separately
                if token == "des" and bare.startswith("3des"):
                    continue
                if token in bare:
                    return False
    return True


def _forward_secrecy_only(data: Dict[str, str]) -> bool:
    """CIS 7.12 — only ECDHE/DHE (EECDH/EDH) key-exchange families enabled."""
    output = _get_output(data, "ssl_ciphers")
    if _not_configured(output):
        return False
    return bool(re.search(r'ECDHE|EECDH|(?<!-)\bDHE|EDH', output, re.IGNORECASE))


def _cert_valid_and_trusted(data: Dict[str, str]) -> bool:
    """CIS 7.2 — certificate exists, is not expired and not self-signed."""
    output = _get_output(data, "ssl_cert_check")
    if not output or "no certificate configured" in output.lower():
        return False
    if "CERT_NOT_EXPIRED" not in output:
        return False
    subject = re.search(r'subject\s*=\s*(.+)', output)
    issuer = re.search(r'issuer\s*=\s*(.+)', output)
    if subject and issuer and subject.group(1).strip() == issuer.group(1).strip():
        return False  # self-signed
    return True


def _key_protected(data: Dict[str, str]) -> bool:
    """CIS 7.3 — private key mode 400/600, owned by root."""
    output = _get_output(data, "ssl_key_perms")
    if not output or "no key configured" in output.lower() or "KEY_NOT_FOUND" in output:
        return False
    m = re.match(r'(\d+)\s+(\S+)', output.strip())
    if not m:
        return False
    return m.group(1) in ("400", "600") and m.group(2) == "root"


def _listen_ips_specified(data: Dict[str, str]) -> bool:
    """CIS 5.13 — every Listen directive names an IP (no bare/wildcard port)."""
    output = _get_output(data, "listen_directives")
    if _not_configured(output):
        return False
    listens = re.findall(r'Listen\s+(\S+)', output, re.IGNORECASE)
    if not listens:
        return False
    for value in listens:
        if re.fullmatch(r'\d+', value):          # "Listen 80"
            return False
        if value.startswith(("0.0.0.0", "[::]", "*")):
            return False
    return True


def _path_in_docroot(output: str) -> bool:
    return bool(re.search(r'/var/www', output))


def _run_dir_secure(data: Dict[str, str]) -> bool:
    """Shared for 3.8/3.9 — the runtime dir must not be world-writable."""
    output = _get_output(data, "run_dir_stat")
    if _not_configured(output):
        return False
    mode_match = re.search(r'Access:\s*\((\d+)', output)
    if not mode_match:
        return False
    mode = mode_match.group(1)[-3:]
    try:
        return not (int(mode[-1], 8) & 0o2)  # 'other' has no write bit
    except (ValueError, IndexError):
        return False


def _default_content_removed(data: Dict[str, str]) -> bool:
    """CIS 5.4 / 8.3 — no default index page, no bundled manual content."""
    page = _get_output(data, "default_page_check")
    manual = _get_output(data, "manual_content")
    page_clean = "no default content detected" in page.lower() or not page.strip()
    manual_clean = _not_configured(manual)
    return page_clean and manual_clean


def _reqtimeout_ok(data: Dict[str, str], part: str, maximum: int) -> bool:
    """CIS 9.5/9.6 — RequestReadTimeout header/body upper bound <= maximum."""
    output = _get_output(data, "request_read_timeout")
    if _not_configured(output):
        return False
    m = re.search(rf'{part}\s*=\s*(\d+)(?:-(\d+))?', output, re.IGNORECASE)
    if not m:
        return False
    upper = int(m.group(2) or m.group(1))
    return upper <= maximum


def _security_header(data: Dict[str, str], key: str) -> bool:
    output = _get_output(data, key)
    return not _not_configured(output)


def _ev(data: Dict[str, str], key: str, limit: int = 500) -> str:
    return _get_output(data, key)[:limit] or "(no output collected)"


# ========================= RULE DEFINITIONS =========================

def build_apache_cis_rules() -> List[ApacheCISRule]:
    """
    Build the complete CIS Apache HTTP Server 2.4 Benchmark v2.0.0 rule set.

    Returns:
        List[ApacheCISRule]: All 83 CIS rules for Apache HTTP Server
    """
    rules: List[ApacheCISRule] = []

    # ============ SECTION 1: PLANNING AND INSTALLATION (manual) ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-1.1", cis_section="1.1",
        title="Ensure the pre-installation planning checklist has been implemented",
        severity="info", level="L1", manual=True,
        rationale="Planning identifies security requirements before the server is exposed.",
        remediation=(
            "MANUAL: Verify a pre-installation checklist was completed — host "
            "hardening baseline, network placement/firewalling, user/group "
            "strategy, and update/patching process documented."
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: f"Package: {_ev(d, 'apache_package_info', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-1.2", cis_section="1.2",
        title="Ensure the server is not a multi-use system",
        severity="info", level="L1", manual=True,
        rationale="Other services on the same host expand the attack surface of the web server.",
        remediation=(
            "MANUAL: Review the listening services below and remove or relocate "
            "any service that is not required for the web server role "
            "(databases, mail, file shares, etc.)."
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: f"Listening services: {_ev(d, 'listening_services', 600)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-1.3", cis_section="1.3",
        title="Ensure Apache is installed from the appropriate binaries",
        severity="info", level="L1", manual=True,
        rationale="Vendor packages receive security updates through the OS package manager.",
        remediation=(
            "MANUAL: Confirm Apache was installed from the distribution's "
            "signed repositories (dpkg/rpm metadata below), not from source or "
            "third-party archives."
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: (
            f"Version: {_ev(d, 'apache_version', 200)}\n"
            f"Package: {_ev(d, 'apache_package_info', 300)}"
        )
    ))

    # ============ SECTION 2: MINIMIZE APACHE MODULES ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.1", cis_section="2.1",
        title="Ensure only necessary authentication and authorization modules are enabled",
        severity="info", level="L1", manual=True,
        rationale="Unused auth/authz modules widen the attack surface and may enable unintended access methods.",
        remediation=(
            "MANUAL: Review the loaded auth*/authz*/ldap modules below and "
            "disable any that are not required for the site's authentication "
            "design (a2dismod <module> / comment out LoadModule)."
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: "\n".join(
            line for line in _get_output(d, "apache_modules").splitlines()
            if re.search(r'auth|ldap', line, re.IGNORECASE)
        )[:500] or "(no auth modules listed)"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.2", cis_section="2.2",
        title="Ensure the log config module is enabled",
        severity="medium", level="L1",
        rationale="mod_log_config provides CustomLog/LogFormat; without it requests cannot be logged for monitoring or forensics.",
        remediation="Enable the module: a2enmod log_config (Debian) or ensure 'LoadModule log_config_module' is present (RHEL)",
        check=lambda d, p: _check_module_enabled(d, "log_config_module"),
        evidence=lambda d, p: f"Modules: {_ev(d, 'apache_modules')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.3", cis_section="2.3",
        title="Ensure the WebDAV modules are disabled",
        severity="high", level="L1",
        rationale="WebDAV (mod_dav, mod_dav_fs) allows remote clients to create and modify files on the server.",
        remediation="Disable WebDAV modules: a2dismod dav dav_fs (Debian) or comment out the LoadModule lines (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "dav_module") and _check_module_disabled(d, "dav_fs_module"),
        evidence=lambda d, p: f"DAV config: {_ev(d, 'mod_dav_config', 300)}\nModules: {_ev(d, 'apache_modules', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.4", cis_section="2.4",
        title="Ensure the status module is disabled",
        severity="high", level="L1",
        rationale="mod_status exposes server internals (workers, requests, client IPs) that help attackers profile the system.",
        remediation="Disable mod_status: a2dismod status (Debian) or comment out 'LoadModule status_module' (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "status_module"),
        evidence=lambda d, p: f"Status config: {_ev(d, 'mod_status_config')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.5", cis_section="2.5",
        title="Ensure the autoindex module is disabled",
        severity="medium", level="L1",
        rationale="mod_autoindex generates directory listings that reveal file structure and potentially sensitive files.",
        remediation="Disable mod_autoindex: a2dismod -f autoindex (Debian) or comment out 'LoadModule autoindex_module' (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "autoindex_module"),
        evidence=lambda d, p: f"Autoindex config: {_ev(d, 'mod_autoindex_config', 300)}\nModules: {_ev(d, 'apache_modules', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.6", cis_section="2.6",
        title="Ensure the proxy modules are disabled",
        severity="high", level="L1",
        rationale="An unneeded mod_proxy can be abused as an open proxy to relay attacks and exfiltrate data.",
        remediation="Disable proxy modules: a2dismod proxy proxy_http proxy_ftp (Debian) or comment out the LoadModule lines (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "proxy_module"),
        evidence=lambda d, p: f"Proxy config: {_ev(d, 'mod_proxy_config', 300)}\nModules: {_ev(d, 'apache_modules', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.7", cis_section="2.7",
        title="Ensure the user directories module is disabled",
        severity="medium", level="L1",
        rationale="mod_userdir maps ~username URLs to home directories, enabling information disclosure and user enumeration.",
        remediation="Disable mod_userdir: a2dismod userdir (Debian) or comment out 'LoadModule userdir_module' (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "userdir_module"),
        evidence=lambda d, p: f"UserDir config: {_ev(d, 'mod_userdir_config')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-2.8", cis_section="2.8",
        title="Ensure the info module is disabled",
        severity="high", level="L1",
        rationale="mod_info discloses the complete server configuration, including modules and directives, to remote clients.",
        remediation="Disable mod_info: a2dismod info (Debian) or comment out 'LoadModule info_module' (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "info_module"),
        evidence=lambda d, p: f"Info config: {_ev(d, 'mod_info_config')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-2.9", cis_section="2.9",
        title="Ensure the basic and digest authentication modules are disabled",
        severity="medium", level="L2",
        rationale="Basic and Digest authentication transmit weakly protected credentials and are superseded by stronger mechanisms.",
        remediation="Disable the modules: a2dismod auth_basic auth_digest (Debian) or comment out the LoadModule lines (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "auth_basic_module") and _check_module_disabled(d, "auth_digest_module"),
        evidence=lambda d, p: "\n".join(
            line for line in _get_output(d, "apache_modules").splitlines()
            if "auth_basic" in line or "auth_digest" in line
        )[:300] or "auth_basic/auth_digest not loaded"
    ))

    # ============ SECTION 3: PRINCIPLES, PERMISSIONS, OWNERSHIP ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.1", cis_section="3.1",
        title="Ensure the Apache web server runs as a non-root user",
        severity="high", level="L1",
        rationale="Worker processes running as root turn any Apache vulnerability into full system compromise.",
        remediation="Set the User and Group directives to www-data (Debian) or apache (RHEL) and restart the service",
        check=lambda d, p: _check_apache_running_non_root(d),
        evidence=lambda d, p: f"User/Group: {_ev(d, 'apache_user_group', 200)}\nProcesses: {_ev(d, 'apache_process', 400)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.2", cis_section="3.2",
        title="Ensure the Apache user account has an invalid shell",
        severity="medium", level="L1",
        rationale="A login shell on the service account allows interactive use if its credentials are ever obtained.",
        remediation="Set an invalid shell: usermod -s /sbin/nologin www-data (or apache)",
        check=lambda d, p: (
            "nologin" in _get_output(d, "apache_user_shell").lower()
            or "/bin/false" in _get_output(d, "apache_user_shell").lower()
        ),
        evidence=lambda d, p: f"Shell: {_ev(d, 'apache_user_shell', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.3", cis_section="3.3",
        title="Ensure the Apache user account is locked",
        severity="low", level="L1",
        rationale="Locking the account prevents password-based authentication as the web server user.",
        remediation="Lock the account: passwd -l www-data (or apache)",
        check=lambda d, p: bool(re.search(r'\s(L|LK)\s', _get_output(d, "apache_user_locked"))),
        evidence=lambda d, p: f"Account status: {_ev(d, 'apache_user_locked', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.4", cis_section="3.4",
        title="Ensure Apache directories and files are owned by root",
        severity="medium", level="L1",
        rationale="Configuration owned by non-root users can be modified to subvert the server.",
        remediation="Restore ownership: chown -R root:root /etc/apache2 (or /etc/httpd)",
        check=lambda d, p: _scan_clean(d, "dirs_not_owned_root"),
        evidence=lambda d, p: f"Paths not owned by root: {_ev(d, 'dirs_not_owned_root')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.5", cis_section="3.5",
        title="Ensure the group is set correctly on Apache directories and files",
        severity="medium", level="L1",
        rationale="Group ownership outside root allows unintended users to modify server configuration.",
        remediation="Restore group ownership: chgrp -R root /etc/apache2 (or /etc/httpd)",
        check=lambda d, p: _scan_clean(d, "dirs_not_group_root"),
        evidence=lambda d, p: f"Paths not group root: {_ev(d, 'dirs_not_group_root')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.6", cis_section="3.6",
        title="Ensure other write access on Apache directories and files is restricted",
        severity="high", level="L1",
        rationale="World-writable configuration or content lets any local user tamper with the web server.",
        remediation="Remove other-write bits: chmod -R o-w /etc/apache2 (or /etc/httpd)",
        check=lambda d, p: _scan_clean(d, "dirs_other_writable"),
        evidence=lambda d, p: f"World-writable paths: {_ev(d, 'dirs_other_writable')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.7", cis_section="3.7",
        title="Ensure the core dump directory is secured",
        severity="medium", level="L1",
        rationale="Core dumps can contain request data and secrets; they must never land in web-accessible or shared paths.",
        remediation=(
            "If CoreDumpDirectory is configured, point it at a root-owned "
            "directory outside the document root (e.g. /var/log/apache2-cores) "
            "with no group/other access."
        ),
        check=lambda d, p: not _path_in_docroot(_get_output(d, "core_dump_config")),
        evidence=lambda d, p: f"CoreDumpDirectory: {_ev(d, 'core_dump_config', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.8", cis_section="3.8",
        title="Ensure the lock file is secured",
        severity="medium", level="L1",
        rationale="A mutex/lock file in an insecure directory allows a local attacker to interfere with or DoS the server.",
        remediation=(
            "Keep the default Mutex, or point 'Mutex file:' at a root-owned "
            "directory outside the document root that is not world-writable."
        ),
        check=lambda d, p: (
            not _path_in_docroot(_get_output(d, "mutex_config"))
            and (
                "file:" not in _get_output(d, "mutex_config").lower()
                or _run_dir_secure(d)
            )
        ),
        evidence=lambda d, p: f"Mutex: {_ev(d, 'mutex_config', 200)}\nRun dir: {_ev(d, 'run_dir_stat', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.9", cis_section="3.9",
        title="Ensure the PID file is secured",
        severity="medium", level="L1",
        rationale="A writable PID file lets an attacker redirect service-management signals to arbitrary processes.",
        remediation="Keep the PID file in the run directory, owned by root and not writable by others.",
        check=lambda d, p: (
            not _path_in_docroot(_get_output(d, "pid_file_config"))
            and _run_dir_secure(d)
        ),
        evidence=lambda d, p: f"PidFile: {_ev(d, 'pid_file_config', 200)}\nRun dir: {_ev(d, 'run_dir_stat', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.10", cis_section="3.10",
        title="Ensure the ScoreBoard file is secured",
        severity="low", level="L1",
        rationale="A file-backed scoreboard in a shared directory enables local tampering with worker coordination.",
        remediation=(
            "Leave ScoreBoardFile unset (in-memory scoreboard), or point it at "
            "a root-owned directory outside the document root."
        ),
        check=lambda d, p: (
            _not_configured(_get_output(d, "scoreboard_config"))
            or not _path_in_docroot(_get_output(d, "scoreboard_config"))
        ),
        evidence=lambda d, p: f"ScoreBoardFile: {_ev(d, 'scoreboard_config', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.11", cis_section="3.11",
        title="Ensure group write access on Apache directories and files is restricted",
        severity="medium", level="L1",
        rationale="Group-writable configuration allows members of that group to alter server behaviour.",
        remediation="Remove group-write bits: chmod -R g-w /etc/apache2 (or /etc/httpd)",
        check=lambda d, p: _scan_clean(d, "dirs_group_writable"),
        evidence=lambda d, p: f"Group-writable paths: {_ev(d, 'dirs_group_writable')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.12", cis_section="3.12",
        title="Ensure group write access on the document root is restricted",
        severity="medium", level="L1",
        rationale="If the Apache group can write web content, a compromised worker process can deface or backdoor the site.",
        remediation="Remove group-write bits from the document root: chmod -R g-w /var/www/html",
        check=lambda d, p: _scan_clean(d, "docroot_group_writable"),
        evidence=lambda d, p: f"Group-writable docroot dirs: {_ev(d, 'docroot_group_writable')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-3.13", cis_section="3.13",
        title="Ensure access to special purpose application writable directories is properly restricted",
        severity="info", level="L1", manual=True,
        rationale="Upload/cache directories that must be writable need compensating controls (no execution, tight scope).",
        remediation=(
            "MANUAL: Review the writable directories below. For each one the "
            "application genuinely needs, ensure it is outside the document "
            "root where possible, has script execution disabled (Options None, "
            "no handlers), and is limited to the minimum required paths."
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: f"Writable dirs under docroot: {_ev(d, 'app_writable_dirs')}"
    ))

    # ============ SECTION 4: APACHE ACCESS CONTROL ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-4.1", cis_section="4.1",
        title="Ensure access to the OS root directory is denied by default",
        severity="high", level="L1",
        rationale="Without a default-deny on <Directory />, misconfigured aliases can expose the entire filesystem.",
        remediation=(
            "In the main config ensure:\n<Directory />\n    AllowOverride None\n"
            "    Require all denied\n</Directory>"
        ),
        check=lambda d, p: bool(re.search(
            r'require all denied|deny from all',
            _get_output(d, "root_directory_block"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"<Directory /> block: {_ev(d, 'root_directory_block')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-4.2", cis_section="4.2",
        title="Ensure appropriate access to web content is allowed",
        severity="info", level="L1", manual=True,
        rationale="Access grants must match the intended audience of each content area.",
        remediation=(
            "MANUAL: Review every 'Require' directive below and confirm each "
            "content area is only as accessible as intended (e.g. admin areas "
            "restricted by IP/auth, public areas 'Require all granted')."
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: f"Require directives: {_ev(d, 'require_directives', 600)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-4.3", cis_section="4.3",
        title="Ensure OverRide is disabled for the OS root directory",
        severity="medium", level="L1",
        rationale=".htaccess overrides on the root directory let content owners change security settings server-wide.",
        remediation="Set 'AllowOverride None' inside the <Directory /> block",
        check=lambda d, p: bool(re.search(
            r'AllowOverride\s+None',
            _get_output(d, "root_directory_block"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"<Directory /> block: {_ev(d, 'root_directory_block')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-4.4", cis_section="4.4",
        title="Ensure OverRide is disabled for all directories",
        severity="medium", level="L1",
        rationale="Any AllowOverride other than None re-enables .htaccess files, moving security policy into content directories.",
        remediation="Set 'AllowOverride None' for every <Directory> block (use AllowOverrideList only where strictly needed)",
        check=lambda d, p: (
            not _not_configured(_get_output(d, "allow_override"))
            and all(
                re.search(r'AllowOverride\s+None', line, re.IGNORECASE)
                for line in _get_output(d, "allow_override").splitlines()
                if re.search(r'AllowOverride\s+\S', line, re.IGNORECASE)
            )
        ),
        evidence=lambda d, p: f"AllowOverride: {_ev(d, 'allow_override')}"
    ))

    # ============ SECTION 5: MINIMIZE FEATURES, CONTENT AND OPTIONS ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.1", cis_section="5.1",
        title="Ensure Options for the OS root directory are restricted",
        severity="medium", level="L1",
        rationale="The root directory must not inherit content features; 'Options None' is the safe baseline.",
        remediation="Set 'Options None' inside the <Directory /> block",
        check=lambda d, p: _root_options_none(d),
        evidence=lambda d, p: f"<Directory /> block: {_ev(d, 'root_directory_block')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.2", cis_section="5.2",
        title="Ensure Options for the web root directory are restricted",
        severity="medium", level="L1",
        rationale="Indexes, Includes and ExecCGI on the web root expose listings and enable server-side execution.",
        remediation="In the web root <Directory> block set 'Options None' or explicitly remove risky options (-Indexes -Includes -ExecCGI)",
        check=lambda d, p: _docroot_options_minimized(d),
        evidence=lambda d, p: f"Web root block: {_ev(d, 'docroot_directory_block')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.3", cis_section="5.3",
        title="Ensure Options for other directories are minimized",
        severity="medium", level="L1",
        rationale="Every directory granting All/Includes/ExecCGI is a potential execution or disclosure vector.",
        remediation="Review all Options directives and remove All, Includes and ExecCGI wherever they are not strictly required",
        check=lambda d, p: _options_restricted(
            _get_output(d, "options_directive"), {"All", "Includes", "ExecCGI"}
        ),
        evidence=lambda d, p: f"Options directives: {_ev(d, 'options_directive')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.4", cis_section="5.4",
        title="Ensure default HTML content is removed",
        severity="medium", level="L1",
        rationale="Default welcome pages and manuals fingerprint the server and confirm a default configuration.",
        remediation="Remove the default index page and bundled manual content (apt purge apache2-doc / rm the default site files)",
        check=lambda d, p: _default_content_removed(d),
        evidence=lambda d, p: (
            f"Default page: {_ev(d, 'default_page_check', 200)}\n"
            f"Manual content: {_ev(d, 'manual_content', 200)}"
        )
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.5", cis_section="5.5",
        title="Ensure the default CGI content printenv script is removed",
        severity="high", level="L1",
        rationale="printenv echoes environment variables, disclosing paths, versions and possibly secrets.",
        remediation="Delete the sample script: rm -f /usr/lib/cgi-bin/printenv /var/www/cgi-bin/printenv",
        check=lambda d, p: "printenv" not in _get_output(d, "test_cgi_files"),
        evidence=lambda d, p: f"Sample CGI files: {_ev(d, 'test_cgi_files', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.6", cis_section="5.6",
        title="Ensure the default CGI content test-cgi script is removed",
        severity="high", level="L1",
        rationale="test-cgi discloses server environment details useful for attack planning.",
        remediation="Delete the sample script: rm -f /usr/lib/cgi-bin/test-cgi /var/www/cgi-bin/test-cgi",
        check=lambda d, p: "test-cgi" not in _get_output(d, "test_cgi_files"),
        evidence=lambda d, p: f"Sample CGI files: {_ev(d, 'test_cgi_files', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.7", cis_section="5.7",
        title="Ensure HTTP request methods are restricted",
        severity="medium", level="L1",
        rationale="Allowing only GET/POST/HEAD (and OPTIONS where needed) blocks abuse of PUT, DELETE and other methods.",
        remediation=(
            "Wrap content directories with:\n<LimitExcept GET POST OPTIONS>\n"
            "    Require all denied\n</LimitExcept>"
        ),
        check=lambda d, p: not _not_configured(_get_output(d, "limit_http_methods")),
        evidence=lambda d, p: f"Method limits: {_ev(d, 'limit_http_methods')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.8", cis_section="5.8",
        title="Ensure the HTTP TRACE method is disabled",
        severity="high", level="L1",
        rationale="TRACE enables Cross-Site Tracing (XST) attacks that can steal credentials and cookies.",
        remediation="Add 'TraceEnable Off' to the main Apache configuration",
        check=lambda d, p: _check_trace_disabled(d),
        evidence=lambda d, p: f"TraceEnable: {_ev(d, 'trace_enable', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.9", cis_section="5.9",
        title="Ensure old HTTP protocol versions are disallowed",
        severity="medium", level="L1",
        rationale="HTTP/1.0 and 0.9 requests lack the Host header and bypass name-based controls.",
        remediation=(
            "Enable mod_rewrite and add:\nRewriteEngine On\n"
            "RewriteCond %{THE_REQUEST} !HTTP/1\\.1$\nRewriteRule .* - [F]"
        ),
        check=lambda d, p: bool(re.search(
            r'THE_REQUEST', _get_output(d, "http_protocol_rewrite")
        )),
        evidence=lambda d, p: f"Protocol rewrite rules: {_ev(d, 'http_protocol_rewrite', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.10", cis_section="5.10",
        title="Ensure access to .ht* files is restricted",
        severity="medium", level="L1",
        rationale=".htaccess/.htpasswd files can contain credentials and security policy and must never be served.",
        remediation=(
            "Add:\n<FilesMatch \"^\\.ht\">\n    Require all denied\n</FilesMatch>"
        ),
        check=lambda d, p: (
            ".ht" in _get_output(d, "ht_files_protection")
            and bool(re.search(
                r'require all denied|deny from all',
                _get_output(d, "ht_files_protection"), re.IGNORECASE
            ))
        ),
        evidence=lambda d, p: f".ht* protection: {_ev(d, 'ht_files_protection')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.11", cis_section="5.11",
        title="Ensure access to inappropriate file extensions is restricted",
        severity="medium", level="L1",
        rationale="Backup, source and config files (.bak, .old, .inc, .sql...) left in the docroot leak code and credentials.",
        remediation=(
            "Add a deny rule for risky extensions, e.g.:\n"
            "<FilesMatch \"\\.(bak|old|orig|save|inc|sql|ini|log|sh)$\">\n"
            "    Require all denied\n</FilesMatch>"
        ),
        check=lambda d, p: (
            "FilesMatch" in _get_output(d, "file_extension_restrictions")
            and bool(re.search(
                r'require all denied|deny from all',
                _get_output(d, "file_extension_restrictions"), re.IGNORECASE
            ))
        ),
        evidence=lambda d, p: f"FilesMatch rules: {_ev(d, 'file_extension_restrictions')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.12", cis_section="5.12",
        title="Ensure IP address based requests are disallowed",
        severity="low", level="L1",
        rationale="Requests addressed to the bare IP bypass name-based virtual hosting and are typical of scanners.",
        remediation=(
            "Enable mod_rewrite and add:\nRewriteEngine On\n"
            "RewriteCond %{HTTP_HOST} !^www\\.example\\.com [NC]\n"
            "RewriteRule .* - [F]"
        ),
        check=lambda d, p: bool(re.search(
            r'RewriteCond.*HTTP_HOST', _get_output(d, "ip_based_restriction")
        )),
        evidence=lambda d, p: f"Host-header rules: {_ev(d, 'ip_based_restriction', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-5.13", cis_section="5.13",
        title="Ensure the IP addresses for listening for requests are specified",
        severity="low", level="L2",
        rationale="Binding to specific addresses prevents the server from unintentionally answering on new interfaces.",
        remediation="Replace bare 'Listen 80' directives with 'Listen <ip>:80' for each intended interface",
        check=lambda d, p: _listen_ips_specified(d),
        evidence=lambda d, p: f"Listen directives: {_ev(d, 'listen_directives', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-5.14", cis_section="5.14",
        title="Ensure browser framing is restricted",
        severity="medium", level="L1",
        rationale="Without X-Frame-Options/frame-ancestors the site can be embedded and clickjacked.",
        remediation="Add 'Header always set X-Frame-Options \"SAMEORIGIN\"' (or a CSP frame-ancestors policy)",
        check=lambda d, p: _security_header(d, "xfo_header"),
        evidence=lambda d, p: f"Framing headers: {_ev(d, 'xfo_header', 300)}"
    ))

    # ============ SECTION 6: LOGGING, MONITORING AND MAINTENANCE ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-6.1", cis_section="6.1",
        title="Ensure the error log filename and severity level are configured correctly",
        severity="medium", level="L1",
        rationale="Error logs at an adequate level are the primary record of attacks and misconfigurations.",
        remediation="Configure 'ErrorLog <path>' and 'LogLevel notice core:info' in the main configuration",
        check=lambda d, p: (
            "errorlog" in _get_output(d, "error_log_config").lower()
            and bool(re.search(
                r'LogLevel\s+\S*(debug|info|notice|warn)',
                _get_output(d, "error_log_config"), re.IGNORECASE
            ))
        ),
        evidence=lambda d, p: f"Error log config: {_ev(d, 'error_log_config', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-6.2", cis_section="6.2",
        title="Ensure a syslog facility is configured for error logging",
        severity="low", level="L1",
        rationale="Shipping errors to syslog preserves evidence off-host even if the server is compromised.",
        remediation="Add 'ErrorLog syslog:local1' (alongside central log collection) to the configuration",
        check=lambda d, p: not _not_configured(_get_output(d, "error_log_syslog")),
        evidence=lambda d, p: f"Syslog error log: {_ev(d, 'error_log_syslog', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-6.3", cis_section="6.3",
        title="Ensure the server access log is configured correctly",
        severity="medium", level="L1",
        rationale="Access logs with a complete format are essential for monitoring and forensics.",
        remediation="Configure 'CustomLog <path> combined' for the server and each virtual host",
        check=lambda d, p: "customlog" in _get_output(d, "access_log_config").lower(),
        evidence=lambda d, p: f"Access log config: {_ev(d, 'access_log_config')}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-6.4", cis_section="6.4",
        title="Ensure log storage and rotation is configured correctly",
        severity="low", level="L1",
        rationale="Unrotated logs fill the disk and complicate retention; rotation with adequate history preserves evidence.",
        remediation="Configure logrotate for the Apache logs (weekly rotation, >= 13 weeks retention)",
        check=lambda d, p: bool(re.search(
            r'rotate\s+\d+|weekly|daily',
            _get_output(d, "log_rotation"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"Logrotate config: {_ev(d, 'log_rotation', 400)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-6.5", cis_section="6.5",
        title="Ensure applicable patches are applied",
        severity="high", level="L1",
        rationale="Unpatched Apache versions carry publicly known, often remotely exploitable vulnerabilities.",
        remediation="Apply pending updates: apt-get install --only-upgrade apache2 (Debian) or dnf update httpd (RHEL)",
        check=lambda d, p: "no pending apache updates" in _get_output(d, "apache_updates").lower(),
        evidence=lambda d, p: (
            f"Pending updates: {_ev(d, 'apache_updates', 300)}\n"
            f"Version: {_ev(d, 'apache_version', 150)}"
        )
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-6.6", cis_section="6.6",
        title="Ensure ModSecurity is installed and enabled",
        severity="medium", level="L2",
        rationale="ModSecurity provides WAF capabilities — request inspection and virtual patching in front of the application.",
        remediation="Install and enable it: apt-get install libapache2-mod-security2 && a2enmod security2 (Debian) or dnf install mod_security (RHEL)",
        check=lambda d, p: "security2" in _get_output(d, "modsecurity_module").lower(),
        evidence=lambda d, p: f"ModSecurity module: {_ev(d, 'modsecurity_module', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-6.7", cis_section="6.7",
        title="Ensure the OWASP ModSecurity Core Rule Set is installed and enabled",
        severity="medium", level="L2",
        rationale="Without a rule set ModSecurity blocks nothing; the OWASP CRS provides baseline attack detection.",
        remediation="Install the CRS: apt-get install modsecurity-crs (Debian) or dnf install mod_security_crs (RHEL) and include it in the ModSecurity config",
        check=lambda d, p: "not found" not in _get_output(d, "modsecurity_crs").lower()
                          and bool(_get_output(d, "modsecurity_crs").strip()),
        evidence=lambda d, p: f"CRS references: {_ev(d, 'modsecurity_crs', 300)}"
    ))

    # ============ SECTION 7: SSL/TLS CONFIGURATION ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.1", cis_section="7.1",
        title="Ensure mod_ssl and/or mod_nss is installed",
        severity="high", level="L1",
        rationale="Without a TLS module all traffic — including credentials — crosses the network in cleartext.",
        remediation="Enable TLS support: a2enmod ssl (Debian) or dnf install mod_ssl (RHEL)",
        check=lambda d, p: bool(re.search(
            r'ssl_module|nss_module', _get_output(d, "ssl_module"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"TLS modules: {_ev(d, 'ssl_module', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.2", cis_section="7.2",
        title="Ensure a valid trusted certificate is installed",
        severity="high", level="L1",
        rationale="Expired or self-signed certificates break trust and train users to click through warnings.",
        remediation="Install a certificate issued by a trusted CA (SSLCertificateFile/SSLCertificateKeyFile) and renew before expiry",
        check=lambda d, p: _cert_valid_and_trusted(d),
        evidence=lambda d, p: f"Certificate: {_ev(d, 'ssl_cert_check', 400)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.3", cis_section="7.3",
        title="Ensure the server's private key is protected",
        severity="high", level="L1",
        rationale="A readable private key allows traffic decryption and server impersonation.",
        remediation="Restrict the key: chown root:root <keyfile> && chmod 400 <keyfile>",
        check=lambda d, p: _key_protected(d),
        evidence=lambda d, p: f"Key permissions: {_ev(d, 'ssl_key_perms', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.4", cis_section="7.4",
        title="Ensure the TLSv1.0 and TLSv1.1 protocols are disabled",
        severity="high", level="L1",
        rationale="TLS 1.0/1.1 (and SSLv3) are vulnerable to downgrade and padding-oracle attacks (POODLE, BEAST).",
        remediation="Set 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1' or 'SSLProtocol TLSv1.2 TLSv1.3'",
        check=lambda d, p: _check_ssl_protocol_secure(d),
        evidence=lambda d, p: f"SSLProtocol: {_ev(d, 'ssl_protocol', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.5", cis_section="7.5",
        title="Ensure weak SSL/TLS ciphers are disabled",
        severity="high", level="L1",
        rationale="NULL, RC4, DES and export-grade ciphers are practically breakable.",
        remediation="Set an SSLCipherSuite excluding weak families, e.g. 'ALL:!EXP:!NULL:!ADH:!LOW:!RC4:!DES'",
        check=lambda d, p: _ciphers_exclude(d, _WEAK_CIPHER_TOKENS),
        evidence=lambda d, p: f"SSLCipherSuite: {_ev(d, 'ssl_ciphers', 400)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.6", cis_section="7.6",
        title="Ensure insecure SSL renegotiation is not enabled",
        severity="medium", level="L1",
        rationale="SSLInsecureRenegotiation re-opens CVE-2009-3555 man-in-the-middle renegotiation attacks.",
        remediation="Remove 'SSLInsecureRenegotiation on' (or set it to off)",
        check=lambda d, p: not bool(re.search(
            r'SSLInsecureRenegotiation\s+on',
            _get_output(d, "ssl_insecure_reneg"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"Renegotiation: {_ev(d, 'ssl_insecure_reneg', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.7", cis_section="7.7",
        title="Ensure SSL compression is not enabled",
        severity="medium", level="L1",
        rationale="TLS compression enables the CRIME attack, recovering secrets from compressed responses.",
        remediation="Ensure 'SSLCompression off' (the Apache 2.4 default) and remove any 'SSLCompression on'",
        check=lambda d, p: not bool(re.search(
            r'SSLCompression\s+on',
            _get_output(d, "ssl_compression"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"SSLCompression: {_ev(d, 'ssl_compression', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.8", cis_section="7.8",
        title="Ensure medium strength SSL/TLS ciphers are disabled",
        severity="medium", level="L1",
        rationale="3DES and IDEA (64-bit block ciphers) are vulnerable to SWEET32 birthday attacks.",
        remediation="Extend SSLCipherSuite with '!3DES:!IDEA'",
        check=lambda d, p: _ciphers_exclude(d, _MEDIUM_CIPHER_TOKENS),
        evidence=lambda d, p: f"SSLCipherSuite: {_ev(d, 'ssl_ciphers', 400)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.9", cis_section="7.9",
        title="Ensure all web content is accessed via HTTPS",
        severity="high", level="L1",
        rationale="Content served over HTTP can be read and modified in transit, including session cookies.",
        remediation="Redirect HTTP to HTTPS in the port-80 virtual host: 'Redirect permanent / https://<site>/' or an equivalent RewriteRule",
        check=lambda d, p: not _not_configured(_get_output(d, "https_redirect")),
        evidence=lambda d, p: f"HTTPS redirects: {_ev(d, 'https_redirect', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.10", cis_section="7.10",
        title="Ensure OCSP stapling is enabled",
        severity="low", level="L1",
        rationale="Stapling delivers certificate revocation status without leaking client browsing to the CA.",
        remediation=(
            "Add:\nSSLUseStapling On\n"
            "SSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\""
        ),
        check=lambda d, p: bool(re.search(
            r'SSLUseStapling\s+on',
            _get_output(d, "ocsp_stapling"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"OCSP stapling: {_ev(d, 'ocsp_stapling', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-7.11", cis_section="7.11",
        title="Ensure HTTP Strict Transport Security (HSTS) is enabled",
        severity="medium", level="L1",
        rationale="HSTS forces browsers to use HTTPS, defeating SSL-stripping downgrade attacks.",
        remediation="Add 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"'",
        check=lambda d, p: "strict-transport-security" in _get_output(d, "hsts_header").lower(),
        evidence=lambda d, p: f"HSTS: {_ev(d, 'hsts_header', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-7.12", cis_section="7.12",
        title="Ensure only cipher suites that provide forward secrecy are enabled",
        severity="medium", level="L2",
        rationale="Without ECDHE/DHE key exchange, one leaked private key decrypts all recorded past traffic.",
        remediation="Restrict SSLCipherSuite to ECDHE/DHE families, e.g. 'EECDH:EDH:!NULL:!SSLv2:!RC4:!aNULL:!3DES:!IDEA'",
        check=lambda d, p: _forward_secrecy_only(d),
        evidence=lambda d, p: f"SSLCipherSuite: {_ev(d, 'ssl_ciphers', 400)}"
    ))

    # ============ SECTION 8: INFORMATION LEAKAGE ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-8.1", cis_section="8.1",
        title="Ensure ServerTokens is set to Prod or ProductOnly",
        severity="medium", level="L1",
        rationale="Fuller ServerTokens values disclose the exact version and modules to every client.",
        remediation="Set 'ServerTokens Prod' in the Apache configuration",
        check=lambda d, p: bool(re.search(
            r'ServerTokens\s+(Prod|ProductOnly)\b',
            _get_output(d, "server_tokens"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"ServerTokens: {_ev(d, 'server_tokens', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-8.2", cis_section="8.2",
        title="Ensure ServerSignature is not enabled",
        severity="medium", level="L1",
        rationale="ServerSignature appends server version details to error pages and listings.",
        remediation="Set 'ServerSignature Off' in the Apache configuration",
        check=lambda d, p: not bool(re.search(
            r'ServerSignature\s+(On|EMail)\b',
            _get_output(d, "server_signature"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"ServerSignature: {_ev(d, 'server_signature', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-8.3", cis_section="8.3",
        title="Ensure all default Apache content is removed",
        severity="medium", level="L1",
        rationale="Icons, manuals and welcome pages fingerprint the installation and occasionally carry vulnerabilities.",
        remediation="Remove or un-alias default content (manual, icons, welcome page) from all enabled configurations",
        check=lambda d, p: _default_content_removed(d),
        evidence=lambda d, p: (
            f"Default page: {_ev(d, 'default_page_check', 200)}\n"
            f"Manual content: {_ev(d, 'manual_content', 200)}"
        )
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-8.4", cis_section="8.4",
        title="Ensure ETag response header fields do not include Inodes",
        severity="low", level="L1",
        rationale="Inode-based ETags leak filesystem details and allow cross-server correlation of files.",
        remediation="Set 'FileETag None' (or 'FileETag MTime Size') in the Apache configuration",
        check=lambda d, p: not bool(re.search(
            r'FileETag\s+[^\n]*\b(INode|All)\b',
            _get_output(d, "file_etag"), re.IGNORECASE
        )),
        evidence=lambda d, p: f"FileETag: {_ev(d, 'file_etag', 200)}"
    ))

    # ============ SECTION 9: DENIAL OF SERVICE MITIGATIONS ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-9.1", cis_section="9.1",
        title="Ensure the TimeOut is set to 10 or less",
        severity="medium", level="L1",
        rationale="A low Timeout limits how long slow clients (Slowloris-style) can hold worker slots.",
        remediation="Set 'Timeout 10' in the Apache configuration",
        check=lambda d, p: _directive_max_ok(d, "timeout_config", "Timeout", 10),
        evidence=lambda d, p: f"Timeout: {_ev(d, 'timeout_config', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-9.2", cis_section="9.2",
        title="Ensure KeepAlive is enabled",
        severity="low", level="L1",
        rationale="KeepAlive reuses connections, reducing the TCP/TLS setup load an attacker can amplify.",
        remediation="Set 'KeepAlive On' in the Apache configuration (the default when unset)",
        check=lambda d, p: not bool(re.search(
            r'^\s*KeepAlive\s+Off\b',
            _get_output(d, "keepalive_config"), re.IGNORECASE | re.MULTILINE
        )),
        evidence=lambda d, p: f"KeepAlive: {_ev(d, 'keepalive_config', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-9.3", cis_section="9.3",
        title="Ensure MaxKeepAliveRequests is set to 100 or greater",
        severity="low", level="L1",
        rationale="A low request cap forces frequent reconnects, wasting capacity under load.",
        remediation="Set 'MaxKeepAliveRequests 100' (or greater); the default of 100 is acceptable",
        check=lambda d, p: _directive_min_ok(
            d, "keepalive_config", "MaxKeepAliveRequests", 100, absent_ok=True
        ),
        evidence=lambda d, p: f"MaxKeepAliveRequests: {_ev(d, 'keepalive_config', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-9.4", cis_section="9.4",
        title="Ensure KeepAliveTimeout is set to 15 or less",
        severity="low", level="L1",
        rationale="Long keep-alive timeouts let idle connections occupy workers; the default of 5 is safe.",
        remediation="Set 'KeepAliveTimeout 15' or less",
        check=lambda d, p: _directive_max_ok(
            d, "keepalive_config", "KeepAliveTimeout", 15, absent_ok=True
        ),
        evidence=lambda d, p: f"KeepAliveTimeout: {_ev(d, 'keepalive_config', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-9.5", cis_section="9.5",
        title="Ensure the timeout limits for request headers are set to 40 or less",
        severity="medium", level="L1",
        rationale="mod_reqtimeout's header limit is the primary defence against Slowloris header attacks.",
        remediation="Enable mod_reqtimeout and set 'RequestReadTimeout header=20-40,MinRate=500'",
        check=lambda d, p: _reqtimeout_ok(d, "header", 40),
        evidence=lambda d, p: f"RequestReadTimeout: {_ev(d, 'request_read_timeout', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-9.6", cis_section="9.6",
        title="Ensure the timeout limits for the request body are set to 20 or less",
        severity="medium", level="L1",
        rationale="A body read limit stops attackers trickling request bodies to exhaust workers.",
        remediation="Set 'RequestReadTimeout body=20,MinRate=500' in the mod_reqtimeout configuration",
        check=lambda d, p: _reqtimeout_ok(d, "body", 20),
        evidence=lambda d, p: f"RequestReadTimeout: {_ev(d, 'request_read_timeout', 200)}"
    ))

    # ============ SECTION 10: REQUEST LIMITS ============

    rules.append(ApacheCISRule(
        id="APACHE-L1-10.1", cis_section="10.1",
        title="Ensure the LimitRequestLine directive is set to 512 or less",
        severity="low", level="L1",
        rationale="Oversized request lines are a common vector for buffer abuse and evasion (default is 8190).",
        remediation="Set 'LimitRequestLine 512' in the Apache configuration",
        check=lambda d, p: _directive_max_ok(d, "request_limits", "LimitRequestLine", 512),
        evidence=lambda d, p: f"Request limits: {_ev(d, 'request_limits', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-10.2", cis_section="10.2",
        title="Ensure the LimitRequestFields directive is set to 100 or less",
        severity="low", level="L1",
        rationale="Capping header count limits header-flood memory abuse; the default of 100 is acceptable.",
        remediation="Set 'LimitRequestFields 100' (or less)",
        check=lambda d, p: _directive_max_ok(
            d, "request_limits", "LimitRequestFields", 100, absent_ok=True
        ),
        evidence=lambda d, p: f"Request limits: {_ev(d, 'request_limits', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-10.3", cis_section="10.3",
        title="Ensure the LimitRequestFieldsize directive is set to 1024 or less",
        severity="low", level="L1",
        rationale="Restricting individual header size (default 8190) limits memory abuse per request.",
        remediation="Set 'LimitRequestFieldSize 1024' in the Apache configuration",
        check=lambda d, p: _directive_max_ok(d, "request_limits", "LimitRequestFieldSize", 1024),
        evidence=lambda d, p: f"Request limits: {_ev(d, 'request_limits', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L1-10.4", cis_section="10.4",
        title="Ensure the LimitRequestBody directive is set to 102400 or less",
        severity="low", level="L1",
        rationale="An unlimited request body (the default) allows resource-exhaustion uploads.",
        remediation="Set 'LimitRequestBody 102400' (raise only for endpoints that genuinely need uploads)",
        check=lambda d, p: _directive_max_ok(d, "request_limits", "LimitRequestBody", 102400),
        evidence=lambda d, p: f"Request limits: {_ev(d, 'request_limits', 300)}"
    ))

    # ============ SECTION 11: SELINUX (RHEL FAMILY) ============

    rules.append(ApacheCISRule(
        id="APACHE-L2-11.1", cis_section="11.1",
        title="Ensure SELinux is enabled in enforcing mode",
        severity="medium", level="L2", distros=["rhel"],
        rationale="Enforcing SELinux confines a compromised Apache process to its policy, containing the blast radius.",
        remediation="Set SELINUX=enforcing in /etc/selinux/config and run 'setenforce 1'",
        check=lambda d, p: "enforcing" in _get_output(d, "selinux_status").lower()
                          and "not available" not in _get_output(d, "selinux_status").lower(),
        evidence=lambda d, p: f"getenforce: {_ev(d, 'selinux_status', 100)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-11.2", cis_section="11.2",
        title="Ensure Apache processes run in the httpd_t confined context",
        severity="medium", level="L2", distros=["rhel"],
        rationale="Apache outside the httpd_t domain is effectively unconfined by SELinux policy.",
        remediation="Restore contexts: restorecon -Rv /usr/sbin/httpd /etc/httpd and restart the service",
        check=lambda d, p: "httpd_t" in _get_output(d, "selinux_httpd_context"),
        evidence=lambda d, p: f"Process contexts: {_ev(d, 'selinux_httpd_context', 300)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-11.3", cis_section="11.3",
        title="Ensure the httpd_t type is not in permissive mode",
        severity="medium", level="L2", distros=["rhel"],
        rationale="A permissive httpd_t domain logs violations but does not block them, silently disabling confinement.",
        remediation="Remove the permissive marking: semanage permissive -d httpd_t",
        check=lambda d, p: "httpd_t not in permissive list" in _get_output(d, "selinux_permissive"),
        evidence=lambda d, p: f"Permissive domains: {_ev(d, 'selinux_permissive', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-11.4", cis_section="11.4",
        title="Ensure only the necessary SELinux booleans are enabled",
        severity="info", level="L2", distros=["rhel"], manual=True,
        rationale="Each enabled httpd_* boolean relaxes the SELinux policy for Apache.",
        remediation=(
            "MANUAL: Review the enabled httpd booleans below and disable any "
            "not required by the application: setsebool -P <boolean> off"
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: f"Enabled httpd booleans: {_ev(d, 'selinux_booleans', 400)}"
    ))

    # ============ SECTION 12: APPARMOR (DEBIAN FAMILY) ============

    rules.append(ApacheCISRule(
        id="APACHE-L2-12.1", cis_section="12.1",
        title="Ensure the AppArmor framework is enabled",
        severity="medium", level="L2", distros=["debian"],
        rationale="AppArmor provides mandatory access control that confines Apache on Debian-family systems.",
        remediation="Install and enable AppArmor: apt-get install apparmor apparmor-utils && systemctl enable --now apparmor",
        check=lambda d, p: "apparmor enabled" in _get_output(d, "apparmor_status").lower(),
        evidence=lambda d, p: f"AppArmor status: {_ev(d, 'apparmor_status', 200)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-12.2", cis_section="12.2",
        title="Ensure the Apache AppArmor profile is configured properly",
        severity="info", level="L2", distros=["debian"], manual=True,
        rationale="An over-permissive profile provides no meaningful confinement.",
        remediation=(
            "MANUAL: Review the profile below (/etc/apparmor.d/usr.sbin.apache2). "
            "It should grant read access to web content, write only to logs and "
            "runtime dirs, and nothing beyond what the sites need. Build one "
            "with aa-autodep/aa-logprof if missing."
        ),
        check=lambda d, p: False,
        evidence=lambda d, p: f"Profile: {_ev(d, 'apparmor_profile', 600)}"
    ))

    rules.append(ApacheCISRule(
        id="APACHE-L2-12.3", cis_section="12.3",
        title="Ensure the Apache AppArmor profile is in enforce mode",
        severity="medium", level="L2", distros=["debian"],
        rationale="A profile in complain mode logs violations without blocking them.",
        remediation="Enforce the profile: aa-enforce /etc/apparmor.d/usr.sbin.apache2 and restart Apache",
        check=lambda d, p: "(enforce)" in _get_output(d, "apparmor_process_profile"),
        evidence=lambda d, p: f"Process confinement: {_ev(d, 'apparmor_process_profile', 200)}"
    ))

    return rules


# ========================= FILTERING FUNCTIONS =========================

def filter_rules_by_profile(rules: List[ApacheCISRule], profile: str) -> List[ApacheCISRule]:
    """
    Filter rules by CIS profile (L1 or FULL).

    Args:
        rules: List of all rules
        profile: "L1" for Level 1 only, "FULL" for all rules

    Returns:
        Filtered list of rules
    """
    if profile == "FULL":
        return rules
    return [r for r in rules if r.level == "L1"]


def filter_rules_by_distro(rules: List[ApacheCISRule], distro_profile: str) -> List[ApacheCISRule]:
    """
    Filter rules by distribution compatibility.

    Args:
        rules: List of all rules
        distro_profile: Distribution profile or family (e.g., "ubuntu_22", "debian", "rhel")

    Returns:
        Rules compatible with the distribution
    """
    filtered = []
    distro_family = distro_profile.split("_")[0] if "_" in distro_profile else distro_profile

    for rule in rules:
        if "all" in rule.distros:
            filtered.append(rule)
        elif distro_profile in rule.distros:
            filtered.append(rule)
        elif distro_family in rule.distros:
            filtered.append(rule)

    return filtered


# ========================= EVALUATION =========================

def evaluate_compliance(
    audit_data: Dict[str, str],
    rules: List[ApacheCISRule],
    distro_profile: str = "ubuntu_22"
) -> Dict[str, Any]:
    """
    Evaluate compliance against CIS rules.

    Manual controls are never scored: they are emitted with status "skipped"
    and evidence explaining what to verify by hand.

    Args:
        audit_data: Dict of command outputs from audit collection
        rules: List of CIS rules to evaluate
        distro_profile: Distribution profile for distro-aware checks

    Returns:
        Dict with compliance summary and findings
    """
    findings = []
    passed_scored = 0
    failed_scored = 0
    manual_checks = 0
    total_weighted = 0
    passed_weighted = 0

    for rule in rules:
        if rule.manual:
            manual_checks += 1
            try:
                evidence = rule.evidence(audit_data, distro_profile)
            except Exception as e:
                evidence = f"Error collecting evidence: {str(e)}"
            findings.append({
                "id": rule.id,
                "cis_section": rule.cis_section,
                "title": rule.title,
                "severity": rule.severity,
                "level": rule.level,
                "compliant": False,
                "manual": True,
                "status": "skipped",
                "evidence": (
                    f"SKIPPED — manual verification required. {rule.remediation}\n\n"
                    f"Collected evidence:\n{evidence}"
                )[:1000],
                "rationale": rule.rationale,
                "remediation": rule.remediation
            })
            continue

        try:
            compliant = rule.check(audit_data, distro_profile)
            evidence = rule.evidence(audit_data, distro_profile)
        except Exception as e:
            compliant = False
            evidence = f"Error evaluating rule: {str(e)}"

        weight = SEVERITY_WEIGHT.get(rule.severity, 1)

        if rule.level != "INFO":
            total_weighted += weight
            if compliant:
                passed_scored += 1
                passed_weighted += weight
            else:
                failed_scored += 1

        findings.append({
            "id": rule.id,
            "cis_section": rule.cis_section,
            "title": rule.title,
            "severity": rule.severity,
            "level": rule.level,
            "compliant": compliant,
            "manual": False,
            "status": "pass" if compliant else "fail",
            "evidence": evidence[:1000] if evidence else "",
            "rationale": rule.rationale,
            "remediation": rule.remediation
        })

    total_rules_scored = passed_scored + failed_scored
    compliance_pct = (passed_scored / total_rules_scored * 100) if total_rules_scored > 0 else 0.0
    weighted_compliance_pct = (passed_weighted / total_weighted * 100) if total_weighted > 0 else 0.0

    return {
        "summary": {
            "total_rules": len(rules),
            "total_rules_scored": total_rules_scored,
            "manual_checks": manual_checks,
            "passed_scored": passed_scored,
            "failed_scored": failed_scored,
            "compliance_pct": round(compliance_pct, 2),
            "weighted_compliance_pct": round(weighted_compliance_pct, 2)
        },
        "findings": findings
    }
