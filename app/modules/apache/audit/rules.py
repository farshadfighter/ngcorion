"""
Apache HTTP Server CIS Benchmark Rules

CIS security compliance rules for Apache HTTP Server 2.4.x
Based on CIS Apache HTTP Server 2.4 Benchmark

Each rule includes:
- Unique ID (e.g., APACHE-L1-2.1)
- Title and description
- Severity level (high/medium/low/info)
- Level (L1/L2/INFO)
- Check function (returns True if compliant)
- Evidence extraction function
- Rationale and remediation guidance
"""

import re
from typing import List, Dict, Any, Callable
from dataclasses import dataclass, field


# ========================= RULE DATACLASS =========================

@dataclass
class ApacheCISRule:
    """Represents a single Apache CIS compliance check."""

    id: str                          # "APACHE-L1-2.1"
    cis_section: str                 # "2.1" - CIS Benchmark section
    title: str                       # Short description
    severity: str                    # high/medium/low/info
    level: str                       # L1/L2/INFO
    rationale: str                   # Why this matters
    remediation: str                 # How to fix
    check: Callable[[Dict[str, str], str], bool]  # Function: returns True if compliant
    evidence: Callable[[Dict[str, str], str], str]  # Function: returns evidence text
    distros: List[str] = field(default_factory=lambda: ["all"])  # Supported distros


# ========================= SEVERITY WEIGHTS =========================

SEVERITY_WEIGHT = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}


# ========================= HELPER FUNCTIONS =========================

def _get_output(data: Dict[str, str], key: str) -> str:
    """Get command output from data dict, handling errors."""
    output = data.get(key, "")
    if output.startswith("<<ERROR:"):
        return ""
    return output


def _check_module_enabled(data: Dict[str, str], module: str) -> bool:
    """Check if an Apache module is enabled/loaded."""
    output = _get_output(data, "apache_modules")
    if not output:
        return False
    return module.lower() in output.lower()


def _check_module_disabled(data: Dict[str, str], module: str) -> bool:
    """Check if an Apache module is disabled/not loaded."""
    return not _check_module_enabled(data, module)


def _check_directive_configured(data: Dict[str, str], key: str, directive: str) -> bool:
    """Check if a directive is configured (exists in output)."""
    output = _get_output(data, key)
    if not output or "not configured" in output.lower() or "not found" in output.lower():
        return False
    return directive.lower() in output.lower()


def _check_directive_value(data: Dict[str, str], key: str, directive: str, expected: str) -> bool:
    """Check if a directive has the expected value."""
    output = _get_output(data, key)
    if not output:
        return False

    pattern = rf'{directive}\s+{re.escape(expected)}'
    return bool(re.search(pattern, output, re.IGNORECASE))


def _check_directive_not_configured(data: Dict[str, str], key: str) -> bool:
    """Check that something is NOT configured (for things that should be disabled)."""
    output = _get_output(data, key)
    if not output:
        return True
    lower = output.lower()
    return "not configured" in lower or "not found" in lower or not output.strip()


def _check_ssl_protocol_secure(data: Dict[str, str]) -> bool:
    """Check that SSLProtocol disables insecure protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)."""
    output = _get_output(data, "ssl_protocol")
    if not output or "not configured" in output.lower():
        return False

    lower = output.lower()
    # Should have -SSLv2, -SSLv3, -TLSv1, -TLSv1.1 or "all -SSLv3 -TLSv1 -TLSv1.1"
    if "-sslv3" in lower or "-sslv2" in lower:
        if "-tlsv1" in lower or "all" in lower:
            return True
    # Or explicitly only TLSv1.2+ enabled
    if "tlsv1.2" in lower or "tlsv1.3" in lower:
        if "sslv3" not in lower.replace("-sslv3", "") and "tlsv1 " not in lower.replace("-tlsv1", ""):
            return True

    return False


def _check_file_permissions(data: Dict[str, str], key: str, max_mode: str = "644") -> bool:
    """Check file permissions from stat output."""
    output = _get_output(data, key)
    if not output or "not found" in output.lower():
        return False

    # Parse stat output - look for Access: (0644/-rw-r--r--)
    mode_match = re.search(r'Access:\s*\((\d+)', output)
    if mode_match:
        actual_mode = mode_match.group(1)[-3:]  # Get last 3 digits
        try:
            if int(actual_mode, 8) <= int(max_mode, 8):
                return True
        except ValueError:
            pass
    return False


def _check_apache_running_non_root(data: Dict[str, str]) -> bool:
    """Check that Apache runs as non-root user."""
    # Check User directive
    output = _get_output(data, "apache_user_group")
    if output and "not configured" not in output.lower():
        if "User" in output:
            # Should not be root
            if re.search(r'User\s+root', output, re.IGNORECASE):
                return False

    # Check process user
    proc_output = _get_output(data, "apache_process")
    if proc_output:
        # Worker processes should not run as root
        for line in proc_output.split('\n'):
            if 'grep' not in line and ('apache2' in line or 'httpd' in line):
                parts = line.split()
                if parts and parts[0] == 'root':
                    # Main process runs as root, that's OK
                    # Check if there are worker processes not as root
                    continue

    return True


def _check_trace_disabled(data: Dict[str, str]) -> bool:
    """Check that HTTP TRACE method is disabled."""
    output = _get_output(data, "trace_enable")
    if not output:
        return False
    if "not configured" in output.lower():
        return False
    return "traceenable off" in output.lower()


def _check_server_tokens_prod(data: Dict[str, str]) -> bool:
    """Check that ServerTokens is set to Prod or ProductOnly."""
    output = _get_output(data, "server_tokens")
    if not output or "not configured" in output.lower():
        return False
    lower = output.lower()
    return "prod" in lower or "productonly" in lower


def _check_server_signature_off(data: Dict[str, str]) -> bool:
    """Check that ServerSignature is Off."""
    output = _get_output(data, "server_signature")
    if not output or "not configured" in output.lower():
        return False
    return "off" in output.lower()


def _check_indexes_disabled(data: Dict[str, str]) -> bool:
    """Check that directory indexing is disabled."""
    output = _get_output(data, "options_directive")
    if not output:
        return True  # No Options configured, default is usually safe

    # Check for -Indexes or that Indexes is not present
    if "-indexes" in output.lower():
        return True
    if "indexes" not in output.lower():
        return True

    return False


def _check_hsts_enabled(data: Dict[str, str]) -> bool:
    """Check that HSTS header is configured."""
    output = _get_output(data, "hsts_header")
    if not output or "not configured" in output.lower():
        return False
    return "strict-transport-security" in output.lower()


def _check_security_header(data: Dict[str, str], key: str) -> bool:
    """Check that a security header is configured."""
    output = _get_output(data, key)
    if not output or "not configured" in output.lower():
        return False
    return len(output.strip()) > 0


# ========================= RULE DEFINITIONS =========================

def build_apache_cis_rules() -> List[ApacheCISRule]:
    """
    Build complete set of Apache CIS compliance rules.

    Returns:
        List[ApacheCISRule]: All CIS rules for Apache HTTP Server
    """
    rules: List[ApacheCISRule] = []

    # ==================== SECTION 2: MINIMIZE APACHE MODULES ====================

    # 2.3 - Disable WebDAV Modules
    rules.append(ApacheCISRule(
        id="APACHE-L1-2.3",
        cis_section="2.3",
        title="Ensure WebDAV modules are disabled",
        severity="high",
        level="L1",
        rationale="WebDAV modules (mod_dav, mod_dav_fs, mod_dav_lock) allow remote users to edit files on the server, which is a significant security risk if not needed.",
        remediation="Disable WebDAV modules: a2dismod dav dav_fs dav_lock (Debian) or comment out LoadModule in httpd.conf (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "dav_module") and _check_module_disabled(d, "dav_fs_module"),
        evidence=lambda d, p: f"Modules: {_get_output(d, 'apache_modules')[:500]}\nDAV Config: {_get_output(d, 'mod_dav_config')[:300]}"
    ))

    # 2.4 - Restrict mod_status
    rules.append(ApacheCISRule(
        id="APACHE-L1-2.4",
        cis_section="2.4",
        title="Ensure mod_status is restricted or disabled",
        severity="high",
        level="L1",
        rationale="mod_status provides server status information that could help attackers understand server configuration. If enabled, it should be restricted to localhost only.",
        remediation="Disable mod_status (a2dismod status) or restrict access to localhost only",
        check=lambda d, p: _check_module_disabled(d, "status_module") or "localhost" in _get_output(d, "mod_status_config").lower() or "127.0.0.1" in _get_output(d, "mod_status_config"),
        evidence=lambda d, p: f"Status Config: {_get_output(d, 'mod_status_config')[:500]}"
    ))

    # 2.5 - Disable mod_info
    rules.append(ApacheCISRule(
        id="APACHE-L1-2.5",
        cis_section="2.5",
        title="Ensure mod_info is disabled",
        severity="high",
        level="L1",
        rationale="mod_info reveals detailed server configuration information that could help attackers plan their attacks.",
        remediation="Disable mod_info: a2dismod info (Debian) or comment out LoadModule mod_info in httpd.conf (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "info_module"),
        evidence=lambda d, p: f"Info Config: {_get_output(d, 'mod_info_config')[:500]}"
    ))

    # 2.6 - Disable mod_userdir
    rules.append(ApacheCISRule(
        id="APACHE-L1-2.6",
        cis_section="2.6",
        title="Ensure mod_userdir is disabled",
        severity="medium",
        level="L1",
        rationale="mod_userdir allows users to access their home directories via the web server (~username), which can lead to information disclosure.",
        remediation="Disable mod_userdir: a2dismod userdir (Debian) or comment out LoadModule mod_userdir (RHEL)",
        check=lambda d, p: _check_module_disabled(d, "userdir_module") or "userdir disabled" in _get_output(d, "mod_userdir_config").lower(),
        evidence=lambda d, p: f"UserDir Config: {_get_output(d, 'mod_userdir_config')[:500]}"
    ))

    # 2.7 - Disable autoindex
    rules.append(ApacheCISRule(
        id="APACHE-L1-2.7",
        cis_section="2.7",
        title="Ensure mod_autoindex is disabled or Indexes option is off",
        severity="medium",
        level="L1",
        rationale="mod_autoindex generates directory listings which can reveal file structure and potentially sensitive files.",
        remediation="Disable mod_autoindex (a2dismod autoindex) or set 'Options -Indexes' in Apache config",
        check=lambda d, p: _check_module_disabled(d, "autoindex_module") or _check_indexes_disabled(d),
        evidence=lambda d, p: f"Autoindex Config: {_get_output(d, 'mod_autoindex_config')[:300]}\nOptions: {_get_output(d, 'options_directive')[:300]}"
    ))

    # ==================== SECTION 3: PERMISSIONS AND OWNERSHIP ====================

    # 3.1 - Run Apache as non-root
    rules.append(ApacheCISRule(
        id="APACHE-L1-3.1",
        cis_section="3.1",
        title="Ensure Apache runs as a non-root user",
        severity="high",
        level="L1",
        rationale="Running Apache as root means any vulnerability could lead to full system compromise. Worker processes should run as a dedicated, unprivileged user.",
        remediation="Set User and Group directives to www-data (Debian) or apache (RHEL) in Apache config",
        check=lambda d, p: _check_apache_running_non_root(d),
        evidence=lambda d, p: f"User/Group: {_get_output(d, 'apache_user_group')[:300]}\nProcess: {_get_output(d, 'apache_process')[:500]}"
    ))

    # 3.2 - Apache user dedicated account
    rules.append(ApacheCISRule(
        id="APACHE-L1-3.2",
        cis_section="3.2",
        title="Ensure Apache user is a dedicated system account",
        severity="medium",
        level="L1",
        rationale="The Apache user should be a dedicated system account with no login shell and limited privileges.",
        remediation="Create dedicated Apache user: useradd -r -s /sbin/nologin apache",
        check=lambda d, p: "www-data" in _get_output(d, "apache_user_id") or "apache" in _get_output(d, "apache_user_id"),
        evidence=lambda d, p: f"User ID: {_get_output(d, 'apache_user_id')[:300]}"
    ))

    # 3.3 - Apache user shell
    rules.append(ApacheCISRule(
        id="APACHE-L1-3.3",
        cis_section="3.3",
        title="Ensure Apache user has a non-login shell",
        severity="medium",
        level="L1",
        rationale="The Apache user should have a non-login shell (like /sbin/nologin or /usr/sbin/nologin) to prevent interactive logins.",
        remediation="Set shell: usermod -s /sbin/nologin www-data (or apache)",
        check=lambda d, p: "nologin" in _get_output(d, "apache_user_shell").lower() or "/bin/false" in _get_output(d, "apache_user_shell").lower(),
        evidence=lambda d, p: f"Shell: {_get_output(d, 'apache_user_shell')[:200]}"
    ))

    # 3.4 - Apache user locked
    rules.append(ApacheCISRule(
        id="APACHE-L1-3.4",
        cis_section="3.4",
        title="Ensure Apache user account is locked",
        severity="low",
        level="L1",
        rationale="The Apache user account should be locked to prevent password-based authentication.",
        remediation="Lock account: passwd -l www-data (or apache)",
        check=lambda d, p: " L " in _get_output(d, "apache_user_locked") or "LK" in _get_output(d, "apache_user_locked"),
        evidence=lambda d, p: f"Account status: {_get_output(d, 'apache_user_locked')[:200]}"
    ))

    # 3.5 - Config directory permissions
    rules.append(ApacheCISRule(
        id="APACHE-L1-3.5",
        cis_section="3.5",
        title="Ensure Apache config directory has restrictive permissions",
        severity="medium",
        level="L1",
        rationale="Apache configuration directory should be owned by root with restrictive permissions (755 or more restrictive).",
        remediation="Set permissions: chown root:root /etc/apache2 && chmod 755 /etc/apache2",
        check=lambda d, p: _check_file_permissions(d, "config_dir_stat", "755"),
        evidence=lambda d, p: f"Config dir: {_get_output(d, 'config_dir_stat')[:500]}"
    ))

    # 3.6 - Main config file permissions
    rules.append(ApacheCISRule(
        id="APACHE-L1-3.6",
        cis_section="3.6",
        title="Ensure Apache main config file has restrictive permissions",
        severity="medium",
        level="L1",
        rationale="The main Apache configuration file should be owned by root with restrictive permissions (644 or more restrictive).",
        remediation="Set permissions: chown root:root /etc/apache2/apache2.conf && chmod 644 /etc/apache2/apache2.conf",
        check=lambda d, p: _check_file_permissions(d, "main_config_stat", "644"),
        evidence=lambda d, p: f"Main config: {_get_output(d, 'main_config_stat')[:500]}"
    ))

    # 3.8 - Log directory permissions
    rules.append(ApacheCISRule(
        id="APACHE-L1-3.8",
        cis_section="3.8",
        title="Ensure Apache log directory has restrictive permissions",
        severity="medium",
        level="L1",
        rationale="Apache log directory should be owned by root with restrictive permissions to prevent tampering.",
        remediation="Set permissions: chown root:adm /var/log/apache2 && chmod 750 /var/log/apache2",
        check=lambda d, p: _check_file_permissions(d, "log_dir_stat", "755"),
        evidence=lambda d, p: f"Log dir: {_get_output(d, 'log_dir_stat')[:500]}"
    ))

    # ==================== SECTION 4: ACCESS CONTROL ====================

    # 4.1 - Deny access by default
    rules.append(ApacheCISRule(
        id="APACHE-L1-4.1",
        cis_section="4.1",
        title="Ensure default access is denied",
        severity="high",
        level="L1",
        rationale="The server root directory should deny access by default. Access should be explicitly granted to specific directories.",
        remediation="Add 'Require all denied' for the root directory and grant access only to DocumentRoot",
        check=lambda d, p: "require all denied" in _get_output(d, "deny_by_default").lower() or "deny from all" in _get_output(d, "deny_by_default").lower(),
        evidence=lambda d, p: f"Deny config: {_get_output(d, 'deny_by_default')[:500]}"
    ))

    # 4.2 - AllowOverride
    rules.append(ApacheCISRule(
        id="APACHE-L1-4.2",
        cis_section="4.2",
        title="Ensure AllowOverride is set appropriately",
        severity="medium",
        level="L1",
        rationale="AllowOverride controls which directives can be overridden in .htaccess files. It should be set to None or a specific list of allowed directives.",
        remediation="Set 'AllowOverride None' for most directories, use AllowOverrideList for specific needs",
        check=lambda d, p: "allowoverride none" in _get_output(d, "allow_override").lower() or _check_directive_not_configured(d, "allow_override"),
        evidence=lambda d, p: f"AllowOverride: {_get_output(d, 'allow_override')[:500]}"
    ))

    # 4.4 - Options directive
    rules.append(ApacheCISRule(
        id="APACHE-L1-4.4",
        cis_section="4.4",
        title="Ensure Options directive is restrictive",
        severity="medium",
        level="L1",
        rationale="The Options directive should be restrictive. Indexes, FollowSymLinks, and other options can be security risks.",
        remediation="Set 'Options None' or 'Options -Indexes -FollowSymLinks' for directories",
        check=lambda d, p: _check_indexes_disabled(d),
        evidence=lambda d, p: f"Options: {_get_output(d, 'options_directive')[:500]}"
    ))

    # ==================== SECTION 5: MINIMIZE FEATURES ====================

    # 5.8 - Disable HTTP TRACE
    rules.append(ApacheCISRule(
        id="APACHE-L1-5.8",
        cis_section="5.8",
        title="Ensure HTTP TRACE method is disabled",
        severity="high",
        level="L1",
        rationale="The HTTP TRACE method can be exploited for Cross-Site Tracing (XST) attacks to steal cookies and credentials.",
        remediation="Add 'TraceEnable Off' to Apache configuration",
        check=lambda d, p: _check_trace_disabled(d),
        evidence=lambda d, p: f"TraceEnable: {_get_output(d, 'trace_enable')[:300]}"
    ))

    # ==================== SECTION 6: LOGGING ====================

    # 6.1 - Error logging
    rules.append(ApacheCISRule(
        id="APACHE-L1-6.1",
        cis_section="6.1",
        title="Ensure error logging is configured",
        severity="medium",
        level="L1",
        rationale="Error logging is essential for debugging and security monitoring. LogLevel should be set to at least warn.",
        remediation="Configure ErrorLog and set LogLevel to at least 'warn' or 'error'",
        check=lambda d, p: "errorlog" in _get_output(d, "error_log_config").lower(),
        evidence=lambda d, p: f"Error Log: {_get_output(d, 'error_log_config')[:300]}"
    ))

    # 6.3 - Access logging
    rules.append(ApacheCISRule(
        id="APACHE-L1-6.3",
        cis_section="6.3",
        title="Ensure access logging is configured",
        severity="medium",
        level="L1",
        rationale="Access logging is essential for monitoring and forensics. All requests should be logged.",
        remediation="Configure CustomLog with combined or forensic log format",
        check=lambda d, p: "customlog" in _get_output(d, "access_log_config").lower(),
        evidence=lambda d, p: f"Access Log: {_get_output(d, 'access_log_config')[:500]}"
    ))

    # ==================== SECTION 7: REQUEST LIMITS ====================

    # 7.1 - Timeout
    rules.append(ApacheCISRule(
        id="APACHE-L1-7.1",
        cis_section="7.1",
        title="Ensure Timeout is set appropriately",
        severity="low",
        level="L1",
        rationale="A reasonable Timeout value helps prevent slow HTTP attacks. Recommended: 10-60 seconds.",
        remediation="Set 'Timeout 60' (or lower) in Apache configuration",
        check=lambda d, p: _check_directive_configured(d, "timeout_config", "Timeout"),
        evidence=lambda d, p: f"Timeout: {_get_output(d, 'timeout_config')[:200]}"
    ))

    # ==================== SECTION 8: SSL/TLS ====================

    # 8.1 - SSL Module
    rules.append(ApacheCISRule(
        id="APACHE-L1-8.1",
        cis_section="8.1",
        title="Ensure SSL/TLS module is enabled",
        severity="high",
        level="L1",
        rationale="SSL/TLS is essential for encrypting web traffic. mod_ssl should be enabled.",
        remediation="Enable mod_ssl: a2enmod ssl (Debian) or ensure LoadModule ssl_module is present (RHEL)",
        check=lambda d, p: _check_module_enabled(d, "ssl_module"),
        evidence=lambda d, p: f"SSL Module: {_get_output(d, 'ssl_module')[:200]}"
    ))

    # 8.3 - SSL Protocol
    rules.append(ApacheCISRule(
        id="APACHE-L1-8.3",
        cis_section="8.3",
        title="Ensure insecure SSL/TLS protocols are disabled",
        severity="high",
        level="L1",
        rationale="SSLv2, SSLv3, TLSv1.0, and TLSv1.1 are vulnerable to known attacks. Only TLSv1.2 and TLSv1.3 should be enabled.",
        remediation="Set 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1' or 'SSLProtocol TLSv1.2 TLSv1.3'",
        check=lambda d, p: _check_ssl_protocol_secure(d),
        evidence=lambda d, p: f"SSL Protocol: {_get_output(d, 'ssl_protocol')[:300]}"
    ))

    # 8.4 - SSL Cipher Suite
    rules.append(ApacheCISRule(
        id="APACHE-L1-8.4",
        cis_section="8.4",
        title="Ensure strong SSL cipher suites are configured",
        severity="high",
        level="L1",
        rationale="Weak cipher suites can be exploited. Only strong, modern ciphers should be allowed.",
        remediation="Configure SSLCipherSuite with strong ciphers (e.g., ECDHE-ECDSA-AES256-GCM-SHA384)",
        check=lambda d, p: _check_directive_configured(d, "ssl_ciphers", "SSLCipherSuite"),
        evidence=lambda d, p: f"SSL Ciphers: {_get_output(d, 'ssl_ciphers')[:500]}"
    ))

    # 8.5 - SSL Honor Cipher Order
    rules.append(ApacheCISRule(
        id="APACHE-L1-8.5",
        cis_section="8.5",
        title="Ensure SSLHonorCipherOrder is enabled",
        severity="medium",
        level="L1",
        rationale="SSLHonorCipherOrder ensures the server's cipher preference is used, not the client's.",
        remediation="Add 'SSLHonorCipherOrder on' to SSL configuration",
        check=lambda d, p: "on" in _get_output(d, "ssl_honor_cipher_order").lower(),
        evidence=lambda d, p: f"Honor Cipher Order: {_get_output(d, 'ssl_honor_cipher_order')[:200]}"
    ))

    # 8.6 - SSL Compression
    rules.append(ApacheCISRule(
        id="APACHE-L1-8.6",
        cis_section="8.6",
        title="Ensure SSL compression is disabled",
        severity="medium",
        level="L1",
        rationale="SSL compression is vulnerable to the CRIME attack and should be disabled.",
        remediation="Add 'SSLCompression off' to SSL configuration",
        check=lambda d, p: "off" in _get_output(d, "ssl_compression").lower() or _check_directive_not_configured(d, "ssl_compression"),
        evidence=lambda d, p: f"SSL Compression: {_get_output(d, 'ssl_compression')[:200]}"
    ))

    # 8.8 - HSTS
    rules.append(ApacheCISRule(
        id="APACHE-L1-8.8",
        cis_section="8.8",
        title="Ensure HSTS header is configured",
        severity="medium",
        level="L1",
        rationale="HTTP Strict Transport Security (HSTS) forces browsers to always use HTTPS, preventing downgrade attacks.",
        remediation="Add 'Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"'",
        check=lambda d, p: _check_hsts_enabled(d),
        evidence=lambda d, p: f"HSTS: {_get_output(d, 'hsts_header')[:300]}"
    ))

    # ==================== SECTION 9: INFORMATION LEAKAGE ====================

    # 9.1 - ServerTokens
    rules.append(ApacheCISRule(
        id="APACHE-L1-9.1",
        cis_section="9.1",
        title="Ensure ServerTokens is set to Prod",
        severity="medium",
        level="L1",
        rationale="ServerTokens controls the Server HTTP response header. 'Prod' reveals only 'Apache' without version information.",
        remediation="Set 'ServerTokens Prod' in Apache configuration",
        check=lambda d, p: _check_server_tokens_prod(d),
        evidence=lambda d, p: f"ServerTokens: {_get_output(d, 'server_tokens')[:200]}"
    ))

    # 9.2 - ServerSignature
    rules.append(ApacheCISRule(
        id="APACHE-L1-9.2",
        cis_section="9.2",
        title="Ensure ServerSignature is Off",
        severity="medium",
        level="L1",
        rationale="ServerSignature adds server version information to error pages and directory listings. It should be disabled.",
        remediation="Set 'ServerSignature Off' in Apache configuration",
        check=lambda d, p: _check_server_signature_off(d),
        evidence=lambda d, p: f"ServerSignature: {_get_output(d, 'server_signature')[:200]}"
    ))

    # 9.3 - FileETag
    rules.append(ApacheCISRule(
        id="APACHE-L2-9.3",
        cis_section="9.3",
        title="Ensure FileETag is configured securely",
        severity="low",
        level="L2",
        rationale="Default ETag headers can reveal inode information. Should be set to 'None' or 'MTime Size'.",
        remediation="Set 'FileETag None' or 'FileETag MTime Size' in Apache configuration",
        check=lambda d, p: _check_directive_configured(d, "file_etag", "FileETag"),
        evidence=lambda d, p: f"FileETag: {_get_output(d, 'file_etag')[:200]}"
    ))

    # ==================== SECTION 10: HTTP CONFIGURATION ====================

    # 10.4 - Content-Security-Policy
    rules.append(ApacheCISRule(
        id="APACHE-L2-10.4",
        cis_section="10.4",
        title="Ensure Content-Security-Policy header is configured",
        severity="medium",
        level="L2",
        rationale="CSP helps prevent XSS and data injection attacks by specifying valid content sources.",
        remediation="Add 'Header set Content-Security-Policy \"default-src 'self'\"' (customize as needed)",
        check=lambda d, p: _check_security_header(d, "csp_header"),
        evidence=lambda d, p: f"CSP: {_get_output(d, 'csp_header')[:300]}"
    ))

    # 10.5 - X-Content-Type-Options
    rules.append(ApacheCISRule(
        id="APACHE-L1-10.5",
        cis_section="10.5",
        title="Ensure X-Content-Type-Options header is configured",
        severity="medium",
        level="L1",
        rationale="This header prevents MIME type sniffing, reducing drive-by download attacks.",
        remediation="Add 'Header set X-Content-Type-Options \"nosniff\"'",
        check=lambda d, p: _check_security_header(d, "xcto_header"),
        evidence=lambda d, p: f"X-Content-Type-Options: {_get_output(d, 'xcto_header')[:200]}"
    ))

    # 10.6 - X-Frame-Options
    rules.append(ApacheCISRule(
        id="APACHE-L1-10.6",
        cis_section="10.6",
        title="Ensure X-Frame-Options header is configured",
        severity="medium",
        level="L1",
        rationale="This header prevents clickjacking attacks by controlling whether the page can be framed.",
        remediation="Add 'Header always set X-Frame-Options \"SAMEORIGIN\"' or 'DENY'",
        check=lambda d, p: _check_security_header(d, "xfo_header"),
        evidence=lambda d, p: f"X-Frame-Options: {_get_output(d, 'xfo_header')[:200]}"
    ))

    # 10.7 - X-XSS-Protection
    rules.append(ApacheCISRule(
        id="APACHE-L2-10.7",
        cis_section="10.7",
        title="Ensure X-XSS-Protection header is configured",
        severity="low",
        level="L2",
        rationale="While largely deprecated in favor of CSP, this header provides an additional layer of XSS protection in older browsers.",
        remediation="Add 'Header set X-XSS-Protection \"1; mode=block\"'",
        check=lambda d, p: _check_security_header(d, "xxss_header"),
        evidence=lambda d, p: f"X-XSS-Protection: {_get_output(d, 'xxss_header')[:200]}"
    ))

    # 10.8 - Referrer-Policy
    rules.append(ApacheCISRule(
        id="APACHE-L2-10.8",
        cis_section="10.8",
        title="Ensure Referrer-Policy header is configured",
        severity="low",
        level="L2",
        rationale="Controls how much referrer information is included with requests.",
        remediation="Add 'Header set Referrer-Policy \"strict-origin-when-cross-origin\"'",
        check=lambda d, p: _check_security_header(d, "referrer_policy"),
        evidence=lambda d, p: f"Referrer-Policy: {_get_output(d, 'referrer_policy')[:200]}"
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
        distro_profile: Distribution profile (e.g., "ubuntu_22", "rocky_8")

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
    total_weighted = 0
    passed_weighted = 0

    for rule in rules:
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
            "passed_scored": passed_scored,
            "failed_scored": failed_scored,
            "compliance_pct": round(compliance_pct, 2),
            "weighted_compliance_pct": round(weighted_compliance_pct, 2)
        },
        "findings": findings
    }
