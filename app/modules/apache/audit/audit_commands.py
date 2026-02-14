"""
Apache HTTP Server CIS Benchmark Audit Commands

Commands organized by CIS Apache HTTP Server 2.4 Benchmark sections:
1.x - Planning and Installation
2.x - Minimize Apache Modules
3.x - Principles, Permissions, and Ownership
4.x - Apache Access Control
5.x - Minimize Features and Content
6.x - Operations - Logging, Monitoring
7.x - Request Limits
8.x - SSL/TLS Configuration
9.x - Information Leakage
10.x - HTTP Configuration Options

Each command includes:
- cmd: The actual command to run
- sudo: Whether sudo is required
- key: Unique identifier for the command output
- section: CIS section reference
"""

from typing import List, Dict, Any


# Distro-aware path configuration
APACHE_PATHS = {
    "debian": {
        "config_dir": "/etc/apache2",
        "main_config": "/etc/apache2/apache2.conf",
        "sites_available": "/etc/apache2/sites-available",
        "sites_enabled": "/etc/apache2/sites-enabled",
        "mods_available": "/etc/apache2/mods-available",
        "mods_enabled": "/etc/apache2/mods-enabled",
        "conf_enabled": "/etc/apache2/conf-enabled",
        "ssl_config": "/etc/apache2/sites-available/default-ssl.conf",
        "service_name": "apache2",
        "binary": "apache2",
        "ctl_binary": "apache2ctl",
        "envvars": "/etc/apache2/envvars",
        "ports_conf": "/etc/apache2/ports.conf",
        "default_docroot": "/var/www/html",
        "log_dir": "/var/log/apache2",
        "run_dir": "/var/run/apache2",
    },
    "rhel": {
        "config_dir": "/etc/httpd",
        "main_config": "/etc/httpd/conf/httpd.conf",
        "sites_available": "/etc/httpd/conf.d",
        "sites_enabled": "/etc/httpd/conf.d",
        "mods_available": "/etc/httpd/conf.modules.d",
        "mods_enabled": "/etc/httpd/conf.modules.d",
        "conf_enabled": "/etc/httpd/conf.d",
        "ssl_config": "/etc/httpd/conf.d/ssl.conf",
        "service_name": "httpd",
        "binary": "httpd",
        "ctl_binary": "apachectl",
        "envvars": "/etc/sysconfig/httpd",
        "ports_conf": "/etc/httpd/conf/httpd.conf",
        "default_docroot": "/var/www/html",
        "log_dir": "/var/log/httpd",
        "run_dir": "/var/run/httpd",
    }
}


def get_distro_family(distro_id: str) -> str:
    """Map distro ID to Apache path family."""
    if distro_id in ("ubuntu", "debian"):
        return "debian"
    elif distro_id in ("rocky", "rhel", "centos", "fedora", "almalinux"):
        return "rhel"
    return "debian"  # Default


def get_apache_paths(distro_id: str) -> Dict[str, str]:
    """Get Apache paths for the given distribution."""
    family = get_distro_family(distro_id)
    return APACHE_PATHS[family]


def get_apache_audit_commands(distro_id: str = "ubuntu") -> List[Dict[str, Any]]:
    """
    Get all audit commands for Apache CIS benchmark.

    Args:
        distro_id: Distribution ID (ubuntu, rocky, rhel, centos)

    Returns:
        List of command dictionaries with {cmd, sudo, key, section}
    """
    paths = get_apache_paths(distro_id)
    commands = []

    # ==================== SECTION 1: PLANNING AND INSTALLATION ====================

    # 1.1 - Apache Installation and Version
    commands.extend([
        {
            "cmd": f"which {paths['binary']} 2>/dev/null && {paths['binary']} -v 2>/dev/null || echo 'not installed'",
            "sudo": False,
            "key": "apache_version",
            "section": "1.1"
        },
        {
            "cmd": f"systemctl is-enabled {paths['service_name']} 2>/dev/null || echo 'not enabled'",
            "sudo": False,
            "key": "apache_enabled",
            "section": "1.2"
        },
        {
            "cmd": f"systemctl is-active {paths['service_name']} 2>/dev/null || echo 'not active'",
            "sudo": False,
            "key": "apache_active",
            "section": "1.2"
        },
        {
            "cmd": f"ps aux | grep -E '{paths['binary']}' | grep -v grep | head -10",
            "sudo": False,
            "key": "apache_process",
            "section": "1.3"
        },
        {
            "cmd": f"{paths['ctl_binary']} -t 2>&1 || echo 'config test failed'",
            "sudo": True,
            "key": "apache_configtest",
            "section": "1.1"
        },
    ])

    # ==================== SECTION 2: MINIMIZE APACHE MODULES ====================

    # 2.1-2.9 - Module checks
    commands.extend([
        {
            "cmd": f"{paths['ctl_binary']} -M 2>/dev/null || {paths['binary']} -M 2>/dev/null || echo 'cannot list modules'",
            "sudo": True,
            "key": "apache_modules",
            "section": "2"
        },
        {
            "cmd": f"ls -la {paths['mods_enabled']}/ 2>/dev/null | head -100 || echo 'no mods dir'",
            "sudo": False,
            "key": "mods_enabled_dir",
            "section": "2"
        },
        # 2.3 - WebDAV modules
        {
            "cmd": f"grep -rE 'mod_dav|LoadModule.*dav' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not found'",
            "sudo": True,
            "key": "mod_dav_config",
            "section": "2.3"
        },
        # 2.4 - Status module
        {
            "cmd": f"grep -rE 'mod_status|server-status' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not found'",
            "sudo": True,
            "key": "mod_status_config",
            "section": "2.4"
        },
        # 2.5 - Info module
        {
            "cmd": f"grep -rE 'mod_info|server-info' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not found'",
            "sudo": True,
            "key": "mod_info_config",
            "section": "2.5"
        },
        # 2.6 - UserDir module
        {
            "cmd": f"grep -rE 'mod_userdir|UserDir' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not found'",
            "sudo": True,
            "key": "mod_userdir_config",
            "section": "2.6"
        },
        # 2.7 - Autoindex module
        {
            "cmd": f"grep -rE 'mod_autoindex|Options.*Indexes' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not found'",
            "sudo": True,
            "key": "mod_autoindex_config",
            "section": "2.7"
        },
        # 2.8 - Proxy modules
        {
            "cmd": f"grep -rE 'mod_proxy' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not found'",
            "sudo": True,
            "key": "mod_proxy_config",
            "section": "2.8"
        },
    ])

    # ==================== SECTION 3: PRINCIPLES, PERMISSIONS, OWNERSHIP ====================

    # 3.1 - Apache running user/group
    commands.extend([
        {
            "cmd": f"grep -E '^\\s*(User|Group)' {paths['main_config']} 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "apache_user_group",
            "section": "3.1"
        },
        {
            "cmd": f"cat {paths['envvars']} 2>/dev/null | grep -E 'APACHE_RUN' || echo 'no envvars'",
            "sudo": False,
            "key": "apache_envvars",
            "section": "3.1"
        },
        # 3.2 - Apache dedicated account
        {
            "cmd": "id www-data 2>/dev/null || id apache 2>/dev/null || echo 'user not found'",
            "sudo": False,
            "key": "apache_user_id",
            "section": "3.2"
        },
        {
            "cmd": "grep -E '^(www-data|apache):' /etc/passwd 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "apache_passwd_entry",
            "section": "3.2"
        },
        # 3.3 - Apache user shell
        {
            "cmd": "getent passwd www-data 2>/dev/null | cut -d: -f7 || getent passwd apache 2>/dev/null | cut -d: -f7 || echo 'unknown'",
            "sudo": False,
            "key": "apache_user_shell",
            "section": "3.3"
        },
        # 3.4 - Apache user locked
        {
            "cmd": "passwd -S www-data 2>/dev/null || passwd -S apache 2>/dev/null || echo 'unknown'",
            "sudo": True,
            "key": "apache_user_locked",
            "section": "3.4"
        },
        # 3.5-3.8 - Directory permissions
        {
            "cmd": f"stat {paths['config_dir']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "config_dir_stat",
            "section": "3.5"
        },
        {
            "cmd": f"stat {paths['main_config']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "main_config_stat",
            "section": "3.6"
        },
        {
            "cmd": f"stat $(which {paths['binary']}) 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "binary_stat",
            "section": "3.7"
        },
        {
            "cmd": f"stat {paths['log_dir']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "log_dir_stat",
            "section": "3.8"
        },
        # 3.9-3.10 - Document root
        {
            "cmd": f"grep -rE 'DocumentRoot' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' | head -20 || echo 'not found'",
            "sudo": True,
            "key": "document_roots",
            "section": "3.9"
        },
        {
            "cmd": f"stat {paths['default_docroot']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "docroot_stat",
            "section": "3.10"
        },
    ])

    # ==================== SECTION 4: APACHE ACCESS CONTROL ====================

    commands.extend([
        # 4.1 - Deny access by default
        {
            "cmd": f"grep -rE 'Require all denied|Order deny,allow|Deny from all' {paths['config_dir']}/ 2>/dev/null | head -30 || echo 'not found'",
            "sudo": True,
            "key": "deny_by_default",
            "section": "4.1"
        },
        # 4.2 - AllowOverride
        {
            "cmd": f"grep -rE '^\\s*AllowOverride' {paths['config_dir']}/ 2>/dev/null | head -30 || echo 'not found'",
            "sudo": True,
            "key": "allow_override",
            "section": "4.2"
        },
        # 4.3 - AllowOverrideList
        {
            "cmd": f"grep -rE '^\\s*AllowOverrideList' {paths['config_dir']}/ 2>/dev/null || echo 'not found'",
            "sudo": True,
            "key": "allow_override_list",
            "section": "4.3"
        },
        # 4.4 - Options directive
        {
            "cmd": f"grep -rE '^\\s*Options' {paths['config_dir']}/ 2>/dev/null | head -30 || echo 'not found'",
            "sudo": True,
            "key": "options_directive",
            "section": "4.4"
        },
    ])

    # ==================== SECTION 5: MINIMIZE FEATURES AND CONTENT ====================

    commands.extend([
        # 5.1-5.3 - Default content
        {
            "cmd": f"ls -la {paths['default_docroot']}/ 2>/dev/null | head -30 || echo 'not found'",
            "sudo": False,
            "key": "default_content",
            "section": "5.1"
        },
        {
            "cmd": "ls -la /var/www/manual/ /usr/share/apache2/default-site/ /usr/share/httpd/noindex/ 2>/dev/null | head -30 || echo 'not found'",
            "sudo": False,
            "key": "manual_content",
            "section": "5.2"
        },
        # 5.3-5.4 - CGI
        {
            "cmd": "ls -la /usr/lib/cgi-bin/ /var/www/cgi-bin/ 2>/dev/null | head -20 || echo 'not found'",
            "sudo": False,
            "key": "cgi_content",
            "section": "5.3"
        },
        {
            "cmd": f"grep -rE 'ScriptAlias|AddHandler.*cgi|Options.*ExecCGI' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not found'",
            "sudo": True,
            "key": "cgi_config",
            "section": "5.4"
        },
        # 5.5-5.7 - Printenv and test-cgi
        {
            "cmd": "ls -la /usr/lib/cgi-bin/printenv /usr/lib/cgi-bin/test-cgi /var/www/cgi-bin/printenv /var/www/cgi-bin/test-cgi 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "test_cgi_files",
            "section": "5.5"
        },
        # 5.8 - HTTP TRACE
        {
            "cmd": f"grep -rE 'TraceEnable' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "trace_enable",
            "section": "5.8"
        },
    ])

    # ==================== SECTION 6: OPERATIONS - LOGGING ====================

    commands.extend([
        # 6.1 - Error Log
        {
            "cmd": f"grep -rE '^\\s*ErrorLog|^\\s*LogLevel' {paths['main_config']} 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "error_log_config",
            "section": "6.1"
        },
        # 6.2 - Syslog for error log
        {
            "cmd": f"grep -rE 'ErrorLog.*syslog' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "error_log_syslog",
            "section": "6.2"
        },
        # 6.3-6.4 - Access Log
        {
            "cmd": f"grep -rE '^\\s*CustomLog|^\\s*LogFormat' {paths['config_dir']}/ 2>/dev/null | head -30 || echo 'not configured'",
            "sudo": True,
            "key": "access_log_config",
            "section": "6.3"
        },
        # 6.5 - Log rotation
        {
            "cmd": f"cat /etc/logrotate.d/{paths['service_name']} 2>/dev/null | head -50 || echo 'not configured'",
            "sudo": False,
            "key": "log_rotation",
            "section": "6.5"
        },
        # 6.6 - Log storage
        {
            "cmd": f"ls -la {paths['log_dir']}/ 2>/dev/null | head -20 || echo 'not found'",
            "sudo": False,
            "key": "log_files",
            "section": "6.6"
        },
        # 6.7 - Forensic logging
        {
            "cmd": f"grep -rE 'mod_log_forensic|ForensicLog' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "forensic_log",
            "section": "6.7"
        },
    ])

    # ==================== SECTION 7: REQUEST LIMITS ====================

    commands.extend([
        # 7.1 - Timeout
        {
            "cmd": f"grep -rE '^\\s*Timeout' {paths['main_config']} {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "timeout_config",
            "section": "7.1"
        },
        # 7.2 - KeepAlive
        {
            "cmd": f"grep -rE '^\\s*KeepAlive|^\\s*MaxKeepAliveRequests|^\\s*KeepAliveTimeout' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "keepalive_config",
            "section": "7.2"
        },
        # 7.3-7.6 - Request Limits
        {
            "cmd": f"grep -rE 'LimitRequestLine|LimitRequestFields|LimitRequestFieldSize|LimitRequestBody' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "request_limits",
            "section": "7.3"
        },
    ])

    # ==================== SECTION 8: SSL/TLS CONFIGURATION ====================

    commands.extend([
        # 8.1 - SSL module
        {
            "cmd": f"{paths['ctl_binary']} -M 2>/dev/null | grep ssl || echo 'ssl not enabled'",
            "sudo": True,
            "key": "ssl_module",
            "section": "8.1"
        },
        # 8.2 - SSL Configuration file
        {
            "cmd": f"cat {paths['ssl_config']} 2>/dev/null | grep -v '^#' | grep -v '^$' | head -100 || echo 'no ssl config'",
            "sudo": True,
            "key": "ssl_config_content",
            "section": "8.2"
        },
        # 8.3 - SSL Protocols
        {
            "cmd": f"grep -rE '^\\s*SSLProtocol' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_protocol",
            "section": "8.3"
        },
        # 8.4 - SSL Cipher Suites
        {
            "cmd": f"grep -rE '^\\s*SSLCipherSuite' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_ciphers",
            "section": "8.4"
        },
        # 8.5 - SSL Honor Cipher Order
        {
            "cmd": f"grep -rE '^\\s*SSLHonorCipherOrder' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "ssl_honor_cipher_order",
            "section": "8.5"
        },
        # 8.6 - SSL Compression
        {
            "cmd": f"grep -rE '^\\s*SSLCompression' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "ssl_compression",
            "section": "8.6"
        },
        # 8.7 - SSL Certificates
        {
            "cmd": f"grep -rE '^\\s*SSLCertificateFile|^\\s*SSLCertificateKeyFile' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_certificates",
            "section": "8.7"
        },
        # 8.8 - HSTS
        {
            "cmd": f"grep -rE 'Strict-Transport-Security' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "hsts_header",
            "section": "8.8"
        },
        # 8.9 - OCSP Stapling
        {
            "cmd": f"grep -rE 'SSLUseStapling|SSLStaplingCache' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "ocsp_stapling",
            "section": "8.9"
        },
    ])

    # ==================== SECTION 9: INFORMATION LEAKAGE ====================

    commands.extend([
        # 9.1 - ServerTokens
        {
            "cmd": f"grep -rE '^\\s*ServerTokens' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "server_tokens",
            "section": "9.1"
        },
        # 9.2 - ServerSignature
        {
            "cmd": f"grep -rE '^\\s*ServerSignature' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "server_signature",
            "section": "9.2"
        },
        # 9.3 - FileETag
        {
            "cmd": f"grep -rE '^\\s*FileETag' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'",
            "sudo": True,
            "key": "file_etag",
            "section": "9.3"
        },
    ])

    # ==================== SECTION 10: HTTP CONFIGURATION OPTIONS ====================

    commands.extend([
        # 10.1 - LimitExcept
        {
            "cmd": f"grep -rE 'LimitExcept|<Limit' {paths['config_dir']}/ 2>/dev/null | grep -v '^#' | head -20 || echo 'not configured'",
            "sudo": True,
            "key": "limit_http_methods",
            "section": "10.1"
        },
        # 10.2 - HTTP Request Methods
        {
            "cmd": f"grep -rE 'RewriteRule.*\\[F\\]|RewriteCond.*REQUEST_METHOD' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "http_methods_rewrite",
            "section": "10.2"
        },
        # 10.3 - mod_reqtimeout
        {
            "cmd": f"grep -rE 'RequestReadTimeout' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "request_read_timeout",
            "section": "10.3"
        },
        # Security Headers
        {
            "cmd": f"grep -rE 'Content-Security-Policy' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "csp_header",
            "section": "10.4"
        },
        {
            "cmd": f"grep -rE 'X-Content-Type-Options' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "xcto_header",
            "section": "10.5"
        },
        {
            "cmd": f"grep -rE 'X-Frame-Options' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "xfo_header",
            "section": "10.6"
        },
        {
            "cmd": f"grep -rE 'X-XSS-Protection' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "xxss_header",
            "section": "10.7"
        },
        {
            "cmd": f"grep -rE 'Referrer-Policy' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "referrer_policy",
            "section": "10.8"
        },
    ])

    # ==================== ADDITIONAL CHECKS ====================

    # Virtual hosts configuration
    commands.extend([
        {
            "cmd": f"{paths['ctl_binary']} -S 2>&1 || echo 'cannot list vhosts'",
            "sudo": True,
            "key": "vhosts_list",
            "section": "info"
        },
        {
            "cmd": f"ls -la {paths['sites_enabled']}/ 2>/dev/null || echo 'no sites-enabled'",
            "sudo": False,
            "key": "sites_enabled_dir",
            "section": "info"
        },
    ])

    return commands


def get_quick_apache_audit_commands(distro_id: str = "ubuntu") -> List[Dict[str, Any]]:
    """
    Get a reduced set of essential Apache audit commands for quick checks.

    Args:
        distro_id: Distribution ID

    Returns:
        List of essential command dictionaries
    """
    paths = get_apache_paths(distro_id)

    return [
        # Basic info
        {"cmd": f"{paths['binary']} -v 2>/dev/null || echo 'not installed'", "sudo": False, "key": "apache_version", "section": "1.1"},
        {"cmd": f"systemctl is-active {paths['service_name']} 2>/dev/null || echo 'not active'", "sudo": False, "key": "apache_active", "section": "1.2"},

        # Critical security settings
        {"cmd": f"grep -E '^\\s*ServerTokens' {paths['main_config']} {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'", "sudo": True, "key": "server_tokens", "section": "9.1"},
        {"cmd": f"grep -E '^\\s*ServerSignature' {paths['main_config']} {paths['config_dir']}/ 2>/dev/null | grep -v '^#' || echo 'not configured'", "sudo": True, "key": "server_signature", "section": "9.2"},
        {"cmd": f"grep -E 'TraceEnable' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'", "sudo": True, "key": "trace_enable", "section": "5.8"},

        # SSL/TLS
        {"cmd": f"grep -E 'SSLProtocol' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'", "sudo": True, "key": "ssl_protocol", "section": "8.3"},

        # Modules
        {"cmd": f"{paths['ctl_binary']} -M 2>/dev/null | head -50 || echo 'cannot list'", "sudo": True, "key": "apache_modules", "section": "2"},

        # User/Group
        {"cmd": f"grep -E '^(User|Group)' {paths['main_config']} 2>/dev/null || echo 'not configured'", "sudo": True, "key": "apache_user_group", "section": "3.1"},
    ]
