"""
Apache HTTP Server CIS Benchmark Audit Commands

Commands organized by CIS Apache HTTP Server 2.4 Benchmark v2.0.0 sections:
1.x  - Planning and Installation
2.x  - Minimize Apache Modules
3.x  - Principles, Permissions, and Ownership
4.x  - Apache Access Control
5.x  - Minimize Features, Content and Options
6.x  - Operations - Logging, Monitoring and Maintenance
7.x  - SSL/TLS Configuration
8.x  - Information Leakage
9.x  - Denial of Service Mitigations
10.x - Request Limits
11.x - Enable SELinux to Restrict Apache Processes (RHEL family)
12.x - Enable AppArmor to Restrict Apache Processes (Debian family)

Each command includes:
- cmd: The actual command to run
- sudo: Whether sudo is required
- key: Unique identifier for the command output
- section: CIS section reference

Compound commands that need sudo across the whole pipeline are wrapped in
``sh -c '...'`` so ``echo <pw> | sudo -S <cmd>`` elevates the entire script,
not just the first word.

The find-based ownership/permission scans end with ``echo 'SCAN_COMPLETE'``
so an empty result (compliant) is distinguishable from a failed command.
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
    Get all audit commands for the Apache CIS benchmark.

    Args:
        distro_id: Distribution ID (ubuntu, rocky, rhel, centos)

    Returns:
        List of command dictionaries with {cmd, sudo, key, section}
    """
    paths = get_apache_paths(distro_id)
    family = get_distro_family(distro_id)
    commands = []

    # ==================== SECTION 1: PLANNING AND INSTALLATION ====================

    commands.extend([
        {
            # Distro detection evidence (the SSH client also parses /etc/os-release)
            "cmd": "cat /etc/os-release | grep ^ID=",
            "sudo": False,
            "key": "os_release_id",
            "section": "1.3"
        },
        {
            "cmd": f"which {paths['binary']} 2>/dev/null && {paths['binary']} -v 2>/dev/null || echo 'not installed'",
            "sudo": False,
            "key": "apache_version",
            "section": "1.3"
        },
        {
            # Evidence for 1.2 (multi-use system): what else listens on this host
            "cmd": "ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20 || echo 'cannot list listeners'",
            "sudo": True,
            "key": "listening_services",
            "section": "1.2"
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
            "section": "3.1"
        },
        {
            "cmd": f"{paths['ctl_binary']} -t 2>&1 || echo 'config test failed'",
            "sudo": True,
            "key": "apache_configtest",
            "section": "1.3"
        },
        {
            # Package origin — evidence for 1.3 (installed from appropriate binaries)
            "cmd": (
                "dpkg -s apache2 2>/dev/null | grep -E '^(Package|Version|Maintainer)' | head -5"
                if family == "debian" else
                "rpm -qi httpd 2>/dev/null | grep -E '^(Name|Version|Vendor|Signature)' | head -5"
            ) + " || echo 'package info unavailable'",
            "sudo": False,
            "key": "apache_package_info",
            "section": "1.3"
        },
    ])

    # ==================== SECTION 2: MINIMIZE APACHE MODULES ====================

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
            "cmd": f"grep -rE 'mod_dav|LoadModule.*dav' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not found'",
            "sudo": True,
            "key": "mod_dav_config",
            "section": "2.3"
        },
        # 2.4 - Status module
        {
            "cmd": f"grep -rE 'mod_status|server-status' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not found'",
            "sudo": True,
            "key": "mod_status_config",
            "section": "2.4"
        },
        # 2.5 - Autoindex module
        {
            "cmd": f"grep -rE 'mod_autoindex|Options.*Indexes' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not found'",
            "sudo": True,
            "key": "mod_autoindex_config",
            "section": "2.5"
        },
        # 2.6 - Proxy modules
        {
            "cmd": f"grep -rE 'mod_proxy' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not found'",
            "sudo": True,
            "key": "mod_proxy_config",
            "section": "2.6"
        },
        # 2.7 - UserDir module
        {
            "cmd": f"grep -rE 'mod_userdir|UserDir' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not found'",
            "sudo": True,
            "key": "mod_userdir_config",
            "section": "2.7"
        },
        # 2.8 - Info module
        {
            "cmd": f"grep -rE 'mod_info|server-info' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not found'",
            "sudo": True,
            "key": "mod_info_config",
            "section": "2.8"
        },
    ])

    # ==================== SECTION 3: PRINCIPLES, PERMISSIONS, OWNERSHIP ====================

    commands.extend([
        # 3.1 - Apache running user/group
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
        {
            "cmd": "id www-data 2>/dev/null || id apache 2>/dev/null || echo 'user not found'",
            "sudo": False,
            "key": "apache_user_id",
            "section": "3.1"
        },
        # 3.2 - Apache user shell
        {
            "cmd": "getent passwd www-data 2>/dev/null | cut -d: -f7 || getent passwd apache 2>/dev/null | cut -d: -f7 || echo 'unknown'",
            "sudo": False,
            "key": "apache_user_shell",
            "section": "3.2"
        },
        # 3.3 - Apache user locked
        {
            "cmd": "passwd -S www-data 2>/dev/null || passwd -S apache 2>/dev/null || echo 'unknown'",
            "sudo": True,
            "key": "apache_user_locked",
            "section": "3.3"
        },
        # 3.4 - Files/dirs owned by root
        {
            "cmd": f"find {paths['config_dir']} ! -user root 2>/dev/null | head -10; echo 'SCAN_COMPLETE'",
            "sudo": True,
            "key": "dirs_not_owned_root",
            "section": "3.4"
        },
        # 3.5 - Group set to root
        {
            "cmd": f"find {paths['config_dir']} ! -group root 2>/dev/null | head -10; echo 'SCAN_COMPLETE'",
            "sudo": True,
            "key": "dirs_not_group_root",
            "section": "3.5"
        },
        # 3.6 - Other write access restricted
        {
            "cmd": f"find {paths['config_dir']} ! -type l -perm /o+w 2>/dev/null | head -10; echo 'SCAN_COMPLETE'",
            "sudo": True,
            "key": "dirs_other_writable",
            "section": "3.6"
        },
        # 3.7 - Core dump directory secured
        {
            "cmd": f"grep -rE '^\\s*CoreDumpDirectory' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "core_dump_config",
            "section": "3.7"
        },
        # 3.8 - Lock file secured (Mutex)
        {
            "cmd": f"grep -rE '^\\s*Mutex' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "mutex_config",
            "section": "3.8"
        },
        {
            "cmd": f"stat {paths['run_dir']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "run_dir_stat",
            "section": "3.8"
        },
        # 3.9 - PID file secured
        {
            "cmd": f"grep -rE 'PidFile' {paths['config_dir']}/ {paths['envvars']} 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -5 || echo 'not configured'",
            "sudo": True,
            "key": "pid_file_config",
            "section": "3.9"
        },
        # 3.10 - ScoreBoard file secured
        {
            "cmd": f"grep -rE 'ScoreBoardFile' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "scoreboard_config",
            "section": "3.10"
        },
        # 3.11 - Group write access restricted
        {
            "cmd": f"find {paths['config_dir']} ! -type l -perm /g+w 2>/dev/null | head -10; echo 'SCAN_COMPLETE'",
            "sudo": True,
            "key": "dirs_group_writable",
            "section": "3.11"
        },
        # 3.12 - Document root group write access restricted
        {
            "cmd": f"find {paths['default_docroot']} -type d -perm /g+w 2>/dev/null | head -10; echo 'SCAN_COMPLETE'",
            "sudo": True,
            "key": "docroot_group_writable",
            "section": "3.12"
        },
        # 3.13 - Application writable directories (manual evidence)
        {
            "cmd": f"find {paths['default_docroot']} -type d \\( -perm /o+w -o -user www-data -o -user apache \\) 2>/dev/null | head -10; echo 'SCAN_COMPLETE'",
            "sudo": True,
            "key": "app_writable_dirs",
            "section": "3.13"
        },
        # Supporting stats
        {
            "cmd": f"stat {paths['config_dir']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "config_dir_stat",
            "section": "3.4"
        },
        {
            "cmd": f"stat {paths['main_config']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "main_config_stat",
            "section": "3.4"
        },
        {
            "cmd": f"stat {paths['log_dir']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "log_dir_stat",
            "section": "3.6"
        },
        {
            "cmd": f"stat {paths['default_docroot']} 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "docroot_stat",
            "section": "3.12"
        },
    ])

    # ==================== SECTION 4: APACHE ACCESS CONTROL ====================

    commands.extend([
        # 4.1 / 4.3 / 5.1 - The <Directory /> block of the main config
        {
            "cmd": f"sed -n '/<Directory \\/>/,/<\\/Directory>/p' {paths['main_config']} 2>/dev/null || echo 'not found'",
            "sudo": True,
            "key": "root_directory_block",
            "section": "4.1"
        },
        # 4.2 - Web content access (manual evidence)
        {
            "cmd": f"grep -rE 'Require ' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -30 || echo 'not found'",
            "sudo": True,
            "key": "require_directives",
            "section": "4.2"
        },
        # 4.4 - AllowOverride for all directories
        {
            "cmd": f"grep -rE '^\\s*AllowOverride' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -30 || echo 'not found'",
            "sudo": True,
            "key": "allow_override",
            "section": "4.4"
        },
    ])

    # ==================== SECTION 5: MINIMIZE FEATURES, CONTENT, OPTIONS ====================

    commands.extend([
        # 5.2 - Web root directory block
        {
            "cmd": f"sed -n '/<Directory \"\\?\\/var\\/www/,/<\\/Directory>/p' {paths['main_config']} 2>/dev/null | head -40 || echo 'not found'",
            "sudo": True,
            "key": "docroot_directory_block",
            "section": "5.2"
        },
        # 5.3 - Options for all directories
        {
            "cmd": f"grep -rE '^\\s*Options' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -30 || echo 'not found'",
            "sudo": True,
            "key": "options_directive",
            "section": "5.3"
        },
        # 5.4 - Default HTML content
        {
            "cmd": f"grep -ilE 'it works|apache2 .*default|test page|apache http server test' {paths['default_docroot']}/index.html /usr/share/httpd/noindex/index.html 2>/dev/null | head -3 || echo 'no default content detected'",
            "sudo": False,
            "key": "default_page_check",
            "section": "5.4"
        },
        {
            "cmd": "ls -d /var/www/manual /usr/share/apache2/default-site /usr/share/httpd/manual 2>/dev/null | head -5 || echo 'not found'",
            "sudo": False,
            "key": "manual_content",
            "section": "5.4"
        },
        # 5.5 / 5.6 - printenv and test-cgi scripts
        {
            "cmd": "ls -la /usr/lib/cgi-bin/printenv /usr/lib/cgi-bin/test-cgi /var/www/cgi-bin/printenv /var/www/cgi-bin/test-cgi 2>/dev/null || echo 'not found'",
            "sudo": False,
            "key": "test_cgi_files",
            "section": "5.5"
        },
        # 5.7 - HTTP request methods restricted
        {
            "cmd": f"grep -rE 'LimitExcept|<Limit' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -20 || echo 'not configured'",
            "sudo": True,
            "key": "limit_http_methods",
            "section": "5.7"
        },
        # 5.8 - HTTP TRACE
        {
            "cmd": f"grep -rE 'TraceEnable' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "trace_enable",
            "section": "5.8"
        },
        # 5.9 - Old HTTP protocol versions disallowed
        {
            "cmd": f"grep -rE 'THE_REQUEST' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -10 || echo 'not configured'",
            "sudo": True,
            "key": "http_protocol_rewrite",
            "section": "5.9"
        },
        # 5.10 - Access to .ht* files restricted
        {
            "cmd": f"grep -rE -A3 'FilesMatch[^>]*\\.ht' {paths['config_dir']}/ 2>/dev/null | grep -vE '^[[:space:]]*#' | head -20 || echo 'not configured'",
            "sudo": True,
            "key": "ht_files_protection",
            "section": "5.10"
        },
        # 5.11 - Inappropriate file extensions restricted
        {
            "cmd": f"grep -rE -A3 '<FilesMatch' {paths['config_dir']}/ 2>/dev/null | head -40 || echo 'not configured'",
            "sudo": True,
            "key": "file_extension_restrictions",
            "section": "5.11"
        },
        # 5.12 - IP address based requests disallowed
        {
            "cmd": f"grep -rE 'RewriteCond.*HTTP_HOST' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -10 || echo 'not configured'",
            "sudo": True,
            "key": "ip_based_restriction",
            "section": "5.12"
        },
        # 5.13 - Listen directives with explicit IP addresses
        {
            "cmd": f"grep -rE '^\\s*Listen' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -10 || echo 'not configured'",
            "sudo": True,
            "key": "listen_directives",
            "section": "5.13"
        },
        # 5.14 - Browser framing restricted
        {
            "cmd": f"grep -rE 'X-Frame-Options|frame-ancestors' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "xfo_header",
            "section": "5.14"
        },
    ])

    # ==================== SECTION 6: LOGGING, MONITORING, MAINTENANCE ====================

    commands.extend([
        # 6.1 - Error log and level
        {
            "cmd": f"grep -rE '^\\s*ErrorLog|^\\s*LogLevel' {paths['main_config']} 2>/dev/null || echo 'not configured'",
            "sudo": True,
            "key": "error_log_config",
            "section": "6.1"
        },
        # 6.2 - Syslog facility for error logging
        {
            "cmd": f"grep -rE 'ErrorLog.*syslog' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "error_log_syslog",
            "section": "6.2"
        },
        # 6.3 - Access log
        {
            "cmd": f"grep -rE '^\\s*CustomLog|^\\s*LogFormat' {paths['config_dir']}/ 2>/dev/null | head -30 || echo 'not configured'",
            "sudo": True,
            "key": "access_log_config",
            "section": "6.3"
        },
        # 6.4 - Log rotation
        {
            "cmd": f"cat /etc/logrotate.d/{paths['service_name']} 2>/dev/null | head -50 || echo 'not configured'",
            "sudo": False,
            "key": "log_rotation",
            "section": "6.4"
        },
        # 6.5 - Applicable patches applied
        {
            "cmd": (
                "apt-get -s upgrade 2>/dev/null | grep -E '^Inst apache2' || echo 'no pending apache updates'"
                if family == "debian" else
                "dnf -q check-update httpd 2>/dev/null | grep -E '^httpd' || echo 'no pending apache updates'"
            ),
            "sudo": True,
            "key": "apache_updates",
            "section": "6.5"
        },
        # 6.6 - ModSecurity installed and enabled
        {
            "cmd": f"{paths['ctl_binary']} -M 2>/dev/null | grep -i security2 || echo 'not loaded'",
            "sudo": True,
            "key": "modsecurity_module",
            "section": "6.6"
        },
        # 6.7 - OWASP ModSecurity Core Rule Set
        {
            "cmd": f"grep -rEli 'owasp|coreruleset|crs-setup' {paths['config_dir']}/ /etc/modsecurity /etc/httpd/modsecurity.d 2>/dev/null | head -10 || echo 'not found'",
            "sudo": True,
            "key": "modsecurity_crs",
            "section": "6.7"
        },
    ])

    # ==================== SECTION 7: SSL/TLS CONFIGURATION ====================

    commands.extend([
        # 7.1 - SSL module
        {
            "cmd": f"{paths['ctl_binary']} -M 2>/dev/null | grep -E 'ssl|nss' || echo 'ssl not enabled'",
            "sudo": True,
            "key": "ssl_module",
            "section": "7.1"
        },
        # 7.2 - Valid trusted certificate
        {
            "cmd": (
                "sh -c 'CERT=$(grep -rhE \"^[[:space:]]*SSLCertificateFile\" " + paths['config_dir'] + "/ 2>/dev/null"
                " | grep -v \"#\" | awk \"{print \\$2}\" | head -1);"
                " if [ -n \"$CERT\" ] && [ -f \"$CERT\" ]; then"
                " openssl x509 -noout -subject -issuer -enddate -in \"$CERT\" 2>/dev/null;"
                " openssl x509 -checkend 0 -noout -in \"$CERT\" 2>/dev/null && echo CERT_NOT_EXPIRED || echo CERT_EXPIRED;"
                " else echo \"no certificate configured\"; fi'"
            ),
            "sudo": True,
            "key": "ssl_cert_check",
            "section": "7.2"
        },
        {
            "cmd": f"grep -rE '^\\s*SSLCertificateFile|^\\s*SSLCertificateKeyFile' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_certificates",
            "section": "7.2"
        },
        # 7.3 - Private key protected
        {
            "cmd": (
                "sh -c 'KEY=$(grep -rhE \"^[[:space:]]*SSLCertificateKeyFile\" " + paths['config_dir'] + "/ 2>/dev/null"
                " | grep -v \"#\" | awk \"{print \\$2}\" | head -1);"
                " if [ -n \"$KEY\" ]; then stat -c \"%a %U %G %n\" \"$KEY\" 2>/dev/null || echo KEY_NOT_FOUND;"
                " else echo \"no key configured\"; fi'"
            ),
            "sudo": True,
            "key": "ssl_key_perms",
            "section": "7.3"
        },
        # 7.4 - TLSv1.0/TLSv1.1 disabled
        {
            "cmd": f"grep -rE '^\\s*SSLProtocol' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_protocol",
            "section": "7.4"
        },
        # 7.5 / 7.8 / 7.12 - Cipher suites
        {
            "cmd": f"grep -rE '^\\s*SSLCipherSuite' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_ciphers",
            "section": "7.5"
        },
        # 7.6 - Insecure renegotiation
        {
            "cmd": f"grep -rE 'SSLInsecureRenegotiation' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_insecure_reneg",
            "section": "7.6"
        },
        # 7.7 - SSL compression
        {
            "cmd": f"grep -rE '^\\s*SSLCompression' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "ssl_compression",
            "section": "7.7"
        },
        # 7.9 - All web content accessed via HTTPS
        {
            "cmd": f"grep -rE 'RewriteRule.*https|Redirect.*https' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -10 || echo 'not configured'",
            "sudo": True,
            "key": "https_redirect",
            "section": "7.9"
        },
        # 7.10 - OCSP stapling
        {
            "cmd": f"grep -rE 'SSLUseStapling|SSLStaplingCache' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "ocsp_stapling",
            "section": "7.10"
        },
        # 7.11 - HSTS
        {
            "cmd": f"grep -rE 'Strict-Transport-Security' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "hsts_header",
            "section": "7.11"
        },
    ])

    # ==================== SECTION 8: INFORMATION LEAKAGE ====================

    commands.extend([
        # 8.1 - ServerTokens
        {
            "cmd": f"grep -rE '^\\s*ServerTokens' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "server_tokens",
            "section": "8.1"
        },
        # 8.2 - ServerSignature
        {
            "cmd": f"grep -rE '^\\s*ServerSignature' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "server_signature",
            "section": "8.2"
        },
        # 8.4 - FileETag
        {
            "cmd": f"grep -rE '^\\s*FileETag' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "file_etag",
            "section": "8.4"
        },
    ])

    # ==================== SECTION 9: DENIAL OF SERVICE MITIGATIONS ====================

    commands.extend([
        # 9.1 - Timeout
        {
            "cmd": f"grep -rE '^\\s*Timeout' {paths['main_config']} {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | grep -vE 'KeepAliveTimeout|RequestReadTimeout' || echo 'not configured'",
            "sudo": True,
            "key": "timeout_config",
            "section": "9.1"
        },
        # 9.2 / 9.3 / 9.4 - KeepAlive settings
        {
            "cmd": f"grep -rE '^\\s*KeepAlive|^\\s*MaxKeepAliveRequests|^\\s*KeepAliveTimeout' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "keepalive_config",
            "section": "9.2"
        },
        # 9.5 / 9.6 - RequestReadTimeout
        {
            "cmd": f"grep -rE 'RequestReadTimeout' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "request_read_timeout",
            "section": "9.5"
        },
    ])

    # ==================== SECTION 10: REQUEST LIMITS ====================

    commands.extend([
        {
            "cmd": f"grep -rE 'LimitRequestLine|LimitRequestFields|LimitRequestFieldSize|LimitRequestBody' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'",
            "sudo": True,
            "key": "request_limits",
            "section": "10.1"
        },
    ])

    # ==================== SECTION 11: SELINUX (RHEL FAMILY) ====================

    commands.extend([
        {
            "cmd": "getenforce 2>/dev/null || echo 'selinux not available'",
            "sudo": False,
            "key": "selinux_status",
            "section": "11.1"
        },
        {
            "cmd": "ps -eZ 2>/dev/null | grep -E 'httpd|apache2' | grep -v grep | head -5 || echo 'no process context'",
            "sudo": False,
            "key": "selinux_httpd_context",
            "section": "11.2"
        },
        {
            "cmd": "semanage permissive -l 2>/dev/null | grep httpd_t || echo 'httpd_t not in permissive list'",
            "sudo": True,
            "key": "selinux_permissive",
            "section": "11.3"
        },
        {
            "cmd": "getsebool -a 2>/dev/null | grep httpd | grep 'on$' | head -20 || echo 'none enabled'",
            "sudo": True,
            "key": "selinux_booleans",
            "section": "11.4"
        },
    ])

    # ==================== SECTION 12: APPARMOR (DEBIAN FAMILY) ====================

    commands.extend([
        {
            "cmd": "aa-status --enabled 2>/dev/null && echo 'apparmor enabled' || echo 'apparmor not enabled'",
            "sudo": True,
            "key": "apparmor_status",
            "section": "12.1"
        },
        {
            "cmd": "cat /etc/apparmor.d/usr.sbin.apache2 2>/dev/null | head -40 || echo 'no apparmor profile file'",
            "sudo": True,
            "key": "apparmor_profile",
            "section": "12.2"
        },
        {
            "cmd": (
                "sh -c 'PID=$(pgrep -x apache2 2>/dev/null | head -1);"
                " PID=${PID:-$(pgrep -x httpd 2>/dev/null | head -1)};"
                " if [ -n \"$PID\" ]; then cat /proc/$PID/attr/current 2>/dev/null;"
                " else echo \"no apache process\"; fi'"
            ),
            "sudo": True,
            "key": "apparmor_process_profile",
            "section": "12.3"
        },
    ])

    # ==================== ADDITIONAL CONTEXT ====================

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
        {
            "cmd": f"grep -rE 'DocumentRoot' {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' | head -20 || echo 'not found'",
            "sudo": True,
            "key": "document_roots",
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
        {"cmd": f"{paths['binary']} -v 2>/dev/null || echo 'not installed'", "sudo": False, "key": "apache_version", "section": "1.3"},
        {"cmd": f"systemctl is-active {paths['service_name']} 2>/dev/null || echo 'not active'", "sudo": False, "key": "apache_active", "section": "1.2"},

        # Critical security settings
        {"cmd": f"grep -E '^\\s*ServerTokens' {paths['main_config']} {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'", "sudo": True, "key": "server_tokens", "section": "8.1"},
        {"cmd": f"grep -E '^\\s*ServerSignature' {paths['main_config']} {paths['config_dir']}/ 2>/dev/null | grep -vE '(^|:)[[:space:]]*#' || echo 'not configured'", "sudo": True, "key": "server_signature", "section": "8.2"},
        {"cmd": f"grep -E 'TraceEnable' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'", "sudo": True, "key": "trace_enable", "section": "5.8"},

        # SSL/TLS
        {"cmd": f"grep -E 'SSLProtocol' {paths['config_dir']}/ 2>/dev/null || echo 'not configured'", "sudo": True, "key": "ssl_protocol", "section": "7.4"},

        # Modules
        {"cmd": f"{paths['ctl_binary']} -M 2>/dev/null | head -50 || echo 'cannot list'", "sudo": True, "key": "apache_modules", "section": "2"},

        # User/Group
        {"cmd": f"grep -E '^(User|Group)' {paths['main_config']} 2>/dev/null || echo 'not configured'", "sudo": True, "key": "apache_user_group", "section": "3.1"},
    ]
