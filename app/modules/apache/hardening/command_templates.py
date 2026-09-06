"""
Apache Hardening Command Templates

Remediation commands for CIS Apache HTTP Server 2.4 Benchmark v2.0.0 checks.
Commands are distro-aware and support parameter substitution.

Every automated fix follows the same contract:
1. Back up the config file(s) being modified (*.bak.cis copies)
2. Apply the change
3. Restart Apache (requires_service_restart — the executor restarts and
   confirms the service came back with `systemctl is-active`)
4. Verify with the config test command (`apache2ctl -t` / `httpd -t`)
   combined with a check-specific grep, emitting PASS or FAIL

Each template includes:
- check_id: The CIS check ID this template fixes
- commands_debian / commands_rhel: distro command lists ({PARAM} placeholders)
- verify_commands_*: Commands that output PASS or FAIL
- requires_service_restart: Whether Apache must restart afterwards

Checks with no template here (3.1 run-as user, 3.7–3.10 runtime files, 5.3
per-directory Options, 5.7 method limits, 5.9/5.12 rewrite policies, 6.2
syslog, 7.9 HTTPS redirects, 11.2/11.3 SELinux contexts) need site-specific
decisions and are intentionally left to manual remediation.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
import copy

from app.core.hardening_param_security import (
    reject_shell_breakout_chars,
    validate_host_list,
    validate_integer,
    validate_path,
    validate_select,
)


# Distro-specific Apache paths and service names
APACHE_CONFIG = {
    "debian": {
        "service": "apache2",
        "config_dir": "/etc/apache2",
        "main_config": "/etc/apache2/apache2.conf",
        "security_conf": "/etc/apache2/conf-available/security.conf",
        "ssl_conf": "/etc/apache2/mods-available/ssl.conf",
        "sites_enabled": "/etc/apache2/sites-enabled",
        "mods_enabled": "/etc/apache2/mods-enabled",
        "enable_mod_cmd": "a2enmod",
        "disable_mod_cmd": "a2dismod",
        "enable_conf_cmd": "a2enconf",
    },
    "rhel": {
        "service": "httpd",
        "config_dir": "/etc/httpd",
        "main_config": "/etc/httpd/conf/httpd.conf",
        "security_conf": "/etc/httpd/conf.d/security.conf",
        "ssl_conf": "/etc/httpd/conf.d/ssl.conf",
        "sites_enabled": "/etc/httpd/conf.d",
        "mods_enabled": "/etc/httpd/conf.modules.d",
        "enable_mod_cmd": None,  # Modules enabled via config files
        "disable_mod_cmd": None,
    }
}

# Shorthands used while building the templates below
_D = APACHE_CONFIG["debian"]
_R = APACHE_CONFIG["rhel"]
_DEB_MAIN = _D["main_config"]
_DEB_SEC = _D["security_conf"]
_DEB_SSL = _D["ssl_conf"]
_RH_MAIN = _R["main_config"]
_RH_SEC = _R["security_conf"]
_RH_SSL = _R["ssl_conf"]

_DEB_BACKUP = f"cp -f {_DEB_MAIN} {_DEB_MAIN}.bak.cis 2>/dev/null || true"
_RH_BACKUP = f"cp -f {_RH_MAIN} {_RH_MAIN}.bak.cis 2>/dev/null || true"
_DEB_SEC_BACKUP = f"cp -f {_DEB_SEC} {_DEB_SEC}.bak.cis 2>/dev/null || true"
_RH_SEC_BACKUP = f"cp -f {_RH_SEC} {_RH_SEC}.bak.cis 2>/dev/null || true"
_DEB_SSL_BACKUP = f"cp -f {_DEB_SSL} {_DEB_SSL}.bak.cis 2>/dev/null || true"
_RH_SSL_BACKUP = f"cp -f {_RH_SSL} {_RH_SSL}.bak.cis 2>/dev/null || true"

# Config test prefixes for verification commands
_DEB_T = "apache2ctl -t >/dev/null 2>&1"
_RH_T = "httpd -t >/dev/null 2>&1"


def get_distro_family(distro_id: str) -> str:
    """Map distro ID to Apache config family."""
    if distro_id in ("ubuntu", "debian"):
        return "debian"
    elif distro_id in ("rocky", "rhel", "centos", "fedora", "almalinux"):
        return "rhel"
    return "debian"  # Default


def get_apache_service_name(distro_id: str) -> str:
    """Get Apache service name for distro."""
    family = get_distro_family(distro_id)
    return APACHE_CONFIG[family]["service"]


@dataclass
class ApacheHardeningTemplate:
    """Template for hardening a specific Apache CIS check."""
    check_id: str
    description: str
    commands_debian: List[str]  # Commands for Debian/Ubuntu
    commands_rhel: List[str]    # Commands for RHEL/Rocky
    requires_reboot: bool = False
    verify_commands_debian: List[str] = field(default_factory=list)
    verify_commands_rhel: List[str] = field(default_factory=list)
    requires_service_restart: bool = True  # Most Apache changes need restart


# Command templates registry
APACHE_HARDENING_TEMPLATES: Dict[str, ApacheHardeningTemplate] = {}


def _register(template: ApacheHardeningTemplate):
    """Register a template in the registry."""
    APACHE_HARDENING_TEMPLATES[template.check_id] = template


def get_apache_hardening_template(check_id: str) -> Optional[ApacheHardeningTemplate]:
    """Get a template by check ID."""
    return APACHE_HARDENING_TEMPLATES.get(check_id)


# Every parameter here is substituted into a `sh -c` shell command line —
# some as a bare unquoted word (`test -f {SSL_CERT_FILE}`), others already
# inside a single- or double-quoted region (a sed program, an echo/printf
# argument), sometimes both for the same parameter across commands.
# Restricting each to a charset/denylist that is inert in every position it
# is used avoids needing to track which context each site uses (see
# app.core.hardening_param_security for the reasoning).
_PATH_PARAMS = {"SSL_CERT_FILE", "SSL_KEY_FILE"}
_HOST_LIST_PARAMS = {"LISTEN_IP"}
# RESTRICTED_EXTENSIONS is wrapped in \"...\" inside a FilesMatch regex
# attribute (see parameter_metadata.py) — also deny embedded double quotes.
_SHELL_TEXT_PARAMS_EXTRA_DENY = {"RESTRICTED_EXTENSIONS": ('"',)}


def _validated_value(param_name: str, param_value: str) -> str:
    """
    Validate a substituted value against the security rules for its
    parameter before it is inserted into a shell command that runs (via
    `sh -c`) on the managed Apache host.
    """
    if param_name in _PATH_PARAMS:
        return validate_path(param_value, param_name)
    if param_name in _HOST_LIST_PARAMS:
        return validate_host_list(param_value, param_name)

    from .parameter_metadata import APACHE_PARAMETER_REGISTRY

    meta = APACHE_PARAMETER_REGISTRY.get(param_name)
    if meta is not None:
        if meta.input_type == "number":
            return validate_integer(
                param_value, param_name, min_value=meta.min_value, max_value=meta.max_value
            )
        if meta.input_type == "select" and meta.options:
            return validate_select(param_value, param_name, meta.options)

    extra = _SHELL_TEXT_PARAMS_EXTRA_DENY.get(param_name, ())
    return reject_shell_breakout_chars(param_value, param_name, extra=extra)


def _substitute_parameters(commands: List[str], parameters: Optional[Dict[str, str]]) -> List[str]:
    """Substitute {PARAM} placeholders via plain replace — str.format() would
    raise on any brace the shell command itself contains."""
    if not parameters:
        return commands
    result = []
    for cmd in commands:
        for name, value in parameters.items():
            cmd = cmd.replace(f"{{{name}}}", _validated_value(name, value))
        result.append(cmd)
    return result


def get_apache_template_commands_for_distro(
    check_id: str,
    distro_id: str,
    parameters: Optional[Dict[str, str]] = None
) -> List[str]:
    """
    Get commands for a check, substituting parameters.

    Args:
        check_id: CIS check ID
        distro_id: Distribution ID (ubuntu, rocky, etc.)
        parameters: Dict of parameter values to substitute

    Returns:
        List of commands with parameters substituted
    """
    template = get_apache_hardening_template(check_id)
    if not template:
        return []

    family = get_distro_family(distro_id)
    if family == "debian":
        commands = copy.deepcopy(template.commands_debian)
    else:
        commands = copy.deepcopy(template.commands_rhel)

    return _substitute_parameters(commands, parameters)


def get_apache_verify_commands_for_distro(
    check_id: str,
    distro_id: str,
    parameters: Optional[Dict[str, str]] = None
) -> List[str]:
    """Get verification commands for a check."""
    template = get_apache_hardening_template(check_id)
    if not template:
        return []

    family = get_distro_family(distro_id)
    if family == "debian":
        commands = copy.deepcopy(template.verify_commands_debian)
    else:
        commands = copy.deepcopy(template.verify_commands_rhel)

    return _substitute_parameters(commands, parameters)


def get_all_supported_check_ids() -> List[str]:
    """Get list of all check IDs that have hardening templates."""
    return list(APACHE_HARDENING_TEMPLATES.keys())


def _rhel_disable_module(module_token: str) -> str:
    """Comment out a LoadModule line across the RHEL module config dir."""
    return (
        f"sed -i 's/^LoadModule {module_token}/#LoadModule {module_token}/' "
        f"{_R['mods_enabled']}/*.conf 2>/dev/null || true"
    )


def _module_template(check_id: str, description: str, deb_mods: str,
                     rhel_tokens: List[str], module_name: str,
                     enable: bool = False) -> ApacheHardeningTemplate:
    """Build an enable/disable-module template with configtest verification."""
    if enable:
        deb_cmds = [_DEB_BACKUP, f"a2enmod {deb_mods} 2>/dev/null || true"]
        rhel_cmds = [_RH_BACKUP] + rhel_tokens
        deb_verify = [f"{_DEB_T} && apache2ctl -M 2>/dev/null | grep -q {module_name} && echo 'PASS' || echo 'FAIL'"]
        rhel_verify = [f"{_RH_T} && httpd -M 2>/dev/null | grep -q {module_name} && echo 'PASS' || echo 'FAIL'"]
    else:
        deb_cmds = [_DEB_BACKUP, f"a2dismod -f {deb_mods} 2>/dev/null || true"]
        rhel_cmds = [_RH_BACKUP] + [_rhel_disable_module(t) for t in rhel_tokens]
        deb_verify = [f"{_DEB_T} && ! apache2ctl -M 2>/dev/null | grep -q {module_name} && echo 'PASS' || echo 'FAIL'"]
        rhel_verify = [f"{_RH_T} && ! httpd -M 2>/dev/null | grep -q {module_name} && echo 'PASS' || echo 'FAIL'"]
    return ApacheHardeningTemplate(
        check_id=check_id,
        description=description,
        commands_debian=deb_cmds,
        commands_rhel=rhel_cmds,
        verify_commands_debian=deb_verify,
        verify_commands_rhel=rhel_verify,
        requires_service_restart=True,
    )


def _directive_cmds(conf: str, directive: str, value: str) -> str:
    """Replace-or-append a top-level directive in a config file."""
    return (
        f"grep -qE '^\\s*{directive}\\b' {conf} "
        f"&& sed -i -E 's/^([[:space:]]*){directive}[[:space:]].*/\\1{directive} {value}/' {conf} "
        f"|| echo '{directive} {value}' >> {conf}"
    )


# ==================== SECTION 2: MINIMIZE APACHE MODULES ====================

_register(_module_template(
    "APACHE-L1-2.2", "Enable the log_config module",
    "log_config", [f"sed -i 's/^#LoadModule log_config_module/LoadModule log_config_module/' {_R['mods_enabled']}/*.conf 2>/dev/null || true"],
    "log_config_module", enable=True,
))

_register(_module_template(
    "APACHE-L1-2.3", "Disable the WebDAV modules",
    "dav_fs dav_lock dav", ["dav_module", "dav_fs_module", "dav_lock_module"],
    "dav_module",
))

_register(_module_template(
    "APACHE-L1-2.4", "Disable the status module",
    "status", ["status_module"], "status_module",
))

_register(_module_template(
    "APACHE-L1-2.5", "Disable the autoindex module",
    "autoindex", ["autoindex_module"], "autoindex_module",
))

_register(_module_template(
    "APACHE-L1-2.6", "Disable the proxy modules",
    "proxy_http proxy_ftp proxy_connect proxy_ajp proxy_balancer proxy_fcgi proxy_wstunnel proxy",
    ["proxy_module", "proxy_http_module", "proxy_ftp_module", "proxy_connect_module"],
    "proxy_module",
))

_register(_module_template(
    "APACHE-L1-2.7", "Disable the user directories module",
    "userdir", ["userdir_module"], "userdir_module",
))

_register(_module_template(
    "APACHE-L1-2.8", "Disable the info module",
    "info", ["info_module"], "info_module",
))

_register(_module_template(
    "APACHE-L2-2.9", "Disable the basic and digest authentication modules",
    "auth_basic auth_digest", ["auth_basic_module", "auth_digest_module"],
    "auth_basic_module",
))


# ==================== SECTION 3: PERMISSIONS AND OWNERSHIP ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-3.2",
    description="Give the Apache user account an invalid shell",
    commands_debian=[_DEB_BACKUP, "usermod -s /usr/sbin/nologin www-data 2>/dev/null || usermod -s /sbin/nologin www-data"],
    commands_rhel=[_RH_BACKUP, "usermod -s /sbin/nologin apache"],
    verify_commands_debian=[f"{_DEB_T} && getent passwd www-data | grep -q nologin && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && getent passwd apache | grep -q nologin && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-3.3",
    description="Lock the Apache user account",
    commands_debian=[_DEB_BACKUP, "passwd -l www-data"],
    commands_rhel=[_RH_BACKUP, "passwd -l apache"],
    verify_commands_debian=[f"{_DEB_T} && passwd -S www-data 2>/dev/null | grep -qE ' (L|LK) ' && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && passwd -S apache 2>/dev/null | grep -qE ' (L|LK) ' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-3.4",
    description="Set root ownership on the Apache configuration tree",
    commands_debian=[_DEB_BACKUP, f"chown -R root:root {_D['config_dir']}"],
    commands_rhel=[_RH_BACKUP, f"chown -R root:root {_R['config_dir']}"],
    verify_commands_debian=[f"{_DEB_T} && [ -z \"$(find {_D['config_dir']} ! -user root 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && [ -z \"$(find {_R['config_dir']} ! -user root 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-3.5",
    description="Set root group on the Apache configuration tree",
    commands_debian=[_DEB_BACKUP, f"chgrp -R root {_D['config_dir']}"],
    commands_rhel=[_RH_BACKUP, f"chgrp -R root {_R['config_dir']}"],
    verify_commands_debian=[f"{_DEB_T} && [ -z \"$(find {_D['config_dir']} ! -group root 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && [ -z \"$(find {_R['config_dir']} ! -group root 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-3.6",
    description="Remove other write access from the Apache configuration tree",
    commands_debian=[_DEB_BACKUP, f"chmod -R o-w {_D['config_dir']}"],
    commands_rhel=[_RH_BACKUP, f"chmod -R o-w {_R['config_dir']}"],
    verify_commands_debian=[f"{_DEB_T} && [ -z \"$(find {_D['config_dir']} ! -type l -perm /o+w 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && [ -z \"$(find {_R['config_dir']} ! -type l -perm /o+w 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-3.11",
    description="Remove group write access from the Apache configuration tree",
    commands_debian=[_DEB_BACKUP, f"chmod -R g-w {_D['config_dir']}"],
    commands_rhel=[_RH_BACKUP, f"chmod -R g-w {_R['config_dir']}"],
    verify_commands_debian=[f"{_DEB_T} && [ -z \"$(find {_D['config_dir']} ! -type l -perm /g+w 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && [ -z \"$(find {_R['config_dir']} ! -type l -perm /g+w 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-3.12",
    description="Remove group write access from the document root",
    commands_debian=[_DEB_BACKUP, "chmod -R g-w /var/www/html"],
    commands_rhel=[_RH_BACKUP, "chmod -R g-w /var/www/html"],
    verify_commands_debian=[f"{_DEB_T} && [ -z \"$(find /var/www/html -type d -perm /g+w 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && [ -z \"$(find /var/www/html -type d -perm /g+w 2>/dev/null | head -1)\" ] && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))


# ==================== SECTION 4: ACCESS CONTROL ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-4.1",
    description="Deny access to the OS root directory by default",
    commands_debian=[
        _DEB_BACKUP,
        f"grep -q '<Directory />' {_DEB_MAIN} || printf '\\n<Directory />\\n\\tOptions None\\n\\tAllowOverride None\\n\\tRequire all denied\\n</Directory>\\n' >> {_DEB_MAIN}",
        f"sed -i '/<Directory \\/>/,/<\\/Directory>/ s/Require all granted/Require all denied/' {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"grep -q '<Directory />' {_RH_MAIN} || printf '\\n<Directory />\\n    Options None\\n    AllowOverride None\\n    Require all denied\\n</Directory>\\n' >> {_RH_MAIN}",
        f"sed -i '/<Directory \\/>/,/<\\/Directory>/ s/Require all granted/Require all denied/' {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_DEB_MAIN} | grep -qi 'Require all denied' && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_RH_MAIN} | grep -qi 'Require all denied' && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-4.3",
    description="Disable OverRide for the OS root directory",
    commands_debian=[
        _DEB_BACKUP,
        f"sed -i '/<Directory \\/>/,/<\\/Directory>/ s/AllowOverride .*/AllowOverride None/' {_DEB_MAIN}",
        f"sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_DEB_MAIN} | grep -q AllowOverride || sed -i '/<Directory \\/>/a\\\\tAllowOverride None' {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"sed -i '/<Directory \\/>/,/<\\/Directory>/ s/AllowOverride .*/AllowOverride None/' {_RH_MAIN}",
        f"sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_RH_MAIN} | grep -q AllowOverride || sed -i '/<Directory \\/>/a\\    AllowOverride None' {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_DEB_MAIN} | grep -qi 'AllowOverride None' && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_RH_MAIN} | grep -qi 'AllowOverride None' && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-4.4",
    description="Disable OverRide for all directories in the main configuration",
    commands_debian=[
        _DEB_BACKUP,
        f"sed -i -E 's/^([[:space:]]*)AllowOverride[[:space:]].*/\\1AllowOverride None/' {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"sed -i -E 's/^([[:space:]]*)AllowOverride[[:space:]].*/\\1AllowOverride None/' {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && ! grep -E '^[[:space:]]*AllowOverride[[:space:]]+' {_DEB_MAIN} | grep -vqi None && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && ! grep -E '^[[:space:]]*AllowOverride[[:space:]]+' {_RH_MAIN} | grep -vqi None && echo 'PASS' || echo 'FAIL'"],
))


# ==================== SECTION 5: FEATURES, CONTENT AND OPTIONS ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.1",
    description="Restrict Options for the OS root directory to None",
    commands_debian=[
        _DEB_BACKUP,
        f"sed -i '/<Directory \\/>/,/<\\/Directory>/ s/^\\([[:space:]]*\\)Options .*/\\1Options None/' {_DEB_MAIN}",
        f"sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_DEB_MAIN} | grep -q Options || sed -i '/<Directory \\/>/a\\\\tOptions None' {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"sed -i '/<Directory \\/>/,/<\\/Directory>/ s/^\\([[:space:]]*\\)Options .*/\\1Options None/' {_RH_MAIN}",
        f"sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_RH_MAIN} | grep -q Options || sed -i '/<Directory \\/>/a\\    Options None' {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_DEB_MAIN} | grep -qE '^[[:space:]]*Options None' && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && sed -n '/<Directory \\/>/,/<\\/Directory>/p' {_RH_MAIN} | grep -qE '^[[:space:]]*Options None' && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.2",
    description="Restrict Options for the web root directory",
    commands_debian=[
        _DEB_BACKUP,
        f"sed -i '/<Directory \\/var\\/www/,/<\\/Directory>/ s/^\\([[:space:]]*\\)Options .*/\\1Options FollowSymLinks/' {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"sed -i '/<Directory \"\\/var\\/www/,/<\\/Directory>/ s/^\\([[:space:]]*\\)Options .*/\\1Options FollowSymLinks/' {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && ! sed -n '/<Directory \\/var\\/www/,/<\\/Directory>/p' {_DEB_MAIN} | grep -E '^[[:space:]]*Options' | grep -qE 'Indexes|Includes|ExecCGI|All' && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && ! sed -n '/<Directory \"\\/var\\/www/,/<\\/Directory>/p' {_RH_MAIN} | grep -E '^[[:space:]]*Options' | grep -qE 'Indexes|Includes|ExecCGI|All' && echo 'PASS' || echo 'FAIL'"],
))

# 5.4 / 8.3 share the same remediation: remove default/bundled content.
_DEFAULT_CONTENT_DEB = [
    _DEB_BACKUP,
    "grep -qiE 'it works|apache2 .*default|test page' /var/www/html/index.html 2>/dev/null && rm -f /var/www/html/index.html || true",
    "rm -rf /var/www/manual /usr/share/apache2/default-site 2>/dev/null || true",
]
_DEFAULT_CONTENT_RHEL = [
    _RH_BACKUP,
    "grep -qiE 'it works|test page|apache http server' /var/www/html/index.html 2>/dev/null && rm -f /var/www/html/index.html || true",
    "rm -rf /usr/share/httpd/noindex /var/www/manual 2>/dev/null || true",
]
_DEFAULT_CONTENT_VERIFY_DEB = [
    f"{_DEB_T} && ! grep -qiE 'it works|apache2 .*default|test page' /var/www/html/index.html 2>/dev/null && [ ! -d /var/www/manual ] && echo 'PASS' || echo 'FAIL'"
]
_DEFAULT_CONTENT_VERIFY_RHEL = [
    f"{_RH_T} && ! grep -qiE 'it works|test page|apache http server' /var/www/html/index.html 2>/dev/null && [ ! -d /usr/share/httpd/noindex ] && echo 'PASS' || echo 'FAIL'"
]

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.4",
    description="Remove default HTML content",
    commands_debian=list(_DEFAULT_CONTENT_DEB),
    commands_rhel=list(_DEFAULT_CONTENT_RHEL),
    verify_commands_debian=list(_DEFAULT_CONTENT_VERIFY_DEB),
    verify_commands_rhel=list(_DEFAULT_CONTENT_VERIFY_RHEL),
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.5",
    description="Remove the default printenv CGI script",
    commands_debian=[_DEB_BACKUP, "rm -f /usr/lib/cgi-bin/printenv /var/www/cgi-bin/printenv"],
    commands_rhel=[_RH_BACKUP, "rm -f /var/www/cgi-bin/printenv /usr/lib/cgi-bin/printenv"],
    verify_commands_debian=[f"{_DEB_T} && [ ! -f /usr/lib/cgi-bin/printenv ] && [ ! -f /var/www/cgi-bin/printenv ] && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && [ ! -f /var/www/cgi-bin/printenv ] && [ ! -f /usr/lib/cgi-bin/printenv ] && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.6",
    description="Remove the default test-cgi script",
    commands_debian=[_DEB_BACKUP, "rm -f /usr/lib/cgi-bin/test-cgi /var/www/cgi-bin/test-cgi"],
    commands_rhel=[_RH_BACKUP, "rm -f /var/www/cgi-bin/test-cgi /usr/lib/cgi-bin/test-cgi"],
    verify_commands_debian=[f"{_DEB_T} && [ ! -f /usr/lib/cgi-bin/test-cgi ] && [ ! -f /var/www/cgi-bin/test-cgi ] && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && [ ! -f /var/www/cgi-bin/test-cgi ] && [ ! -f /usr/lib/cgi-bin/test-cgi ] && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.8",
    description="Disable the HTTP TRACE method",
    commands_debian=[
        _DEB_BACKUP,
        f"grep -q '^TraceEnable' {_DEB_MAIN} && sed -i 's/^TraceEnable.*/TraceEnable Off/' {_DEB_MAIN} || echo 'TraceEnable Off' >> {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"grep -q '^TraceEnable' {_RH_MAIN} && sed -i 's/^TraceEnable.*/TraceEnable Off/' {_RH_MAIN} || echo 'TraceEnable Off' >> {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -qi 'TraceEnable Off' {_DEB_MAIN} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -qi 'TraceEnable Off' {_RH_MAIN} && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.10",
    description="Restrict access to .ht* files",
    commands_debian=[
        _DEB_BACKUP,
        f"grep -rqE 'FilesMatch[^>]*\\.ht' {_D['config_dir']}/ || printf '\\n<FilesMatch \"^\\\\.ht\">\\n\\tRequire all denied\\n</FilesMatch>\\n' >> {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"grep -rqE 'FilesMatch[^>]*\\.ht' {_R['config_dir']}/ || printf '\\n<FilesMatch \"^\\\\.ht\">\\n    Require all denied\\n</FilesMatch>\\n' >> {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -rqE 'FilesMatch[^>]*\\.ht' {_D['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -rqE 'FilesMatch[^>]*\\.ht' {_R['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.11",
    description="Restrict access to inappropriate file extensions ({RESTRICTED_EXTENSIONS})",
    commands_debian=[
        _DEB_SEC_BACKUP,
        f"grep -q 'RESTRICTED_EXT_CIS' {_DEB_SEC} 2>/dev/null || printf '\\n# RESTRICTED_EXT_CIS\\n<FilesMatch \"\\\\.({{RESTRICTED_EXTENSIONS}})$\">\\n\\tRequire all denied\\n</FilesMatch>\\n' >> {_DEB_SEC}",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_SEC_BACKUP,
        f"grep -q 'RESTRICTED_EXT_CIS' {_RH_SEC} 2>/dev/null || printf '\\n# RESTRICTED_EXT_CIS\\n<FilesMatch \"\\\\.({{RESTRICTED_EXTENSIONS}})$\">\\n    Require all denied\\n</FilesMatch>\\n' >> {_RH_SEC}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -q 'RESTRICTED_EXT_CIS' {_DEB_SEC} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -q 'RESTRICTED_EXT_CIS' {_RH_SEC} && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L2-5.13",
    description="Bind listeners to a specific IP address ({LISTEN_IP})",
    commands_debian=[
        f"cp -f {_D['ports_conf'] if 'ports_conf' in _D else '/etc/apache2/ports.conf'} /etc/apache2/ports.conf.bak.cis 2>/dev/null || true",
        "sed -i -E 's/^Listen[[:space:]]+([0-9]+)$/Listen {LISTEN_IP}:\\1/' /etc/apache2/ports.conf",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"sed -i -E 's/^Listen[[:space:]]+([0-9]+)$/Listen {{LISTEN_IP}}:\\1/' {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && ! grep -qE '^Listen [0-9]+$' /etc/apache2/ports.conf && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && ! grep -qE '^Listen [0-9]+$' {_RH_MAIN} && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.14",
    description="Restrict browser framing with X-Frame-Options ({X_FRAME_OPTIONS})",
    commands_debian=[
        _DEB_SEC_BACKUP,
        "a2enmod headers 2>/dev/null || true",
        f"grep -q 'X-Frame-Options' {_DEB_SEC} 2>/dev/null || echo 'Header always set X-Frame-Options \"{{X_FRAME_OPTIONS}}\"' >> {_DEB_SEC}",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_SEC_BACKUP,
        f"grep -q 'X-Frame-Options' {_RH_SEC} 2>/dev/null || echo 'Header always set X-Frame-Options \"{{X_FRAME_OPTIONS}}\"' >> {_RH_SEC}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -q 'X-Frame-Options' {_DEB_SEC} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -q 'X-Frame-Options' {_RH_SEC} && echo 'PASS' || echo 'FAIL'"],
))


# ==================== SECTION 6: LOGGING, MONITORING, MAINTENANCE ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-6.1",
    description="Configure the error log and severity level",
    commands_debian=[
        _DEB_BACKUP,
        _directive_cmds(_DEB_MAIN, "LogLevel", "notice core:info"),
        f"grep -qE '^\\s*ErrorLog' {_DEB_MAIN} || printf 'ErrorLog ${{APACHE_LOG_DIR}}/error.log\\n' >> {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        _directive_cmds(_RH_MAIN, "LogLevel", "notice core:info"),
        f"grep -qE '^\\s*ErrorLog' {_RH_MAIN} || echo 'ErrorLog logs/error_log' >> {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -qE '^\\s*LogLevel notice core:info' {_DEB_MAIN} && grep -qE '^\\s*ErrorLog' {_DEB_MAIN} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -qE '^\\s*LogLevel notice core:info' {_RH_MAIN} && grep -qE '^\\s*ErrorLog' {_RH_MAIN} && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-6.3",
    description="Configure the server access log",
    commands_debian=[
        _DEB_BACKUP,
        f"grep -rqE '^\\s*CustomLog' {_D['config_dir']}/ || printf 'CustomLog ${{APACHE_LOG_DIR}}/access.log combined\\n' >> {_DEB_MAIN}",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"grep -rqE '^\\s*CustomLog' {_R['config_dir']}/ || echo 'CustomLog logs/access_log combined' >> {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -rqE '^\\s*CustomLog' {_D['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -rqE '^\\s*CustomLog' {_R['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-6.4",
    description="Configure log rotation for the Apache logs",
    commands_debian=[
        _DEB_BACKUP,
        "test -f /etc/logrotate.d/apache2 || printf '/var/log/apache2/*.log {\\n\\tweekly\\n\\trotate 13\\n\\tcompress\\n\\tdelaycompress\\n\\tmissingok\\n\\tnotifempty\\n}\\n' > /etc/logrotate.d/apache2",
    ],
    commands_rhel=[
        _RH_BACKUP,
        "test -f /etc/logrotate.d/httpd || printf '/var/log/httpd/*log {\\n    weekly\\n    rotate 13\\n    compress\\n    delaycompress\\n    missingok\\n    notifempty\\n}\\n' > /etc/logrotate.d/httpd",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -qE 'rotate|weekly|daily' /etc/logrotate.d/apache2 && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -qE 'rotate|weekly|daily' /etc/logrotate.d/httpd && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-6.5",
    description="Apply pending Apache security patches",
    commands_debian=[
        _DEB_BACKUP,
        "apt-get update -qq 2>/dev/null || true",
        "apt-get install -y --only-upgrade apache2 2>&1 | tail -3",
    ],
    commands_rhel=[
        _RH_BACKUP,
        "dnf install -y httpd 2>&1 | tail -3",
    ],
    verify_commands_debian=[f"{_DEB_T} && ! apt-get -s upgrade 2>/dev/null | grep -qE '^Inst apache2' && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && ! dnf -q check-update httpd 2>/dev/null | grep -qE '^httpd' && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L2-6.6",
    description="Install and enable ModSecurity",
    commands_debian=[
        _DEB_BACKUP,
        "apt-get install -y libapache2-mod-security2 2>&1 | tail -3",
        "a2enmod security2 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_BACKUP,
        "dnf install -y mod_security 2>&1 | tail -3",
    ],
    verify_commands_debian=[f"{_DEB_T} && apache2ctl -M 2>/dev/null | grep -q security2 && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && httpd -M 2>/dev/null | grep -q security2 && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L2-6.7",
    description="Install and enable the OWASP ModSecurity Core Rule Set",
    commands_debian=[
        _DEB_BACKUP,
        "apt-get install -y modsecurity-crs 2>&1 | tail -3",
        "test -f /etc/modsecurity/modsecurity.conf || cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_BACKUP,
        "dnf install -y mod_security_crs 2>&1 | tail -3",
    ],
    verify_commands_debian=[f"{_DEB_T} && ls /usr/share/modsecurity-crs 2>/dev/null | grep -q . && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && rpm -q mod_security_crs >/dev/null 2>&1 && echo 'PASS' || echo 'FAIL'"],
))


# ==================== SECTION 7: SSL/TLS CONFIGURATION ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.1",
    description="Install/enable the SSL/TLS module",
    commands_debian=[_DEB_BACKUP, "a2enmod ssl 2>/dev/null || true"],
    commands_rhel=[_RH_BACKUP, "dnf install -y mod_ssl 2>&1 | tail -3"],
    verify_commands_debian=[f"{_DEB_T} && apache2ctl -M 2>/dev/null | grep -q ssl_module && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && httpd -M 2>/dev/null | grep -q ssl_module && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.2",
    description="Install the server certificate and key ({SSL_CERT_FILE})",
    commands_debian=[
        f"cp -f {_D['ssl_conf']} {_D['ssl_conf']}.bak.cis 2>/dev/null || true",
        "cp -f /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak.cis 2>/dev/null || true",
        "test -f {SSL_CERT_FILE} && test -f {SSL_KEY_FILE} || echo 'CERT_OR_KEY_MISSING - upload the files first'",
        "sed -i -E 's|^([[:space:]]*)SSLCertificateFile[[:space:]].*|\\1SSLCertificateFile {SSL_CERT_FILE}|' /etc/apache2/sites-available/default-ssl.conf 2>/dev/null || true",
        "sed -i -E 's|^([[:space:]]*)SSLCertificateKeyFile[[:space:]].*|\\1SSLCertificateKeyFile {SSL_KEY_FILE}|' /etc/apache2/sites-available/default-ssl.conf 2>/dev/null || true",
        "a2ensite default-ssl 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_SSL_BACKUP,
        "test -f {SSL_CERT_FILE} && test -f {SSL_KEY_FILE} || echo 'CERT_OR_KEY_MISSING - upload the files first'",
        f"sed -i -E 's|^([[:space:]]*)SSLCertificateFile[[:space:]].*|\\1SSLCertificateFile {{SSL_CERT_FILE}}|' {_RH_SSL} 2>/dev/null || true",
        f"sed -i -E 's|^([[:space:]]*)SSLCertificateKeyFile[[:space:]].*|\\1SSLCertificateKeyFile {{SSL_KEY_FILE}}|' {_RH_SSL} 2>/dev/null || true",
    ],
    verify_commands_debian=[f"{_DEB_T} && test -f {{SSL_CERT_FILE}} && openssl x509 -checkend 0 -noout -in {{SSL_CERT_FILE}} 2>/dev/null && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && test -f {{SSL_CERT_FILE}} && openssl x509 -checkend 0 -noout -in {{SSL_CERT_FILE}} 2>/dev/null && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.3",
    description="Protect the server's private key (mode 400, owner root)",
    commands_debian=[
        _DEB_BACKUP,
        f"KEY=$(grep -rhE '^[[:space:]]*SSLCertificateKeyFile' {_D['config_dir']}/ 2>/dev/null | grep -v '#' | awk '{{print $2}}' | head -1); if [ -n \"$KEY\" ] && [ -f \"$KEY\" ]; then chown root:root \"$KEY\"; chmod 400 \"$KEY\"; fi",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"KEY=$(grep -rhE '^[[:space:]]*SSLCertificateKeyFile' {_R['config_dir']}/ 2>/dev/null | grep -v '#' | awk '{{print $2}}' | head -1); if [ -n \"$KEY\" ] && [ -f \"$KEY\" ]; then chown root:root \"$KEY\"; chmod 400 \"$KEY\"; fi",
    ],
    verify_commands_debian=[
        f"{_DEB_T} && KEY=$(grep -rhE '^[[:space:]]*SSLCertificateKeyFile' {_D['config_dir']}/ 2>/dev/null | grep -v '#' | awk '{{print $2}}' | head -1); [ -n \"$KEY\" ] && stat -c '%a %U' \"$KEY\" 2>/dev/null | grep -qE '^(400|600) root$' && echo 'PASS' || echo 'FAIL'",
    ],
    verify_commands_rhel=[
        f"{_RH_T} && KEY=$(grep -rhE '^[[:space:]]*SSLCertificateKeyFile' {_R['config_dir']}/ 2>/dev/null | grep -v '#' | awk '{{print $2}}' | head -1); [ -n \"$KEY\" ] && stat -c '%a %U' \"$KEY\" 2>/dev/null | grep -qE '^(400|600) root$' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.4",
    description="Disable TLSv1.0 and TLSv1.1 ({SSL_PROTOCOLS})",
    commands_debian=[
        _DEB_SSL_BACKUP,
        f"grep -q '^\\s*SSLProtocol' {_DEB_SSL} && sed -i -E 's/^([[:space:]]*)SSLProtocol.*/\\1SSLProtocol {{SSL_PROTOCOLS}}/' {_DEB_SSL} || echo 'SSLProtocol {{SSL_PROTOCOLS}}' >> {_DEB_SSL}",
    ],
    commands_rhel=[
        _RH_SSL_BACKUP,
        f"grep -q '^\\s*SSLProtocol' {_RH_SSL} && sed -i -E 's/^([[:space:]]*)SSLProtocol.*/\\1SSLProtocol {{SSL_PROTOCOLS}}/' {_RH_SSL} || echo 'SSLProtocol {{SSL_PROTOCOLS}}' >> {_RH_SSL}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -qE 'SSLProtocol.*(-TLSv1|TLSv1\\.[23])' {_DEB_SSL} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -qE 'SSLProtocol.*(-TLSv1|TLSv1\\.[23])' {_RH_SSL} && echo 'PASS' || echo 'FAIL'"],
))


def _cipher_template(check_id: str, description: str) -> ApacheHardeningTemplate:
    """7.5 / 7.8 / 7.12 all remediate via the same SSLCipherSuite directive."""
    return ApacheHardeningTemplate(
        check_id=check_id,
        description=description,
        commands_debian=[
            _DEB_SSL_BACKUP,
            f"grep -q '^\\s*SSLCipherSuite' {_DEB_SSL} && sed -i -E 's/^([[:space:]]*)SSLCipherSuite.*/\\1SSLCipherSuite {{SSL_CIPHER_SUITE}}/' {_DEB_SSL} || echo 'SSLCipherSuite {{SSL_CIPHER_SUITE}}' >> {_DEB_SSL}",
        ],
        commands_rhel=[
            _RH_SSL_BACKUP,
            f"grep -q '^\\s*SSLCipherSuite' {_RH_SSL} && sed -i -E 's/^([[:space:]]*)SSLCipherSuite.*/\\1SSLCipherSuite {{SSL_CIPHER_SUITE}}/' {_RH_SSL} || echo 'SSLCipherSuite {{SSL_CIPHER_SUITE}}' >> {_RH_SSL}",
        ],
        verify_commands_debian=[f"{_DEB_T} && grep -q '^\\s*SSLCipherSuite' {_DEB_SSL} && echo 'PASS' || echo 'FAIL'"],
        verify_commands_rhel=[f"{_RH_T} && grep -q '^\\s*SSLCipherSuite' {_RH_SSL} && echo 'PASS' || echo 'FAIL'"],
    )


_register(_cipher_template("APACHE-L1-7.5", "Disable weak SSL/TLS ciphers ({SSL_CIPHER_SUITE})"))
_register(_cipher_template("APACHE-L1-7.8", "Disable medium strength SSL/TLS ciphers ({SSL_CIPHER_SUITE})"))
_register(_cipher_template("APACHE-L2-7.12", "Enable only forward-secrecy cipher suites ({SSL_CIPHER_SUITE})"))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.6",
    description="Disable insecure SSL renegotiation",
    commands_debian=[
        _DEB_SSL_BACKUP,
        f"sed -i -E 's/^([[:space:]]*)SSLInsecureRenegotiation[[:space:]]+[Oo]n/\\1SSLInsecureRenegotiation off/' {_DEB_SSL} 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_SSL_BACKUP,
        f"sed -i -E 's/^([[:space:]]*)SSLInsecureRenegotiation[[:space:]]+[Oo]n/\\1SSLInsecureRenegotiation off/' {_RH_SSL} 2>/dev/null || true",
    ],
    verify_commands_debian=[f"{_DEB_T} && ! grep -rqiE '^[[:space:]]*SSLInsecureRenegotiation[[:space:]]+on' {_D['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && ! grep -rqiE '^[[:space:]]*SSLInsecureRenegotiation[[:space:]]+on' {_R['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.7",
    description="Disable SSL compression",
    commands_debian=[
        _DEB_SSL_BACKUP,
        f"grep -q '^\\s*SSLCompression' {_DEB_SSL} && sed -i -E 's/^([[:space:]]*)SSLCompression.*/\\1SSLCompression off/' {_DEB_SSL} || echo 'SSLCompression off' >> {_DEB_SSL}",
    ],
    commands_rhel=[
        _RH_SSL_BACKUP,
        f"grep -q '^\\s*SSLCompression' {_RH_SSL} && sed -i -E 's/^([[:space:]]*)SSLCompression.*/\\1SSLCompression off/' {_RH_SSL} || echo 'SSLCompression off' >> {_RH_SSL}",
    ],
    verify_commands_debian=[f"{_DEB_T} && ! grep -rqiE '^[[:space:]]*SSLCompression[[:space:]]+on' {_D['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && ! grep -rqiE '^[[:space:]]*SSLCompression[[:space:]]+on' {_R['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.10",
    description="Enable OCSP stapling",
    commands_debian=[
        _DEB_SSL_BACKUP,
        f"grep -q 'SSLUseStapling' {_DEB_SSL} || printf 'SSLUseStapling On\\nSSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"\\n' >> {_DEB_SSL}",
        f"sed -i -E 's/^([[:space:]]*)SSLUseStapling[[:space:]]+[Oo]ff/\\1SSLUseStapling On/' {_DEB_SSL}",
    ],
    commands_rhel=[
        _RH_SSL_BACKUP,
        f"grep -q 'SSLUseStapling' {_RH_SSL} || printf 'SSLUseStapling On\\nSSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"\\n' >> {_RH_SSL}",
        f"sed -i -E 's/^([[:space:]]*)SSLUseStapling[[:space:]]+[Oo]ff/\\1SSLUseStapling On/' {_RH_SSL}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -qiE 'SSLUseStapling[[:space:]]+on' {_DEB_SSL} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -qiE 'SSLUseStapling[[:space:]]+on' {_RH_SSL} && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.11",
    description="Enable HTTP Strict Transport Security ({HSTS_MAX_AGE}s)",
    commands_debian=[
        _DEB_SEC_BACKUP,
        "a2enmod headers 2>/dev/null || true",
        f"grep -q 'Strict-Transport-Security' {_DEB_SEC} 2>/dev/null || echo 'Header always set Strict-Transport-Security \"max-age={{HSTS_MAX_AGE}}; includeSubDomains\"' >> {_DEB_SEC}",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_SEC_BACKUP,
        f"grep -q 'Strict-Transport-Security' {_RH_SEC} 2>/dev/null || echo 'Header always set Strict-Transport-Security \"max-age={{HSTS_MAX_AGE}}; includeSubDomains\"' >> {_RH_SEC}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -q 'Strict-Transport-Security' {_DEB_SEC} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -q 'Strict-Transport-Security' {_RH_SEC} && echo 'PASS' || echo 'FAIL'"],
))


# ==================== SECTION 8: INFORMATION LEAKAGE ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.1",
    description="Set ServerTokens to Prod",
    commands_debian=[
        _DEB_SEC_BACKUP,
        f"grep -q '^ServerTokens' {_DEB_SEC} && sed -i 's/^ServerTokens.*/ServerTokens Prod/' {_DEB_SEC} || echo 'ServerTokens Prod' >> {_DEB_SEC}",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"grep -q '^ServerTokens' {_RH_MAIN} && sed -i 's/^ServerTokens.*/ServerTokens Prod/' {_RH_MAIN} || echo 'ServerTokens Prod' >> {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -qi 'ServerTokens Prod' {_DEB_SEC} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -qi 'ServerTokens Prod' {_RH_MAIN} && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.2",
    description="Set ServerSignature to Off",
    commands_debian=[
        _DEB_SEC_BACKUP,
        f"grep -q '^ServerSignature' {_DEB_SEC} && sed -i 's/^ServerSignature.*/ServerSignature Off/' {_DEB_SEC} || echo 'ServerSignature Off' >> {_DEB_SEC}",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        _RH_BACKUP,
        f"grep -q '^ServerSignature' {_RH_MAIN} && sed -i 's/^ServerSignature.*/ServerSignature Off/' {_RH_MAIN} || echo 'ServerSignature Off' >> {_RH_MAIN}",
    ],
    verify_commands_debian=[f"{_DEB_T} && grep -qi 'ServerSignature Off' {_DEB_SEC} && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && grep -qi 'ServerSignature Off' {_RH_MAIN} && echo 'PASS' || echo 'FAIL'"],
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.3",
    description="Remove all default Apache content",
    commands_debian=list(_DEFAULT_CONTENT_DEB),
    commands_rhel=list(_DEFAULT_CONTENT_RHEL),
    verify_commands_debian=list(_DEFAULT_CONTENT_VERIFY_DEB),
    verify_commands_rhel=list(_DEFAULT_CONTENT_VERIFY_RHEL),
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.4",
    description="Ensure ETag headers do not expose inodes (FileETag None)",
    commands_debian=[_DEB_BACKUP, _directive_cmds(_DEB_MAIN, "FileETag", "None")],
    commands_rhel=[_RH_BACKUP, _directive_cmds(_RH_MAIN, "FileETag", "None")],
    verify_commands_debian=[f"{_DEB_T} && ! grep -rqiE 'FileETag.*(INode|All)' {_D['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=[f"{_RH_T} && ! grep -rqiE 'FileETag.*(INode|All)' {_R['config_dir']}/ && echo 'PASS' || echo 'FAIL'"],
))


# ==================== SECTION 9: DENIAL OF SERVICE MITIGATIONS ====================

def _simple_directive_template(check_id: str, description: str,
                               directive: str, value: str,
                               verify_regex: str) -> ApacheHardeningTemplate:
    return ApacheHardeningTemplate(
        check_id=check_id,
        description=description,
        commands_debian=[_DEB_BACKUP, _directive_cmds(_DEB_MAIN, directive, value)],
        commands_rhel=[_RH_BACKUP, _directive_cmds(_RH_MAIN, directive, value)],
        verify_commands_debian=[f"{_DEB_T} && grep -qE '{verify_regex}' {_DEB_MAIN} && echo 'PASS' || echo 'FAIL'"],
        verify_commands_rhel=[f"{_RH_T} && grep -qE '{verify_regex}' {_RH_MAIN} && echo 'PASS' || echo 'FAIL'"],
    )


_register(_simple_directive_template(
    "APACHE-L1-9.1", "Set Timeout to 10 seconds",
    "Timeout", "10", r"^\s*Timeout 10$",
))

_register(_simple_directive_template(
    "APACHE-L1-9.2", "Enable KeepAlive",
    "KeepAlive", "On", r"^\s*KeepAlive On$",
))

_register(_simple_directive_template(
    "APACHE-L1-9.3", "Set MaxKeepAliveRequests to 100",
    "MaxKeepAliveRequests", "100", r"^\s*MaxKeepAliveRequests 100$",
))

_register(_simple_directive_template(
    "APACHE-L1-9.4", "Set KeepAliveTimeout to 15 or less",
    "KeepAliveTimeout", "15", r"^\s*KeepAliveTimeout 15$",
))

# 9.5 / 9.6 both land in the mod_reqtimeout configuration.
_REQTIMEOUT_LINE = "RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500"

def _reqtimeout_template(check_id: str, description: str) -> ApacheHardeningTemplate:
    deb_conf = "/etc/apache2/mods-available/reqtimeout.conf"
    rh_conf = "/etc/httpd/conf.d/reqtimeout.conf"
    return ApacheHardeningTemplate(
        check_id=check_id,
        description=description,
        commands_debian=[
            f"cp -f {deb_conf} {deb_conf}.bak.cis 2>/dev/null || true",
            "a2enmod reqtimeout 2>/dev/null || true",
            f"grep -q 'RequestReadTimeout' {deb_conf} 2>/dev/null && sed -i -E 's/^([[:space:]]*)RequestReadTimeout.*/\\1{_REQTIMEOUT_LINE}/' {deb_conf} || echo '{_REQTIMEOUT_LINE}' >> {deb_conf}",
        ],
        commands_rhel=[
            f"cp -f {rh_conf} {rh_conf}.bak.cis 2>/dev/null || true",
            f"grep -q 'RequestReadTimeout' {rh_conf} 2>/dev/null && sed -i -E 's/^([[:space:]]*)RequestReadTimeout.*/\\1{_REQTIMEOUT_LINE}/' {rh_conf} || echo '{_REQTIMEOUT_LINE}' >> {rh_conf}",
        ],
        verify_commands_debian=[f"{_DEB_T} && grep -q 'header=20-40' {deb_conf} && grep -q 'body=20' {deb_conf} && echo 'PASS' || echo 'FAIL'"],
        verify_commands_rhel=[f"{_RH_T} && grep -q 'header=20-40' {rh_conf} && grep -q 'body=20' {rh_conf} && echo 'PASS' || echo 'FAIL'"],
    )


_register(_reqtimeout_template(
    "APACHE-L1-9.5", "Limit request header read time (header=20-40, MinRate=500)"))
_register(_reqtimeout_template(
    "APACHE-L1-9.6", "Limit request body read time (body=20, MinRate=500)"))


# ==================== SECTION 10: REQUEST LIMITS ====================

_register(_simple_directive_template(
    "APACHE-L1-10.1", "Set LimitRequestLine to 512",
    "LimitRequestLine", "512", r"^\s*LimitRequestLine 512$",
))

_register(_simple_directive_template(
    "APACHE-L1-10.2", "Set LimitRequestFields to 100",
    "LimitRequestFields", "100", r"^\s*LimitRequestFields 100$",
))

_register(_simple_directive_template(
    "APACHE-L1-10.3", "Set LimitRequestFieldSize to 1024",
    "LimitRequestFieldSize", "1024", r"^\s*LimitRequestFieldSize 1024$",
))

_register(_simple_directive_template(
    "APACHE-L1-10.4", "Set LimitRequestBody to 102400",
    "LimitRequestBody", "102400", r"^\s*LimitRequestBody 102400$",
))


# ==================== SECTION 11: SELINUX (RHEL FAMILY) ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L2-11.1",
    description="Enable SELinux in enforcing mode",
    commands_debian=[
        "echo 'SELinux is not applicable on Debian/Ubuntu (see the AppArmor 12.x controls)'",
    ],
    commands_rhel=[
        "cp -f /etc/selinux/config /etc/selinux/config.bak.cis 2>/dev/null || true",
        "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
        "setenforce 1 2>/dev/null || true",
    ],
    verify_commands_debian=["echo 'FAIL - SELinux not applicable on this distribution'"],
    verify_commands_rhel=[f"{_RH_T} && getenforce 2>/dev/null | grep -q Enforcing && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart=False,
))


# ==================== SECTION 12: APPARMOR (DEBIAN FAMILY) ====================

_register(ApacheHardeningTemplate(
    check_id="APACHE-L2-12.1",
    description="Enable the AppArmor framework",
    commands_debian=[
        _DEB_BACKUP,
        "apt-get install -y apparmor apparmor-utils 2>&1 | tail -3",
        "systemctl enable apparmor 2>/dev/null || true",
        "systemctl start apparmor 2>/dev/null || true",
    ],
    commands_rhel=[
        "echo 'AppArmor is not applicable on RHEL/Rocky (see the SELinux 11.x controls)'",
    ],
    verify_commands_debian=[f"{_DEB_T} && aa-status --enabled 2>/dev/null && echo 'PASS' || echo 'FAIL'"],
    verify_commands_rhel=["echo 'FAIL - AppArmor not applicable on this distribution'"],
    requires_service_restart=False,
))

_register(ApacheHardeningTemplate(
    check_id="APACHE-L2-12.3",
    description="Put the Apache AppArmor profile in enforce mode",
    commands_debian=[
        _DEB_BACKUP,
        "test -f /etc/apparmor.d/usr.sbin.apache2 && aa-enforce /etc/apparmor.d/usr.sbin.apache2 2>/dev/null || echo 'NO_PROFILE - create one with aa-autodep first (see 12.2)'",
    ],
    commands_rhel=[
        "echo 'AppArmor is not applicable on RHEL/Rocky (see the SELinux 11.x controls)'",
    ],
    verify_commands_debian=[
        f"{_DEB_T} && PID=$(pgrep -x apache2 | head -1); [ -n \"$PID\" ] && cat /proc/$PID/attr/current 2>/dev/null | grep -q '(enforce)' && echo 'PASS' || echo 'FAIL'",
    ],
    verify_commands_rhel=["echo 'FAIL - AppArmor not applicable on this distribution'"],
))
