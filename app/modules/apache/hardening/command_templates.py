"""
Apache Hardening Command Templates

Remediation commands for each CIS check. Commands are distro-aware and
support parameter substitution.

Each template includes:
- check_id: The CIS check ID this template fixes
- commands: List of commands to execute (with {PARAM} placeholders)
- requires_reboot: Whether a reboot is needed for changes to take effect
- verify_commands: Commands to verify the fix was applied
- requires_service_restart: Service to restart (auto-mapped by distro)
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
import copy


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


def _substitute_parameters(commands: List[str], parameters: Optional[Dict[str, str]]) -> List[str]:
    """Substitute {PARAM} placeholders via plain replace — str.format() would
    raise on any brace the shell command itself contains."""
    if not parameters:
        return commands
    result = []
    for cmd in commands:
        for name, value in parameters.items():
            cmd = cmd.replace(f"{{{name}}}", str(value))
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


# ==================== SECTION 2: MINIMIZE APACHE MODULES ====================

# 2.5 - Disable mod_info
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-2.5",
    description="Disable mod_info module",
    commands_debian=[
        "a2dismod info 2>/dev/null || true",
    ],
    commands_rhel=[
        "sed -i 's/^LoadModule info_module/#LoadModule info_module/' /etc/httpd/conf.modules.d/00-base.conf 2>/dev/null || true",
        "sed -i 's/^LoadModule info_module/#LoadModule info_module/' /etc/httpd/conf.modules.d/*.conf 2>/dev/null || true",
    ],
    verify_commands_debian=[
        "apache2ctl -M 2>/dev/null | grep -q info_module && echo 'FAIL' || echo 'PASS'"
    ],
    verify_commands_rhel=[
        "httpd -M 2>/dev/null | grep -q info_module && echo 'FAIL' || echo 'PASS'"
    ]
))

# 2.6 - Disable mod_userdir
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-2.6",
    description="Disable mod_userdir module",
    commands_debian=[
        "a2dismod userdir 2>/dev/null || true",
    ],
    commands_rhel=[
        "sed -i 's/^LoadModule userdir_module/#LoadModule userdir_module/' /etc/httpd/conf.modules.d/00-base.conf 2>/dev/null || true",
    ],
    verify_commands_debian=[
        "apache2ctl -M 2>/dev/null | grep -q userdir_module && echo 'FAIL' || echo 'PASS'"
    ],
    verify_commands_rhel=[
        "httpd -M 2>/dev/null | grep -q userdir_module && echo 'FAIL' || echo 'PASS'"
    ]
))

# 2.7 - Disable autoindex / Indexes option
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-2.7",
    description="Disable directory listing (Indexes)",
    commands_debian=[
        "a2dismod autoindex 2>/dev/null || true",
        # Also ensure Options -Indexes in config
        "grep -q '^\\s*Options.*-Indexes' /etc/apache2/apache2.conf || sed -i '/<Directory \\/var\\/www\\/>/,/<\\/Directory>/ s/Options.*/Options -Indexes -FollowSymLinks/' /etc/apache2/apache2.conf 2>/dev/null || true",
    ],
    commands_rhel=[
        "sed -i 's/^LoadModule autoindex_module/#LoadModule autoindex_module/' /etc/httpd/conf.modules.d/00-base.conf 2>/dev/null || true",
        "sed -i 's/Options Indexes/Options -Indexes/g' /etc/httpd/conf/httpd.conf 2>/dev/null || true",
    ],
    verify_commands_debian=[
        "apache2ctl -M 2>/dev/null | grep -q autoindex_module && echo 'FAIL' || echo 'PASS'"
    ],
    verify_commands_rhel=[
        "httpd -M 2>/dev/null | grep -q autoindex_module && echo 'FAIL' || echo 'PASS'"
    ]
))


# ==================== SECTION 5: MINIMIZE FEATURES ====================

# 5.8 - Disable HTTP TRACE method
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-5.8",
    description="Disable HTTP TRACE method",
    commands_debian=[
        "grep -q '^TraceEnable' /etc/apache2/apache2.conf || echo 'TraceEnable Off' >> /etc/apache2/apache2.conf",
        "sed -i 's/^TraceEnable.*/TraceEnable Off/' /etc/apache2/apache2.conf",
    ],
    commands_rhel=[
        "grep -q '^TraceEnable' /etc/httpd/conf/httpd.conf || echo 'TraceEnable Off' >> /etc/httpd/conf/httpd.conf",
        "sed -i 's/^TraceEnable.*/TraceEnable Off/' /etc/httpd/conf/httpd.conf",
    ],
    verify_commands_debian=[
        "grep -q 'TraceEnable Off' /etc/apache2/apache2.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -q 'TraceEnable Off' /etc/httpd/conf/httpd.conf && echo 'PASS' || echo 'FAIL'"
    ]
))


# ==================== SECTION 6: LOGGING ====================

# 6.1 - Configure error logging
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-6.1",
    description="Configure error logging with appropriate level",
    commands_debian=[
        "sed -i 's/^LogLevel.*/LogLevel warn/' /etc/apache2/apache2.conf 2>/dev/null || true",
        "grep -q '^LogLevel' /etc/apache2/apache2.conf || echo 'LogLevel warn' >> /etc/apache2/apache2.conf",
    ],
    commands_rhel=[
        "sed -i 's/^LogLevel.*/LogLevel warn/' /etc/httpd/conf/httpd.conf 2>/dev/null || true",
        "grep -q '^LogLevel' /etc/httpd/conf/httpd.conf || echo 'LogLevel warn' >> /etc/httpd/conf/httpd.conf",
    ],
    verify_commands_debian=[
        "grep -qE '^LogLevel (warn|error|crit)' /etc/apache2/apache2.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -qE '^LogLevel (warn|error|crit)' /etc/httpd/conf/httpd.conf && echo 'PASS' || echo 'FAIL'"
    ]
))


# ==================== SECTION 7: REQUEST LIMITS ====================

# 7.1 - Configure Timeout
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-7.1",
    description="Set appropriate request timeout",
    commands_debian=[
        "sed -i 's/^Timeout.*/Timeout 60/' /etc/apache2/apache2.conf 2>/dev/null || true",
        "grep -q '^Timeout' /etc/apache2/apache2.conf || echo 'Timeout 60' >> /etc/apache2/apache2.conf",
    ],
    commands_rhel=[
        "sed -i 's/^Timeout.*/Timeout 60/' /etc/httpd/conf/httpd.conf 2>/dev/null || true",
        "grep -q '^Timeout' /etc/httpd/conf/httpd.conf || echo 'Timeout 60' >> /etc/httpd/conf/httpd.conf",
    ],
    verify_commands_debian=[
        "grep -qE '^Timeout [0-9]+' /etc/apache2/apache2.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -qE '^Timeout [0-9]+' /etc/httpd/conf/httpd.conf && echo 'PASS' || echo 'FAIL'"
    ]
))


# ==================== SECTION 8: SSL/TLS CONFIGURATION ====================

# 8.1 - Enable SSL module
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.1",
    description="Enable SSL/TLS module",
    commands_debian=[
        "a2enmod ssl 2>/dev/null || true",
    ],
    commands_rhel=[
        "yum install -y mod_ssl 2>/dev/null || dnf install -y mod_ssl 2>/dev/null || true",
    ],
    verify_commands_debian=[
        "apache2ctl -M 2>/dev/null | grep -q ssl_module && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "httpd -M 2>/dev/null | grep -q ssl_module && echo 'PASS' || echo 'FAIL'"
    ]
))

# 8.3 - Disable insecure SSL protocols
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.3",
    description="Disable insecure SSL/TLS protocols (SSLv3, TLSv1.0, TLSv1.1)",
    commands_debian=[
        "grep -q '^SSLProtocol' /etc/apache2/mods-available/ssl.conf && sed -i 's/^SSLProtocol.*/SSLProtocol {SSL_PROTOCOLS}/' /etc/apache2/mods-available/ssl.conf || echo 'SSLProtocol {SSL_PROTOCOLS}' >> /etc/apache2/mods-available/ssl.conf",
    ],
    commands_rhel=[
        "grep -q '^SSLProtocol' /etc/httpd/conf.d/ssl.conf && sed -i 's/^SSLProtocol.*/SSLProtocol {SSL_PROTOCOLS}/' /etc/httpd/conf.d/ssl.conf || echo 'SSLProtocol {SSL_PROTOCOLS}' >> /etc/httpd/conf.d/ssl.conf",
    ],
    verify_commands_debian=[
        "grep -qE 'SSLProtocol.*(all|-SSLv3|-TLSv1)' /etc/apache2/mods-available/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -qE 'SSLProtocol.*(all|-SSLv3|-TLSv1)' /etc/httpd/conf.d/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ]
))

# 8.4 - Configure strong cipher suites
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.4",
    description="Configure strong SSL cipher suites",
    commands_debian=[
        "grep -q '^SSLCipherSuite' /etc/apache2/mods-available/ssl.conf && sed -i 's/^SSLCipherSuite.*/SSLCipherSuite {SSL_CIPHER_SUITE}/' /etc/apache2/mods-available/ssl.conf || echo 'SSLCipherSuite {SSL_CIPHER_SUITE}' >> /etc/apache2/mods-available/ssl.conf",
    ],
    commands_rhel=[
        "grep -q '^SSLCipherSuite' /etc/httpd/conf.d/ssl.conf && sed -i 's/^SSLCipherSuite.*/SSLCipherSuite {SSL_CIPHER_SUITE}/' /etc/httpd/conf.d/ssl.conf || echo 'SSLCipherSuite {SSL_CIPHER_SUITE}' >> /etc/httpd/conf.d/ssl.conf",
    ],
    verify_commands_debian=[
        "grep -q '^SSLCipherSuite' /etc/apache2/mods-available/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -q '^SSLCipherSuite' /etc/httpd/conf.d/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ]
))

# 8.5 - Enable SSLHonorCipherOrder
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.5",
    description="Enable SSLHonorCipherOrder",
    commands_debian=[
        "grep -q '^SSLHonorCipherOrder' /etc/apache2/mods-available/ssl.conf && sed -i 's/^SSLHonorCipherOrder.*/SSLHonorCipherOrder on/' /etc/apache2/mods-available/ssl.conf || echo 'SSLHonorCipherOrder on' >> /etc/apache2/mods-available/ssl.conf",
    ],
    commands_rhel=[
        "grep -q '^SSLHonorCipherOrder' /etc/httpd/conf.d/ssl.conf && sed -i 's/^SSLHonorCipherOrder.*/SSLHonorCipherOrder on/' /etc/httpd/conf.d/ssl.conf || echo 'SSLHonorCipherOrder on' >> /etc/httpd/conf.d/ssl.conf",
    ],
    verify_commands_debian=[
        "grep -qi 'SSLHonorCipherOrder on' /etc/apache2/mods-available/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -qi 'SSLHonorCipherOrder on' /etc/httpd/conf.d/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ]
))

# 8.6 - Disable SSL compression
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.6",
    description="Disable SSL compression",
    commands_debian=[
        "grep -q '^SSLCompression' /etc/apache2/mods-available/ssl.conf && sed -i 's/^SSLCompression.*/SSLCompression off/' /etc/apache2/mods-available/ssl.conf || echo 'SSLCompression off' >> /etc/apache2/mods-available/ssl.conf",
    ],
    commands_rhel=[
        "grep -q '^SSLCompression' /etc/httpd/conf.d/ssl.conf && sed -i 's/^SSLCompression.*/SSLCompression off/' /etc/httpd/conf.d/ssl.conf || echo 'SSLCompression off' >> /etc/httpd/conf.d/ssl.conf",
    ],
    verify_commands_debian=[
        "grep -qi 'SSLCompression off' /etc/apache2/mods-available/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -qi 'SSLCompression off' /etc/httpd/conf.d/ssl.conf && echo 'PASS' || echo 'FAIL'"
    ]
))

# 8.8 - Enable HSTS header
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-8.8",
    description="Enable HTTP Strict Transport Security (HSTS)",
    commands_debian=[
        "a2enmod headers 2>/dev/null || true",
        "grep -q 'Strict-Transport-Security' /etc/apache2/conf-available/security.conf 2>/dev/null || echo 'Header always set Strict-Transport-Security \"max-age={HSTS_MAX_AGE}; includeSubDomains\"' >> /etc/apache2/conf-available/security.conf",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        "grep -q 'Strict-Transport-Security' /etc/httpd/conf.d/security.conf 2>/dev/null || echo 'Header always set Strict-Transport-Security \"max-age={HSTS_MAX_AGE}; includeSubDomains\"' >> /etc/httpd/conf.d/security.conf",
    ],
    verify_commands_debian=[
        "grep -q 'Strict-Transport-Security' /etc/apache2/conf-available/security.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -q 'Strict-Transport-Security' /etc/httpd/conf.d/security.conf && echo 'PASS' || echo 'FAIL'"
    ]
))


# ==================== SECTION 9: INFORMATION LEAKAGE ====================

# 9.1 - Set ServerTokens to Prod
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-9.1",
    description="Set ServerTokens to Prod",
    commands_debian=[
        "grep -q '^ServerTokens' /etc/apache2/conf-available/security.conf && sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf || echo 'ServerTokens Prod' >> /etc/apache2/conf-available/security.conf",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        "grep -q '^ServerTokens' /etc/httpd/conf/httpd.conf && sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/httpd/conf/httpd.conf || echo 'ServerTokens Prod' >> /etc/httpd/conf/httpd.conf",
    ],
    verify_commands_debian=[
        "grep -qi 'ServerTokens Prod' /etc/apache2/conf-available/security.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -qi 'ServerTokens Prod' /etc/httpd/conf/httpd.conf && echo 'PASS' || echo 'FAIL'"
    ]
))

# 9.2 - Set ServerSignature to Off
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-9.2",
    description="Set ServerSignature to Off",
    commands_debian=[
        "grep -q '^ServerSignature' /etc/apache2/conf-available/security.conf && sed -i 's/^ServerSignature.*/ServerSignature Off/' /etc/apache2/conf-available/security.conf || echo 'ServerSignature Off' >> /etc/apache2/conf-available/security.conf",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        "grep -q '^ServerSignature' /etc/httpd/conf/httpd.conf && sed -i 's/^ServerSignature.*/ServerSignature Off/' /etc/httpd/conf/httpd.conf || echo 'ServerSignature Off' >> /etc/httpd/conf/httpd.conf",
    ],
    verify_commands_debian=[
        "grep -qi 'ServerSignature Off' /etc/apache2/conf-available/security.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -qi 'ServerSignature Off' /etc/httpd/conf/httpd.conf && echo 'PASS' || echo 'FAIL'"
    ]
))


# ==================== SECTION 10: HTTP CONFIGURATION ====================

# 10.5 - X-Content-Type-Options header
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-10.5",
    description="Set X-Content-Type-Options header",
    commands_debian=[
        "a2enmod headers 2>/dev/null || true",
        "grep -q 'X-Content-Type-Options' /etc/apache2/conf-available/security.conf 2>/dev/null || echo 'Header always set X-Content-Type-Options \"nosniff\"' >> /etc/apache2/conf-available/security.conf",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        "grep -q 'X-Content-Type-Options' /etc/httpd/conf.d/security.conf 2>/dev/null || echo 'Header always set X-Content-Type-Options \"nosniff\"' >> /etc/httpd/conf.d/security.conf",
    ],
    verify_commands_debian=[
        "grep -q 'X-Content-Type-Options' /etc/apache2/conf-available/security.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -q 'X-Content-Type-Options' /etc/httpd/conf.d/security.conf && echo 'PASS' || echo 'FAIL'"
    ]
))

# 10.6 - X-Frame-Options header
_register(ApacheHardeningTemplate(
    check_id="APACHE-L1-10.6",
    description="Set X-Frame-Options header",
    commands_debian=[
        "a2enmod headers 2>/dev/null || true",
        "grep -q 'X-Frame-Options' /etc/apache2/conf-available/security.conf 2>/dev/null || echo 'Header always set X-Frame-Options \"{X_FRAME_OPTIONS}\"' >> /etc/apache2/conf-available/security.conf",
        "a2enconf security 2>/dev/null || true",
    ],
    commands_rhel=[
        "grep -q 'X-Frame-Options' /etc/httpd/conf.d/security.conf 2>/dev/null || echo 'Header always set X-Frame-Options \"{X_FRAME_OPTIONS}\"' >> /etc/httpd/conf.d/security.conf",
    ],
    verify_commands_debian=[
        "grep -q 'X-Frame-Options' /etc/apache2/conf-available/security.conf && echo 'PASS' || echo 'FAIL'"
    ],
    verify_commands_rhel=[
        "grep -q 'X-Frame-Options' /etc/httpd/conf.d/security.conf && echo 'PASS' || echo 'FAIL'"
    ]
))
