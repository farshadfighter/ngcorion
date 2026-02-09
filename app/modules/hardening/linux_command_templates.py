"""
Linux Hardening Command Templates

Remediation commands for each CIS check. Commands are distro-aware and
support parameter substitution.

Each template includes:
- check_id: The CIS check ID this template fixes
- commands: List of commands to execute
- requires_reboot: Whether a reboot is needed for changes to take effect
- verify_commands: Commands to verify the fix was applied
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class LinuxHardeningTemplate:
    """Template for hardening a specific CIS check."""
    check_id: str
    description: str
    commands: List[str]  # Commands with {PARAM} placeholders
    requires_reboot: bool = False
    verify_commands: List[str] = field(default_factory=list)
    distros: List[str] = field(default_factory=lambda: ["all"])  # Which distros this applies to
    requires_service_restart: Optional[str] = None  # Service to restart after applying


# Command templates registry
LINUX_HARDENING_TEMPLATES: Dict[str, LinuxHardeningTemplate] = {}


def _register(template: LinuxHardeningTemplate):
    """Register a template in the registry."""
    LINUX_HARDENING_TEMPLATES[template.check_id] = template


# ==================== SECTION 1: INITIAL SETUP ====================

# 1.1.1.x - Disable unused filesystems
for fs in ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"]:
    section = {"cramfs": "1", "freevxfs": "2", "jffs2": "3", "hfs": "4",
               "hfsplus": "5", "squashfs": "6", "udf": "7"}[fs]
    _register(LinuxHardeningTemplate(
        check_id=f"LNX-L1-1.1.1.{section}",
        description=f"Disable {fs} filesystem",
        commands=[
            f"echo 'install {fs} /bin/true' > /etc/modprobe.d/{fs}.conf",
            f"echo 'blacklist {fs}' >> /etc/modprobe.d/{fs}.conf",
            f"rmmod {fs} 2>/dev/null || true"
        ],
        verify_commands=[
            f"modprobe -n -v {fs} 2>&1 | grep -q 'install /bin/true' && echo 'PASS' || echo 'FAIL'",
            f"lsmod | grep {fs} || echo 'NOT_LOADED'"
        ]
    ))

# 1.1.1.8 - Disable USB storage
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.1.1.8",
    description="Disable USB storage",
    commands=[
        "echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf",
        "echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf",
        "rmmod usb-storage 2>/dev/null || true"
    ],
    verify_commands=[
        "modprobe -n -v usb-storage 2>&1 | grep -q 'install /bin/true' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 1.5.1 - Enable ASLR
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.5.1",
    description="Enable Address Space Layout Randomization (ASLR)",
    commands=[
        "echo 'kernel.randomize_va_space = 2' > /etc/sysctl.d/60-aslr.conf",
        "sysctl -w kernel.randomize_va_space=2"
    ],
    verify_commands=[
        "sysctl kernel.randomize_va_space | grep -q '= 2' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 1.5.4 - Restrict core dumps
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.5.4",
    description="Restrict core dumps",
    commands=[
        "echo 'fs.suid_dumpable = 0' > /etc/sysctl.d/60-coredump.conf",
        "sysctl -w fs.suid_dumpable=0",
        "echo '* hard core 0' >> /etc/security/limits.conf"
    ],
    verify_commands=[
        "sysctl fs.suid_dumpable | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 1.6.1 - Configure MOTD
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.6.1",
    description="Configure message of the day",
    commands=[
        "cat > /etc/motd << 'EOF'\n{MOTD_TEXT}\nEOF",
        "chmod 644 /etc/motd"
    ],
    verify_commands=[
        "test -s /etc/motd && echo 'PASS' || echo 'FAIL'"
    ]
))

# 1.6.2 - Configure local login banner
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.6.2",
    description="Configure local login warning banner",
    commands=[
        "cat > /etc/issue << 'EOF'\n{BANNER_TEXT}\nEOF",
        "chmod 644 /etc/issue"
    ],
    verify_commands=[
        "test -s /etc/issue && echo 'PASS' || echo 'FAIL'"
    ]
))

# ==================== SECTION 2: SERVICES ====================

# Disable dangerous services
dangerous_services = [
    ("avahi-daemon", "2.2.1"),
    ("cups", "2.2.2"),
    ("dhcpd", "2.2.3"),
    ("slapd", "2.2.4"),
    ("nfs-server", "2.2.5"),
    ("rpcbind", "2.2.6"),
    ("named", "2.2.7"),
    ("vsftpd", "2.2.8"),
    ("httpd", "2.2.9"),
    ("dovecot", "2.2.10"),
    ("smb", "2.2.11"),
    ("squid", "2.2.12"),
    ("snmpd", "2.2.13"),
    ("rsync", "2.2.14"),
    ("nis", "2.2.15"),
    ("telnet.socket", "2.2.16"),
]

for service, section in dangerous_services:
    _register(LinuxHardeningTemplate(
        check_id=f"LNX-L1-{section}",
        description=f"Disable {service} service",
        commands=[
            f"systemctl stop {service} 2>/dev/null || true",
            f"systemctl disable {service} 2>/dev/null || true",
            f"systemctl mask {service} 2>/dev/null || true"
        ],
        verify_commands=[
            f"systemctl is-enabled {service} 2>/dev/null | grep -qE 'disabled|masked' && echo 'PASS' || echo 'FAIL'"
        ]
    ))

# 2.4.1 - Time synchronization (chrony)
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-2.4.1",
    description="Configure time synchronization with chrony",
    commands=[
        "apt-get install -y chrony 2>/dev/null || dnf install -y chrony 2>/dev/null || true",
        "systemctl enable chronyd 2>/dev/null || systemctl enable chrony 2>/dev/null || true",
        "systemctl start chronyd 2>/dev/null || systemctl start chrony 2>/dev/null || true"
    ],
    verify_commands=[
        "systemctl is-enabled chrony 2>/dev/null || systemctl is-enabled chronyd 2>/dev/null | grep -q enabled && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="chronyd"
))

# ==================== SECTION 3: NETWORK CONFIGURATION ====================

# 3.1.1 - Disable IP forwarding
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.1.1",
    description="Disable IP forwarding",
    commands=[
        "echo 'net.ipv4.ip_forward = 0' > /etc/sysctl.d/60-netipv4_sysctl.conf",
        "echo 'net.ipv6.conf.all.forwarding = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.ip_forward=0",
        "sysctl -w net.ipv6.conf.all.forwarding=0"
    ],
    verify_commands=[
        "sysctl net.ipv4.ip_forward | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.1.2 - Disable packet redirect sending
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.1.2",
    description="Disable packet redirect sending",
    commands=[
        "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.conf.all.send_redirects=0",
        "sysctl -w net.ipv4.conf.default.send_redirects=0"
    ],
    verify_commands=[
        "sysctl net.ipv4.conf.all.send_redirects | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.2.1 - Reject source routed packets
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.1",
    description="Reject source routed packets",
    commands=[
        "echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.conf.all.accept_source_route=0",
        "sysctl -w net.ipv4.conf.default.accept_source_route=0"
    ],
    verify_commands=[
        "sysctl net.ipv4.conf.all.accept_source_route | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.2.2 - Reject ICMP redirects
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.2",
    description="Reject ICMP redirects",
    commands=[
        "echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.conf.all.accept_redirects=0",
        "sysctl -w net.ipv4.conf.default.accept_redirects=0"
    ],
    verify_commands=[
        "sysctl net.ipv4.conf.all.accept_redirects | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.2.4 - Log suspicious packets
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.4",
    description="Log suspicious packets (martians)",
    commands=[
        "echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.conf.all.log_martians=1",
        "sysctl -w net.ipv4.conf.default.log_martians=1"
    ],
    verify_commands=[
        "sysctl net.ipv4.conf.all.log_martians | grep -q '= 1' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.2.5 - Ignore broadcast ICMP
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.5",
    description="Ignore broadcast ICMP requests",
    commands=[
        "echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ],
    verify_commands=[
        "sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -q '= 1' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.2.7 - Enable Reverse Path Filtering
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.7",
    description="Enable Reverse Path Filtering",
    commands=[
        "echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.conf.all.rp_filter=1",
        "sysctl -w net.ipv4.conf.default.rp_filter=1"
    ],
    verify_commands=[
        "sysctl net.ipv4.conf.all.rp_filter | grep -q '= 1' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.2.8 - Enable TCP SYN Cookies
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.8",
    description="Enable TCP SYN Cookies",
    commands=[
        "echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.tcp_syncookies=1"
    ],
    verify_commands=[
        "sysctl net.ipv4.tcp_syncookies | grep -q '= 1' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 3.4.1 - Enable firewall (Ubuntu: ufw, RHEL: firewalld)
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.4.1",
    description="Enable firewall (ufw for Ubuntu)",
    commands=[
        "apt-get install -y ufw 2>/dev/null || dnf install -y firewalld 2>/dev/null || true",
        "ufw default {FIREWALL_DEFAULT_POLICY} incoming 2>/dev/null || firewall-cmd --set-default-zone=drop 2>/dev/null || true",
        "ufw default allow outgoing 2>/dev/null || true",
        "ufw allow ssh 2>/dev/null || firewall-cmd --permanent --add-service=ssh 2>/dev/null || true",
        "ufw --force enable 2>/dev/null || systemctl enable --now firewalld 2>/dev/null || true"
    ],
    verify_commands=[
        "ufw status | grep -q 'Status: active' && echo 'PASS' || firewall-cmd --state | grep -q 'running' && echo 'PASS' || echo 'FAIL'"
    ],
    distros=["all"]
))

# ==================== SECTION 4: LOGGING AND AUDITING ====================

# 4.1.1 - Enable rsyslog
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-4.1.1",
    description="Enable rsyslog",
    commands=[
        "apt-get install -y rsyslog 2>/dev/null || dnf install -y rsyslog 2>/dev/null || true",
        "systemctl enable rsyslog",
        "systemctl start rsyslog"
    ],
    verify_commands=[
        "systemctl is-enabled rsyslog | grep -q enabled && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="rsyslog"
))

# 4.1.1.1 - Enable journald
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-4.1.1.1",
    description="Ensure systemd-journald is enabled",
    commands=[
        "systemctl enable systemd-journald",
        "systemctl start systemd-journald"
    ],
    verify_commands=[
        "systemctl is-enabled systemd-journald | grep -qE 'enabled|static' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 4.2.1 - Enable auditd
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-4.2.1",
    description="Enable auditd",
    commands=[
        "apt-get install -y auditd audispd-plugins 2>/dev/null || dnf install -y audit 2>/dev/null || true",
        "systemctl enable auditd",
        "systemctl start auditd"
    ],
    verify_commands=[
        "systemctl is-enabled auditd | grep -q enabled && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="auditd"
))

# 4.2.2 - Configure audit log storage
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-4.2.2",
    description="Configure audit log storage",
    commands=[
        "sed -i 's/^max_log_file.*/max_log_file = {AUDIT_MAX_LOG_FILE}/' /etc/audit/auditd.conf",
        "sed -i 's/^space_left_action.*/space_left_action = {AUDIT_SPACE_LEFT_ACTION}/' /etc/audit/auditd.conf",
        "systemctl restart auditd"
    ],
    verify_commands=[
        "grep -q 'max_log_file = {AUDIT_MAX_LOG_FILE}' /etc/audit/auditd.conf && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="auditd"
))

# ==================== SECTION 5: ACCESS, AUTHENTICATION, AUTHORIZATION ====================

# 5.1.1 - Enable cron
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.1.1",
    description="Enable cron daemon",
    commands=[
        "systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null || true",
        "systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null || true"
    ],
    verify_commands=[
        "systemctl is-enabled cron 2>/dev/null || systemctl is-enabled crond 2>/dev/null | grep -q enabled && echo 'PASS' || echo 'FAIL'"
    ]
))

# 5.2.1 - Secure sshd_config permissions
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.1",
    description="Set permissions on /etc/ssh/sshd_config",
    commands=[
        "chown root:root /etc/ssh/sshd_config",
        "chmod 600 /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "stat -c '%a %U:%G' /etc/ssh/sshd_config | grep -q '600 root:root' && echo 'PASS' || echo 'FAIL'"
    ]
))

# 5.2.6 - Disable X11 forwarding
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.6",
    description="Disable SSH X11 forwarding",
    commands=[
        "sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config",
        "grep -q '^X11Forwarding' /etc/ssh/sshd_config || echo 'X11Forwarding no' >> /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "sshd -T | grep -q 'x11forwarding no' && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# 5.2.7 - Set SSH MaxAuthTries
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.7",
    description="Set SSH MaxAuthTries",
    commands=[
        "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries {SSH_MAX_AUTH_TRIES}/' /etc/ssh/sshd_config",
        "grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries {SSH_MAX_AUTH_TRIES}' >> /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "sshd -T | grep -q 'maxauthtries {SSH_MAX_AUTH_TRIES}' && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# 5.2.10 - Disable SSH root login
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.10",
    description="Disable SSH root login",
    commands=[
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "sshd -T | grep -q 'permitrootlogin no' && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# 5.2.11 - Disable SSH empty passwords
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.11",
    description="Disable SSH empty passwords",
    commands=[
        "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config",
        "grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "sshd -T | grep -q 'permitemptypasswords no' && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# 5.2.12 - Disable SSH user environment
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.12",
    description="Disable SSH PermitUserEnvironment",
    commands=[
        "sed -i 's/^#*PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config",
        "grep -q '^PermitUserEnvironment' /etc/ssh/sshd_config || echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "sshd -T | grep -q 'permituserenvironment no' && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# 5.2.13 - Configure SSH idle timeout
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.13",
    description="Configure SSH idle timeout",
    commands=[
        "sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval {SSH_CLIENT_ALIVE_INTERVAL}/' /etc/ssh/sshd_config",
        "grep -q '^ClientAliveInterval' /etc/ssh/sshd_config || echo 'ClientAliveInterval {SSH_CLIENT_ALIVE_INTERVAL}' >> /etc/ssh/sshd_config",
        "sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax {SSH_CLIENT_ALIVE_COUNT_MAX}/' /etc/ssh/sshd_config",
        "grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config || echo 'ClientAliveCountMax {SSH_CLIENT_ALIVE_COUNT_MAX}' >> /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "sshd -T | grep -q 'clientaliveinterval {SSH_CLIENT_ALIVE_INTERVAL}' && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# 5.2.15 - Limit SSH access
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.15",
    description="Limit SSH access to specific users/groups",
    commands=[
        "test -n '{ALLOWED_SSH_USERS}' && (grep -q '^AllowUsers' /etc/ssh/sshd_config && sed -i 's/^AllowUsers.*/AllowUsers {ALLOWED_SSH_USERS}/' /etc/ssh/sshd_config || echo 'AllowUsers {ALLOWED_SSH_USERS}' >> /etc/ssh/sshd_config) || true",
        "test -n '{ALLOWED_SSH_GROUPS}' && (grep -q '^AllowGroups' /etc/ssh/sshd_config && sed -i 's/^AllowGroups.*/AllowGroups {ALLOWED_SSH_GROUPS}/' /etc/ssh/sshd_config || echo 'AllowGroups {ALLOWED_SSH_GROUPS}' >> /etc/ssh/sshd_config) || true"
    ],
    verify_commands=[
        "grep -qE '^Allow(Users|Groups)' /etc/ssh/sshd_config && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# 5.3.1 - Configure password quality
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.3.1",
    description="Configure password quality requirements",
    commands=[
        "apt-get install -y libpam-pwquality 2>/dev/null || dnf install -y pam_pwquality 2>/dev/null || true",
        "sed -i 's/^#*minlen.*/minlen = {PASS_MIN_LEN}/' /etc/security/pwquality.conf",
        "grep -q '^minlen' /etc/security/pwquality.conf || echo 'minlen = {PASS_MIN_LEN}' >> /etc/security/pwquality.conf",
        "sed -i 's/^#*minclass.*/minclass = 4/' /etc/security/pwquality.conf",
        "grep -q '^minclass' /etc/security/pwquality.conf || echo 'minclass = 4' >> /etc/security/pwquality.conf"
    ],
    verify_commands=[
        "grep -q 'minlen = {PASS_MIN_LEN}' /etc/security/pwquality.conf && echo 'PASS' || echo 'FAIL'"
    ]
))

# 5.4.1.1 - Set password max days
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.4.1.1",
    description="Set password expiration to {PASS_MAX_DAYS} days",
    commands=[
        "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t{PASS_MAX_DAYS}/' /etc/login.defs"
    ],
    verify_commands=[
        "grep -q 'PASS_MAX_DAYS.*{PASS_MAX_DAYS}' /etc/login.defs && echo 'PASS' || echo 'FAIL'"
    ]
))

# 5.4.1.2 - Set password min days
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.4.1.2",
    description="Set minimum days between password changes",
    commands=[
        "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\\t{PASS_MIN_DAYS}/' /etc/login.defs"
    ],
    verify_commands=[
        "grep -q 'PASS_MIN_DAYS.*{PASS_MIN_DAYS}' /etc/login.defs && echo 'PASS' || echo 'FAIL'"
    ]
))

# 5.5.1 - Restrict root login
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.5.1",
    description="Restrict root login to console",
    commands=[
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config"
    ],
    verify_commands=[
        "sshd -T | grep -q 'permitrootlogin no' && echo 'PASS' || echo 'FAIL'"
    ],
    requires_service_restart="sshd"
))

# ==================== SECTION 6: SYSTEM MAINTENANCE ====================

# 6.1.1 - Set permissions on /etc/passwd
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.1",
    description="Set permissions on /etc/passwd",
    commands=[
        "chown root:root /etc/passwd",
        "chmod 644 /etc/passwd"
    ],
    verify_commands=[
        "stat -c '%a %U:%G' /etc/passwd | grep -q '644 root:root' && echo 'PASS' || echo 'FAIL'"
    ]
))


def get_linux_hardening_template(check_id: str) -> Optional[LinuxHardeningTemplate]:
    """Get hardening template for a specific check."""
    return LINUX_HARDENING_TEMPLATES.get(check_id)


def get_linux_template_commands(check_id: str, parameters: Dict[str, str] = None) -> List[str]:
    """
    Get commands for a check with parameter substitution.

    Args:
        check_id: CIS check ID
        parameters: Dict of parameter name -> value

    Returns:
        List of commands with parameters substituted
    """
    template = get_linux_hardening_template(check_id)
    if not template:
        return []

    parameters = parameters or {}
    commands = []

    for cmd in template.commands:
        # Substitute parameters
        for param_name, param_value in parameters.items():
            cmd = cmd.replace(f"{{{param_name}}}", str(param_value))
        commands.append(cmd)

    return commands


def get_linux_verify_commands(check_id: str, parameters: Dict[str, str] = None) -> List[str]:
    """Get verification commands with parameter substitution."""
    template = get_linux_hardening_template(check_id)
    if not template:
        return []

    parameters = parameters or {}
    commands = []

    for cmd in template.verify_commands:
        for param_name, param_value in parameters.items():
            cmd = cmd.replace(f"{{{param_name}}}", str(param_value))
        commands.append(cmd)

    return commands


def get_all_supported_checks() -> List[str]:
    """Get list of all checks that have hardening templates."""
    return list(LINUX_HARDENING_TEMPLATES.keys())
