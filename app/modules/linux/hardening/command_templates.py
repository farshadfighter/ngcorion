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
import copy
import re
import shlex


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
        "(systemctl is-enabled chrony 2>/dev/null || systemctl is-enabled chronyd 2>/dev/null) | grep -q enabled && echo 'PASS' || echo 'FAIL'"
    ]
))

# ==================== SECTION 3: NETWORK CONFIGURATION ====================

# 3.1.1 - Disable IP forwarding
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.1.1",
    description="Disable IP forwarding",
    commands=[
        "echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
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
        "(systemctl is-enabled cron 2>/dev/null || systemctl is-enabled crond 2>/dev/null) | grep -q enabled && echo 'PASS' || echo 'FAIL'"
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
        "sshd -T | grep -q 'clientaliveinterval {SSH_CLIENT_ALIVE_INTERVAL}' && echo 'PASS' || echo 'FAIL'",
        "sshd -T | grep -q 'clientalivecountmax {SSH_CLIENT_ALIVE_COUNT_MAX}' && echo 'PASS' || echo 'FAIL'"
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

# ==================== EXPANDED TEMPLATES ====================

# 6.1.2-6.1.9 - File Permissions for system files
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.2",
    description="Set permissions on /etc/passwd",
    commands=[
        "chown root:root /etc/passwd",
        "chmod 644 /etc/passwd"
    ],
    verify_commands=["stat -c '%a %U:%G' /etc/passwd | grep -q '644 root:root' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.3",
    description="Set permissions on /etc/shadow",
    commands=[
        "chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow",
        "chmod 640 /etc/shadow"
    ],
    verify_commands=["stat -c '%a' /etc/shadow | grep -q '640' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.4",
    description="Set permissions on /etc/group",
    commands=[
        "chown root:root /etc/group",
        "chmod 644 /etc/group"
    ],
    verify_commands=["stat -c '%a %U:%G' /etc/group | grep -q '644 root:root' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.5",
    description="Set permissions on /etc/gshadow",
    commands=[
        "chown root:shadow /etc/gshadow 2>/dev/null || chown root:root /etc/gshadow",
        "chmod 640 /etc/gshadow"
    ],
    verify_commands=["stat -c '%a' /etc/gshadow | grep -q '640' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.6",
    description="Set permissions on /etc/passwd-",
    commands=[
        "chown root:root /etc/passwd-",
        "chmod 644 /etc/passwd-"
    ],
    verify_commands=["stat -c '%a %U:%G' /etc/passwd- | grep -q '644 root:root' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.7",
    description="Set permissions on /etc/shadow-",
    commands=[
        "chown root:shadow /etc/shadow- 2>/dev/null || chown root:root /etc/shadow-",
        "chmod 640 /etc/shadow-"
    ],
    verify_commands=["stat -c '%a' /etc/shadow- | grep -q '640' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.8",
    description="Set permissions on /etc/group-",
    commands=[
        "chown root:root /etc/group-",
        "chmod 644 /etc/group-"
    ],
    verify_commands=["stat -c '%a %U:%G' /etc/group- | grep -q '644 root:root' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-6.1.9",
    description="Set permissions on /etc/gshadow-",
    commands=[
        "chown root:shadow /etc/gshadow- 2>/dev/null || chown root:root /etc/gshadow-",
        "chmod 640 /etc/gshadow-"
    ],
    verify_commands=["stat -c '%a' /etc/gshadow- | grep -q '640' && echo 'PASS' || echo 'FAIL'"]
))

# 3.3.1-3.3.3 - IPv6 Hardening
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.3.1",
    description="Disable IPv6 router advertisements",
    commands=[
        "echo 'net.ipv6.conf.all.accept_ra = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf",
        "echo 'net.ipv6.conf.default.accept_ra = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf",
        "sysctl -w net.ipv6.conf.all.accept_ra=0",
        "sysctl -w net.ipv6.conf.default.accept_ra=0"
    ],
    verify_commands=["sysctl net.ipv6.conf.all.accept_ra | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.3.2",
    description="Disable IPv6 redirects",
    commands=[
        "echo 'net.ipv6.conf.all.accept_redirects = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf",
        "echo 'net.ipv6.conf.default.accept_redirects = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf",
        "sysctl -w net.ipv6.conf.all.accept_redirects=0",
        "sysctl -w net.ipv6.conf.default.accept_redirects=0"
    ],
    verify_commands=["sysctl net.ipv6.conf.all.accept_redirects | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-3.3.3",
    description="Disable IPv6",
    commands=[
        "echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.d/60-netipv6_sysctl.conf",
        "echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.d/60-netipv6_sysctl.conf",
        "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
        "sysctl -w net.ipv6.conf.default.disable_ipv6=1"
    ],
    verify_commands=["sysctl net.ipv6.conf.all.disable_ipv6 | grep -q '= 1' && echo 'PASS' || echo 'FAIL'"]
))

# 4.2.3.x - Audit Rules
_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.1",
    description="Configure audit rules for time changes",
    commands=[
        "cat >> /etc/audit/rules.d/time-change.rules << 'EOF'\n-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change\n-a always,exit -F arch=b64 -S clock_settime -k time-change\n-a always,exit -F arch=b32 -S clock_settime -k time-change\n-w /etc/localtime -p wa -k time-change\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'time-change' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.2",
    description="Configure audit rules for identity changes",
    commands=[
        "cat >> /etc/audit/rules.d/identity.rules << 'EOF'\n-w /etc/group -p wa -k identity\n-w /etc/passwd -p wa -k identity\n-w /etc/gshadow -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/security/opasswd -p wa -k identity\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'identity' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.3",
    description="Configure audit rules for system locale changes",
    commands=[
        "cat >> /etc/audit/rules.d/system-locale.rules << 'EOF'\n-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale\n-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale\n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale\n-w /etc/hostname -p wa -k system-locale\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'system-locale' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.4",
    description="Configure audit rules for MAC policy changes",
    commands=[
        "cat >> /etc/audit/rules.d/MAC-policy.rules << 'EOF'\n-w /etc/apparmor/ -p wa -k MAC-policy\n-w /etc/apparmor.d/ -p wa -k MAC-policy\n-w /etc/selinux/ -p wa -k MAC-policy\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'MAC-policy' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.5",
    description="Configure audit rules for login events",
    commands=[
        "cat >> /etc/audit/rules.d/logins.rules << 'EOF'\n-w /var/log/faillog -p wa -k logins\n-w /var/log/lastlog -p wa -k logins\n-w /var/log/tallylog -p wa -k logins\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'logins' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.6",
    description="Configure audit rules for session events",
    commands=[
        "cat >> /etc/audit/rules.d/session.rules << 'EOF'\n-w /var/run/utmp -p wa -k session\n-w /var/log/wtmp -p wa -k session\n-w /var/log/btmp -p wa -k session\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'session' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.7",
    description="Configure audit rules for permission changes",
    commands=[
        "cat >> /etc/audit/rules.d/perm-mod.rules << 'EOF'\n-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\n-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'perm_mod' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L2-4.2.3.11",
    description="Configure audit rules for sudo changes",
    commands=[
        "cat >> /etc/audit/rules.d/scope.rules << 'EOF'\n-w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d/ -p wa -k scope\nEOF",
        "augenrules --load 2>/dev/null || service auditd reload"
    ],
    verify_commands=["auditctl -l | grep -q 'scope' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="auditd"
))

# 5.1.2-5.1.5 - Cron Access Control
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.1.2",
    description="Set permissions on /etc/crontab",
    commands=[
        "chown root:root /etc/crontab",
        "chmod 600 /etc/crontab"
    ],
    verify_commands=["stat -c '%a %U:%G' /etc/crontab | grep -q '600 root:root' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.1.3",
    description="Set permissions on /etc/cron.hourly",
    commands=[
        "chown root:root /etc/cron.hourly",
        "chmod 700 /etc/cron.hourly"
    ],
    verify_commands=["stat -c '%a %U:%G' /etc/cron.hourly | grep -q '700 root:root' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.1.4",
    description="Set permissions on /etc/cron.d",
    commands=[
        "chown root:root /etc/cron.d",
        "chmod 700 /etc/cron.d"
    ],
    verify_commands=["stat -c '%a %U:%G' /etc/cron.d | grep -q '700 root:root' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.1.5",
    description="Restrict cron to authorized users",
    commands=[
        "rm -f /etc/cron.deny",
        "echo 'root' > /etc/cron.allow",
        "chown root:root /etc/cron.allow",
        "chmod 640 /etc/cron.allow"
    ],
    verify_commands=["test -f /etc/cron.allow && echo 'PASS' || echo 'FAIL'"]
))

# 5.3.3 - PAM Faillock
# Note: The distro-aware template function will transform /etc/pam.d/common-auth
# to /etc/pam.d/password-auth for RHEL-based systems
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.3.3",
    description="Configure PAM faillock for brute force protection",
    commands=[
        "apt-get install -y libpam-modules 2>/dev/null || dnf install -y pam 2>/dev/null || true",
        "cat > /etc/security/faillock.conf << 'EOF'\ndenial = {FAILLOCK_DENY}\nunlock_time = {FAILLOCK_UNLOCK_TIME}\nfail_interval = 900\naudit\nsilent\nEOF",
        "grep -q 'pam_faillock' /etc/pam.d/common-auth || sed -i '/pam_unix.so/i auth required pam_faillock.so preauth' /etc/pam.d/common-auth"
    ],
    verify_commands=["test -f /etc/security/faillock.conf && echo 'PASS' || echo 'FAIL'"]
))

# 5.2.14-5.2.19 - Additional SSH settings
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.14",
    description="Configure SSH warning banner",
    commands=[
        "cat > /etc/ssh/banner << 'EOF'\n{SSH_BANNER_TEXT}\nEOF",
        "sed -i 's/^#*Banner.*/Banner \\/etc\\/ssh\\/banner/' /etc/ssh/sshd_config",
        "grep -q '^Banner' /etc/ssh/sshd_config || echo 'Banner /etc/ssh/banner' >> /etc/ssh/sshd_config"
    ],
    verify_commands=["test -f /etc/ssh/banner && sshd -T | grep -q 'banner /etc/ssh/banner' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="sshd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.15b",
    description="Disable SSH TCP forwarding",
    commands=[
        "sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config",
        "grep -q '^AllowTcpForwarding' /etc/ssh/sshd_config || echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config"
    ],
    verify_commands=["sshd -T | grep -q 'allowtcpforwarding no' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="sshd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.16",
    description="Configure SSH MaxStartups",
    commands=[
        "sed -i 's/^#*MaxStartups.*/MaxStartups {SSH_MAX_STARTUPS}/' /etc/ssh/sshd_config",
        "grep -q '^MaxStartups' /etc/ssh/sshd_config || echo 'MaxStartups {SSH_MAX_STARTUPS}' >> /etc/ssh/sshd_config"
    ],
    verify_commands=["sshd -T | grep -q 'maxstartups' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="sshd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.17",
    description="Configure SSH MaxSessions",
    commands=[
        "sed -i 's/^#*MaxSessions.*/MaxSessions {SSH_MAX_SESSIONS}/' /etc/ssh/sshd_config",
        "grep -q '^MaxSessions' /etc/ssh/sshd_config || echo 'MaxSessions {SSH_MAX_SESSIONS}' >> /etc/ssh/sshd_config"
    ],
    verify_commands=["sshd -T | grep -q 'maxsessions' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="sshd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.18",
    description="Configure SSH LoginGraceTime",
    commands=[
        "sed -i 's/^#*LoginGraceTime.*/LoginGraceTime {SSH_LOGIN_GRACE_TIME}/' /etc/ssh/sshd_config",
        "grep -q '^LoginGraceTime' /etc/ssh/sshd_config || echo 'LoginGraceTime {SSH_LOGIN_GRACE_TIME}' >> /etc/ssh/sshd_config"
    ],
    verify_commands=["sshd -T | grep -q 'logingracetime' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="sshd"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.2.19",
    description="Enable SSH PAM",
    commands=[
        "sed -i 's/^#*UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config",
        "grep -q '^UsePAM' /etc/ssh/sshd_config || echo 'UsePAM yes' >> /etc/ssh/sshd_config"
    ],
    verify_commands=["sshd -T | grep -q 'usepam yes' && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="sshd"
))

# 5.4.1.3-5.4.1.5 - Account Policy
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.4.1.3",
    description="Set password warning age",
    commands=[
        "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\\t{PASS_WARN_AGE}/' /etc/login.defs"
    ],
    verify_commands=["grep -q 'PASS_WARN_AGE.*{PASS_WARN_AGE}' /etc/login.defs && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.4.1.4",
    description="Set inactive password lock",
    commands=[
        "useradd -D -f {INACTIVE_DAYS}"
    ],
    verify_commands=["useradd -D | grep -q 'INACTIVE={INACTIVE_DAYS}' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.4.1.5",
    description="Set default UMASK",
    commands=[
        "sed -i 's/^UMASK.*/UMASK\\t{UMASK_VALUE}/' /etc/login.defs"
    ],
    verify_commands=["grep -q 'UMASK.*{UMASK_VALUE}' /etc/login.defs && echo 'PASS' || echo 'FAIL'"]
))

# 1.1.8.x - Mount Options
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.1.8.1",
    description="Set nodev option on /tmp",
    commands=[
        "sed -i '/\\/tmp/s/defaults/defaults,nodev/' /etc/fstab",
        "mount -o remount,nodev /tmp 2>/dev/null || true"
    ],
    verify_commands=["mount | grep '/tmp' | grep -q 'nodev' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.1.8.2",
    description="Set nosuid option on /tmp",
    commands=[
        "sed -i '/\\/tmp/s/defaults/defaults,nosuid/' /etc/fstab",
        "mount -o remount,nosuid /tmp 2>/dev/null || true"
    ],
    verify_commands=["mount | grep '/tmp' | grep -q 'nosuid' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.1.8.3",
    description="Set noexec option on /tmp",
    commands=[
        "sed -i '/\\/tmp/s/defaults/defaults,noexec/' /etc/fstab",
        "mount -o remount,noexec /tmp 2>/dev/null || true"
    ],
    verify_commands=["mount | grep '/tmp' | grep -q 'noexec' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.1.8.4",
    description="Set nodev option on /dev/shm",
    commands=[
        "grep -q '/dev/shm' /etc/fstab && sed -i '/\\/dev\\/shm/s/defaults/defaults,nodev/' /etc/fstab || echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab",
        "mount -o remount,nodev /dev/shm 2>/dev/null || true"
    ],
    verify_commands=["mount | grep '/dev/shm' | grep -q 'nodev' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.1.8.5",
    description="Set nosuid option on /dev/shm",
    commands=[
        "grep -q '/dev/shm' /etc/fstab && sed -i '/\\/dev\\/shm/s/defaults/defaults,nosuid/' /etc/fstab || echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab",
        "mount -o remount,nosuid /dev/shm 2>/dev/null || true"
    ],
    verify_commands=["mount | grep '/dev/shm' | grep -q 'nosuid' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.1.8.6",
    description="Set noexec option on /dev/shm",
    commands=[
        "grep -q '/dev/shm' /etc/fstab && sed -i '/\\/dev\\/shm/s/defaults/defaults,noexec/' /etc/fstab || echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab",
        "mount -o remount,noexec /dev/shm 2>/dev/null || true"
    ],
    verify_commands=["mount | grep '/dev/shm' | grep -q 'noexec' && echo 'PASS' || echo 'FAIL'"]
))

# 4.1.1.2-4.1.1.4 - Journald Configuration
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-4.1.1.2",
    description="Enable journald compression",
    commands=[
        "sed -i 's/^#*Compress=.*/Compress=yes/' /etc/systemd/journald.conf",
        "grep -q '^Compress=' /etc/systemd/journald.conf || echo 'Compress=yes' >> /etc/systemd/journald.conf",
        "systemctl restart systemd-journald"
    ],
    verify_commands=["grep -q '^Compress=yes' /etc/systemd/journald.conf && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="systemd-journald"
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-4.1.1.3",
    description="Configure journald persistent storage",
    commands=[
        "sed -i 's/^#*Storage=.*/Storage=persistent/' /etc/systemd/journald.conf",
        "grep -q '^Storage=' /etc/systemd/journald.conf || echo 'Storage=persistent' >> /etc/systemd/journald.conf",
        "mkdir -p /var/log/journal",
        "systemctl restart systemd-journald"
    ],
    verify_commands=["grep -q '^Storage=persistent' /etc/systemd/journald.conf && echo 'PASS' || echo 'FAIL'"],
    requires_service_restart="systemd-journald"
))

# 3.2.3, 3.2.6 - Network Parameters
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.3",
    description="Disable secure ICMP redirects",
    commands=[
        "echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "echo 'net.ipv4.conf.default.secure_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.conf.all.secure_redirects=0",
        "sysctl -w net.ipv4.conf.default.secure_redirects=0"
    ],
    verify_commands=["sysctl net.ipv4.conf.all.secure_redirects | grep -q '= 0' && echo 'PASS' || echo 'FAIL'"]
))

_register(LinuxHardeningTemplate(
    check_id="LNX-L1-3.2.6",
    description="Ignore bogus ICMP responses",
    commands=[
        "echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf",
        "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ],
    verify_commands=["sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -q '= 1' && echo 'PASS' || echo 'FAIL'"]
))

# 5.3.2 - Password History
# Note: The distro-aware template function will transform /etc/pam.d/common-password
# to /etc/pam.d/system-auth for RHEL-based systems
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.3.2",
    description="Configure password reuse limit",
    commands=[
        "apt-get install -y libpam-pwquality 2>/dev/null || dnf install -y pam_pwquality 2>/dev/null || true",
        "grep -q 'pam_pwhistory' /etc/pam.d/common-password || sed -i '/pam_unix.so/a password required pam_pwhistory.so remember={PASS_REMEMBER} use_authtok' /etc/pam.d/common-password"
    ],
    verify_commands=["grep -qE 'pam_pwhistory|remember=' /etc/pam.d/common-password && echo 'PASS' || echo 'FAIL'"]
))

# 5.6 - Su restriction
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-5.6",
    description="Restrict su command to wheel group",
    commands=[
        "groupadd wheel 2>/dev/null || true",
        "sed -i 's/^#.*pam_wheel.so$/auth required pam_wheel.so use_uid/' /etc/pam.d/su",
        "grep -q '^auth.*pam_wheel.so' /etc/pam.d/su || echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su"
    ],
    verify_commands=["grep -q 'pam_wheel.so' /etc/pam.d/su && echo 'PASS' || echo 'FAIL'"]
))

# 1.6.3 - Remote login banner
_register(LinuxHardeningTemplate(
    check_id="LNX-L1-1.6.3",
    description="Configure remote login warning banner",
    commands=[
        "cat > /etc/issue.net << 'EOF'\n{BANNER_TEXT}\nEOF",
        "chmod 644 /etc/issue.net"
    ],
    verify_commands=["test -s /etc/issue.net && echo 'PASS' || echo 'FAIL'"]
))


# ==================== RHEL-SPECIFIC HARDENING TEMPLATES ====================
# Templates for RHEL-specific CIS checks (LNX-RHEL-L1-* and LNX-RHEL-L2-*)
# These apply to RHEL-based distros: rhel, rocky, centos, fedora, almalinux

_RHEL_DISTROS = ["rhel", "rocky", "centos", "fedora", "almalinux"]

# LNX-RHEL-L1-1.2.3 - Ensure gpgcheck is globally activated
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.2.3",
    description="Ensure gpgcheck is globally activated",
    commands=[
        "sed -i 's/^gpgcheck=.*/gpgcheck=1/' /etc/dnf/dnf.conf",
        "grep -q '^gpgcheck' /etc/dnf/dnf.conf || echo 'gpgcheck=1' >> /etc/dnf/dnf.conf",
        "for f in /etc/yum.repos.d/*.repo; do sed -i 's/^gpgcheck=.*/gpgcheck=1/' \"$f\"; done"
    ],
    verify_commands=[
        "grep -q '^gpgcheck=1' /etc/dnf/dnf.conf && echo 'PASS' || echo 'FAIL'",
        "grep -rq 'gpgcheck=0' /etc/yum.repos.d/ && echo 'FAIL' || echo 'PASS'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.2.4 - Ensure crypto policies are not LEGACY
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.2.4",
    description="Ensure system-wide crypto policy is not LEGACY",
    commands=[
        "update-crypto-policies --set {CRYPTO_POLICY}"
    ],
    verify_commands=[
        "update-crypto-policies --show | grep -qiE 'DEFAULT|FUTURE|FIPS' && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.2.5 - Ensure crypto policies don't use SHA1
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.2.5",
    description="Ensure system-wide crypto policy disables SHA1 in certificate verification",
    commands=[
        "update-crypto-policies --set {CRYPTO_POLICY}",
        "update-crypto-policies"
    ],
    verify_commands=[
        "update-crypto-policies --show | grep -qi 'LEGACY' && echo 'FAIL' || echo 'PASS'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.3.1 - Ensure sudo is installed
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.3.1",
    description="Ensure sudo is installed",
    commands=[
        "dnf install -y sudo"
    ],
    verify_commands=[
        "rpm -q sudo >/dev/null 2>&1 && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.3.2 - Ensure sudo uses pty
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.3.2",
    description="Ensure sudo commands use pty",
    commands=[
        "grep -q '^Defaults.*use_pty' /etc/sudoers || echo 'Defaults use_pty' >> /etc/sudoers.d/99-cis-use-pty",
        "chmod 440 /etc/sudoers.d/99-cis-use-pty 2>/dev/null || true"
    ],
    verify_commands=[
        "grep -rqE '^Defaults.*use_pty' /etc/sudoers /etc/sudoers.d/ && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.3.3 - Ensure sudo log file exists
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.3.3",
    description="Ensure sudo log file is configured",
    commands=[
        "grep -q '^Defaults.*logfile=' /etc/sudoers || echo 'Defaults logfile=\"/var/log/sudo.log\"' >> /etc/sudoers.d/99-cis-sudo-log",
        "chmod 440 /etc/sudoers.d/99-cis-sudo-log 2>/dev/null || true"
    ],
    verify_commands=[
        "grep -rqE '^Defaults.*logfile=' /etc/sudoers /etc/sudoers.d/ && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.4.2 - Ensure bootloader password is set (MANUAL)
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.4.2",
    description="Ensure bootloader password is set (manual - requires interactive grub2-setpassword)",
    commands=[
        "echo 'MANUAL: Run grub2-setpassword interactively to set the bootloader password'",
        "echo 'Then run: grub2-mkconfig -o /boot/grub2/grub.cfg'"
    ],
    verify_commands=[
        "test -f /boot/grub2/user.cfg && grep -q '^GRUB2_PASSWORD=' /boot/grub2/user.cfg && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.6.1 - Ensure SELinux is installed
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.6.1",
    description="Ensure SELinux is installed",
    commands=[
        "dnf install -y libselinux"
    ],
    verify_commands=[
        "rpm -q libselinux >/dev/null 2>&1 && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.6.3 - Ensure SELinux policy is configured
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.6.3",
    description="Ensure SELinux policy is configured",
    commands=[
        "sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE={SELINUX_POLICY_TYPE}/' /etc/selinux/config",
        "grep -q '^SELINUXTYPE=' /etc/selinux/config || echo 'SELINUXTYPE={SELINUX_POLICY_TYPE}' >> /etc/selinux/config"
    ],
    verify_commands=[
        "grep -q '^SELINUXTYPE={SELINUX_POLICY_TYPE}' /etc/selinux/config && echo 'PASS' || echo 'FAIL'"
    ],
    requires_reboot=True,
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.6.5 - Ensure SELinux mode is enforcing
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.6.5",
    description="Ensure SELinux mode is set to enforcing",
    commands=[
        "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
        "grep -q '^SELINUX=' /etc/selinux/config || echo 'SELINUX=enforcing' >> /etc/selinux/config",
        "setenforce 1 2>/dev/null || true"
    ],
    verify_commands=[
        "getenforce | grep -qi 'enforcing' && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.6.6 - Ensure no unconfined services (MANUAL)
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.6.6",
    description="Ensure no unconfined services exist (manual review required)",
    commands=[
        "echo 'MANUAL REVIEW: Check output of the following command for unconfined services:'",
        "ps -eZ | grep unconfined_service_t || echo 'No unconfined services found'"
    ],
    verify_commands=[
        "ps -eZ | grep -q 'unconfined_service_t' && echo 'FAIL' || echo 'PASS'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.6.7 - Ensure SETroubleshoot is not installed
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.6.7",
    description="Ensure SETroubleshoot is not installed",
    commands=[
        "dnf remove -y setroubleshoot 2>/dev/null || true"
    ],
    verify_commands=[
        "rpm -q setroubleshoot >/dev/null 2>&1 && echo 'FAIL' || echo 'PASS'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-1.6.8 - Ensure mcstrans is not installed
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-1.6.8",
    description="Ensure mcstrans is not installed",
    commands=[
        "dnf remove -y mcstrans 2>/dev/null || true"
    ],
    verify_commands=[
        "rpm -q mcstrans >/dev/null 2>&1 && echo 'FAIL' || echo 'PASS'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-5.3.1.1 - Ensure minimum password length (pwquality)
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-5.3.1.1",
    description="Ensure password minimum length is configured via pwquality",
    commands=[
        "dnf install -y libpwquality 2>/dev/null || true",
        "sed -i 's/^#*\\s*minlen.*/minlen = {PWQUALITY_MINLEN}/' /etc/security/pwquality.conf",
        "grep -q '^minlen' /etc/security/pwquality.conf || echo 'minlen = {PWQUALITY_MINLEN}' >> /etc/security/pwquality.conf"
    ],
    verify_commands=[
        "grep -qE '^minlen\\s*=\\s*{PWQUALITY_MINLEN}' /etc/security/pwquality.conf && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-5.3.3 - Ensure pam faillock is configured
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-5.3.3",
    description="Ensure pam faillock module is configured",
    commands=[
        "cat > /etc/security/faillock.conf << 'EOF'\ndeny = {FAILLOCK_DENY}\nunlock_time = {FAILLOCK_UNLOCK_TIME}\nfail_interval = 900\naudit\nsilent\nEOF",
        "authselect enable-feature with-faillock 2>/dev/null || true"
    ],
    verify_commands=[
        "test -f /etc/security/faillock.conf && grep -q '^deny' /etc/security/faillock.conf && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-5.3.4 - Ensure authselect is configured
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-5.3.4",
    description="Ensure authselect profile is selected and configured",
    commands=[
        "authselect select {AUTHSELECT_PROFILE} --force 2>/dev/null || authselect select sssd --force"
    ],
    verify_commands=[
        "authselect current 2>/dev/null | grep -q 'Profile ID' && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L1-5.3.5 - Ensure pam_tally2 is not used
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L1-5.3.5",
    description="Ensure pam_tally2 is not used (replaced by faillock)",
    commands=[
        "sed -i '/pam_tally2/d' /etc/pam.d/system-auth 2>/dev/null || true",
        "sed -i '/pam_tally2/d' /etc/pam.d/password-auth 2>/dev/null || true"
    ],
    verify_commands=[
        "grep -rq 'pam_tally2' /etc/pam.d/ && echo 'FAIL' || echo 'PASS'"
    ],
    distros=_RHEL_DISTROS
))

# LNX-RHEL-L2-5.4.2 - Ensure system accounts are non-interactive (MANUAL)
_register(LinuxHardeningTemplate(
    check_id="LNX-RHEL-L2-5.4.2",
    description="Ensure system accounts are secured (manual review required)",
    commands=[
        "echo 'MANUAL REVIEW: Verify system accounts have nologin shell and are locked'",
        "awk -F: '($3 < 1000 && $1 != \"root\" && $1 != \"sync\" && $1 != \"shutdown\" && $1 != \"halt\" && $7 !~ /nologin|false/) {print $1}' /etc/passwd"
    ],
    verify_commands=[
        "awk -F: '($3 < 1000 && $1 != \"root\" && $1 != \"sync\" && $1 != \"shutdown\" && $1 != \"halt\" && $7 !~ /nologin|false/) {print}' /etc/passwd | wc -l | grep -q '^0$' && echo 'PASS' || echo 'FAIL'"
    ],
    distros=_RHEL_DISTROS
))


def get_linux_hardening_template(check_id: str) -> Optional[LinuxHardeningTemplate]:
    """Get hardening template for a specific check."""
    return LINUX_HARDENING_TEMPLATES.get(check_id)


# ==================== DISTRO-AWARE TEMPLATE HELPERS ====================

def get_distro_pam_paths(distro_id: str) -> Dict[str, str]:
    """
    Get distro-specific PAM file paths.

    Args:
        distro_id: Distribution ID (ubuntu, rocky, rhel, etc.)

    Returns:
        Dict with 'password' and 'auth' PAM file paths
    """
    is_debian = distro_id in ("ubuntu", "debian")
    if is_debian:
        return {
            "password": "/etc/pam.d/common-password",
            "auth": "/etc/pam.d/common-auth",
        }
    else:
        # RHEL-based: Rocky, CentOS, RHEL, AlmaLinux, Fedora
        return {
            "password": "/etc/pam.d/system-auth",
            "auth": "/etc/pam.d/password-auth",
        }


def get_distro_service_name(service: str, distro_id: str) -> str:
    """
    Get distro-specific service name.

    Args:
        service: Generic service name (cron, httpd)
        distro_id: Distribution ID

    Returns:
        Distro-specific service name
    """
    is_debian = distro_id in ("ubuntu", "debian")
    service_map = {
        ("cron", True): "cron",
        ("cron", False): "crond",
        ("httpd", True): "apache2",
        ("httpd", False): "httpd",
        ("chrony", True): "chrony",
        ("chrony", False): "chronyd",
        # OpenSSH server unit: ssh.service on Debian/Ubuntu, sshd.service on RHEL
        ("sshd", True): "ssh",
        ("sshd", False): "sshd",
        # Samba file-server unit: smbd.service on Debian/Ubuntu, smb.service on RHEL
        ("smb", True): "smbd",
        ("smb", False): "smb",
    }
    return service_map.get((service, is_debian), service)


# systemctl subcommands whose following argument is a unit (service) name.
_SYSTEMCTL_VERBS = (
    "start", "stop", "restart", "reload", "try-restart", "reload-or-restart",
    "enable", "disable", "mask", "unmask", "is-enabled", "is-active", "status",
)
# Matches the unit argument of a systemctl call (skipping any --flags), so that
# only real service names are rewritten — never path-like tokens such as
# /etc/cron.daily or files referenced elsewhere in a command.
_SERVICE_ARG_RE = re.compile(
    r"(systemctl\s+(?:--[\w=.-]+\s+)*(?:" + "|".join(_SYSTEMCTL_VERBS) + r")\s+)([\w@.:-]+)"
)


def _remap_service_names(cmd: str, distro_id: str) -> str:
    """
    Rewrite distro-variant service names in the unit argument of systemctl
    commands (e.g. ``systemctl disable httpd`` -> ``systemctl disable apache2``
    on Debian/Ubuntu). Unknown services are left unchanged.
    """
    return _SERVICE_ARG_RE.sub(
        lambda m: m.group(1) + get_distro_service_name(m.group(2), distro_id),
        cmd,
    )


def get_distro_mac_paths(distro_id: str) -> List[str]:
    """
    Get distro-specific MAC (Mandatory Access Control) paths.

    Args:
        distro_id: Distribution ID

    Returns:
        List of MAC-related paths for audit rules
    """
    is_debian = distro_id in ("ubuntu", "debian")
    if is_debian:
        return ["/etc/apparmor/", "/etc/apparmor.d/"]
    else:
        return ["/etc/selinux/"]


def get_linux_hardening_template_for_distro(
    check_id: str,
    distro_id: str = "ubuntu"
) -> Optional[LinuxHardeningTemplate]:
    """
    Get hardening template with distro-specific commands.

    This transforms generic templates into distro-specific ones by:
    - Replacing PAM file paths (common-password -> system-auth for RHEL-based)
    - Replacing MAC paths (AppArmor -> SELinux for RHEL-based)
    - Adjusting service names (cron -> crond for RHEL-based)

    Args:
        check_id: CIS check ID
        distro_id: Distribution ID (ubuntu, rocky, rhel, etc.)

    Returns:
        LinuxHardeningTemplate with distro-specific commands, or None if not found
    """
    template = LINUX_HARDENING_TEMPLATES.get(check_id)
    if not template:
        return None

    pam_paths = get_distro_pam_paths(distro_id)
    is_debian = distro_id in ("ubuntu", "debian")

    # Special handling for MAC policy rules (LNX-L2-4.2.3.4)
    if check_id == "LNX-L2-4.2.3.4":
        mac_paths = get_distro_mac_paths(distro_id)
        mac_rules = "\n".join([f"-w {path} -p wa -k MAC-policy" for path in mac_paths])
        return LinuxHardeningTemplate(
            check_id=template.check_id,
            description=template.description,
            commands=[
                f"cat > /etc/audit/rules.d/MAC-policy.rules << 'EOF'\n{mac_rules}\nEOF",
                "augenrules --load 2>/dev/null || service auditd reload"
            ],
            requires_reboot=template.requires_reboot,
            verify_commands=template.verify_commands.copy(),
            distros=template.distros.copy(),
            requires_service_restart=template.requires_service_restart
        )

    # Transform commands based on distro
    transformed_commands = []
    for cmd in template.commands:
        new_cmd = cmd
        if not is_debian:
            # RHEL-based: Replace Debian PAM paths with RHEL paths
            new_cmd = new_cmd.replace("/etc/pam.d/common-password", pam_paths["password"])
            new_cmd = new_cmd.replace("/etc/pam.d/common-auth", pam_paths["auth"])
        # Rewrite distro-variant service names (e.g. httpd -> apache2 on Debian)
        new_cmd = _remap_service_names(new_cmd, distro_id)
        transformed_commands.append(new_cmd)

    # Transform verify commands
    transformed_verify = []
    for cmd in template.verify_commands:
        new_cmd = cmd
        if not is_debian:
            new_cmd = new_cmd.replace("/etc/pam.d/common-password", pam_paths["password"])
            new_cmd = new_cmd.replace("/etc/pam.d/common-auth", pam_paths["auth"])
        new_cmd = _remap_service_names(new_cmd, distro_id)
        transformed_verify.append(new_cmd)

    # The executor restarts requires_service_restart via `systemctl restart <svc>`,
    # so it needs the distro-specific unit name too (e.g. sshd -> ssh on Debian).
    restart_service = template.requires_service_restart
    if restart_service:
        restart_service = get_distro_service_name(restart_service, distro_id)

    return LinuxHardeningTemplate(
        check_id=template.check_id,
        description=template.description,
        commands=transformed_commands,
        requires_reboot=template.requires_reboot,
        verify_commands=transformed_verify,
        distros=template.distros.copy() if template.distros else ["all"],
        requires_service_restart=restart_service
    )


# Parameters whose value is inserted into a quoted heredoc body (cat << 'EOF').
# These must NOT be shell-quoted: shlex.quote would wrap the literal text in
# stray single quotes inside the heredoc.
_HEREDOC_PARAMS = {"MOTD_TEXT", "BANNER_TEXT"}


def _substitute_params(cmd: str, parameters: Dict[str, str]) -> str:
    """
    Substitute {PARAM} placeholders in a command string.

    Values are shell-quoted with shlex.quote for injection safety, except
    heredoc-body parameters (see _HEREDOC_PARAMS) which are inserted literally.
    """
    for param_name, param_value in parameters.items():
        value = str(param_value)
        if param_name not in _HEREDOC_PARAMS:
            value = shlex.quote(value)
        cmd = cmd.replace(f"{{{param_name}}}", value)
    return cmd


def get_linux_template_commands_for_distro(
    check_id: str,
    distro_id: str = "ubuntu",
    parameters: Dict[str, str] = None
) -> List[str]:
    """
    Get commands for a check with distro-specific paths and parameter substitution.

    Args:
        check_id: CIS check ID
        distro_id: Distribution ID
        parameters: Dict of parameter name -> value

    Returns:
        List of commands with distro paths and parameters substituted
    """
    template = get_linux_hardening_template_for_distro(check_id, distro_id)
    if not template:
        return []

    parameters = parameters or {}
    commands = []

    for cmd in template.commands:
        # Substitute parameters
        cmd = _substitute_params(cmd, parameters)
        commands.append(cmd)

    return commands


def get_linux_verify_commands_for_distro(
    check_id: str,
    distro_id: str = "ubuntu",
    parameters: Dict[str, str] = None
) -> List[str]:
    """
    Get verification commands with distro-specific paths and parameter substitution.

    Args:
        check_id: CIS check ID
        distro_id: Distribution ID
        parameters: Dict of parameter name -> value

    Returns:
        List of verification commands with distro paths and parameters substituted
    """
    template = get_linux_hardening_template_for_distro(check_id, distro_id)
    if not template:
        return []

    parameters = parameters or {}
    commands = []

    for cmd in template.verify_commands:
        cmd = _substitute_params(cmd, parameters)
        commands.append(cmd)

    return commands


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
        cmd = _substitute_params(cmd, parameters)
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
        cmd = _substitute_params(cmd, parameters)
        commands.append(cmd)

    return commands


def get_all_supported_checks() -> List[str]:
    """Get list of all checks that have hardening templates."""
    return list(LINUX_HARDENING_TEMPLATES.keys())
