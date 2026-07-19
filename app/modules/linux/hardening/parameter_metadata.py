"""
Linux Hardening Parameter Metadata

Defines UI metadata for each hardening parameter used in command templates.
This metadata is used to generate dynamic forms in the frontend.

Each parameter includes:
- type: Input type (password, text, textarea, number, ip, select)
- label: Display name for the form field
- description: Help text/tooltip
- placeholder: Example value
- validation: Validation rules (optional)
- default: Default value (optional)
- options: Choices for select type (optional)
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ParameterMetadata:
    """Metadata for a single hardening parameter."""
    name: str
    input_type: str  # password, text, textarea, number, ip, select
    label: str
    description: str
    required: bool = True
    default: Optional[str] = None
    placeholder: Optional[str] = None
    validation: Optional[str] = None
    options: Optional[List[str]] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None


# Parameter registry - all known parameters and their UI metadata
LINUX_PARAMETER_REGISTRY: Dict[str, ParameterMetadata] = {
    # ==================== NETWORK CONFIGURATION ====================
    "SYSLOG_SERVER": ParameterMetadata(
        name="SYSLOG_SERVER",
        input_type="ip",
        label="Syslog Server IP",
        description="IP address of central syslog server for remote logging",
        required=True,
        placeholder="192.168.1.100"
    ),

    "NTP_SERVER": ParameterMetadata(
        name="NTP_SERVER",
        input_type="ip",
        label="NTP Server IP",
        description="IP address of NTP time server",
        required=True,
        placeholder="pool.ntp.org"
    ),

    "ALLOWED_SSH_USERS": ParameterMetadata(
        name="ALLOWED_SSH_USERS",
        input_type="text",
        label="Allowed SSH Users",
        description="Space-separated list of users allowed to SSH (AllowUsers)",
        required=False,
        placeholder="admin deploy operator",
        default=""
    ),

    "ALLOWED_SSH_GROUPS": ParameterMetadata(
        name="ALLOWED_SSH_GROUPS",
        input_type="text",
        label="Allowed SSH Groups",
        description="Space-separated list of groups allowed to SSH (AllowGroups)",
        required=False,
        placeholder="sshusers wheel",
        default=""
    ),

    # ==================== BANNER TEXT ====================
    "BANNER_TEXT": ParameterMetadata(
        name="BANNER_TEXT",
        input_type="textarea",
        label="Warning Banner",
        description="Warning/legal banner text displayed to users",
        required=True,
        placeholder="Authorized users only. All activity is monitored and logged.",
        validation="min_length:10"
    ),

    "MOTD_TEXT": ParameterMetadata(
        name="MOTD_TEXT",
        input_type="textarea",
        label="MOTD Message",
        description="Message of the day displayed after login",
        required=False,
        placeholder="Welcome to this system. Unauthorized access is prohibited.",
        default="Authorized access only. All activity is monitored and logged."
    ),

    # ==================== PASSWORD POLICY ====================
    "PASS_MAX_DAYS": ParameterMetadata(
        name="PASS_MAX_DAYS",
        input_type="number",
        label="Password Max Age (days)",
        description="Maximum days before password must be changed",
        required=False,
        default="365",
        min_value=1,
        max_value=365
    ),

    "PASS_MIN_DAYS": ParameterMetadata(
        name="PASS_MIN_DAYS",
        input_type="number",
        label="Password Min Age (days)",
        description="Minimum days before password can be changed",
        required=False,
        default="1",
        min_value=0,
        max_value=7
    ),

    "PASS_WARN_AGE": ParameterMetadata(
        name="PASS_WARN_AGE",
        input_type="number",
        label="Password Warning Age (days)",
        description="Days before expiry to warn user",
        required=False,
        default="7",
        min_value=1,
        max_value=30
    ),

    "PASS_MIN_LEN": ParameterMetadata(
        name="PASS_MIN_LEN",
        input_type="number",
        label="Minimum Password Length",
        description="Minimum password length requirement",
        required=False,
        default="14",
        min_value=8,
        max_value=128
    ),

    # ==================== SSH CONFIGURATION ====================
    "SSH_MAX_AUTH_TRIES": ParameterMetadata(
        name="SSH_MAX_AUTH_TRIES",
        input_type="number",
        label="SSH Max Auth Tries",
        description="Maximum SSH authentication attempts",
        required=False,
        default="4",
        min_value=1,
        max_value=10
    ),

    "SSH_CLIENT_ALIVE_INTERVAL": ParameterMetadata(
        name="SSH_CLIENT_ALIVE_INTERVAL",
        input_type="number",
        label="SSH Client Alive Interval (seconds)",
        description="Interval for SSH keepalive checks",
        required=False,
        default="300",
        min_value=60,
        max_value=900
    ),

    "SSH_CLIENT_ALIVE_COUNT_MAX": ParameterMetadata(
        name="SSH_CLIENT_ALIVE_COUNT_MAX",
        input_type="number",
        label="SSH Client Alive Count Max",
        description="Maximum missed keepalive responses before disconnect",
        required=False,
        default="3",
        min_value=0,
        max_value=10
    ),

    "SSH_LOG_LEVEL": ParameterMetadata(
        name="SSH_LOG_LEVEL",
        input_type="select",
        label="SSH Log Level",
        description="SSH daemon logging verbosity",
        required=False,
        options=["INFO", "VERBOSE"],
        default="INFO"
    ),

    # ==================== AUDIT CONFIGURATION ====================
    "AUDIT_MAX_LOG_FILE": ParameterMetadata(
        name="AUDIT_MAX_LOG_FILE",
        input_type="number",
        label="Audit Max Log File Size (MB)",
        description="Maximum size of audit log files before rotation",
        required=False,
        default="8",
        min_value=1,
        max_value=100
    ),

    "AUDIT_SPACE_LEFT_ACTION": ParameterMetadata(
        name="AUDIT_SPACE_LEFT_ACTION",
        input_type="select",
        label="Audit Space Left Action",
        description="Action when audit disk space is low",
        required=False,
        options=["email", "syslog", "exec", "suspend", "single", "halt"],
        default="email"
    ),

    "AUDIT_BACKLOG_LIMIT": ParameterMetadata(
        name="AUDIT_BACKLOG_LIMIT",
        input_type="number",
        label="Audit Backlog Limit",
        description="Kernel audit backlog buffer size (audit_backlog_limit boot parameter)",
        required=False,
        default="8192",
        min_value=8192,
        max_value=65536
    ),

    # ==================== FIREWALL CONFIGURATION ====================
    "FIREWALL_DEFAULT_POLICY": ParameterMetadata(
        name="FIREWALL_DEFAULT_POLICY",
        input_type="select",
        label="Firewall Default Policy",
        description="Default policy for incoming connections",
        required=False,
        options=["deny", "reject"],
        default="deny"
    ),

    # ==================== SYSCTL SETTINGS (have CIS defaults) ====================
    "SYSCTL_KERNEL_RANDOMIZE_VA_SPACE": ParameterMetadata(
        name="SYSCTL_KERNEL_RANDOMIZE_VA_SPACE",
        input_type="select",
        label="ASLR Level",
        description="Address Space Layout Randomization setting",
        required=False,
        options=["0", "1", "2"],
        default="2"
    ),

    "SYSCTL_FS_SUID_DUMPABLE": ParameterMetadata(
        name="SYSCTL_FS_SUID_DUMPABLE",
        input_type="select",
        label="Core Dump Setting",
        description="Allow core dumps for SUID programs",
        required=False,
        options=["0", "1", "2"],
        default="0"
    ),

    # ==================== EXPANDED PARAMETERS ====================

    # PAM Faillock
    "FAILLOCK_DENY": ParameterMetadata(
        name="FAILLOCK_DENY",
        input_type="number",
        label="Failed Login Attempts",
        description="Number of failed login attempts before lockout",
        required=False,
        default="5",
        min_value=3,
        max_value=10
    ),

    "FAILLOCK_UNLOCK_TIME": ParameterMetadata(
        name="FAILLOCK_UNLOCK_TIME",
        input_type="number",
        label="Lockout Duration (seconds)",
        description="Seconds before locked account is automatically unlocked",
        required=False,
        default="900",
        min_value=300,
        max_value=3600
    ),

    # SSH Additional Settings
    "SSH_BANNER_TEXT": ParameterMetadata(
        name="SSH_BANNER_TEXT",
        input_type="textarea",
        label="SSH Banner Text",
        description="Warning banner displayed before SSH login",
        required=False,
        default="Authorized access only. All activity is monitored and logged.",
        placeholder="Authorized users only. All access is logged."
    ),

    "SSH_MAX_STARTUPS": ParameterMetadata(
        name="SSH_MAX_STARTUPS",
        input_type="text",
        label="SSH Max Startups",
        description="Maximum concurrent unauthenticated connections (format: start:rate:full)",
        required=False,
        default="10:30:60",
        placeholder="10:30:60"
    ),

    "SSH_MAX_SESSIONS": ParameterMetadata(
        name="SSH_MAX_SESSIONS",
        input_type="number",
        label="SSH Max Sessions",
        description="Maximum sessions per network connection",
        required=False,
        default="10",
        min_value=1,
        max_value=20
    ),

    "SSH_LOGIN_GRACE_TIME": ParameterMetadata(
        name="SSH_LOGIN_GRACE_TIME",
        input_type="number",
        label="SSH Login Grace Time (seconds)",
        description="Time allowed for authentication before disconnection",
        required=False,
        default="60",
        min_value=30,
        max_value=120
    ),

    # Account Policy
    "INACTIVE_DAYS": ParameterMetadata(
        name="INACTIVE_DAYS",
        input_type="number",
        label="Inactive Password Lock (days)",
        description="Days after password expiry before account is locked",
        required=False,
        default="30",
        min_value=1,
        max_value=60
    ),

    "UMASK_VALUE": ParameterMetadata(
        name="UMASK_VALUE",
        input_type="text",
        label="Default UMASK",
        description="Default file creation mask for new files",
        required=False,
        default="027",
        placeholder="027"
    ),

    "PASS_REMEMBER": ParameterMetadata(
        name="PASS_REMEMBER",
        input_type="number",
        label="Password History Count",
        description="Number of previous passwords to remember (prevent reuse)",
        required=False,
        default="5",
        min_value=3,
        max_value=24
    ),

    # ==================== RHEL-SPECIFIC PARAMETERS ====================

    "CRYPTO_POLICY": ParameterMetadata(
        name="CRYPTO_POLICY",
        input_type="select",
        label="System-wide Crypto Policy",
        description="RHEL system-wide cryptographic policy (must not be LEGACY)",
        required=False,
        options=["DEFAULT", "FUTURE", "FIPS"],
        default="DEFAULT"
    ),

    "SELINUX_POLICY_TYPE": ParameterMetadata(
        name="SELINUX_POLICY_TYPE",
        input_type="select",
        label="SELinux Policy Type",
        description="SELinux policy type to configure",
        required=False,
        options=["targeted", "mls"],
        default="targeted"
    ),

    "AUTHSELECT_PROFILE": ParameterMetadata(
        name="AUTHSELECT_PROFILE",
        input_type="text",
        label="Authselect Profile",
        description="Authselect profile name to select (e.g., sssd, winbind, minimal)",
        required=False,
        default="sssd",
        placeholder="sssd"
    ),

    "PWQUALITY_MINLEN": ParameterMetadata(
        name="PWQUALITY_MINLEN",
        input_type="number",
        label="Password Minimum Length (pwquality)",
        description="Minimum password length enforced by pwquality on RHEL systems",
        required=False,
        default="14",
        min_value=8,
        max_value=128
    ),
}


# Mapping of Linux check numbers to their required parameters
LINUX_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    # ==================== SECTION 1: INITIAL SETUP ====================

    # 1.1.1.x - Disable unused filesystems (no params needed)
    "LNX-L1-1.1.1.1": [],  # cramfs
    "LNX-L1-1.1.1.2": [],  # freevxfs
    "LNX-L1-1.1.1.3": [],  # jffs2
    "LNX-L1-1.1.1.4": [],  # hfs
    "LNX-L1-1.1.1.5": [],  # hfsplus
    "LNX-L1-1.1.1.6": [],  # squashfs
    "LNX-L1-1.1.1.7": [],  # udf
    "LNX-L1-1.1.1.8": [],  # USB storage

    # 1.1.8.x - Mount options (no params)
    "LNX-L1-1.1.8.1": [],  # nodev on /tmp
    "LNX-L1-1.1.8.2": [],  # nosuid on /tmp
    "LNX-L1-1.1.8.3": [],  # noexec on /tmp
    "LNX-L1-1.1.8.4": [],  # nodev on /dev/shm
    "LNX-L1-1.1.8.5": [],  # nosuid on /dev/shm
    "LNX-L1-1.1.8.6": [],  # noexec on /dev/shm

    # 1.2.x - Package management
    "LNX-L1-1.2.1": [],  # Repo configured - informational
    "LNX-L1-1.2.2": [],  # GPG keys - informational

    # 1.9 - Automatic updates
    "LNX-L1-1.9": [],       # unattended-upgrades - no params
    "LNX-INFO-1.9.1": [],   # pending updates - informational
    "LNX-INFO-2.5": [],     # listening ports - informational

    # 1.3.x - MAC
    "LNX-L1-1.3.1": [],  # MAC installed - no params
    "LNX-L1-1.3.2": [],  # MAC enforcing - no params

    # 1.4.x - GRUB
    "LNX-L1-1.4.1": [],  # GRUB permissions - no params
    "LNX-L1-1.4.2": [],  # GRUB password - manual
    "LNX-L1-1.4.3": [],  # Single user mode - no params

    # 1.5.x - Process hardening
    "LNX-L1-1.5.1": [],  # ASLR - no params
    "LNX-L1-1.5.2": [],  # ptrace_scope - no params
    "LNX-L1-1.5.4": [],  # Core dumps - no params

    # 1.6.x - Banners
    "LNX-L1-1.6.1": ["MOTD_TEXT"],
    "LNX-L1-1.6.2": ["BANNER_TEXT"],
    "LNX-L1-1.6.3": ["BANNER_TEXT"],  # Remote banner

    # ==================== SECTION 2: SERVICES ====================

    # 2.1.x - inetd services
    "LNX-L1-2.1.1": [],   # xinetd
    "LNX-L1-2.1.2": [],   # openbsd-inetd

    # 2.2.x - Disable dangerous services (no params needed)
    "LNX-L1-2.2.1": [],   # avahi-daemon
    "LNX-L1-2.2.2": [],   # cups
    "LNX-L1-2.2.3": [],   # dhcpd
    "LNX-L1-2.2.4": [],   # slapd
    "LNX-L1-2.2.5": [],   # nfs-server
    "LNX-L1-2.2.6": [],   # rpcbind
    "LNX-L1-2.2.7": [],   # named
    "LNX-L1-2.2.8": [],   # vsftpd
    "LNX-L1-2.2.9": [],   # httpd
    "LNX-L1-2.2.10": [],  # dovecot
    "LNX-L1-2.2.11": [],  # smb
    "LNX-L1-2.2.12": [],  # squid
    "LNX-L1-2.2.13": [],  # snmpd
    "LNX-L1-2.2.14": [],  # rsync
    "LNX-L1-2.2.15": [],  # nis
    "LNX-L1-2.2.16": [],  # telnet.socket

    # 2.3.x - Service clients - informational
    "LNX-L1-2.3.1": [],   # nis client
    "LNX-L1-2.3.2": [],   # rsh client
    "LNX-L1-2.3.3": [],   # talk client
    "LNX-L1-2.3.4": [],   # telnet client
    "LNX-L1-2.3.5": [],   # ldap-utils

    # 2.4.x - Time sync (template installs/enables chrony; no parameters used)
    "LNX-L1-2.4.1": [],

    # ==================== SECTION 3: NETWORK ====================

    "LNX-L1-3.1.1": [],  # IP forwarding - no params
    "LNX-L1-3.1.2": [],  # Packet redirects - no params

    "LNX-L1-3.2.1": [],  # Source routing - no params
    "LNX-L1-3.2.2": [],  # ICMP redirects - no params
    "LNX-L1-3.2.3": [],  # Secure redirects - no params
    "LNX-L1-3.2.4": [],  # Log martians - no params
    "LNX-L1-3.2.5": [],  # Broadcast ICMP - no params
    "LNX-L1-3.2.6": [],  # Bogus ICMP - no params
    "LNX-L1-3.2.7": [],  # RP filter - no params
    "LNX-L1-3.2.8": [],  # TCP SYN cookies - no params

    # 3.3.x - IPv6
    "LNX-L1-3.3.1": [],  # IPv6 RA - no params
    "LNX-L1-3.3.2": [],  # IPv6 redirects - no params
    "LNX-L2-3.3.3": [],  # Disable IPv6 - no params

    # 3.4.x - Firewall
    "LNX-L1-3.4.1": ["FIREWALL_DEFAULT_POLICY"],

    # ==================== SECTION 4: LOGGING ====================

    "LNX-L1-4.1.1": [],    # rsyslog enabled - no params
    "LNX-L1-4.1.1.1": [],  # journald enabled - no params
    "LNX-L1-4.1.1.2": [],  # journald compress - no params
    "LNX-L1-4.1.1.3": [],  # journald persistent - no params
    "LNX-L1-4.1.1.4": [],  # journald forward - no params

    "LNX-L1-4.2.1": [],    # auditd enabled - no params
    "LNX-L1-4.2.2": ["AUDIT_MAX_LOG_FILE", "AUDIT_SPACE_LEFT_ACTION"],

    # 4.2.3.x - Audit rules (no params - use CIS defaults)
    "LNX-L2-4.2.3.1": [],   # time-change
    "LNX-L2-4.2.3.2": [],   # identity
    "LNX-L2-4.2.3.3": [],   # system-locale
    "LNX-L2-4.2.3.4": [],   # MAC-policy
    "LNX-L2-4.2.3.5": [],   # logins
    "LNX-L2-4.2.3.6": [],   # session
    "LNX-L2-4.2.3.7": [],   # perm-mod
    "LNX-L2-4.2.3.8": [],   # access
    "LNX-L2-4.2.3.9": [],   # mounts
    "LNX-L2-4.2.3.10": [],  # delete
    "LNX-L2-4.2.3.11": [],  # scope
    "LNX-L2-4.2.3.12": [],  # actions

    # ==================== SECTION 5: ACCESS CONTROL ====================

    # 5.1.x - Cron
    "LNX-L1-5.1.1": [],   # cron enabled - no params
    "LNX-L1-5.1.2": [],   # crontab permissions - no params
    "LNX-L1-5.1.3": [],   # cron.hourly permissions - no params
    "LNX-L1-5.1.4": [],   # cron.d permissions - no params
    "LNX-L1-5.1.5": [],   # cron access - no params

    # 5.2.x - SSH
    "LNX-L1-5.2.1": [],   # sshd_config permissions - no params
    "LNX-L1-5.2.2": [],   # SSH host key permissions - no params
    "LNX-L1-5.2.4": [],   # SSH Protocol - no params
    "LNX-L1-5.2.5": ["SSH_LOG_LEVEL"],
    "LNX-L1-5.2.6": [],   # X11 forwarding - no params
    "LNX-L1-5.2.7": ["SSH_MAX_AUTH_TRIES"],
    "LNX-L1-5.2.8": [],   # IgnoreRhosts - no params
    "LNX-L1-5.2.9": [],   # HostbasedAuthentication - no params
    "LNX-L1-5.2.10": [],  # PermitRootLogin - no params
    "LNX-L1-5.2.11": [],  # PermitEmptyPasswords - no params
    "LNX-L1-5.2.12": [],  # PermitUserEnvironment - no params
    "LNX-L1-5.2.13": ["SSH_CLIENT_ALIVE_INTERVAL", "SSH_CLIENT_ALIVE_COUNT_MAX"],
    "LNX-L1-5.2.14": ["SSH_BANNER_TEXT"],  # SSH banner
    "LNX-L1-5.2.15": ["ALLOWED_SSH_USERS", "ALLOWED_SSH_GROUPS"],
    "LNX-L1-5.2.15b": [],  # AllowTcpForwarding - no params
    "LNX-L1-5.2.16": ["SSH_MAX_STARTUPS"],
    "LNX-L1-5.2.17": ["SSH_MAX_SESSIONS"],
    "LNX-L1-5.2.18": ["SSH_LOGIN_GRACE_TIME"],
    "LNX-L1-5.2.19": [],  # UsePAM - no params

    # 5.3.x - PAM
    "LNX-L1-5.3.1": ["PASS_MIN_LEN"],
    "LNX-L1-5.3.2": ["PASS_REMEMBER"],  # Password history
    "LNX-L1-5.3.3": ["FAILLOCK_DENY", "FAILLOCK_UNLOCK_TIME"],  # Faillock

    # 5.4.x - Account settings
    "LNX-L1-5.4.1.1": ["PASS_MAX_DAYS"],
    "LNX-L1-5.4.1.2": ["PASS_MIN_DAYS"],
    "LNX-L1-5.4.1.3": ["PASS_WARN_AGE"],
    "LNX-L1-5.4.1.4": ["INACTIVE_DAYS"],
    "LNX-L1-5.4.1.5": ["UMASK_VALUE"],
    "LNX-L1-5.4.1.6": [],  # ENCRYPT_METHOD SHA512 - no params

    # 5.5.x - Root login
    "LNX-L1-5.5.1": [],   # Restrict root login - no params

    # 5.6 - Su
    "LNX-L1-5.6": [],     # Su restriction - no params

    # ==================== SECTION 6: SYSTEM MAINTENANCE ====================

    # 6.1.x - File permissions
    "LNX-L1-6.1.1": [],   # passwd permissions - no params
    "LNX-L1-6.1.2": [],   # passwd permissions - no params
    "LNX-L1-6.1.3": [],   # shadow permissions - no params
    "LNX-L1-6.1.4": [],   # group permissions - no params
    "LNX-L1-6.1.5": [],   # gshadow permissions - no params
    "LNX-L1-6.1.6": [],   # passwd- permissions - no params
    "LNX-L1-6.1.7": [],   # shadow- permissions - no params
    "LNX-L1-6.1.8": [],   # group- permissions - no params
    "LNX-L1-6.1.9": [],   # gshadow- permissions - no params

    # 6.1.10-12 - Informational checks (no hardening)
    "LNX-INFO-6.1.10": [],  # SUID audit - informational
    "LNX-INFO-6.1.11": [],  # World-writable - informational
    "LNX-INFO-6.1.12": [],  # Unowned files - informational

    # 6.2.x - User settings
    "LNX-L1-6.2.1": [],   # UID 0 check - manual review
    "LNX-L1-6.2.2": [],   # Empty passwords - manual
    "LNX-L1-6.2.3": [],   # Legacy entries - manual
    "LNX-L1-6.2.4": [],   # Home dirs exist - manual
    "LNX-L1-6.2.5": [],   # Home dir permissions - manual
    "LNX-L1-6.2.6": [],   # Home dir ownership - manual
    "LNX-L1-6.2.7": [],   # .forward files - manual
    "LNX-L1-6.2.8": [],   # .netrc files - manual
    "LNX-L1-6.2.9": [],   # .rhosts files - manual
    "LNX-L1-6.2.10": [],  # UID 0 strict - manual

    # L2 Partition checks - informational
    "LNX-L2-1.1.2": [],   # /tmp partition
    "LNX-L2-1.1.3": [],   # /var partition
    "LNX-L2-1.1.4": [],   # /var/tmp partition
    "LNX-L2-1.1.5": [],   # /var/log partition
    "LNX-L2-1.1.6": [],   # /var/log/audit partition
    "LNX-L2-1.1.7": [],   # /home partition

    # ==================== RHEL-SPECIFIC CHECKS ====================

    # 1.2.x - Package management (RHEL)
    "LNX-RHEL-L1-1.2.3": [],                        # gpgcheck - no params
    "LNX-RHEL-L1-1.2.4": ["CRYPTO_POLICY"],         # crypto policy not LEGACY
    "LNX-RHEL-L1-1.2.5": ["CRYPTO_POLICY"],         # crypto policy no SHA1
    "LNX-RHEL-L1-1.2.6": [],                        # RHSM registration - manual
    "LNX-RHEL-L1-1.2.7": [],                        # dnf-automatic - no params

    # 1.3.x - Sudo / AIDE (RHEL)
    "LNX-RHEL-L1-1.3.1": [],                        # sudo installed - no params
    "LNX-RHEL-L1-1.3.2": [],                        # sudo use_pty - no params
    "LNX-RHEL-L1-1.3.3": [],                        # sudo log file - no params
    "LNX-RHEL-L1-1.3.4": [],                        # AIDE installed - no params
    "LNX-RHEL-L1-1.3.5": [],                        # AIDE scheduled - no params

    # 1.8.x - GUI login (RHEL)
    "LNX-RHEL-L1-1.8.1": [],                        # GDM removed - manual

    # 3.4.x - Firewall (RHEL)
    "LNX-RHEL-L1-3.4.2": [],                        # firewalld enabled+running - no params

    # 4.1.1.x - Boot-time auditing (RHEL)
    "LNX-RHEL-L2-4.1.1.2": [],                      # audit=1 boot param - no params
    "LNX-RHEL-L2-4.1.1.3": ["AUDIT_BACKLOG_LIMIT"], # audit backlog limit

    # 5.2.x - SSH (RHEL)
    "LNX-RHEL-L1-5.2.20": [],                       # sshd crypto override removed - no params

    # 1.4.x - Bootloader (RHEL)
    "LNX-RHEL-L1-1.4.2": [],                        # bootloader password - manual

    # 1.6.x - SELinux (RHEL)
    "LNX-RHEL-L1-1.6.1": [],                        # SELinux installed - no params
    "LNX-RHEL-L1-1.6.2": [],                        # SELinux not disabled in grub - no params
    "LNX-RHEL-L1-1.6.3": ["SELINUX_POLICY_TYPE"],   # SELinux policy type
    "LNX-RHEL-L1-1.6.5": [],                        # SELinux enforcing - no params
    "LNX-RHEL-L1-1.6.6": [],                        # unconfined services - manual
    "LNX-RHEL-L1-1.6.7": [],                        # SETroubleshoot removed - no params
    "LNX-RHEL-L1-1.6.8": [],                        # mcstrans removed - no params

    # 5.3.x - PAM / Password (RHEL)
    "LNX-RHEL-L1-5.3.1.1": ["PWQUALITY_MINLEN"],   # pwquality minlen
    "LNX-RHEL-L1-5.3.3": ["FAILLOCK_DENY", "FAILLOCK_UNLOCK_TIME"],  # faillock
    "LNX-RHEL-L1-5.3.4": ["AUTHSELECT_PROFILE"],    # authselect profile
    "LNX-RHEL-L1-5.3.5": [],                        # pam_tally2 removal - no params

    # 5.4.x - Account policy (RHEL)
    "LNX-RHEL-L2-5.4.2": [],                        # system accounts - manual
}


def get_linux_parameter_metadata(param_name: str) -> Optional[ParameterMetadata]:
    """Get metadata for a parameter by name."""
    return LINUX_PARAMETER_REGISTRY.get(param_name)


def get_linux_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """Get all parameter metadata for a specific check."""
    param_names = LINUX_CHECK_PARAMETER_MAP.get(check_number, [])
    return [
        LINUX_PARAMETER_REGISTRY[name]
        for name in param_names
        if name in LINUX_PARAMETER_REGISTRY
    ]


def get_linux_required_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """Get only required parameters (no defaults) for a specific check."""
    params = get_linux_parameters_for_check(check_number)
    return [p for p in params if p.required and p.default is None]


def linux_check_has_required_params(check_number: str) -> bool:
    """Check if a check has any required parameters without defaults."""
    return len(get_linux_required_parameters_for_check(check_number)) > 0


def get_linux_check_defaults(check_number: str) -> Dict[str, str]:
    """Get default values for a check's parameters."""
    params = get_linux_parameters_for_check(check_number)
    return {
        p.name: p.default
        for p in params
        if p.default is not None
    }


def _has_hardening_template(check_number: str) -> bool:
    """True when a remediation template is registered for this check."""
    # Imported lazily/locally to keep module import order flexible
    # (command_templates does not import this module, so no cycle).
    from .command_templates import LINUX_HARDENING_TEMPLATES
    return check_number in LINUX_HARDENING_TEMPLATES


def is_linux_check_auto_fixable(check_number: str) -> bool:
    """
    Determine if a check can be auto-fixed with defaults only.

    A check is auto-fixable if:
    - A hardening template exists for it, AND
    - It has no parameters, or all its parameters have default values.

    (Param-map membership alone is NOT enough: informational/manual checks are
    listed there for UI metadata but have no remediation template.)
    """
    if check_number not in LINUX_CHECK_PARAMETER_MAP:
        return False
    if not _has_hardening_template(check_number):
        return False

    params = get_linux_parameters_for_check(check_number)
    if not params:
        return True
    return all(p.default is not None for p in params)


def aggregate_linux_parameters_for_checks(check_numbers: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate all unique parameters needed for a set of checks.

    Returns dict of parameter names to their metadata and which checks use them.
    """
    aggregated: Dict[str, Dict[str, Any]] = {}

    for check_number in check_numbers:
        params = get_linux_parameters_for_check(check_number)
        for param in params:
            if param.name not in aggregated:
                aggregated[param.name] = {
                    "type": param.input_type,
                    "label": param.label,
                    "description": param.description,
                    "required": param.required and param.default is None,
                    "default": param.default,
                    "placeholder": param.placeholder,
                    "validation": param.validation,
                    "options": param.options,
                    "min_value": param.min_value,
                    "max_value": param.max_value,
                    "checks": [check_number]
                }
            else:
                if check_number not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_number)

    return aggregated


def categorize_linux_checks_by_fixability(check_numbers: List[str]) -> Dict[str, List[str]]:
    """
    Categorize checks into auto-fixable and needs-params.
    """
    auto_fixable = []
    needs_params = []
    not_supported = []

    for check_number in check_numbers:
        if (check_number not in LINUX_CHECK_PARAMETER_MAP
                or not _has_hardening_template(check_number)):
            not_supported.append(check_number)
        elif is_linux_check_auto_fixable(check_number):
            auto_fixable.append(check_number)
        else:
            needs_params.append(check_number)

    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params,
        "not_supported": not_supported
    }


def get_linux_auto_fix_preview(check_numbers: List[str]) -> List[Dict[str, Any]]:
    """
    Get preview of what will be applied in automatic mode.
    """
    preview = []

    for check_number in check_numbers:
        if is_linux_check_auto_fixable(check_number):
            defaults = get_linux_check_defaults(check_number)
            preview.append({
                "check_number": check_number,
                "defaults": defaults
            })

    return preview
