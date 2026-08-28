"""
Linux CIS Benchmark Audit Commands

Supports Ubuntu 20.04/22.04/24.04, Rocky Linux 8/9/10, RHEL 8/9/10.

Commands organized by CIS Benchmark sections:
1.x - Initial Setup (Filesystem, Boot, Kernel)
2.x - Services
3.x - Network Configuration
4.x - Logging and Auditing
5.x - Access, Authentication, Authorization
6.x - System Maintenance

Each command includes:
- cmd: The actual command to run
- sudo: Whether sudo is required
- key: Unique identifier for the command output
- section: CIS section reference
- description: What this command checks
"""

from typing import List, Dict, Any


def get_linux_audit_commands(distro_id: str = "ubuntu") -> List[Dict[str, Any]]:
    """
    Get all audit commands for Linux CIS benchmark.

    Args:
        distro_id: Distribution ID (ubuntu, rocky, rhel, centos)

    Returns:
        List of command dictionaries
    """
    commands = []

    # Determine distro-specific tools
    is_debian = distro_id in ("ubuntu", "debian")
    is_rhel = distro_id in ("rocky", "rhel", "centos", "fedora", "almalinux")
    is_rhel_family = is_rhel  # alias for clarity in RHEL-specific blocks
    pkg_mgr = "apt" if is_debian else "dnf"
    firewall = "ufw" if is_debian else "firewalld"
    mac = "apparmor" if is_debian else "selinux"

    # ==================== SECTION 1: INITIAL SETUP ====================

    # 1.1 Filesystem Configuration
    commands.extend([
        {"cmd": "cat /etc/fstab", "sudo": False, "key": "fstab", "section": "1.1"},
        {"cmd": "mount | grep -E '\\s/tmp\\s'", "sudo": False, "key": "mount_tmp", "section": "1.1.2"},
        {"cmd": "mount | grep -E '\\s/var\\s'", "sudo": False, "key": "mount_var", "section": "1.1.3"},
        {"cmd": "mount | grep -E '\\s/var/tmp\\s'", "sudo": False, "key": "mount_var_tmp", "section": "1.1.4"},
        {"cmd": "mount | grep -E '\\s/var/log\\s'", "sudo": False, "key": "mount_var_log", "section": "1.1.5"},
        {"cmd": "mount | grep -E '\\s/var/log/audit\\s'", "sudo": False, "key": "mount_var_log_audit", "section": "1.1.6"},
        {"cmd": "mount | grep -E '\\s/home\\s'", "sudo": False, "key": "mount_home", "section": "1.1.7"},
        {"cmd": "mount | grep -E '\\s/dev/shm\\s'", "sudo": False, "key": "mount_dev_shm", "section": "1.1.8"},
        {"cmd": "df -h --output=target | grep -E '^/'", "sudo": False, "key": "df_mounts", "section": "1.1"},
        {"cmd": "findmnt -n -l -t ext4,xfs,btrfs 2>/dev/null || echo 'no mounts'", "sudo": False, "key": "findmnt_all", "section": "1.1"},
    ])

    # 1.1.1 - Disable unused filesystems
    commands.extend([
        {"cmd": "modprobe -n -v cramfs 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_cramfs", "section": "1.1.1.1"},
        {"cmd": "lsmod | grep cramfs || echo 'not loaded'", "sudo": False, "key": "lsmod_cramfs", "section": "1.1.1.1"},
        {"cmd": "modprobe -n -v freevxfs 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_freevxfs", "section": "1.1.1.2"},
        {"cmd": "lsmod | grep freevxfs || echo 'not loaded'", "sudo": False, "key": "lsmod_freevxfs", "section": "1.1.1.2"},
        {"cmd": "modprobe -n -v jffs2 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_jffs2", "section": "1.1.1.3"},
        {"cmd": "lsmod | grep jffs2 || echo 'not loaded'", "sudo": False, "key": "lsmod_jffs2", "section": "1.1.1.3"},
        {"cmd": "modprobe -n -v hfs 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_hfs", "section": "1.1.1.4"},
        {"cmd": "lsmod | grep hfs || echo 'not loaded'", "sudo": False, "key": "lsmod_hfs", "section": "1.1.1.4"},
        {"cmd": "modprobe -n -v hfsplus 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_hfsplus", "section": "1.1.1.5"},
        {"cmd": "lsmod | grep hfsplus || echo 'not loaded'", "sudo": False, "key": "lsmod_hfsplus", "section": "1.1.1.5"},
        {"cmd": "modprobe -n -v squashfs 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_squashfs", "section": "1.1.1.6"},
        {"cmd": "lsmod | grep squashfs || echo 'not loaded'", "sudo": False, "key": "lsmod_squashfs", "section": "1.1.1.6"},
        {"cmd": "modprobe -n -v udf 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_udf", "section": "1.1.1.7"},
        {"cmd": "lsmod | grep udf || echo 'not loaded'", "sudo": False, "key": "lsmod_udf", "section": "1.1.1.7"},
        {"cmd": "modprobe -n -v usb-storage 2>&1 || echo 'not available'", "sudo": True, "key": "modprobe_usb_storage", "section": "1.1.1.8"},
        {"cmd": "lsmod | grep usb-storage || echo 'not loaded'", "sudo": False, "key": "lsmod_usb_storage", "section": "1.1.1.8"},
    ])

    # 1.2 - Package Management
    if is_debian:
        commands.extend([
            {"cmd": "apt-cache policy 2>/dev/null | head -50", "sudo": False, "key": "apt_sources", "section": "1.2"},
            {"cmd": "cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'none'", "sudo": False, "key": "apt_sources_list", "section": "1.2.1"},
            {"cmd": "apt-key list 2>/dev/null | head -50 || echo 'no keys'", "sudo": False, "key": "apt_keys", "section": "1.2.2"},
            # 1.9 - Automatic security updates
            {"cmd": "dpkg -s unattended-upgrades 2>/dev/null | grep Status || echo 'not installed'", "sudo": False, "key": "unattended_upgrades_installed", "section": "1.9"},
            {"cmd": "cat /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -E 'Unattended-Upgrade|Update-Package-Lists' | head -10 || echo 'not configured'", "sudo": False, "key": "unattended_upgrades_config", "section": "1.9"},
            # 1.9.1 - Pending updates (inventory)
            {"cmd": "apt list --upgradable 2>/dev/null | head -30 || echo 'apt not available'", "sudo": False, "key": "pending_updates", "section": "1.9.1"},
        ])
    else:
        commands.extend([
            # dnf/yum repolist can hang for well over the SSH read timeout when
            # repos are unreachable (each mirror is retried before giving up),
            # so `timeout` bounds the whole call and lets the fallback/echo run.
            {"cmd": "timeout 15 dnf repolist 2>/dev/null || timeout 15 yum repolist 2>/dev/null || echo 'no repos'", "sudo": False, "key": "dnf_repos", "section": "1.2", "timeout": 45},
            {"cmd": "rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release}\\n' 2>/dev/null || echo 'no keys'", "sudo": False, "key": "rpm_gpg_keys", "section": "1.2.1"},
            # 1.2.3 - gpgcheck enabled in dnf.conf
            {"cmd": "grep -E '^\\s*gpgcheck' /etc/dnf/dnf.conf 2>/dev/null || echo 'not configured'", "sudo": False, "key": "dnf_gpgcheck", "section": "1.2.3"},
            # 1.2.4 - Crypto policies (RHEL 8+)
            {"cmd": "update-crypto-policies --show 2>/dev/null || echo 'not available'", "sudo": False, "key": "crypto_policy", "section": "1.2.4"},
            {"cmd": "cat /etc/crypto-policies/state/current 2>/dev/null || echo 'not available'", "sudo": False, "key": "crypto_policy_state", "section": "1.2.4"},
            # 1.9.1 - Pending updates (inventory)
            # Same network-hang risk as dnf_repos above: check-update refreshes
            # repo metadata, which can stall far past the SSH read timeout when
            # a repo is unreachable. `timeout` bounds it so the shell always
            # returns and the fallback chain (yum, then the echo) still runs.
            {"cmd": "timeout 15 dnf check-update 2>/dev/null | head -30 || timeout 15 yum check-update 2>/dev/null | head -30 || echo 'up to date or dnf unavailable'", "sudo": False, "key": "pending_updates", "section": "1.9.1", "timeout": 45},
        ])

    # 1.3 - Mandatory Access Control
    if is_debian:
        # AppArmor for Ubuntu/Debian
        commands.extend([
            {"cmd": "dpkg -s apparmor 2>/dev/null | grep -i status || echo 'not installed'", "sudo": False, "key": "apparmor_installed", "section": "1.3.1"},
            {"cmd": "systemctl is-enabled apparmor 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "apparmor_enabled", "section": "1.3.1"},
            {"cmd": "aa-status 2>/dev/null || echo 'apparmor not running'", "sudo": True, "key": "apparmor_status", "section": "1.3.1"},
            {"cmd": "cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo 'unknown'", "sudo": False, "key": "apparmor_kernel", "section": "1.3.1"},
        ])
    else:
        # SELinux for RHEL/Rocky
        commands.extend([
            {"cmd": "rpm -q libselinux 2>/dev/null || echo 'not installed'", "sudo": False, "key": "selinux_installed", "section": "1.6.1"},
            {"cmd": "getenforce 2>/dev/null || echo 'unknown'", "sudo": False, "key": "selinux_status", "section": "1.6.4"},
            {"cmd": "sestatus 2>/dev/null || echo 'not available'", "sudo": False, "key": "sestatus", "section": "1.6.4"},
            {"cmd": "cat /etc/selinux/config 2>/dev/null || echo 'no config'", "sudo": False, "key": "selinux_config", "section": "1.6.3"},
            # 1.6.6 - Unconfined services
            {"cmd": "ps -eZ 2>/dev/null | grep unconfined_service_t | head -20 || echo 'none'", "sudo": False, "key": "selinux_unconfined", "section": "1.6.6"},
            # 1.6.7 - SETroubleshoot not installed
            {"cmd": "rpm -q setroubleshoot 2>/dev/null || echo 'not installed'", "sudo": False, "key": "setroubleshoot_installed", "section": "1.6.7"},
            # 1.6.8 - MCS Translation Service (mcstrans) not installed
            {"cmd": "rpm -q mcstrans 2>/dev/null || echo 'not installed'", "sudo": False, "key": "mcstrans_installed", "section": "1.6.8"},
            # 1.3 - Sudo configuration
            {"cmd": "rpm -q sudo 2>/dev/null || echo 'not installed'", "sudo": False, "key": "sudo_installed", "section": "1.3.1"},
            {"cmd": "grep -rE '^\\s*Defaults.*use_pty' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'not configured'", "sudo": True, "key": "sudo_use_pty", "section": "1.3.2"},
            {"cmd": "grep -rE '^\\s*Defaults.*logfile' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'not configured'", "sudo": True, "key": "sudo_logfile", "section": "1.3.3"},
            # authselect (RHEL 7.7+ / RHEL 8+)
            {"cmd": "authselect current 2>/dev/null || echo 'authselect not configured'", "sudo": False, "key": "authselect_profile", "section": "5.3"},
            {"cmd": "authselect list 2>/dev/null | head -20 || echo 'authselect not available'", "sudo": False, "key": "authselect_list", "section": "5.3"},
        ])

    # 1.4 - Boot Settings
    # RHEL uses /boot/grub2/, Ubuntu/Debian uses /boot/grub/
    if is_debian:
        grub_cfg = "/boot/grub/grub.cfg"
    else:
        grub_cfg = "/boot/grub2/grub.cfg"

    # EFI RHEL installs keep grub.cfg under /boot/efi/EFI/redhat/ — include it
    # in the fallback chain so 1.4.x doesn't false-FAIL on EFI systems.
    commands.extend([
        {"cmd": f"cat {grub_cfg} 2>/dev/null | head -100 || cat /boot/grub/grub.cfg 2>/dev/null | head -100 || cat /boot/efi/EFI/redhat/grub.cfg 2>/dev/null | head -100 || echo 'no grub config'", "sudo": True, "key": "grub_config", "section": "1.4"},
        {"cmd": f"stat {grub_cfg} 2>/dev/null || stat /boot/grub/grub.cfg 2>/dev/null || stat /boot/efi/EFI/redhat/grub.cfg 2>/dev/null || echo 'no grub config'", "sudo": True, "key": "grub_permissions", "section": "1.4.1"},
        {"cmd": f"grep -E '^\\s*password' {grub_cfg} 2>/dev/null || echo 'no grub password'", "sudo": True, "key": "grub_password", "section": "1.4.2"},
        {"cmd": f"grep -E 'single|emergency' {grub_cfg} 2>/dev/null || echo 'none'", "sudo": True, "key": "grub_single_mode", "section": "1.4.3"},
    ])

    # 1.5 - Additional Process Hardening
    commands.extend([
        {"cmd": "sysctl kernel.randomize_va_space 2>/dev/null || echo 'unknown'", "sudo": False, "key": "aslr", "section": "1.5.1"},
        {"cmd": "grep -E 'kernel\\.randomize_va_space' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null || echo 'not configured'", "sudo": False, "key": "aslr_config", "section": "1.5.1"},
        {"cmd": "dmesg | grep -i 'NX.*protection' 2>/dev/null || echo 'check /proc/cpuinfo'", "sudo": True, "key": "nx_bit", "section": "1.5.2"},
        {"cmd": "cat /proc/sys/kernel/core_pattern 2>/dev/null || echo 'unknown'", "sudo": False, "key": "core_pattern", "section": "1.5.3"},
        {"cmd": "sysctl fs.suid_dumpable 2>/dev/null || echo 'unknown'", "sudo": False, "key": "suid_dumpable", "section": "1.5.4"},
        {"cmd": "sysctl kernel.yama.ptrace_scope 2>/dev/null || echo 'unknown'", "sudo": False, "key": "ptrace_scope", "section": "1.5.2"},
    ])

    # 5.4.1.6 - Password hashing algorithm
    commands.append({"cmd": "grep -E '^\\s*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null || echo 'not configured'", "sudo": False, "key": "encrypt_method", "section": "5.4.1.6"})

    # 1.6 - Banner/MOTD
    commands.extend([
        {"cmd": "cat /etc/motd 2>/dev/null || echo 'no motd'", "sudo": False, "key": "motd", "section": "1.6.1"},
        {"cmd": "cat /etc/issue 2>/dev/null || echo 'no issue'", "sudo": False, "key": "issue", "section": "1.6.2"},
        {"cmd": "cat /etc/issue.net 2>/dev/null || echo 'no issue.net'", "sudo": False, "key": "issue_net", "section": "1.6.3"},
        {"cmd": "stat /etc/motd /etc/issue /etc/issue.net 2>/dev/null || echo 'stat failed'", "sudo": False, "key": "banner_permissions", "section": "1.6.4"},
    ])

    # ==================== SECTION 2: SERVICES ====================

    # 2.1 - inetd Services
    commands.extend([
        {"cmd": "systemctl is-enabled xinetd 2>/dev/null || echo 'not installed'", "sudo": False, "key": "xinetd_enabled", "section": "2.1"},
        {"cmd": "systemctl status xinetd 2>/dev/null || echo 'not running'", "sudo": False, "key": "xinetd_status", "section": "2.1"},
    ])
    if is_debian:
        commands.append({"cmd": "dpkg -s openbsd-inetd 2>/dev/null | grep Status || echo 'not installed'", "sudo": False, "key": "openbsd_inetd_installed", "section": "2.1.2"})
    else:
        commands.append({"cmd": "rpm -q inetd openbsd-inetd 2>/dev/null | grep -v 'not installed' || echo 'not installed'", "sudo": False, "key": "openbsd_inetd_installed", "section": "2.1.2"})

    # 2.5 - Listening services / open ports (inventory)
    commands.append({"cmd": "ss -tulpn 2>/dev/null | head -60 || netstat -tulpn 2>/dev/null | head -60 || echo 'ss not available'", "sudo": True, "key": "listening_ports", "section": "2.5"})

    # 2.2 - Special Purpose Services
    services_to_check = [
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

    # Adjust service names for distro (e.g. httpd -> apache2, smb -> smbd on Debian/Ubuntu).
    # Keep this in sync with _resolve_service_name() in rules.py and
    # get_distro_service_name() in hardening/command_templates.py.
    _debian_service_aliases = {"httpd": "apache2", "smb": "smbd"}
    if is_debian:
        services_to_check = [(_debian_service_aliases.get(s, s), sec) for s, sec in services_to_check]

    for service, section in services_to_check:
        commands.append({
            "cmd": f"systemctl is-enabled {service} 2>/dev/null || echo 'not installed'",
            "sudo": False,
            "key": f"svc_{service}_enabled",
            "section": section
        })

    # 2.3 - Service Clients
    clients_to_check = [
        ("nis", "ypbind", "2.3.1"),
        ("rsh", "rsh", "2.3.2"),
        ("talk", "talk", "2.3.3"),
        ("telnet", "telnet", "2.3.4"),
        ("ldap-utils", "ldapsearch", "2.3.5"),
    ]

    for pkg, cmd, section in clients_to_check:
        if is_debian:
            commands.append({
                "cmd": f"dpkg -s {pkg} 2>/dev/null | grep Status || echo 'not installed'",
                "sudo": False,
                "key": f"client_{pkg}_installed",
                "section": section
            })
        else:
            commands.append({
                "cmd": f"rpm -q {pkg} 2>/dev/null || echo 'not installed'",
                "sudo": False,
                "key": f"client_{pkg}_installed",
                "section": section
            })

    # 2.4 - Time Synchronization
    commands.extend([
        {"cmd": "systemctl is-enabled systemd-timesyncd 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "timesyncd_enabled", "section": "2.4.1"},
        {"cmd": "systemctl is-enabled chrony 2>/dev/null || systemctl is-enabled chronyd 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "chrony_enabled", "section": "2.4.1"},
        {"cmd": "systemctl is-enabled ntp 2>/dev/null || systemctl is-enabled ntpd 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "ntp_enabled", "section": "2.4.1"},
        {"cmd": "timedatectl status 2>/dev/null || echo 'timedatectl not available'", "sudo": False, "key": "timedatectl", "section": "2.4.1"},
        {"cmd": "cat /etc/chrony.conf /etc/chrony/chrony.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no chrony config'", "sudo": False, "key": "chrony_config", "section": "2.4.2"},
        {"cmd": "cat /etc/ntp.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no ntp config'", "sudo": False, "key": "ntp_config", "section": "2.4.2"},
    ])

    # ==================== SECTION 3: NETWORK CONFIGURATION ====================

    # 3.1 - Network Parameters (Host Only)
    commands.extend([
        {"cmd": "sysctl net.ipv4.ip_forward 2>/dev/null || echo 'unknown'", "sudo": False, "key": "ip_forward", "section": "3.1.1"},
        {"cmd": "sysctl net.ipv4.conf.all.send_redirects 2>/dev/null || echo 'unknown'", "sudo": False, "key": "send_redirects_all", "section": "3.1.2"},
        {"cmd": "sysctl net.ipv4.conf.default.send_redirects 2>/dev/null || echo 'unknown'", "sudo": False, "key": "send_redirects_default", "section": "3.1.2"},
    ])

    # 3.2 - Network Parameters (Host and Router)
    commands.extend([
        {"cmd": "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null || echo 'unknown'", "sudo": False, "key": "accept_source_route_all", "section": "3.2.1"},
        {"cmd": "sysctl net.ipv4.conf.default.accept_source_route 2>/dev/null || echo 'unknown'", "sudo": False, "key": "accept_source_route_default", "section": "3.2.1"},
        {"cmd": "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null || echo 'unknown'", "sudo": False, "key": "accept_redirects_all", "section": "3.2.2"},
        {"cmd": "sysctl net.ipv4.conf.default.accept_redirects 2>/dev/null || echo 'unknown'", "sudo": False, "key": "accept_redirects_default", "section": "3.2.2"},
        {"cmd": "sysctl net.ipv4.conf.all.secure_redirects 2>/dev/null || echo 'unknown'", "sudo": False, "key": "secure_redirects_all", "section": "3.2.3"},
        {"cmd": "sysctl net.ipv4.conf.all.log_martians 2>/dev/null || echo 'unknown'", "sudo": False, "key": "log_martians_all", "section": "3.2.4"},
        {"cmd": "sysctl net.ipv4.conf.default.log_martians 2>/dev/null || echo 'unknown'", "sudo": False, "key": "log_martians_default", "section": "3.2.4"},
        {"cmd": "sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo 'unknown'", "sudo": False, "key": "icmp_echo_ignore_broadcasts", "section": "3.2.5"},
        {"cmd": "sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null || echo 'unknown'", "sudo": False, "key": "icmp_ignore_bogus", "section": "3.2.6"},
        {"cmd": "sysctl net.ipv4.conf.all.rp_filter 2>/dev/null || echo 'unknown'", "sudo": False, "key": "rp_filter_all", "section": "3.2.7"},
        {"cmd": "sysctl net.ipv4.conf.default.rp_filter 2>/dev/null || echo 'unknown'", "sudo": False, "key": "rp_filter_default", "section": "3.2.7"},
        {"cmd": "sysctl net.ipv4.tcp_syncookies 2>/dev/null || echo 'unknown'", "sudo": False, "key": "tcp_syncookies", "section": "3.2.8"},
    ])

    # 3.3 - IPv6
    commands.extend([
        {"cmd": "sysctl net.ipv6.conf.all.accept_ra 2>/dev/null || echo 'unknown'", "sudo": False, "key": "ipv6_accept_ra_all", "section": "3.3.1"},
        {"cmd": "sysctl net.ipv6.conf.default.accept_ra 2>/dev/null || echo 'unknown'", "sudo": False, "key": "ipv6_accept_ra_default", "section": "3.3.1"},
        {"cmd": "sysctl net.ipv6.conf.all.accept_redirects 2>/dev/null || echo 'unknown'", "sudo": False, "key": "ipv6_accept_redirects_all", "section": "3.3.2"},
        {"cmd": "sysctl net.ipv6.conf.default.accept_redirects 2>/dev/null || echo 'unknown'", "sudo": False, "key": "ipv6_accept_redirects_default", "section": "3.3.2"},
        {"cmd": "sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 'unknown'", "sudo": False, "key": "ipv6_disabled", "section": "3.3.3"},
    ])

    # 3.4 - Firewall Configuration
    if is_debian:
        commands.extend([
            {"cmd": "ufw status verbose 2>/dev/null || echo 'ufw not installed'", "sudo": True, "key": "ufw_status", "section": "3.4"},
            {"cmd": "ufw status numbered 2>/dev/null || echo 'ufw not installed'", "sudo": True, "key": "ufw_rules", "section": "3.4"},
            {"cmd": "iptables -L -n -v 2>/dev/null || echo 'iptables not available'", "sudo": True, "key": "iptables_rules", "section": "3.4"},
            {"cmd": "ip6tables -L -n -v 2>/dev/null || echo 'ip6tables not available'", "sudo": True, "key": "ip6tables_rules", "section": "3.4"},
        ])
    else:
        commands.extend([
            {"cmd": "firewall-cmd --state 2>/dev/null || echo 'firewalld not installed'", "sudo": True, "key": "firewalld_state", "section": "3.4"},
            {"cmd": "firewall-cmd --list-all 2>/dev/null || echo 'firewalld not installed'", "sudo": True, "key": "firewalld_rules", "section": "3.4"},
            {"cmd": "systemctl is-enabled firewalld 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "firewalld_enabled", "section": "3.4"},
            {"cmd": "iptables -L -n -v 2>/dev/null || echo 'iptables not available'", "sudo": True, "key": "iptables_rules", "section": "3.4"},
            # nftables (default backend for firewalld in RHEL 8+)
            {"cmd": "nft list ruleset 2>/dev/null | head -50 || echo 'nft not available'", "sudo": True, "key": "nft_rules", "section": "3.4"},
            {"cmd": "systemctl is-enabled nftables 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "nftables_enabled", "section": "3.4"},
        ])

    # 3.5 - Wireless
    commands.extend([
        {"cmd": "nmcli radio all 2>/dev/null || echo 'nmcli not available'", "sudo": False, "key": "wireless_status", "section": "3.5"},
        {"cmd": "ip link show | grep -i wireless || echo 'no wireless interfaces'", "sudo": False, "key": "wireless_interfaces", "section": "3.5"},
    ])

    # ==================== SECTION 4: LOGGING AND AUDITING ====================

    # 4.1 - Configure Logging
    commands.extend([
        {"cmd": "systemctl is-enabled rsyslog 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "rsyslog_enabled", "section": "4.1.1"},
        {"cmd": "cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no rsyslog config'", "sudo": False, "key": "rsyslog_config", "section": "4.1.2"},
        {"cmd": "ls -la /var/log/ 2>/dev/null | head -50", "sudo": False, "key": "varlog_permissions", "section": "4.1.3"},
        {"cmd": "cat /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | grep -v '^#' | grep -v '^$' | head -100 || echo 'no logrotate config'", "sudo": False, "key": "logrotate_config", "section": "4.1.4"},
    ])

    # 4.1.1 - journald
    commands.extend([
        {"cmd": "systemctl is-enabled systemd-journald 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "journald_enabled", "section": "4.1.1.1"},
        {"cmd": "cat /etc/systemd/journald.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no journald config'", "sudo": False, "key": "journald_config", "section": "4.1.1.2"},
    ])

    # 4.2 - Configure auditd
    commands.extend([
        {"cmd": "systemctl is-enabled auditd 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "auditd_enabled", "section": "4.2.1"},
        {"cmd": "systemctl status auditd 2>/dev/null | head -20 || echo 'auditd not running'", "sudo": False, "key": "auditd_status", "section": "4.2.1"},
        {"cmd": "cat /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no auditd config'", "sudo": True, "key": "auditd_config", "section": "4.2.2"},
        {"cmd": "cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no audit rules'", "sudo": True, "key": "audit_rules", "section": "4.2.3"},
        {"cmd": "auditctl -l 2>/dev/null || echo 'auditctl not available'", "sudo": True, "key": "audit_rules_loaded", "section": "4.2.3"},
        {"cmd": "grep -E '^\\s*max_log_file\\s*=' /etc/audit/auditd.conf 2>/dev/null || echo 'not configured'", "sudo": True, "key": "audit_max_log", "section": "4.2.2"},
        {"cmd": "grep -E '^\\s*space_left_action\\s*=' /etc/audit/auditd.conf 2>/dev/null || echo 'not configured'", "sudo": True, "key": "audit_space_left", "section": "4.2.2"},
    ])

    # ==================== SECTION 5: ACCESS, AUTHENTICATION, AUTHORIZATION ====================

    # 5.1 - Configure cron
    commands.extend([
        {"cmd": "systemctl is-enabled cron 2>/dev/null || systemctl is-enabled crond 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "cron_enabled", "section": "5.1.1"},
        {"cmd": "stat /etc/crontab 2>/dev/null || echo 'no crontab'", "sudo": False, "key": "crontab_permissions", "section": "5.1.2"},
        {"cmd": "stat /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null || echo 'stat failed'", "sudo": False, "key": "cron_dirs_permissions", "section": "5.1.3"},
        {"cmd": "stat /etc/cron.d 2>/dev/null || echo 'no cron.d'", "sudo": False, "key": "crond_permissions", "section": "5.1.4"},
        {"cmd": "cat /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null || echo 'no cron allow/deny files'", "sudo": True, "key": "cron_access", "section": "5.1.5"},
    ])

    # 5.2 - SSH Server Configuration
    commands.extend([
        {"cmd": "cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no sshd config'", "sudo": True, "key": "sshd_config", "section": "5.2"},
        {"cmd": "stat /etc/ssh/sshd_config 2>/dev/null || echo 'no sshd config'", "sudo": False, "key": "sshd_config_permissions", "section": "5.2.1"},
        {"cmd": "find /etc/ssh -name 'ssh_host_*_key' -exec stat {} \\; 2>/dev/null || echo 'no host keys'", "sudo": True, "key": "ssh_host_keys_permissions", "section": "5.2.2"},
        {"cmd": "sshd -T 2>/dev/null | head -100 || echo 'sshd -T failed'", "sudo": True, "key": "sshd_effective_config", "section": "5.2"},
    ])

    # 5.3 - Configure PAM (distro-aware paths)
    # Ubuntu/Debian: /etc/pam.d/common-password, /etc/pam.d/common-auth
    # Rocky/RHEL: /etc/pam.d/system-auth, /etc/pam.d/password-auth
    if is_debian:
        pam_password_file = "/etc/pam.d/common-password"
        pam_auth_file = "/etc/pam.d/common-auth"
    else:
        pam_password_file = "/etc/pam.d/system-auth"
        pam_auth_file = "/etc/pam.d/password-auth"

    commands.extend([
        {"cmd": f"cat {pam_password_file} 2>/dev/null || echo 'no pam password config'", "sudo": True, "key": "pam_password", "section": "5.3.1"},
        {"cmd": f"cat {pam_auth_file} 2>/dev/null || echo 'no pam auth config'", "sudo": True, "key": "pam_auth", "section": "5.3.2"},
        {"cmd": "cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no pwquality config'", "sudo": True, "key": "pwquality_config", "section": "5.3.1"},
        {"cmd": "cat /etc/login.defs 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no login.defs'", "sudo": False, "key": "login_defs", "section": "5.3.3"},
    ])

    # 5.4 - User Accounts and Environment
    commands.extend([
        {"cmd": "cat /etc/shadow 2>/dev/null | head -50 || echo 'cannot read shadow'", "sudo": True, "key": "shadow_file", "section": "5.4.1"},
        {"cmd": "cat /etc/passwd | head -50", "sudo": False, "key": "passwd_file", "section": "5.4.2"},
        {"cmd": "cat /etc/group | head -50", "sudo": False, "key": "group_file", "section": "5.4.3"},
        {"cmd": "grep -E '^\\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null || echo 'not configured'", "sudo": False, "key": "pass_max_days", "section": "5.4.1.1"},
        {"cmd": "grep -E '^\\s*PASS_MIN_DAYS' /etc/login.defs 2>/dev/null || echo 'not configured'", "sudo": False, "key": "pass_min_days", "section": "5.4.1.2"},
        {"cmd": "grep -E '^\\s*PASS_WARN_AGE' /etc/login.defs 2>/dev/null || echo 'not configured'", "sudo": False, "key": "pass_warn_age", "section": "5.4.1.3"},
        {"cmd": "grep -E '^\\s*INACTIVE' /etc/default/useradd 2>/dev/null || echo 'not configured'", "sudo": False, "key": "inactive_days", "section": "5.4.1.4"},
        {"cmd": "useradd -D 2>/dev/null || echo 'useradd not available'", "sudo": False, "key": "useradd_defaults", "section": "5.4.1.5"},
    ])

    # 5.5 - Root Login
    commands.extend([
        {"cmd": "grep -E '^\\s*PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || echo 'not configured'", "sudo": True, "key": "permit_root_login", "section": "5.5.1"},
        {"cmd": "cat /etc/securetty 2>/dev/null || echo 'no securetty'", "sudo": True, "key": "securetty", "section": "5.5.2"},
    ])

    # 5.6 - Su Command
    commands.extend([
        {"cmd": "cat /etc/pam.d/su 2>/dev/null || echo 'no pam su config'", "sudo": True, "key": "pam_su", "section": "5.6"},
        {"cmd": "grep wheel /etc/group 2>/dev/null || echo 'no wheel group'", "sudo": False, "key": "wheel_group", "section": "5.6"},
    ])

    # ==================== SECTION 6: SYSTEM MAINTENANCE ====================

    # 6.1 - System File Permissions
    commands.extend([
        {"cmd": "stat /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || echo 'stat failed'", "sudo": True, "key": "system_files_permissions", "section": "6.1"},
        {"cmd": "stat /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow- 2>/dev/null || echo 'no backup files'", "sudo": True, "key": "system_backup_files_permissions", "section": "6.1"},
    ])

    # 6.2 - User and Group Settings
    commands.extend([
        {"cmd": "awk -F: '($3 == 0) { print $1 }' /etc/passwd 2>/dev/null || echo 'check failed'", "sudo": False, "key": "uid_0_accounts", "section": "6.2.1"},
        {"cmd": "awk -F: '($2 == \"\") { print $1 }' /etc/shadow 2>/dev/null || echo 'check failed'", "sudo": True, "key": "empty_password_accounts", "section": "6.2.2"},
        {"cmd": "grep -E '^\\+:' /etc/passwd /etc/shadow /etc/group 2>/dev/null || echo 'no legacy entries'", "sudo": True, "key": "legacy_entries", "section": "6.2.3"},
        {"cmd": "awk -F: 'BEGIN {c=0} ($3 >= 1000 && $3 != 65534) { c++; if (c <= 20) print $1\":\"$6 }' /etc/passwd 2>/dev/null || echo 'check failed'", "sudo": False, "key": "user_home_dirs", "section": "6.2.4"},
        {"cmd": "cat /etc/shells 2>/dev/null || echo 'no shells file'", "sudo": False, "key": "valid_shells", "section": "6.2.5"},
    ])

    # Additional security checks
    commands.extend([
        # SUID/SGID files (limited output)
        {"cmd": "find / -perm /6000 -type f 2>/dev/null | head -50 || echo 'find failed'", "sudo": True, "key": "suid_sgid_files", "section": "6.1.10"},
        # World-writable files (limited output)
        {"cmd": "find / -xdev -type f -perm -0002 2>/dev/null | head -30 || echo 'none found'", "sudo": True, "key": "world_writable_files", "section": "6.1.11"},
        # Unowned files (limited output)
        {"cmd": "find / -xdev -nouser -o -nogroup 2>/dev/null | head -30 || echo 'none found'", "sudo": True, "key": "unowned_files", "section": "6.1.12"},
    ])

    # ==================== EXPANDED COMMANDS ====================

    # PAM faillock / tally configuration
    commands.extend([
        {"cmd": "grep -E 'pam_faillock|pam_tally2' /etc/pam.d/* 2>/dev/null || echo 'not configured'", "sudo": True, "key": "pam_faillock", "section": "5.3.3"},
    ])

    # Mount options for specific partitions
    commands.extend([
        {"cmd": "findmnt -n /tmp -o OPTIONS 2>/dev/null || mount | grep '/tmp' | awk '{print $6}' || echo 'not mounted'", "sudo": False, "key": "mount_tmp_options", "section": "1.1.8"},
        {"cmd": "findmnt -n /var/tmp -o OPTIONS 2>/dev/null || mount | grep '/var/tmp' | awk '{print $6}' || echo 'not mounted'", "sudo": False, "key": "mount_var_tmp_options", "section": "1.1.8"},
        {"cmd": "findmnt -n /dev/shm -o OPTIONS 2>/dev/null || mount | grep '/dev/shm' | awk '{print $6}' || echo 'not mounted'", "sudo": False, "key": "mount_dev_shm_options", "section": "1.1.8"},
        {"cmd": "findmnt -n /home -o OPTIONS 2>/dev/null || mount | grep '/home' | awk '{print $6}' || echo 'not mounted'", "sudo": False, "key": "mount_home_options", "section": "1.1.8"},
    ])

    # User dot files checks
    commands.extend([
        {"cmd": "find /home -maxdepth 3 -name '.forward' 2>/dev/null | head -20 || echo 'none found'", "sudo": True, "key": "user_forward_files", "section": "6.2.7"},
        {"cmd": "find /home -maxdepth 3 -name '.netrc' 2>/dev/null | head -20 || echo 'none found'", "sudo": True, "key": "user_netrc_files", "section": "6.2.8"},
        {"cmd": "find /home -maxdepth 3 -name '.rhosts' 2>/dev/null | head -20 || echo 'none found'", "sudo": True, "key": "user_rhosts_files", "section": "6.2.9"},
    ])

    # Home directory permissions
    commands.extend([
        {"cmd": "awk -F: '($3 >= 1000 && $3 != 65534) { system(\"ls -ld \" $6 \" 2>/dev/null\") }' /etc/passwd 2>/dev/null | head -30 || echo 'check failed'", "sudo": False, "key": "user_home_dirs_permissions", "section": "6.2.5"},
    ])

    # SSH Banner
    commands.extend([
        {"cmd": "cat /etc/ssh/banner 2>/dev/null || cat /etc/ssh/sshd-banner 2>/dev/null || echo 'no banner file'", "sudo": False, "key": "ssh_banner", "section": "5.2.14"},
    ])

    # Journald specific settings
    commands.extend([
        {"cmd": "grep -E '^Compress=' /etc/systemd/journald.conf 2>/dev/null || echo 'not configured'", "sudo": False, "key": "journald_compress", "section": "4.1.1.2"},
        {"cmd": "grep -E '^Storage=' /etc/systemd/journald.conf 2>/dev/null || echo 'not configured'", "sudo": False, "key": "journald_storage", "section": "4.1.1.3"},
        {"cmd": "grep -E '^ForwardToSyslog=' /etc/systemd/journald.conf 2>/dev/null || echo 'not configured'", "sudo": False, "key": "journald_forward", "section": "4.1.1.4"},
    ])

    # UMASK check
    commands.extend([
        {"cmd": "grep -E '^UMASK' /etc/login.defs 2>/dev/null || echo 'not configured'", "sudo": False, "key": "umask_login_defs", "section": "5.4.1.5"},
    ])

    # Pam wheel/su restriction
    commands.extend([
        {"cmd": "grep -E 'pam_wheel' /etc/pam.d/su 2>/dev/null || echo 'not configured'", "sudo": True, "key": "pam_wheel", "section": "5.6"},
    ])

    # Password history (pam_pwhistory) - use distro-aware path
    commands.extend([
        {"cmd": f"grep -E 'pam_pwhistory|remember' {pam_password_file} 2>/dev/null || echo 'not configured'", "sudo": True, "key": "pam_pwhistory", "section": "5.3.2"},
    ])

    # ==================== RHEL-SPECIFIC EXPANDED CHECKS ====================
    if is_rhel_family:
        commands.extend([
            # 1.2.3 - Ensure gpgcheck is enabled for all repos
            {"cmd": "grep -rE '^\\s*gpgcheck\\s*=' /etc/yum.repos.d/ 2>/dev/null | grep -v 'gpgcheck=1' | head -20 || echo 'all repos have gpgcheck enabled'", "sudo": False, "key": "dnf_repo_gpgcheck", "section": "1.2.3"},
            # 1.2.4/1.2.5 - Crypto policy detail
            {"cmd": "update-crypto-policies --show 2>/dev/null || echo 'not available'", "sudo": False, "key": "crypto_policy_current", "section": "1.2.4"},
            # SELinux policy type
            {"cmd": "grep -E '^\\s*SELINUXTYPE' /etc/selinux/config 2>/dev/null || echo 'not configured'", "sudo": False, "key": "selinux_policy_type", "section": "1.6.3"},
            # 5.3 PAM - faillock configuration (RHEL 7+, replaces pam_tally2)
            {"cmd": "grep -rE 'pam_faillock' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || echo 'not configured'", "sudo": True, "key": "pam_faillock_rhel", "section": "5.3.3"},
            {"cmd": "cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'no faillock.conf'", "sudo": True, "key": "faillock_conf", "section": "5.3.3"},
            # 5.3 PAM - pwquality settings
            {"cmd": "grep -E 'minlen|dcredit|ucredit|lcredit|ocredit' /etc/security/pwquality.conf 2>/dev/null || echo 'not configured'", "sudo": False, "key": "pwquality_detail", "section": "5.3.1"},
            # GRUB2 specific permissions (RHEL path)
            {"cmd": "stat /boot/grub2/grub.cfg 2>/dev/null || echo 'no grub2 config'", "sudo": True, "key": "grub2_permissions", "section": "1.4.1"},
            {"cmd": "stat /boot/grub2/user.cfg 2>/dev/null || echo 'no grub2 user.cfg'", "sudo": True, "key": "grub2_user_cfg", "section": "1.4.2"},
            # Check if GRUB has password set
            {"cmd": "grep -E 'set superusers|password_pbkdf2' /boot/grub2/grub.cfg /boot/grub2/user.cfg /etc/grub.d/* 2>/dev/null | head -5 || echo 'no grub password'", "sudo": True, "key": "grub2_password", "section": "1.4.2"},
            # 5.4.2 - Ensure system accounts are secured (shell set to nologin/false)
            {"cmd": "awk -F: '($3 < 1000) {print $1\": \"$7}' /etc/passwd 2>/dev/null | grep -v '/sbin/nologin\\|/bin/false\\|halt\\|sync\\|shutdown' | head -20 || echo 'all system accounts secured'", "sudo": False, "key": "system_accounts_shell", "section": "5.4.2"},
            # Check for any remaining pam_tally2 (should not be present in RHEL 10)
            {"cmd": "grep -rE 'pam_tally2' /etc/pam.d/ 2>/dev/null | head -5 || echo 'pam_tally2 not found'", "sudo": True, "key": "pam_tally2_check", "section": "5.3"},
            # DNF automatic updates. No dnf-makecache fallback: that timer is
            # enabled by default and would mask a missing dnf-automatic.
            {"cmd": "systemctl is-enabled dnf-automatic.timer 2>/dev/null || echo 'not enabled'", "sudo": False, "key": "dnf_automatic", "section": "1.2.7"},
            # 1.6.2 - SELinux must not be disabled via kernel cmdline / grub
            {"cmd": "grep -E 'selinux=0|enforcing=0' /proc/cmdline /etc/default/grub /boot/grub2/grubenv 2>/dev/null || echo 'not disabled in bootloader'", "sudo": True, "key": "selinux_bootloader", "section": "1.6.2"},
            # 4.1.1.2/4.1.1.3 - auditing enabled at boot
            {"cmd": "cat /proc/cmdline 2>/dev/null || echo 'unknown'", "sudo": False, "key": "kernel_cmdline", "section": "4.1.1"},
            # 1.3.4/1.3.5 - AIDE filesystem integrity
            {"cmd": "rpm -q aide 2>/dev/null || echo 'not installed'", "sudo": False, "key": "aide_installed", "section": "1.3.4"},
            {"cmd": "grep -rs aide /etc/crontab /etc/cron.d /etc/cron.daily /var/spool/cron 2>/dev/null | head -5 || systemctl is-enabled aidecheck.timer 2>/dev/null || echo 'not scheduled'", "sudo": True, "key": "aide_cron", "section": "1.3.5"},
            # 1.8.1 - GDM (GUI login) not installed on servers
            {"cmd": "rpm -q gdm 2>/dev/null || echo 'not installed'", "sudo": False, "key": "gdm_installed", "section": "1.8.1"},
            # 5.2.20 - sshd must not override system-wide crypto policy
            {"cmd": "grep -E '^\\s*CRYPTO_POLICY=' /etc/sysconfig/sshd 2>/dev/null || echo 'not overridden'", "sudo": True, "key": "sshd_crypto_override", "section": "5.2.20"},
        ])
        # 1.2.6 - Subscription Manager (real RHEL only; Rocky/Alma have no RHSM)
        if distro_id == "rhel":
            commands.append({"cmd": "subscription-manager identity 2>&1 | head -5 || echo 'not registered'", "sudo": True, "key": "rhsm_identity", "section": "1.2.6"})

        # CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1 — additional data
        # collection (see app.modules.linux.rhel). Harmless on rhel_8/9: the
        # extra output is only scored by rules gated to the rhel_10/rocky_10
        # profiles. Imported lazily to avoid an import cycle at module load.
        from app.modules.linux.rhel import build_rhel10_audit_commands
        commands.extend(build_rhel10_audit_commands())

        # CIS RHEL 8 / 9 Benchmarks — additional data collection (repo_gpgcheck in
        # /etc/yum.conf on RHEL 8). Harmless on rhel_9/rhel_10: the extra output is
        # only scored by rules gated to the rhel_8 profile. Imported lazily to
        # avoid an import cycle at module load.
        from app.modules.linux.rhel import build_rhel_audit_commands
        commands.extend(build_rhel_audit_commands())

        # Rocky Linux 8/9/10 — additional data collection (repo_gpgcheck in
        # /etc/yum.conf on Rocky 8). Harmless on RHEL: the extra output is only
        # scored by rules gated to the rocky_* profiles. Imported lazily to
        # avoid an import cycle at module load.
        from app.modules.linux.rocky import build_rocky_audit_commands
        commands.extend(build_rocky_audit_commands())

    # CIS Ubuntu 22.04 / 24.04 Benchmarks — additional data collection (see
    # app.modules.linux.ubuntu). Harmless on ubuntu_20: the extra output is only
    # scored by rules gated to the ubuntu_22/ubuntu_24 profiles. Imported lazily
    # to avoid an import cycle at module load.
    if is_debian:
        from app.modules.linux.ubuntu import build_ubuntu_audit_commands
        commands.extend(build_ubuntu_audit_commands())

    return commands


def get_quick_audit_commands(distro_id: str = "ubuntu") -> List[Dict[str, Any]]:
    """
    Get a reduced set of essential audit commands for quick checks.

    Args:
        distro_id: Distribution ID

    Returns:
        List of essential command dictionaries
    """
    is_debian = distro_id in ("ubuntu", "debian")

    commands = [
        # Distro info
        {"cmd": "cat /etc/os-release", "sudo": False, "key": "os_release", "section": "info"},
        {"cmd": "uname -a", "sudo": False, "key": "uname", "section": "info"},

        # Critical security settings
        {"cmd": "sysctl kernel.randomize_va_space", "sudo": False, "key": "aslr", "section": "1.5.1"},
        {"cmd": "cat /etc/ssh/sshd_config | grep -v '^#' | grep -v '^$'", "sudo": True, "key": "sshd_config", "section": "5.2"},
        {"cmd": "cat /etc/login.defs | grep -E 'PASS_|UMASK'", "sudo": False, "key": "login_defs", "section": "5.4"},

        # Services
        {"cmd": "systemctl list-unit-files --state=enabled --type=service", "sudo": False, "key": "enabled_services", "section": "2"},

        # Firewall
        {"cmd": "ufw status verbose 2>/dev/null || firewall-cmd --state 2>/dev/null || echo 'no firewall'", "sudo": True, "key": "firewall", "section": "3.4"},

        # Logging
        {"cmd": "systemctl is-enabled auditd rsyslog 2>/dev/null", "sudo": False, "key": "logging_services", "section": "4"},

        # User accounts
        {"cmd": "awk -F: '($3 == 0) { print $1 }' /etc/passwd", "sudo": False, "key": "root_accounts", "section": "6.2.1"},
    ]

    # MAC framework
    if is_debian:
        commands.append({"cmd": "aa-status 2>/dev/null || echo 'apparmor not running'", "sudo": True, "key": "mac_status", "section": "1.3"})
    else:
        commands.append({"cmd": "getenforce 2>/dev/null || echo 'selinux unknown'", "sudo": False, "key": "mac_status", "section": "1.3"})

    return commands
