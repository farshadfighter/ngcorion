"""
Read-only collection for an ESXi 7/8 audit, over SSH with esxcli and
vim-cmd (the ESXi shell is busybox; there is no sudo - the account needs the
Administrator role).

Advanced settings are read one by one (only the options the benchmark
names), plus services, NTP, syslog, core dump, firewall, SNMP, software
acceptance level and VIBs, boot/encryption settings, standard vSwitch and
port group security policies, iSCSI CHAP direction, lockdown mode, the
number of root SSH keys (never the keys), and for each registered VM the
.vmx keys the benchmark names - other .vmx lines (guestinfo values can hold
secrets) are never read.
"""

from typing import Dict

from app.modules.benchmark.rules import assemble

NOT_ESXI = "NOT_ESXI"

ADVANCED_OPTIONS = (
    "/UserVars/DcuiTimeOut", "/UserVars/ESXiShellInteractiveTimeOut", "/UserVars/ESXiShellTimeOut",
    "/UserVars/HostClientSessionTimeout", "/UserVars/HostClientCEIPOptIn", "/UserVars/SuppressShellWarning",
    "/UserVars/SuppressHyperthreadWarning", "/Security/AccountLockFailures", "/Security/AccountUnlockTime",
    "/Security/PasswordQualityControl", "/Security/PasswordHistory", "/Security/PasswordMaxDays",
    "/Config/HostAgent/plugins/solo/enableMob", "/Config/HostAgent/log/level", "/Net/BlockGuestBPDU",
    "/Net/DVFilterBindIpAddress", "/DCUI/Access", "/Annotations/WelcomeMessage", "/Config/Etc/issue",
    "/Syslog/global/logHost", "/Syslog/global/auditRecord/storageEnable", "/Syslog/global/auditRecord/remoteEnable",
    "/Syslog/global/logFilteringEnabled", "/Syslog/global/certificate/checkSSLCerts", "/Mem/ShareForceSalting",
    "/VMkernel/Boot/execInstalledOnly",
)

ADVANCED = ("for o in " + " ".join(ADVANCED_OPTIONS) + "; do echo \"### $o\"; "
            "esxcli system settings advanced list -o \"$o\" 2>&1 | grep -E '^ *(Type|Int Value|String Value):'; done")

SERVICES = (
    "for s in SSH ESXShell slpd sfcbd-watchdog snmpd ntpd; do "
    "p=$(chkconfig --list 2>/dev/null | awk -v n=\"$s\" '$1==n {print $2}'); "
    "r=$(/etc/init.d/$s status 2>&1 | head -1); echo \"$s|${p:-unknown}|$r\"; done"
)

VSWITCH = (
    "esxcli network vswitch standard list 2>/dev/null | grep -E '^[^ ]' | while read -r v; do "
    "echo \"### vswitch|$v\"; esxcli network vswitch standard policy security get -v \"$v\"; done; "
    "esxcli network vswitch standard portgroup list | tail -n +3 | "
    "awk '{ vlan=$NF; clients=$(NF-1); vs=$(NF-2); $NF=\"\"; $(NF-1)=\"\"; $(NF-2)=\"\"; "
    "sub(/ +$/, \"\"); print $0 \"|\" vs \"|\" vlan }' | while IFS='|' read -r pg vs vlan; do "
    "echo \"### portgroup|$pg|$vs|$vlan\"; esxcli network vswitch standard portgroup policy security get -p \"$pg\"; done"
)

ISCSI = (
    "esxcli iscsi adapter list 2>/dev/null | tail -n +3 | awk '{print $1}' | while read -r a; do "
    "echo \"### $a\"; esxcli iscsi adapter auth chap get -A \"$a\" -d uni 2>&1 | grep -E 'Level'; "
    "esxcli iscsi adapter auth chap get -A \"$a\" -d mutual 2>&1 | grep -E 'Level' | sed 's/Level/Mutual Level/'; done; echo END"
)

# Only these .vmx keys are read.
VMX_KEYS = ("isolation\\.tools\\.(copy|paste|dnd|diskShrink|diskWiper)\\.disable|isolation\\.device\\.connectable\\.disable|"
            "tools\\.setInfo\\.sizeLimit|tools\\.guestlib\\.enableHostInfo|RemoteDisplay\\.maxConnections|log\\.keepOld|"
            "log\\.rotateSize|mks\\.enable3d|(floppy|serial|parallel|usb)[0-9]*\\.present|scsi[0-9]+:[0-9]+\\.mode|"
            "pciPassthru[0-9]+\\.present")
VMS = (
    "vim-cmd vmsvc/getallvms 2>/dev/null | tail -n +2 | "
    "sed -n 's/^\\([0-9][0-9]*\\) *\\(.*[^ ]\\) *\\[\\([^]]*\\)\\] \\([^ ]*\\.vmx\\).*/\\2|\\3|\\4/p' | "
    "while IFS='|' read -r name ds path; do echo \"### $name\"; "
    f"grep -iE '^({VMX_KEYS}) *=' \"/vmfs/volumes/$ds/$path\" 2>/dev/null | tr -d '\\r'; done; echo END"
)

COMMANDS = {
    "ESXI_VERSION": f"vmware -vl 2>/dev/null || echo {NOT_ESXI}",
    "ADVANCED": ADVANCED,
    "SERVICES": SERVICES,
    "NTP": "esxcli system ntp get 2>&1",
    "SYSLOG": "esxcli system syslog config get",
    "COREDUMP": "esxcli system coredump network get",
    "FIREWALL": "esxcli network firewall get; echo '### rulesets'; esxcli network firewall ruleset list; "
                "echo '### allowedip'; esxcli network firewall ruleset allowedip list",
    "SNMP": "esxcli system snmp get",
    "ACCEPTANCE": "esxcli software acceptance get",
    "VIBS": "esxcli software vib list | tail -n +3 | awk '{print $1 \"|\" $2 \"|\" $3 \"|\" $4}'",
    "ENCRYPTION": "esxcli system settings encryption get 2>&1",
    "FIPS": "echo \"ssh=$(esxcli system security fips140 ssh get 2>&1 | awk -F': ' '/Enabled/ {print $2}')\"; "
            "echo \"rhttpproxy=$(esxcli system security fips140 rhttpproxy get 2>&1 | awk -F': ' '/Enabled/ {print $2}')\"",
    "LOCKDOWN": "vim-cmd hostsvc/hostsummary 2>/dev/null | grep -o 'lockdownMode = \"[A-Za-z]*\"' || echo unknown",
    # grep -c exits 1 when it counts 0; the count is printed either way.
    "SSH_KEYS": "n=$(grep -cvE '^[[:space:]]*(#|$)' /etc/ssh/keys-root/authorized_keys 2>/dev/null); echo \"${n:-0}\"",
    "ACCOUNTS": "esxcli system account list | tail -n +3 | awk '{print $1}'",
    "VSWITCH": VSWITCH,
    "ISCSI": ISCSI,
    "VMS": VMS,
}


def esxi_commands() -> Dict[str, str]:
    return dict(COMMANDS)


def collect(conn) -> str:
    version = conn.run(COMMANDS["ESXI_VERSION"])
    if NOT_ESXI in version or "VMware ESXi" not in version:
        return assemble({"ESXI_VERSION": NOT_ESXI})
    out = {"ESXI_VERSION": version}
    out.update({name: conn.run(script) for name, script in COMMANDS.items() if name != "ESXI_VERSION"})
    return assemble(out)
