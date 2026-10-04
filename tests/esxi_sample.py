"""
Sample collector output of an ESXi 8.0 Update 2 host (esx01, standalone,
not in lockdown), in the shape the ESXi collection scripts print - esxcli's
own text formats. Built here, not captured from a host: no ESXi machine is
available to the test suite.

Typical out-of-the-box state with a few operator changes: SSH on, shell
timeouts 0, the stock password policy, no remote syslog, no NTP, one
community VIB, a second vSwitch accepting MAC changes and forged
transmits, a monitoring port group on VLAN 4095, an iSCSI adapter without
CHAP, and three VMs - one hardened, one default, one lab VM with a USB
controller and a nonpersistent disk.
"""
# The app is imported inside the functions: tests/fake_esxi.py imports the
# constants here in a process without the app on its path.

INT_OPTIONS = {
    "/UserVars/DcuiTimeOut": 600, "/UserVars/ESXiShellInteractiveTimeOut": 0, "/UserVars/ESXiShellTimeOut": 0,
    "/UserVars/HostClientSessionTimeout": 900, "/UserVars/HostClientCEIPOptIn": 0,
    "/UserVars/SuppressShellWarning": 0, "/UserVars/SuppressHyperthreadWarning": 0,
    "/Security/AccountLockFailures": 5, "/Security/AccountUnlockTime": 900, "/Security/PasswordHistory": 0,
    "/Security/PasswordMaxDays": 99999, "/Config/HostAgent/plugins/solo/enableMob": 0, "/Net/BlockGuestBPDU": 0,
    "/Syslog/global/auditRecord/storageEnable": 0, "/Syslog/global/auditRecord/remoteEnable": 0,
    "/Syslog/global/logFilteringEnabled": 0, "/Syslog/global/certificate/checkSSLCerts": 1,
    "/Mem/ShareForceSalting": 2, "/VMkernel/Boot/execInstalledOnly": 0,
}
STRING_OPTIONS = {
    "/Security/PasswordQualityControl": "retry=3 min=disabled,disabled,disabled,7,7",
    "/Config/HostAgent/log/level": "info", "/Net/DVFilterBindIpAddress": "", "/DCUI/Access": "root",
    "/Annotations/WelcomeMessage": "", "/Config/Etc/issue": "", "/Syslog/global/logHost": "",
}


def advanced(ints=None, strings=None):
    from app.modules.esxi.collect import ADVANCED_OPTIONS
    ints = {**INT_OPTIONS, **(ints or {})}
    strings = {**STRING_OPTIONS, **(strings or {})}
    out = []
    for path in ADVANCED_OPTIONS:
        out.append(f"### {path}")
        if path in strings:
            out += ["   Type: string", "   Int Value: 0", f"   String Value: {strings[path]}"]
        else:
            out += ["   Type: integer", f"   Int Value: {ints[path]}", "   String Value: "]
    return "\n".join(out)


def firewall_rulesets(open_all=("vSphereClient", "webAccess", "CIMHttpServer", "CIMHttpsServer")):
    enabled = {"sshServer": True, "sshClient": False, "nfsClient": False, "dhcp": True, "dns": True, "snmp": False,
               "ntpClient": False, "CIMHttpServer": True, "CIMHttpsServer": True, "CIMSLP": False,
               "vSphereClient": True, "webAccess": True, "syslog": False, "vMotion": True}
    lines = ["Name            Enabled", "--------------  -------"]
    lines += [f"{n:<16}{str(e).lower()}" for n, e in enabled.items()]
    lines += ["### allowedip", "Ruleset         Allowed IP Addresses", "--------------  --------------------"]
    for n in enabled:
        lines.append(f"{n:<16}{'All' if n in open_all or n not in ('sshServer', 'vMotion') else '10.10.0.0/24'}")
    return "\n".join(lines)


def policy(promisc="false", mac="false", forged="false"):
    return (f"   Allow Promiscuous: {promisc}\n   Allow MAC Address Changes: {mac}\n"
            f"   Allow Forged Transmits: {forged}")


VSWITCH = "\n".join([
    "### vswitch|vSwitch0", policy(),
    "### vswitch|vSwitch1", policy(mac="true", forged="true"),
    "### portgroup|Management Network|vSwitch0|0", policy(),
    "### portgroup|VM Network|vSwitch0|20", policy(),
    "### portgroup|Backup Network|vSwitch1|30", policy(mac="true", forged="true"),
    "### portgroup|Trunk-Monitor|vSwitch1|4095", policy(promisc="true", mac="true", forged="true"),
])

HARDENED_VMX = [
    'isolation.tools.copy.disable = "TRUE"', 'isolation.tools.paste.disable = "TRUE"',
    'isolation.tools.dnd.disable = "TRUE"', 'isolation.tools.diskShrink.disable = "TRUE"',
    'isolation.tools.diskWiper.disable = "TRUE"', 'isolation.device.connectable.disable = "TRUE"',
    'tools.setInfo.sizeLimit = "1048576"', 'RemoteDisplay.maxConnections = "1"', 'log.keepOld = "10"',
    'log.rotateSize = "2048000"', 'tools.guestlib.enableHostInfo = "FALSE"', 'mks.enable3d = "FALSE"',
]
VMS = "\n".join(
    ["### db01"] + HARDENED_VMX
    + ["### web01", 'tools.guestlib.enableHostInfo = "FALSE"', 'scsi0:0.mode = "persistent"']
    + ["### lab-nested", 'usb.present = "TRUE"', 'serial0.present = "TRUE"', 'scsi0:1.mode = "independent-nonpersistent"',
       'isolation.tools.copy.disable = "FALSE"', 'pciPassthru0.present = "TRUE"']
    + ["END"])

SECTIONS = {
    "ESXI_VERSION": "VMware ESXi 8.0.2 build-22380479\nVMware ESXi 8.0 Update 2",
    "ADVANCED": None,  # filled in by dump()
    "SERVICES": "\n".join([
        "SSH|on|SSH is running", "ESXShell|off|ESXShell is not running", "slpd|off|slpd is not running",
        "sfcbd-watchdog|on|sfcbd is running", "snmpd|off|snmpd is not running", "ntpd|off|ntpd is not running"]),
    "NTP": "   Enabled: false\n   Loglevel: warning\n   Server: ",
    "SYSLOG": "\n".join([
        "   Check Certificate Revocation: false", "   Default Network Retry Timeout: 180",
        "   Enforce SSLCertificates: true", "   Local Log Output: /scratch/log",
        "   Local Log Output Is Configured: false", "   Local Log Output Is Persistent: true",
        "   Log Level: error", "   Log Filtering: false", "   Remote Host: <none>"]),
    "COREDUMP": "   Enabled: false\n   Host VNic: \n   Network Server IP: \n   Network Server Port: 0",
    "FIREWALL": "   Default Action: DROP\n   Enabled: true\n   Loaded: true\n### rulesets\n" + firewall_rulesets(),
    "SNMP": "\n".join(["   Authentication: ", "   Communities: ", "   Enable: false", "   Engineid: ",
                       "   Hwsrc: indications", "   Port: 161", "   Privacy: ", "   Syscontact: ",
                       "   Syslocation: ", "   Targets: ", "   Users: "]),
    "ACCEPTANCE": "PartnerSupported",
    "VIBS": "\n".join([
        "esx-base|8.0.2-0.0.22380479|VMware|VMwareCertified", "vsan|8.0.2-0.0.22380479|VMware|VMwareCertified",
        "lsi-mr3|7.727.02.00-1OEM.800.1.0.20613240|BCM|VMwareCertified",
        "nvidia-vgpu|535.104.06-1OEM.800.1.0.20613240|NVD|PartnerSupported",
        "net-usbnic|1.12-2vmw.800.1.0.20613240|VFrontDe|CommunitySupported"]),
    "ENCRYPTION": ("   Mode: NONE\n   Require Executables Only From Installed VIBs: false\n"
                   "   Require Secure Boot: false"),
    "FIPS": "ssh=true\nrhttpproxy=true",
    "LOCKDOWN": 'lockdownMode = "lockdownDisabled"',
    "SSH_KEYS": "1",
    "ACCOUNTS": "root\ndcui\nvpxuser\nopsadmin",
    "VSWITCH": VSWITCH,
    "ISCSI": "### vmhba64\n   Level: prohibited\n   Mutual Level: prohibited\nEND",
    "VMS": VMS,
}


def dump(**changes) -> str:
    from app.modules.benchmark.rules import assemble
    return assemble({**SECTIONS, "ADVANCED": advanced(), **changes})
