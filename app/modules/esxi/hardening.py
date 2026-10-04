"""
VMware ESXi remediation with esxcli and vim-cmd.

Advanced settings are set with `esxcli system settings advanced set` and
verified by reading them back. SSH itself (5.3) and lockdown mode (5.4) are
left to the operator: this module works over SSH, and lockdown mode is
managed from vCenter. VM settings (section 8) change the .vmx and are applied
from vCenter or the Host Client with the VM powered off.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from . import rules as R

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))
TEMPLATES.param(ParamMeta(
    name="NTP_SERVERS", input_type="text", label="NTP servers",
    description="Comma-separated NTP servers (host names or addresses).", required=True,
    validation=r"[A-Za-z0-9.:-]+(,[A-Za-z0-9.:-]+)*", placeholder="ntp1.corp.example.com,ntp2.corp.example.com"))
TEMPLATES.param(ParamMeta(
    name="SYSLOG_HOST", input_type="text", label="Remote syslog collector",
    description="Collector URL: ssl://host:1514, tcp://host:514 or udp://host:514.", required=True,
    validation=r"(udp|tcp|ssl)://[A-Za-z0-9.:\[\]-]+", placeholder="ssl://syslog.corp.example.com:1514"))
TEMPLATES.param(ParamMeta(
    name="BANNER_TEXT", input_type="text", label="Login banner text",
    description="Warning shown on the DCUI and before SSH login.", required=True,
    validation=r"[A-Za-z0-9 .,:()/-]{10,400}", placeholder="Authorized use only. Activity is monitored."))


def _add(sec, description, statements, verify, warning=None, params=(), restart=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"ESXI-{sec}", description=description, statements=statements, verify_statements=verify,
        parameters=list(params), warning=warning, requires_restart=restart))


def _read(path: str, field: str) -> str:
    return (f"esxcli system settings advanced list -o {path} | awk -F': ' '/^ *{field}:/ "
            "{ sub(/^ */, \"\", $2); print $2; exit }'")


def adv_int(sec, description, path, value, cond, warning=None, params=()):
    """cond: a test on $v (the read-back integer), e.g. '[ \"$v\" -le 600 ]'."""
    _add(sec, description, [f"esxcli system settings advanced set -o {path} -i {value}"],
         [f"v=$({_read(path, 'Int Value')}); if [ -n \"$v\" ] && {cond}; then echo PASS; else echo FAIL; fi"],
         warning=warning, params=params)


def adv_str(sec, description, path, value, cond, warning=None, params=()):
    _add(sec, description, [f"esxcli system settings advanced set -o {path} -s '{value}'"],
         [f"v=$({_read(path, 'String Value')}); if {cond}; then echo PASS; else echo FAIL; fi"],
         warning=warning, params=params)


# 1 Install
_add("1.2", "Set the VIB acceptance level to PartnerSupported",
     ["esxcli software acceptance set --level=PartnerSupported"],
     ["case \"$(esxcli software acceptance get)\" in VMwareCertified|VMwareAccepted|PartnerSupported) echo PASS;; "
      "*) echo FAIL;; esac"],
     warning="Community-supported VIBs can no longer be installed; esxcli refuses the change while any are installed.",
     params=["CONFIRM"])
_add("1.4", "Enforce Secure Boot", ["esxcli system settings encryption set --require-secure-boot=T"],
     ["esxcli system settings encryption get | grep -q 'Require Secure Boot: true' && echo PASS || echo FAIL"],
     warning="The host only boots with UEFI Secure Boot enabled in its firmware and a TPM 2.0; check both first. "
             "Takes effect at the next reboot.", params=["CONFIRM"], restart=True)
_add("1.5", "Protect the host configuration with the TPM", ["esxcli system settings encryption set --mode=TPM"],
     ["esxcli system settings encryption get | grep -q 'Mode: TPM' && echo PASS || echo FAIL"],
     warning="Needs a TPM 2.0. Back up the recovery key (esxcli system settings encryption recovery list) - "
             "without it a replaced TPM leaves the host unbootable.", params=["CONFIRM"], restart=True)
_add("1.6", "Allow only executables from installed VIBs",
     ["esxcli system settings encryption set --require-exec-installed-only=T"],
     ["esxcli system settings encryption get | grep -q 'Require Executables Only From Installed VIBs: true' "
      "&& echo PASS || echo FAIL"],
     warning="Scripts and binaries copied to the host outside a VIB stop running. Takes effect at the next reboot.",
     params=["CONFIRM"], restart=True)

# 2 Communication
_add("2.1", "Configure and enable NTP",
     ["set -- $(echo '{NTP_SERVERS}' | tr ',' ' '); a=''; for s in \"$@\"; do a=\"$a -s $s\"; done; "
      "esxcli system ntp set $a -e true; esxcli network firewall ruleset set -r ntpClient -e true"],
     ["esxcli system ntp get | grep -q 'Enabled: true' && esxcli system ntp get | grep -qE 'Server: .+' "
      "&& echo PASS || echo FAIL"], params=["NTP_SERVERS"])
_add("2.2", "Enable the firewall with a default DROP action",
     ["esxcli network firewall set --enabled=true --default-action=false"],
     ["esxcli network firewall get | grep -q 'Default Action: DROP' && esxcli network firewall get | "
      "grep -q 'Enabled: true' && echo PASS || echo FAIL"],
     warning="Traffic not allowed by a ruleset is dropped.", params=["CONFIRM"])
adv_int("2.4", "Disable the Managed Object Browser", "/Config/HostAgent/plugins/solo/enableMob", 0, "[ \"$v\" = 0 ]")
_add("2.5", "Disable SNMP", ["esxcli system snmp set --enable=false"],
     ["esxcli system snmp get | grep -q 'Enable: false' && echo PASS || echo FAIL"],
     warning="Monitoring systems that poll this host over SNMP stop receiving data.", params=["CONFIRM"])
_add("2.6", "Clear the dvfilter API bind address", ["esxcli system settings advanced set -o /Net/DVFilterBindIpAddress -d"],
     [f"v=$({_read('/Net/DVFilterBindIpAddress', 'String Value')}); [ -z \"$v\" ] && echo PASS || echo FAIL"],
     warning="Network security appliances that use the dvfilter API stop working.", params=["CONFIRM"])
_add("2.9", "Stop and disable the SLP service",
     ["/etc/init.d/slpd stop; esxcli network firewall ruleset set -r CIMSLP -e 0; chkconfig slpd off"],
     ["chkconfig --list | awk '$1==\"slpd\" {print $2}' | grep -qx off && /etc/init.d/slpd status 2>&1 | "
      "grep -qi 'not running' && echo PASS || echo FAIL"],
     warning="CIM-based hardware monitoring that discovers the host through SLP stops finding it.", params=["CONFIRM"])
adv_int("2.10", "Block guest BPDUs", "/Net/BlockGuestBPDU", 1, "[ \"$v\" = 1 ]")
_add("2.11", "Use FIPS 140-2 cryptography for SSH", ["esxcli system security fips140 ssh set -e true"],
     ["esxcli system security fips140 ssh get | grep -q 'Enabled: true' && echo PASS || echo FAIL"],
     warning="SSH clients that only offer non-FIPS algorithms can no longer connect.")
_add("2.12", "Use FIPS 140-2 cryptography for the reverse HTTP proxy",
     ["esxcli system security fips140 rhttpproxy set -e true"],
     ["esxcli system security fips140 rhttpproxy get | grep -q 'Enabled: true' && echo PASS || echo FAIL"],
     warning="Takes effect when rhttpproxy restarts (/etc/init.d/rhttpproxy restart, or a reboot).", restart=True)

# 3 Logging
_add("3.3", "Send logs to a remote syslog collector",
     ["esxcli system syslog config set --loghost='{SYSLOG_HOST}'; esxcli network firewall ruleset set -r syslog -e true; "
      "esxcli system syslog reload"],
     [f"v=$({_read('/Syslog/global/logHost', 'String Value')}); [ \"$v\" = '{{SYSLOG_HOST}}' ] && echo PASS || echo FAIL"],
     params=["SYSLOG_HOST"])
_add("3.4", "Store audit records on the host", ["esxcli system auditrecords local enable"],
     [f"v=$({_read('/Syslog/global/auditRecord/storageEnable', 'Int Value')}); [ \"$v\" = 1 ] && echo PASS || echo FAIL"])
_add("3.5", "Send audit records to the remote collector", ["esxcli system auditrecords remote enable"],
     [f"v=$({_read('/Syslog/global/auditRecord/remoteEnable', 'Int Value')}); [ \"$v\" = 1 ] && echo PASS || echo FAIL"])
adv_int("3.6", "Disable log filtering", "/Syslog/global/logFilteringEnabled", 0, "[ \"$v\" = 0 ]")
adv_str("3.7", "Set the host agent log level to info", "/Config/HostAgent/log/level", "info", "[ \"$v\" = info ]")
adv_int("3.8", "Check the syslog collector's certificate", "/Syslog/global/certificate/checkSSLCerts", 1, "[ \"$v\" = 1 ]")

# 4 Access
adv_str("4.2", "Require complex passwords (15 characters minimum)", "/Security/PasswordQualityControl",
        f"retry=3 {R.PASSWORD_POLICY}", f"echo \"$v\" | grep -q '{R.PASSWORD_POLICY}'",
        warning="New and changed passwords must be at least 15 characters; existing passwords keep working.")
adv_int("4.3", "Lock accounts after 5 failed logins", "/Security/AccountLockFailures", 5, "[ \"$v\" -ge 1 ] && [ \"$v\" -le 5 ]")
adv_int("4.4", "Unlock accounts after 15 minutes", "/Security/AccountUnlockTime", 900, "[ \"$v\" -ge 900 ]")
adv_int("4.5", "Remember the last 5 passwords", "/Security/PasswordHistory", 5, "[ \"$v\" -ge 5 ]")
adv_int("4.6", "Expire passwords after 90 days", "/Security/PasswordMaxDays", 90, "[ \"$v\" -ge 1 ] && [ \"$v\" -le 90 ]",
        warning="Local account passwords older than 90 days must be changed at the next login, root included.",
        params=["CONFIRM"])
adv_str("4.10", "Allow only root to override lockdown mode at the DCUI", "/DCUI/Access", "root", "[ \"$v\" = root ]",
        warning="Other accounts listed in DCUI.Access lose DCUI access in lockdown mode.", params=["CONFIRM"])

# 5 Console
adv_int("5.1", "Time out the DCUI after 600 seconds", "/UserVars/DcuiTimeOut", 600, "[ \"$v\" -ge 1 ] && [ \"$v\" -le 600 ]")
_add("5.2", "Disable and stop the ESXi shell", ["vim-cmd hostsvc/disable_esx_shell; vim-cmd hostsvc/stop_esx_shell"],
     ["chkconfig --list | awk '$1==\"ESXShell\" {print $2}' | grep -qx off && /etc/init.d/ESXShell status 2>&1 | "
      "grep -qi 'not running' && echo PASS || echo FAIL"])
_add("5.5", "Remove root's SSH authorized keys", [": > /etc/ssh/keys-root/authorized_keys"],
     ["[ \"$(grep -cvE '^[[:space:]]*(#|$)' /etc/ssh/keys-root/authorized_keys)\" = 0 ] && echo PASS || echo FAIL"],
     warning="Key-based SSH logins as root stop working; automation using them must switch to another method.",
     params=["CONFIRM"])
adv_int("5.6", "Close idle shell and SSH sessions after 300 seconds", "/UserVars/ESXiShellInteractiveTimeOut", 300,
        "[ \"$v\" -ge 1 ] && [ \"$v\" -le 300 ]")
adv_int("5.7", "Stop the shell services 1 hour after they start", "/UserVars/ESXiShellTimeOut", 3600,
        "[ \"$v\" -ge 1 ] && [ \"$v\" -le 3600 ]",
        warning="SSH and the ESXi shell turn themselves off one hour after being started.", params=["CONFIRM"])
adv_int("5.8", "Close idle Host Client sessions after 900 seconds", "/UserVars/HostClientSessionTimeout", 900,
        "[ \"$v\" -ge 1 ] && [ \"$v\" -le 900 ]")
adv_str("5.9", "Set the DCUI welcome message", "/Annotations/WelcomeMessage", "{BANNER_TEXT}", "[ -n \"$v\" ]",
        params=["BANNER_TEXT"])
adv_str("5.10", "Set the SSH login banner", "/Config/Etc/issue", "{BANNER_TEXT}", "[ -n \"$v\" ]",
        params=["BANNER_TEXT"])
adv_int("5.11", "Show the ESXi shell warning", "/UserVars/SuppressShellWarning", 0, "[ \"$v\" = 0 ]")
adv_int("5.12", "Show the hyperthreading warning", "/UserVars/SuppressHyperthreadWarning", 0, "[ \"$v\" = 0 ]")
adv_int("5.13", "Opt the Host Client out of CEIP", "/UserVars/HostClientCEIPOptIn", 2, "[ \"$v\" = 2 ]")

# 7 Network
_POLICY_SET = ("--allow-forged-transmits=false", "--allow-mac-change=false", "--allow-promiscuous=false")
_POLICY_FIELD = ("Allow Forged Transmits", "Allow MAC Address Changes", "Allow Promiscuous")
_PG_LIST = ("esxcli network vswitch standard portgroup list | tail -n +3 | "
            "awk '{ $NF=\"\"; $(NF-1)=\"\"; $(NF-2)=\"\"; sub(/ +$/, \"\"); print }'")
_POLICY_TEXT = ("forged transmits", "MAC address changes", "promiscuous mode")
for _sec, _opt, _field, _text, _warn in zip(
        ("7.1", "7.2", "7.3"), _POLICY_SET, _POLICY_FIELD, _POLICY_TEXT,
        ("VMs that send frames with a different source MAC (nested ESXi, some load balancers) lose connectivity.",
         "VMs that change their MAC address inside the guest (some clusters, nested ESXi) lose connectivity.",
         "Network monitors and IDS VMs that rely on promiscuous mode stop seeing other VMs' traffic.")):
    _add(_sec, f"Reject {_text} on every standard vSwitch and port group",
         ["esxcli network vswitch standard list | grep -E '^[^ ]' | while read -r v; do "
          f"esxcli network vswitch standard policy security set -v \"$v\" {_opt} || exit 1; done && "
          f"{_PG_LIST} | while read -r p; do esxcli network vswitch standard portgroup policy security set -p \"$p\" "
          f"{_opt} || exit 1; done"],
         ["r=PASS; esxcli network vswitch standard list | grep -E '^[^ ]' | while read -r v; do "
          f"esxcli network vswitch standard policy security get -v \"$v\" | grep -q '{_field}: true' && echo FAIL; done; "
          f"{_PG_LIST} | while read -r p; do esxcli network vswitch standard portgroup policy security get -p \"$p\" | "
          f"grep -q '{_field}: true' && echo FAIL; done; echo $r"],
         warning=_warn, params=["CONFIRM"])
adv_int("7.8", "Salt transparent page sharing per VM", "/Mem/ShareForceSalting", 2, "[ \"$v\" = 2 ]")

# Guidance only
_GUIDANCE = {
    "1.1": "Patch the host with vSphere Lifecycle Manager or esxcli software profile update.",
    "1.3": "Remove unapproved community VIBs: esxcli software vib remove -n <vib>.",
    "2.3": "Limit each enabled ruleset to management networks: esxcli network firewall ruleset set -r <ruleset> -a false; "
           "esxcli network firewall ruleset allowedip add -r <ruleset> -i <network>.",
    "3.1": "Point network core dumps at a collector: esxcli system coredump network set -v vmk0 -i <ip> -o 6500 -e true.",
    "3.2": "Set Syslog.global.logDir to a directory on a persistent datastore.",
    "5.3": "When auditing and hardening are done: vim-cmd hostsvc/disable_ssh; vim-cmd hostsvc/stop_ssh. "
           "(This module connects over SSH, so it does not turn SSH off itself.)",
    "5.4": "Enable lockdown mode from vCenter (Configure > System > Security Profile > Lockdown Mode).",
    "6.1": "Configure mutual CHAP on each iSCSI adapter and target.",
    "7.4": "Move port groups off VLAN 4095 unless the guests tag VLANs themselves.",
    "7.5": "Move port groups off the native VLAN.",
    "7.6": "Move port groups off VLAN IDs reserved by the physical switches.",
}
for _r in R.all_rules():
    if _r.id not in TEMPLATES.templates:
        TEMPLATES.manual(_r.id, _GUIDANCE.get(_r.section, _r.remediation))
