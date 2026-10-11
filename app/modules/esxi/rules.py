"""
VMware ESXi 7/8 rules after the CIS VMware ESXi Benchmark: 1 install,
2 communication, 3 logging, 4 access, 5 console, 6 storage, 7 network,
8 virtual machines (each registered VM's .vmx).

This module reaches the host over SSH, so the "SSH disabled" control (5.3)
fails while the audit runs by design; disable SSH once auditing and
hardening are done. Item numbers follow the benchmark's content rather than
a specific edition's PDF and can differ slightly from the edition in use.
"""

import re
from typing import Dict, List, Optional, Tuple

from app.modules.benchmark.rules import BenchmarkRule, section

from .collect import NOT_ESXI

PASSWORD_POLICY = "min=disabled,disabled,disabled,disabled,15"
RESERVED_VLANS = set(range(1001, 1025)) | set(range(3968, 4048)) | {4094}


# ── data access ──────────────────────────────────────────────────────────

def _blocks(d, name) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    cur = None
    for line in section(d, name).splitlines():
        if line.startswith("### "):
            cur = line[4:].strip()
            out[cur] = []
        elif cur is not None and line.strip() and line.strip() != "END":
            out[cur].append(line.strip())
    return out


def _kv(lines) -> Dict[str, str]:
    out = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def adv(d, path) -> Optional[str]:
    """An advanced option's value (int options as their number, strings as text)."""
    info = _kv(_blocks(d, "ADVANCED").get(path, []))
    if not info:
        return None
    if info.get("Type", "").lower() in ("string",):
        return info.get("String Value", "")
    return info.get("Int Value")


def adv_int(d, path) -> Optional[int]:
    """An advanced setting as an integer, or None."""
    try:
        return int(adv(d, path))
    except (TypeError, ValueError):
        return None


def kv_section(d, name) -> Dict[str, str]:
    return _kv(section(d, name).splitlines())


def services(d) -> Dict[str, Tuple[str, str]]:
    """Services by key: (running state, startup policy)."""
    out = {}
    for line in section(d, "SERVICES").splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3:
            out[parts[0]] = (parts[1], parts[2])
    return out


def service_text(d, name) -> str:
    policy, status = services(d).get(name, ("unknown", "not reported"))
    return f"startup policy {policy}, {status}"


def service_off(d, name) -> bool:
    policy, status = services(d).get(name, ("unknown", ""))
    return policy == "off" and "not running" in status.lower()


def _table_rows(text):
    """The data rows of an esxcli table (header and dash rule dropped)."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    for i, line in enumerate(lines):
        if line.lstrip().startswith("---"):
            return lines[i + 1:]
    return lines


def firewall(d) -> Tuple[Dict[str, str], Dict[str, bool], Dict[str, str]]:
    """The firewall: global settings, enabled state per ruleset, allowed IPs per ruleset."""
    text = section(d, "FIREWALL")
    head, _, rest = text.partition("### rulesets")
    rulesets_text, _, allowed_text = rest.partition("### allowedip")
    enabled = {}
    for line in _table_rows(rulesets_text):
        parts = line.split()
        if len(parts) >= 2:
            enabled[parts[0]] = parts[-1] == "true"
    allowed = {}
    for line in _table_rows(allowed_text):
        parts = line.split(None, 1)
        if len(parts) == 2:
            allowed[parts[0]] = parts[1].strip()
    return _kv(head.splitlines()), enabled, allowed


def vswitch_policies(d) -> List[Tuple[str, str, Dict[str, str], Optional[int]]]:
    """(kind, name, policy, vlan) for each standard vSwitch and port group."""
    out = []
    for key, lines in _blocks(d, "VSWITCH").items():
        parts = key.split("|")
        if parts[0] == "vswitch" and len(parts) >= 2:
            out.append(("vSwitch", parts[1], _kv(lines), None))
        elif parts[0] == "portgroup" and len(parts) >= 4:
            vlan = int(parts[3]) if parts[3].isdigit() else None
            out.append(("port group", parts[1], _kv(lines), vlan))
    return out


def vms(d) -> Dict[str, Dict[str, str]]:
    """Per VM, its .vmx settings (lower-case keys)."""
    out = {}
    for name, lines in _blocks(d, "VMS").items():
        keys = {}
        for line in lines:
            if "=" in line:
                k, v = line.split("=", 1)
                keys[k.strip().lower()] = v.strip().strip('"')
        out[name] = keys
    return out


def version(d) -> str:
    return section(d, "ESXI_VERSION").strip().splitlines()[0] if section(d, "ESXI_VERSION").strip() else ""


def _names(items, limit=15) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _true(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


# ── rule builders ────────────────────────────────────────────────────────

def _rule(rules, sec, title, severity, check, evidence, remediation, sections, level="L1", manual=False):
    rules.append(BenchmarkRule(
        id=f"ESXI-{sec}", section=sec, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation, description=title,
        manual=manual, data_sections=list(sections), source="CIS"))


def _manual(rules, sec, title, severity, guidance, evidence=None, level="L1", sections=()):
    _rule(rules, sec, title, severity, lambda d: False, evidence or (lambda d: "Review on the host or in vCenter."),
          guidance, sections, level=level, manual=True)


def _adv_rule(rules, sec, title, severity, path, ok, remediation, level="L1"):
    _rule(rules, sec, title, severity, lambda d: adv(d, path) is not None and ok(adv(d, path)),
          lambda d: f"{path.strip('/').replace('/', '.')} = "
          + (repr(adv(d, path)) if adv(d, path) is not None else "not present on this host"),
          remediation, ["ADVANCED"], level=level)


def _int_between(lo, hi):
    def ok(v):
        """Whether a setting value lies in the allowed range."""
        try:
            return lo <= int(v) <= hi
        except (TypeError, ValueError):
            return False
    return ok


def _vm_rule(rules, sec, title, severity, key, ok, default_ok, remediation, level="L1"):
    """A .vmx setting every VM must have; `default_ok` when the key is absent
    and VMware's default is already the secure value."""
    def offenders(d):
        """VMs whose setting is missing (when the default is not acceptable) or out of range."""
        out = []
        for name, keys in vms(d).items():
            v = keys.get(key.lower())
            if (v is None and not default_ok) or (v is not None and not ok(v)):
                out.append(f"{name} ({v if v is not None else 'not set'})")
        return out
    _rule(rules, sec, title, severity, lambda d: not offenders(d),
          lambda d: f"{len(vms(d))} VMs; not compliant: {_names(offenders(d))}"
          + ("; absent = VMware's secure default" if default_ok else ""), remediation, ["VMS"], level=level)


def _vm_true(v):
    return _true(v)


def _vm_false(v):
    return not _true(v)


def _policy_rule(rules, sec, title, field, remediation):
    def offenders(d):
        return [f"{kind} {name}" for kind, name, policy, _vlan in vswitch_policies(d)
                if _true(policy.get(field, "true"))]
    _rule(rules, sec, title, "high", lambda d: bool(vswitch_policies(d)) and not offenders(d),
          lambda d: f"{field} allowed on: {_names(offenders(d))}", remediation, ["VSWITCH"])


def build_rules() -> List[BenchmarkRule]:
    """All CIS ESXi rules, in the benchmark's order: install, communication, logging, access, console,
    storage, network, virtual machines.
    """
    r: List[BenchmarkRule] = []

    # 1 Install ───────────────────────────────────────────────────────────
    _manual(r, "1.1", "Ensure ESXi is properly patched", "high",
            "Apply the current ESXi patch release; compare the build with VMware's release notes.",
            lambda d: section(d, "ESXI_VERSION").strip().replace("\n", " · "), sections=["ESXI_VERSION"])
    _rule(r, "1.2", "Ensure the Image Profile VIB acceptance level is configured properly", "high",
          lambda d: section(d, "ACCEPTANCE").strip() in ("VMwareCertified", "VMwareAccepted", "PartnerSupported"),
          lambda d: f"acceptance level = {section(d, 'ACCEPTANCE').strip()}",
          "esxcli software acceptance set --level=PartnerSupported", ["ACCEPTANCE"])

    def community_vibs(d):
        return [ln.split("|")[0] for ln in section(d, "VIBS").splitlines()
                if ln.count("|") >= 3 and ln.split("|")[3] == "CommunitySupported"]
    _manual(r, "1.3", "Ensure no unauthorized kernel modules are loaded on the host", "high",
            "Remove community-supported VIBs and drivers that are not approved.",
            lambda d: "CommunitySupported VIBs: " + _names(community_vibs(d)), sections=["VIBS"])
    _rule(r, "1.4", "Ensure the host enforces Secure Boot", "high",
          lambda d: _true(kv_section(d, "ENCRYPTION").get("Require Secure Boot")),
          lambda d: f"Require Secure Boot = {kv_section(d, 'ENCRYPTION').get('Require Secure Boot')}",
          "esxcli system settings encryption set --require-secure-boot=T (needs UEFI Secure Boot and a TPM).",
          ["ENCRYPTION"], level="L2")
    _rule(r, "1.5", "Ensure the host configuration is protected with a TPM", "medium",
          lambda d: kv_section(d, "ENCRYPTION").get("Mode") == "TPM",
          lambda d: f"configuration encryption mode = {kv_section(d, 'ENCRYPTION').get('Mode')}",
          "esxcli system settings encryption set --mode=TPM (needs a TPM 2.0).", ["ENCRYPTION"], level="L2")
    _rule(r, "1.6", "Ensure only executables from installed VIBs can run (execInstalledOnly)", "high",
          lambda d: _true(kv_section(d, "ENCRYPTION").get("Require Executables Only From Installed VIBs"))
          or adv(d, "/VMkernel/Boot/execInstalledOnly") == "1",
          lambda d: (f"Require Executables Only From Installed VIBs = "
                     f"{kv_section(d, 'ENCRYPTION').get('Require Executables Only From Installed VIBs')}; "
                     f"VMkernel.Boot.execInstalledOnly = {adv(d, '/VMkernel/Boot/execInstalledOnly')}"),
          "esxcli system settings encryption set --require-exec-installed-only=T", ["ENCRYPTION", "ADVANCED"])

    # 2 Communication ─────────────────────────────────────────────────────
    def ntp(d):
        return kv_section(d, "NTP")
    _rule(r, "2.1", "Ensure NTP time synchronization is configured properly", "medium",
          lambda d: _true(ntp(d).get("Enabled")) and bool(ntp(d).get("Server")),
          lambda d: f"NTP enabled = {ntp(d).get('Enabled')}, servers = {ntp(d).get('Server') or 'none'}",
          "esxcli system ntp set -s <server> -e true", ["NTP"])
    _rule(r, "2.2", "Ensure the ESXi host firewall is enabled and drops by default", "high",
          lambda d: firewall(d)[0].get("Default Action") == "DROP" and _true(firewall(d)[0].get("Enabled")),
          lambda d: f"default action = {firewall(d)[0].get('Default Action')}, enabled = {firewall(d)[0].get('Enabled')}",
          "esxcli network firewall set --default-action=false --enabled=true", ["FIREWALL"])

    def open_rulesets(d):
        _head, enabled, allowed = firewall(d)
        return [name for name, on in enabled.items() if on and allowed.get(name, "All") == "All"]
    _rule(r, "2.3", "Ensure the ESXi host firewall restricts access to services running on the host", "medium",
          lambda d: not open_rulesets(d), lambda d: "enabled rulesets open to all IP addresses: " + _names(open_rulesets(d)),
          "esxcli network firewall ruleset set -r <ruleset> -a false; ruleset allowedip add -r <ruleset> -i <network>",
          ["FIREWALL"])
    _adv_rule(r, "2.4", "Ensure the Managed Object Browser (MOB) is disabled", "medium",
              "/Config/HostAgent/plugins/solo/enableMob", lambda v: v == "0",
              "esxcli system settings advanced set -o /Config/HostAgent/plugins/solo/enableMob -i 0")

    def snmp(d):
        return kv_section(d, "SNMP")
    _rule(r, "2.5", "Ensure SNMP is configured properly (disabled, or v3 only)", "medium",
          lambda d: not _true(snmp(d).get("Enable")) or not snmp(d).get("Communities"),
          lambda d: f"SNMP enabled = {snmp(d).get('Enable')}, v1/v2c communities = {snmp(d).get('Communities') or 'none'}",
          "esxcli system snmp set --enable=false (or configure SNMPv3 users only)", ["SNMP"])
    _adv_rule(r, "2.6", "Ensure dvfilter API is not configured if not used", "medium", "/Net/DVFilterBindIpAddress",
              lambda v: not str(v).strip(), "esxcli system settings advanced set -o /Net/DVFilterBindIpAddress -d")
    _manual(r, "2.7", "Ensure the default self-signed certificate for ESXi communication is not used", "medium",
            "Replace the host certificate with one issued by your CA (or VMCA in vCenter).")
    _manual(r, "2.8", "Ensure CIM access is limited", "medium",
            "Give CIM-based tools a dedicated limited account; stop sfcbd-watchdog where CIM is not used.",
            lambda d: f"sfcbd-watchdog: {service_text(d, 'sfcbd-watchdog')}", sections=["SERVICES"])
    _rule(r, "2.9", "Ensure the SLP service is disabled", "high", lambda d: service_off(d, "slpd"),
          lambda d: f"slpd: {service_text(d, 'slpd')}",
          "/etc/init.d/slpd stop; chkconfig slpd off; esxcli network firewall ruleset set -r CIMSLP -e 0", ["SERVICES"])
    _adv_rule(r, "2.10", "Ensure BPDU filter is enabled on the host", "low", "/Net/BlockGuestBPDU", lambda v: v == "1",
              "esxcli system settings advanced set -o /Net/BlockGuestBPDU -i 1")

    def fips(d):
        return _kv(ln.replace("=", ":", 1) for ln in section(d, "FIPS").splitlines())
    _rule(r, "2.11", "Ensure SSH uses FIPS 140-2 validated cryptography", "medium",
          lambda d: _true(fips(d).get("ssh")), lambda d: f"fips140 ssh = {fips(d).get('ssh')}",
          "esxcli system security fips140 ssh set -e true", ["FIPS"])
    _rule(r, "2.12", "Ensure the reverse HTTP proxy uses FIPS 140-2 validated cryptography", "medium",
          lambda d: _true(fips(d).get("rhttpproxy")), lambda d: f"fips140 rhttpproxy = {fips(d).get('rhttpproxy')}",
          "esxcli system security fips140 rhttpproxy set -e true (restart rhttpproxy)", ["FIPS"])

    # 3 Logging ───────────────────────────────────────────────────────────
    _rule(r, "3.1", "Ensure a centralized location is configured to collect ESXi host core dumps", "medium",
          lambda d: _true(kv_section(d, "COREDUMP").get("Enabled")),
          lambda d: (f"network core dump enabled = {kv_section(d, 'COREDUMP').get('Enabled')}, "
                     f"server = {kv_section(d, 'COREDUMP').get('Network Server IP') or 'none'}"),
          "esxcli system coredump network set -v vmk0 -i <collector> -o 6500; esxcli system coredump network set -e true",
          ["COREDUMP"])
    _rule(r, "3.2", "Ensure persistent logging is configured for all ESXi hosts", "medium",
          lambda d: _true(kv_section(d, "SYSLOG").get("Local Log Output Is Persistent")),
          lambda d: (f"log directory = {kv_section(d, 'SYSLOG').get('Local Log Output')}, persistent = "
                     f"{kv_section(d, 'SYSLOG').get('Local Log Output Is Persistent')}"),
          "Point Syslog.global.logDir to a persistent datastore.", ["SYSLOG"])
    def loghost(d):
        v = (adv(d, "/Syslog/global/logHost") or kv_section(d, "SYSLOG").get("Remote Host") or "").strip()
        return "" if v.lower() in ("<none>", "none") else v
    _rule(r, "3.3", "Ensure remote logging is configured for ESXi hosts", "high",
          lambda d: bool(loghost(d)), lambda d: f"remote syslog host = {loghost(d) or 'none'}",
          "esxcli system syslog config set --loghost=ssl://<collector>:1514; esxcli system syslog reload",
          ["ADVANCED", "SYSLOG"])
    _adv_rule(r, "3.4", "Ensure audit records are stored on the host", "medium",
              "/Syslog/global/auditRecord/storageEnable", lambda v: v == "1", "esxcli system auditrecords local enable",
              level="L2")
    _adv_rule(r, "3.5", "Ensure audit records are sent to the remote log collector", "medium",
              "/Syslog/global/auditRecord/remoteEnable", lambda v: v == "1", "esxcli system auditrecords remote enable",
              level="L2")
    _adv_rule(r, "3.6", "Ensure log filtering is disabled", "low", "/Syslog/global/logFilteringEnabled",
              lambda v: v == "0", "esxcli system settings advanced set -o /Syslog/global/logFilteringEnabled -i 0")
    _adv_rule(r, "3.7", "Ensure the host agent logs at info level", "low", "/Config/HostAgent/log/level",
              lambda v: str(v).lower() == "info", "esxcli system settings advanced set -o /Config/HostAgent/log/level -s info")
    _adv_rule(r, "3.8", "Ensure the remote log collector's certificate is checked", "medium",
              "/Syslog/global/certificate/checkSSLCerts", lambda v: v == "1",
              "esxcli system settings advanced set -o /Syslog/global/certificate/checkSSLCerts -i 1")

    # 4 Access ────────────────────────────────────────────────────────────
    _manual(r, "4.1", "Ensure a non-root user account exists for local admin access", "medium",
            "Create named administrator accounts and use root only for break-glass access.",
            lambda d: "local accounts: " + _names(section(d, "ACCOUNTS").split()), sections=["ACCOUNTS"])
    _adv_rule(r, "4.2", "Ensure passwords are required to be complex", "high", "/Security/PasswordQualityControl",
              lambda v: PASSWORD_POLICY in str(v),
              f"esxcli system settings advanced set -o /Security/PasswordQualityControl -s 'retry=3 {PASSWORD_POLICY}'")
    _adv_rule(r, "4.3", "Ensure the maximum failed login attempts is set to 5", "medium", "/Security/AccountLockFailures",
              _int_between(1, 5), "esxcli system settings advanced set -o /Security/AccountLockFailures -i 5")
    _adv_rule(r, "4.4", "Ensure account lockout is set to 15 minutes", "medium", "/Security/AccountUnlockTime",
              _int_between(900, 10 ** 9), "esxcli system settings advanced set -o /Security/AccountUnlockTime -i 900")
    _adv_rule(r, "4.5", "Ensure previous 5 passwords are prohibited", "medium", "/Security/PasswordHistory",
              _int_between(5, 10 ** 6), "esxcli system settings advanced set -o /Security/PasswordHistory -i 5")
    _adv_rule(r, "4.6", "Ensure passwords expire after 90 days or less", "medium", "/Security/PasswordMaxDays",
              _int_between(1, 90), "esxcli system settings advanced set -o /Security/PasswordMaxDays -i 90")
    _manual(r, "4.7", "Ensure Active Directory is used for local user authentication", "medium",
            "Join the host to Active Directory (or use vCenter) for named administrator accounts.", level="L2")
    _manual(r, "4.8", "Ensure only authorized users and groups belong to the esxAdminsGroup group", "high",
            "Review the AD group named in Config.HostAgent.plugins.hostsvc.esxAdminsGroup.")
    _manual(r, "4.9", "Ensure the Exception Users list is properly configured", "high",
            "Keep lockdown-mode exception users to service accounts that need direct access.")
    _adv_rule(r, "4.10", "Ensure DCUI.Access lists only users allowed to override lockdown mode", "medium",
              "/DCUI/Access", lambda v: str(v).strip() == "root",
              "esxcli system settings advanced set -o /DCUI/Access -s root")

    # 5 Console ───────────────────────────────────────────────────────────
    _adv_rule(r, "5.1", "Ensure the DCUI times out after 600 seconds or less", "low", "/UserVars/DcuiTimeOut",
              _int_between(1, 600), "esxcli system settings advanced set -o /UserVars/DcuiTimeOut -i 600")
    _rule(r, "5.2", "Ensure the ESXi shell is disabled", "high", lambda d: service_off(d, "ESXShell"),
          lambda d: f"ESXi shell: {service_text(d, 'ESXShell')}",
          "vim-cmd hostsvc/disable_esx_shell; vim-cmd hostsvc/stop_esx_shell", ["SERVICES"])
    _rule(r, "5.3", "Ensure SSH is disabled", "high", lambda d: service_off(d, "SSH"),
          lambda d: (f"SSH: {service_text(d, 'SSH')} (this audit connects over SSH; disable it once auditing "
                     "and hardening are done)"),
          "vim-cmd hostsvc/disable_ssh; vim-cmd hostsvc/stop_ssh", ["SERVICES"])

    def lockdown(d):
        m = re.search(r'"([A-Za-z]+)"', section(d, "LOCKDOWN"))
        return m.group(1) if m else "unknown"
    _rule(r, "5.4", "Ensure Normal Lockdown Mode is enabled", "high",
          lambda d: lockdown(d) in ("lockdownNormal", "lockdownStrict"), lambda d: f"lockdown mode = {lockdown(d)}",
          "Enable lockdown mode from vCenter (host > Configure > Security Profile).", ["LOCKDOWN"])
    _rule(r, "5.5", "Ensure SSH authorized_keys file is empty", "high",
          lambda d: section(d, "SSH_KEYS").strip() == "0",
          lambda d: f"keys in /etc/ssh/keys-root/authorized_keys: {section(d, 'SSH_KEYS').strip()}",
          "Empty /etc/ssh/keys-root/authorized_keys.", ["SSH_KEYS"])
    _adv_rule(r, "5.6", "Ensure idle ESXi shell and SSH sessions time out after 300 seconds or less", "medium",
              "/UserVars/ESXiShellInteractiveTimeOut", _int_between(1, 300),
              "esxcli system settings advanced set -o /UserVars/ESXiShellInteractiveTimeOut -i 300")
    _adv_rule(r, "5.7", "Ensure the shell services timeout is set to 1 hour or less", "medium",
              "/UserVars/ESXiShellTimeOut", _int_between(1, 3600),
              "esxcli system settings advanced set -o /UserVars/ESXiShellTimeOut -i 3600")
    _adv_rule(r, "5.8", "Ensure the Host Client session times out after 900 seconds or less", "medium",
              "/UserVars/HostClientSessionTimeout", _int_between(1, 900),
              "esxcli system settings advanced set -o /UserVars/HostClientSessionTimeout -i 900")
    _adv_rule(r, "5.9", "Ensure the DCUI welcome message is configured", "low", "/Annotations/WelcomeMessage",
              lambda v: bool(str(v).strip()), "esxcli system settings advanced set -o /Annotations/WelcomeMessage -s '<banner>'")
    _adv_rule(r, "5.10", "Ensure a login banner is configured for SSH connections", "low", "/Config/Etc/issue",
              lambda v: bool(str(v).strip()), "esxcli system settings advanced set -o /Config/Etc/issue -s '<banner>'")
    _adv_rule(r, "5.11", "Ensure the ESXi shell warning is not suppressed", "low", "/UserVars/SuppressShellWarning",
              lambda v: v == "0", "esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 0")
    _adv_rule(r, "5.12", "Ensure the hyperthreading warning is not suppressed", "low",
              "/UserVars/SuppressHyperthreadWarning", lambda v: v == "0",
              "esxcli system settings advanced set -o /UserVars/SuppressHyperthreadWarning -i 0")
    _adv_rule(r, "5.13", "Ensure the Host Client does not join the Customer Experience Improvement Program", "low",
              "/UserVars/HostClientCEIPOptIn", lambda v: v == "2",
              "esxcli system settings advanced set -o /UserVars/HostClientCEIPOptIn -i 2", level="L2")

    # 6 Storage ───────────────────────────────────────────────────────────
    def chap(d):
        """iSCSI adapters without mutual CHAP."""
        out = []
        for adapter, lines in _blocks(d, "ISCSI").items():
            info = _kv(lines)
            if info.get("Mutual Level", "prohibited").lower() not in ("required",):
                out.append(f"{adapter} (uni {info.get('Level')}, mutual {info.get('Mutual Level')})")
        return out
    _rule(r, "6.1", "Ensure bidirectional CHAP authentication for iSCSI traffic is enabled", "high",
          lambda d: not chap(d), lambda d: "iSCSI adapters without mutual CHAP: " + _names(chap(d))
          + ("" if _blocks(d, "ISCSI") else " (no iSCSI adapters)"),
          "esxcli iscsi adapter auth chap set -A <vmhba> -d mutual -l required -N <name> -S <secret>", ["ISCSI"])
    _manual(r, "6.2", "Ensure the uniqueness of CHAP authentication secrets for iSCSI traffic", "medium",
            "Use a different CHAP secret on each host and target.")
    _manual(r, "6.3", "Ensure storage area network (SAN) resources are segregated properly", "medium",
            "Zone and mask LUNs so each host sees only its storage.")

    # 7 Network ───────────────────────────────────────────────────────────
    _policy_rule(r, "7.1", "Ensure the vSwitch Forged Transmits policy is set to reject", "Allow Forged Transmits",
                 "esxcli network vswitch standard policy security set -v <vSwitch> --allow-forged-transmits=false")
    _policy_rule(r, "7.2", "Ensure the vSwitch MAC Address Change policy is set to reject", "Allow MAC Address Changes",
                 "esxcli network vswitch standard policy security set -v <vSwitch> --allow-mac-change=false")
    _policy_rule(r, "7.3", "Ensure the vSwitch Promiscuous Mode policy is set to reject", "Allow Promiscuous",
                 "esxcli network vswitch standard policy security set -v <vSwitch> --allow-promiscuous=false")

    def vlan_groups(d, bad):
        return [f"{name} (VLAN {vlan})" for kind, name, _p, vlan in vswitch_policies(d)
                if kind == "port group" and vlan is not None and bad(vlan)]
    _rule(r, "7.4", "Ensure port groups are not configured to VLAN 4095 except for Virtual Guest Tagging", "medium",
          lambda d: not vlan_groups(d, lambda v: v == 4095),
          lambda d: "port groups on VLAN 4095: " + _names(vlan_groups(d, lambda v: v == 4095)),
          "Give each port group its own VLAN unless the guest does the tagging.", ["VSWITCH"])
    _rule(r, "7.5", "Ensure port groups are not configured to the value of the native VLAN", "medium",
          lambda d: not vlan_groups(d, lambda v: v == 1),
          lambda d: "port groups on VLAN 1: " + _names(vlan_groups(d, lambda v: v == 1)),
          "Move port groups off the native VLAN.", ["VSWITCH"])
    _rule(r, "7.6", "Ensure port groups are not configured to VLAN values reserved by upstream physical switches",
          "low", lambda d: not vlan_groups(d, lambda v: v in RESERVED_VLANS),
          lambda d: "port groups on reserved VLANs: " + _names(vlan_groups(d, lambda v: v in RESERVED_VLANS)),
          "Use VLAN IDs the physical switches do not reserve.", ["VSWITCH"], level="L2")
    _manual(r, "7.7", "Ensure Virtual Distributed Switch Netflow traffic is sent to an authorized collector", "low",
            "Review NetFlow collectors on distributed switches in vCenter.", level="L2")
    _adv_rule(r, "7.8", "Ensure inter-VM transparent page sharing is disabled (salting)", "low", "/Mem/ShareForceSalting",
              lambda v: v == "2", "esxcli system settings advanced set -o /Mem/ShareForceSalting -i 2")

    # 8 Virtual machines ──────────────────────────────────────────────────
    _vm_rule(r, "8.1", "Ensure unauthorized copy operations are disabled", "medium", "isolation.tools.copy.disable",
             _vm_true, True, "Set isolation.tools.copy.disable = TRUE in the VM's advanced settings.")
    _vm_rule(r, "8.2", "Ensure unauthorized paste operations are disabled", "medium", "isolation.tools.paste.disable",
             _vm_true, True, "Set isolation.tools.paste.disable = TRUE.")
    _vm_rule(r, "8.3", "Ensure drag and drop operations are disabled", "medium", "isolation.tools.dnd.disable",
             _vm_true, True, "Set isolation.tools.dnd.disable = TRUE.")
    _vm_rule(r, "8.4", "Ensure virtual disk shrinking is disabled", "medium", "isolation.tools.diskShrink.disable",
             _vm_true, False, "Set isolation.tools.diskShrink.disable = TRUE.")
    _vm_rule(r, "8.5", "Ensure virtual disk wiping is disabled", "medium", "isolation.tools.diskWiper.disable",
             _vm_true, False, "Set isolation.tools.diskWiper.disable = TRUE.")
    _vm_rule(r, "8.6", "Ensure unauthorized modification and disconnection of devices is disabled", "medium",
             "isolation.device.connectable.disable", _vm_true, False, "Set isolation.device.connectable.disable = TRUE.")
    _vm_rule(r, "8.7", "Ensure informational messages from the VM to the VMX file are limited", "low",
             "tools.setInfo.sizeLimit", lambda v: v.isdigit() and int(v) <= 1048576, True,
             "Set tools.setInfo.sizeLimit = 1048576.")
    _vm_rule(r, "8.8", "Ensure only one remote console connection is permitted to a VM", "medium",
             "RemoteDisplay.maxConnections", lambda v: v == "1", False, "Set RemoteDisplay.maxConnections = 1.")
    _vm_rule(r, "8.9", "Ensure the number of VM log files is configured properly", "low", "log.keepOld",
             lambda v: v.isdigit() and 0 < int(v) <= 10, False, "Set log.keepOld = 10.")
    _vm_rule(r, "8.10", "Ensure VM log file size is limited", "low", "log.rotateSize",
             lambda v: v.isdigit() and 0 < int(v) <= 2048000, False, "Set log.rotateSize = 2048000.")
    _vm_rule(r, "8.11", "Ensure host information is not sent to guests", "medium", "tools.guestlib.enableHostInfo",
             _vm_false, True, "Set tools.guestlib.enableHostInfo = FALSE.")
    _vm_rule(r, "8.12", "Ensure 3D features are disabled when not required", "low", "mks.enable3d",
             _vm_false, True, "Set mks.enable3d = FALSE.", level="L2")

    def devices(d):
        return [f"{name} ({k})" for name, keys in vms(d).items() for k, v in keys.items()
                if re.match(r"^(floppy|serial|parallel|usb)\d*\.present$", k) and _true(v)]
    _rule(r, "8.13", "Ensure unnecessary virtual hardware (floppy, serial, parallel, USB) is removed", "medium",
          lambda d: not devices(d), lambda d: "devices present: " + _names(devices(d)),
          "Remove unused floppy, serial, parallel and USB devices from the VMs.", ["VMS"])

    def nonpersistent(d):
        return [f"{name} ({k})" for name, keys in vms(d).items() for k, v in keys.items()
                if re.match(r"^scsi\d+:\d+\.mode$", k) and "nonpersistent" in v.lower()]
    _rule(r, "8.14", "Ensure independent nonpersistent disks are not used", "medium",
          lambda d: not nonpersistent(d), lambda d: "independent nonpersistent disks: " + _names(nonpersistent(d)),
          "Change the disk mode to dependent (or independent persistent).", ["VMS"], level="L2")
    _manual(r, "8.15", "Ensure PCI and PCIe device passthrough is disabled where not required", "medium",
            "Remove passthrough devices that are not needed.",
            lambda d: "VMs with passthrough devices: " + _names(
                name for name, keys in vms(d).items() if any(re.match(r"^pcipassthru\d+\.present$", k) and _true(v)
                                                             for k, v in keys.items())), sections=["VMS"])

    r.sort(key=lambda x: tuple(int(p) for p in x.section.split(".")))
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    """The rules for a dump (ESXi 7 or 8); ValueError when the host is not ESXi."""
    v = version(dump)
    if not v or v == NOT_ESXI:
        raise ValueError("This host is not VMware ESXi (vmware -v did not answer).")
    m = re.search(r"ESXi (\d+)\.", v)
    if m and int(m.group(1)) < 7:
        raise ValueError(f"This benchmark covers ESXi 7 and 8; the host runs {v}.")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    kinds = [kind for kind, _n, _p, _v in vswitch_policies(dump)]
    return (f"{version(dump)}, {len(vms(dump))} VMs, {kinds.count('vSwitch')} standard vSwitches, "
            f"{kinds.count('port group')} port groups")
