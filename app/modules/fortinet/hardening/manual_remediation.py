"""
FortiGate MANUAL-check remediation catalog.

The auto-remediation templates in :mod:`command_templates` cover the 21 controls
that can be hardened without operator judgement. The remaining CIS controls are
"Manual" — historically the "View Fix" modal only *showed* their commands. This
catalog upgrades a subset of them to be *executable*: it pairs each supported
manual check with a well-formed, parameterised command block and the UI metadata
needed to collect any operator input first.

Only the inner ``config``/``set``/``end`` block is stored here; the scope wrapper
(``config global`` or ``config vdom`` / ``edit <vdom>``) is added by the SSH engine
from the control's ``scope`` in ``audit/rules.py`` — exactly like the auto-fix
templates. Blocks are balanced (every ``config`` closed by ``end``, every ``edit``
by ``next``) so they return cleanly to the scope prompt.

Manual execution deliberately performs **NO post-fix verification** and never
flips the audit result to PASS — a manual control cannot be proven from config
alone (that's why it is Manual). The endpoint just renders + pushes the block and
reports the device output/errors.

Controls that are pure prose (e.g. "upgrade firmware") or need per-object
judgement (rewriting policies, blocking app categories) intentionally have NO
entry here and stay read-only in the modal. Controls whose fix must be computed
from live device state declare ``dynamic`` with an empty ``commands`` list
(FG-NET-002 WAN allowaccess): their per-target block is built at execute time
from ``show system interface``, never from this catalog.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ManualParam:
    """UI + rendering metadata for one manual-remediation parameter."""
    name: str
    label: str
    input_type: str = "text"          # text | number | password | ip | select
    required: bool = True
    default: Optional[str] = None
    placeholder: Optional[str] = None
    description: str = ""
    options: Optional[List[str]] = None
    secret: bool = False              # redact from echoed commands / output
    # Smart-dropdown metadata — where the UI gets REAL values for this parameter:
    #   None             -> free text; the operator invents the value (new names,
    #                       passwords, IPs). The only parameters allowed to stay text.
    #   "audit_evidence" -> options are the failing objects already identified in the
    #                       audit result's evidence (parsed server-side by
    #                       parse_evidence_options; rendered as a multi-select).
    #   "device"         -> options are existing device objects fetched live over SSH
    #                       via the device-options endpoint (option_type keys
    #                       DEVICE_OPTION_TYPES; rendered as a dropdown).
    source: Optional[str] = None
    option_type: Optional[str] = None       # DEVICE_OPTION_TYPES key (source="device")
    evidence_parser: Optional[str] = None   # "policy_ids" | "table_names" (source="audit_evidence")
    multi: bool = False                     # multi-select; the block repeats per value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "type": self.input_type,
            "required": self.required,
            "default": self.default,
            "placeholder": self.placeholder,
            "description": self.description,
            "options": self.options,
            "secret": self.secret,
            "source": self.source,
            "option_type": self.option_type,
            "multi": self.multi,
        }


@dataclass
class ManualRemediation:
    """An executable remediation for a CIS 'Manual' FortiGate control.

    ``dynamic`` marks a check whose commands cannot be a static block and are
    computed at execute time from live device state (``commands`` stays empty):
      "wan_iface_allowaccess" -> FG-NET-002; per selected WAN interface, strip
      only the forbidden management services from the live ``allowaccess``
      (FortiGateHardeningExecutor.build_wan_iface_allowaccess_blocks).
    """
    commands: List[str]
    parameters: List[ManualParam] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    dynamic: Optional[str] = None


@dataclass
class DeviceOptionSpec:
    """One fetchable class of existing device objects (smart-dropdown source).

    ``command`` is a ``show <table>`` whose entry names (``edit "<name>"``) become
    the dropdown options. Options are read in the control's scope/VDOM, except
    when ``scope_override`` forces ``global`` (objects that only live in the
    global context on multi-VDOM devices, e.g. local certificates)."""
    command: str
    label: str
    scope_override: Optional[str] = None  # "global" | None (= control's scope)


# option_type -> how to fetch it. Referenced by ManualParam.option_type; the
# device-options endpoint refuses option_types not declared by the check.
DEVICE_OPTION_TYPES: Dict[str, DeviceOptionSpec] = {
    "av_profiles":     DeviceOptionSpec("show antivirus profile", "Antivirus profiles"),
    "ips_sensors":     DeviceOptionSpec("show ips sensor", "IPS sensors"),
    "app_lists":       DeviceOptionSpec("show application list", "Application control lists"),
    "dns_profiles":    DeviceOptionSpec("show dnsfilter profile", "DNS filter profiles"),
    "admin_users":     DeviceOptionSpec("show system admin", "Administrator accounts"),
    "admin_profiles":  DeviceOptionSpec("show system accprofile", "Admin access profiles"),
    "snmp_users":      DeviceOptionSpec("show system snmp user", "SNMPv3 users"),
    "interfaces":      DeviceOptionSpec("show system interface", "Interfaces"),
    "address_objects": DeviceOptionSpec("show firewall address", "Address objects"),
    "services":        DeviceOptionSpec("show firewall service custom", "Service objects"),
    "certificates":    DeviceOptionSpec("show vpn certificate local", "Local certificates",
                                        scope_override="global"),
}


_P = ManualParam  # brevity in the table below


# check_id -> executable manual remediation. Scope is taken from the control at
# execution time (audit/rules.py), so it is NOT duplicated here.
MANUAL_REMEDIATION_TEMPLATES: Dict[str, ManualRemediation] = {

    # ===== 1 Network Settings =====
    "FG-NET-001": ManualRemediation(  # 1.2 intra-zone traffic
        commands=["config system zone", 'edit "{ZONE}"', "set intrazone deny", "next", "end"],
        parameters=[_P("ZONE", "Zone(s)", placeholder="zone1",
                       description="Security zone(s) to set to intra-zone deny — the failing "
                                   "zones from the audit evidence.",
                       source="audit_evidence", evidence_parser="table_names", multi=True)],
        warnings=["The command block is applied once per selected zone."],
    ),

    "FG-NET-002": ManualRemediation(  # 1.3 mgmt services exposed on WAN interfaces
        # Computed at EXECUTE time from live `show system interface` (the same
        # mechanism as FG-BL-002's dynamic auto-fix): for each SELECTED WAN
        # interface, strip only http/https/ssh/telnet from allowaccess and
        # preserve every other service (ping/snmp/fgfm/...). No static block is
        # possible — the surviving services depend on the device's live config.
        commands=[],
        dynamic="wan_iface_allowaccess",
        parameters=[_P("INTERFACES", "WAN interface(s)", placeholder="wan1",
                       description="WAN-role interfaces exposing management services — the "
                                   "flagged interfaces from the audit evidence, with the "
                                   "exposed services shown in parentheses. Only the selected "
                                   "interfaces are changed.",
                       source="audit_evidence", evidence_parser="wan_iface_services",
                       multi=True)],
        warnings=["Removes HTTP/HTTPS/SSH/Telnet from each selected interface's management "
                  "access (allowaccess); other services (ping/snmp/fgfm/...) are preserved.",
                  "LOCKOUT RISK: selecting the interface your own management session enters "
                  "through cuts off remote administration on it. The app refuses to modify "
                  "the interface holding the IP it is connected to — fix that one from the "
                  "console or a dedicated management interface."],
    ),

    # ===== 2.1 General Settings =====
    "FG-SYS-002": ManualRemediation(  # 2.1.3 timezone
        commands=["config system global", "set timezone {TIMEZONE}", "end"],
        parameters=[_P("TIMEZONE", "Timezone ID", input_type="number", required=False, default="41",
                       description="FortiOS timezone index (run 'set timezone ?' for the list; 41 = Tehran).")],
        warnings=["Timezone is set by numeric FortiOS index, not name."],
    ),
    "FG-BL-005": ManualRemediation(  # 2.1.10 admin GUI TLS versions
        commands=["config system global", "set admin-https-ssl-versions tlsv1-2 tlsv1-3", "end"],
        warnings=["Restricts the admin GUI to TLS 1.2/1.3. Older browsers/tools may lose access."],
    ),

    # ===== 2.3 SNMP =====
    "FG-BL-050": ManualRemediation(  # 2.3.1 only SNMPv3
        commands=[
            "config system snmp sysinfo", "set status enable", "end",
            "config system snmp user", 'edit "{SNMP_USER}"',
            "set security-level auth-priv",
            "set auth-proto sha256", "set auth-pwd {SNMP_AUTH_PWD}",
            "set priv-proto aes256", "set priv-pwd {SNMP_PRIV_PWD}",
            "next", "end",
        ],
        parameters=[
            _P("SNMP_USER", "SNMPv3 username", placeholder="monitor",
               description="Name of the SNMPv3 user to create or update."),
            _P("SNMP_AUTH_PWD", "Auth password", input_type="password", secret=True,
               description="SHA-256 authentication password (min 8 chars)."),
            _P("SNMP_PRIV_PWD", "Privacy password", input_type="password", secret=True,
               description="AES-256 privacy/encryption password (min 8 chars)."),
        ],
        warnings=["Creates/updates an SNMPv3 user with auth-priv. Remove any SNMPv1/v2c communities separately."],
    ),
    "FG-SNMP-001": ManualRemediation(  # 2.3.2 SNMPv3 trusted hosts
        commands=["config system snmp user", 'edit "{SNMP_USER}"',
                  "set notify-hosts {TRUSTED_HOSTS}", "next", "end"],
        parameters=[
            _P("SNMP_USER", "SNMPv3 username", placeholder="monitor",
               description="Existing SNMPv3 user to restrict.",
               source="device", option_type="snmp_users"),
            _P("TRUSTED_HOSTS", "Trusted host(s)", placeholder="10.0.0.5 10.0.0.6",
               description="Space-separated SNMP manager IP(s) allowed to poll/receive traps."),
        ],
    ),

    # ===== 2.4 Administrators =====
    "FG-BL-021": ManualRemediation(  # 2.4.1 change default admin password
        commands=["config system admin", 'edit "{ADMIN_USER}"', "set password {NEW_PASSWORD}", "next", "end"],
        parameters=[
            _P("ADMIN_USER", "Admin account", required=False, default="admin",
               description="Administrator account whose password to change.",
               source="device", option_type="admin_users"),
            _P("NEW_PASSWORD", "New password", input_type="password", secret=True,
               description="Strong password for the account. Existing sessions are not dropped."),
        ],
        warnings=["Changing the password of the account you are connected as does not drop this session, "
                  "but make sure you record the new password before reconnecting."],
    ),
    "FG-BL-020": ManualRemediation(  # 2.4.2 trusted hosts for admins
        commands=["config system admin", 'edit "{ADMIN_USER}"',
                  "set trusthost1 {TRUSTED_SUBNET} {TRUSTED_MASK}", "next", "end"],
        parameters=[
            _P("ADMIN_USER", "Admin account", placeholder="admin",
               description="Administrator account to restrict.",
               source="device", option_type="admin_users"),
            _P("TRUSTED_SUBNET", "Trusted subnet", input_type="ip", placeholder="10.0.0.0",
               description="Management network allowed to reach this admin."),
            _P("TRUSTED_MASK", "Netmask", required=False, default="255.255.255.0", placeholder="255.255.255.0",
               description="Netmask for the trusted subnet."),
        ],
        warnings=["Sets trusthost1. An admin with a trusthost can only log in from that subnet — "
                  "make sure your management host is inside it."],
    ),
    "FG-ADM-001": ManualRemediation(  # 2.4.3 admin access profiles
        commands=["config system admin", 'edit "{ADMIN_USER}"', 'set accprofile "{ACCPROFILE}"', "next", "end"],
        parameters=[
            _P("ADMIN_USER", "Admin account", placeholder="operator",
               description="Administrator account to assign a profile to.",
               source="device", option_type="admin_users"),
            _P("ACCPROFILE", "Access profile", placeholder="prof_admin",
               description="Least-privilege admin access profile name.",
               source="device", option_type="admin_profiles"),
        ],
    ),
    "FG-LIP-001": ManualRemediation(  # 2.4.6 local-in policy
        commands=["config firewall local-in-policy", "edit {POLICY_ID}",
                  'set intf "{INTF}"', 'set srcaddr "{SRCADDR}"', 'set dstaddr "{DSTADDR}"',
                  'set service "{SERVICE}"', 'set schedule "always"', "set action {ACTION}",
                  "next", "end"],
        parameters=[
            _P("POLICY_ID", "Policy ID", input_type="number", placeholder="1",
               description="Numeric ID for the local-in policy entry."),
            _P("INTF", "Interface", placeholder="wan1",
               description="Interface the local-in policy applies to.",
               source="device", option_type="interfaces"),
            _P("SRCADDR", "Source address", required=False, default="all",
               description="Source address object (default: all).",
               source="device", option_type="address_objects"),
            _P("DSTADDR", "Destination address", required=False, default="all",
               description="Destination address object (default: all).",
               source="device", option_type="address_objects"),
            _P("SERVICE", "Service", required=False, default="ALL",
               description="Service object to match (default: ALL).",
               source="device", option_type="services"),
            _P("ACTION", "Action", input_type="select", options=["deny", "accept"], default="deny",
               description="Allow or deny the matched management traffic."),
        ],
        warnings=["Local-in policies govern traffic TO the FortiGate itself. A too-broad deny can lock you out — "
                  "verify the interface/source before applying."],
    ),
    "FG-BL-007": ManualRemediation(  # 2.4.7 change default admin ports
        commands=["config system global", "set admin-sport {ADMIN_SPORT}",
                  "set admin-ssh-port {ADMIN_SSH_PORT}", "end"],
        parameters=[
            _P("ADMIN_SPORT", "HTTPS admin port", input_type="number", required=False, default="10443",
               description="Non-default HTTPS management port."),
            _P("ADMIN_SSH_PORT", "SSH admin port", input_type="number", required=False, default="2222",
               description="Non-default SSH management port."),
        ],
        warnings=["New management ports apply to future connections. This SSH session stays up; "
                  "reconnect on the new SSH port next time."],
    ),

    # ===== 2.5 High Availability =====
    "FG-HA-004": ManualRemediation(  # 2.5.1 enable HA
        commands=["config system ha", "set mode a-p", 'set group-name "{HA_GROUP_NAME}"',
                  "set hbdev {HA_HBDEV} {HA_PRIORITY}", "end"],
        parameters=[
            _P("HA_GROUP_NAME", "HA group name", placeholder="HA-CLUSTER",
               description="Shared cluster group name (must match on all members)."),
            _P("HA_HBDEV", "Heartbeat interface", placeholder="port10",
               description="Interface used for HA heartbeat.",
               source="device", option_type="interfaces"),
            _P("HA_PRIORITY", "Heartbeat priority", input_type="number", required=False, default="50",
               description="Heartbeat device priority (0-512)."),
        ],
        warnings=["Enabling HA changes cluster behaviour and can cause a brief failover. "
                  "Only apply on a device intended to join an HA cluster."],
    ),
    "FG-HA-006": ManualRemediation(  # 2.5.3 HA reserved management interface
        commands=["config system ha", "set ha-mgmt-status enable",
                  "config ha-mgmt-interfaces", "edit 1",
                  'set interface "{HA_MGMT_INTF}"', "set gateway {HA_MGMT_GATEWAY}",
                  "next", "end", "end"],
        parameters=[
            _P("HA_MGMT_INTF", "Reserved mgmt interface", placeholder="mgmt",
               description="Interface reserved for out-of-band HA management.",
               source="device", option_type="interfaces"),
            _P("HA_MGMT_GATEWAY", "Mgmt gateway", input_type="ip", placeholder="10.0.0.1",
               description="Default gateway for the reserved management interface."),
        ],
        warnings=["Only valid on an HA-configured device."],
    ),

    # ===== 3 Policy =====
    "FG-BL-082": ManualRemediation(  # 3.4 logging on firewall policy
        commands=["config firewall policy", "edit {POLICY_ID}", "set logtraffic all", "next", "end"],
        parameters=[_P("POLICY_ID", "Policy ID(s)", input_type="number", placeholder="1",
                       description="Failing firewall policies (from the audit evidence) to "
                                   "enable full logging on.",
                       source="audit_evidence", evidence_parser="policy_ids", multi=True)],
        warnings=["Enables logtraffic=all once per selected policy."],
    ),

    # ===== 4.1 IPS =====
    "FG-UTM-003": ManualRemediation(  # 4.1.2 apply IPS sensor to policy
        commands=["config firewall policy", "edit {POLICY_ID}",
                  "set utm-status enable", 'set ips-sensor "{IPS_SENSOR}"', "next", "end"],
        parameters=[
            _P("POLICY_ID", "Policy ID(s)", input_type="number", placeholder="1",
               description="Accept policies missing an IPS sensor (from the audit evidence).",
               source="audit_evidence", evidence_parser="policy_ids", multi=True),
            _P("IPS_SENSOR", "IPS sensor", required=False, default="default",
               description="IPS sensor profile to attach (fetched from the device).",
               source="device", option_type="ips_sensors"),
        ],
    ),

    # ===== 4.2 Antivirus =====
    "FG-UTM-002": ManualRemediation(  # 4.2.2 apply AV profile to policy
        commands=["config firewall policy", "edit {POLICY_ID}",
                  "set utm-status enable", 'set av-profile "{AV_PROFILE}"', "next", "end"],
        parameters=[
            _P("POLICY_ID", "Policy ID(s)", input_type="number", placeholder="1",
               description="Accept policies missing an antivirus profile (from the audit evidence).",
               source="audit_evidence", evidence_parser="policy_ids", multi=True),
            _P("AV_PROFILE", "AV profile", required=False, default="default",
               description="Antivirus profile to attach (fetched from the device).",
               source="device", option_type="av_profiles"),
        ],
    ),
    "FG-AV-002": ManualRemediation(  # 4.2.3 outbreak prevention
        commands=["config antivirus profile", 'edit "{AV_PROFILE}"',
                  "config http", "set outbreak-prevention block", "end", "next", "end"],
        parameters=[_P("AV_PROFILE", "AV profile", required=False, default="default",
                       description="Antivirus profile to enable outbreak prevention on.",
                       source="device", option_type="av_profiles")],
    ),

    # ===== 4.3 DNS Filter =====
    "FG-DNS-002": ManualRemediation(  # 4.3.2 log all DNS
        commands=["config dnsfilter profile", 'edit "{DNS_PROFILE}"',
                  "set log-all-domain enable", "next", "end"],
        parameters=[_P("DNS_PROFILE", "DNS filter profile", required=False, default="default",
                       description="DNS filter profile to enable full query logging on.",
                       source="device", option_type="dns_profiles")],
    ),

    # ===== 4.4 Application Control =====
    "FG-APP-002": ManualRemediation(  # 4.4.2 enforce default app ports
        commands=["config application list", 'edit "{APP_LIST}"',
                  "set enforce-default-app-port enable", "next", "end"],
        parameters=[_P("APP_LIST", "Application list", required=False, default="default",
                       description="Application control sensor to update.",
                       source="device", option_type="app_lists")],
        warnings=["The 'enforce-default-app-port' field is absent on some models (e.g. 60F) and will "
                  "return a parse error there — that is a build limitation, not an app fault."],
    ),
    "FG-APP-003": ManualRemediation(  # 4.4.3 log app control traffic
        commands=["config application list", 'edit "{APP_LIST}"',
                  "set other-application-log enable", "next", "end"],
        parameters=[_P("APP_LIST", "Application list", required=False, default="default",
                       description="Application control sensor to enable logging on.",
                       source="device", option_type="app_lists")],
    ),
    "FG-APP-004": ManualRemediation(  # 4.4.4 apply app control to policy
        commands=["config firewall policy", "edit {POLICY_ID}",
                  "set utm-status enable", 'set application-list "{APP_LIST}"', "next", "end"],
        parameters=[
            _P("POLICY_ID", "Policy ID(s)", input_type="number", placeholder="1",
               description="Accept policies missing an application list (from the audit evidence).",
               source="audit_evidence", evidence_parser="policy_ids", multi=True),
            _P("APP_LIST", "Application list", required=False, default="default",
               description="Application control sensor to attach (fetched from the device).",
               source="device", option_type="app_lists"),
        ],
    ),

    # ===== 5 Security Fabric =====
    "FG-FAB-002": ManualRemediation(  # 5.2.1.1 Security Fabric
        commands=["config system csf", "set status enable", 'set group-name "{CSF_GROUP_NAME}"', "end"],
        parameters=[_P("CSF_GROUP_NAME", "Fabric group name", placeholder="fabric-hq",
                       description="Security Fabric group name (root coordinator).")],
        warnings=["Enabling the Security Fabric changes upstream/downstream device relationships."],
    ),

    # ===== 6 VPN =====
    "FG-VPN-SSL-003": ManualRemediation(  # 6.1.1 SSL-VPN server cert
        commands=["config vpn ssl settings", 'set servercert "{SERVERCERT}"', "end"],
        parameters=[_P("SERVERCERT", "Server certificate", placeholder="my-signed-cert",
                       description="Name of an installed trusted/CA-signed certificate.",
                       source="device", option_type="certificates")],
        warnings=["The certificate must already be imported on the device."],
    ),
    "FG-VPN-SSL-001": ManualRemediation(  # 6.1.2 SSL-VPN min TLS
        commands=["config vpn ssl settings", "set ssl-min-proto-ver tls1-2", "end"],
        warnings=["Restricts SSL-VPN to TLS 1.2+. Older FortiClient builds may need updating."],
    ),
}


def has_manual_remediation(check_id: str) -> bool:
    """Whether ``check_id`` can be executed from the manual 'View Fix' modal."""
    return check_id in MANUAL_REMEDIATION_TEMPLATES


def get_manual_remediation(check_id: str) -> ManualRemediation:
    """Return the executable manual remediation (raises KeyError if none)."""
    if check_id not in MANUAL_REMEDIATION_TEMPLATES:
        raise KeyError(f"No manual remediation template for {check_id}")
    return MANUAL_REMEDIATION_TEMPLATES[check_id]


def get_manual_parameters(check_id: str) -> List[ManualParam]:
    rem = MANUAL_REMEDIATION_TEMPLATES.get(check_id)
    return list(rem.parameters) if rem else []


def get_all_manual_executable_checks() -> List[str]:
    return list(MANUAL_REMEDIATION_TEMPLATES.keys())


def device_option_types_for_check(check_id: str) -> List[str]:
    """The DEVICE_OPTION_TYPES keys this check's parameters actually use — the
    device-options endpoint refuses anything else (no arbitrary reads)."""
    rem = MANUAL_REMEDIATION_TEMPLATES.get(check_id)
    if not rem:
        return []
    return [s.option_type for s in rem.parameters
            if s.source == "device" and s.option_type]


class ManualParameterError(ValueError):
    """Raised when required manual-remediation parameters are missing/invalid."""


# Evidence parsers (source="audit_evidence"). These match the evidence strings
# built by app/modules/fortinet/audit/service.py:
#   policy_ids         -> `_policy_field_evidence`: one "Policy ID <id>: ..." line
#                         per failing policy (policy_field_eq/_present rules).
#   table_names        -> `_table_evidence_line` for table_all_match: the failing
#                         entry names after "missing '<label>':" up to
#                         "(NON-COMPLIANT)".
#   wan_iface_services -> `_wan_mgmt_evidence` (FG-NET-002): one
#                         "Interface <name> (role=wan) exposes: http, ssh
#                         (NON-COMPLIANT)" line per flagged WAN interface. The
#                         option keeps the services in the label —
#                         "wan1 (http ssh)" — space-separated, because the comma
#                         is the multi-select join character; only the leading
#                         name is used at execute time (selection_object_name).
_POLICY_ID_RE = re.compile(r"Policy ID (\S+?):")
_TABLE_MISSING_RE = re.compile(r"missing '[^']*':\s*(.+?)\s*\(NON-COMPLIANT\)",
                               re.IGNORECASE | re.DOTALL)
_WAN_IFACE_EXPOSED_RE = re.compile(
    r"Interface\s+(\S+)\s+\(role=[^)]*\)\s+exposes:\s*(.+?)\s*\(NON-COMPLIANT\)",
    re.IGNORECASE)


def selection_object_name(value: str) -> str:
    """Object name inside an evidence-derived selection: 'wan1 (http ssh)' ->
    'wan1' (a bare name passes through unchanged)."""
    return (value or "").split(" (", 1)[0].strip()


def parse_evidence_options(check_id: str, evidence: Optional[str]) -> Dict[str, List[str]]:
    """Per-parameter dropdown options parsed from a failing result's evidence.

    Returns ``{param_name: [option, ...]}`` for every ``source="audit_evidence"``
    parameter of ``check_id`` (empty list when nothing could be parsed — the UI
    then falls back to free input)."""
    rem = MANUAL_REMEDIATION_TEMPLATES.get(check_id)
    if not rem:
        return {}
    out: Dict[str, List[str]] = {}
    text = evidence or ""
    for spec in rem.parameters:
        if spec.source != "audit_evidence":
            continue
        values: List[str] = []
        if spec.evidence_parser == "policy_ids":
            values = _POLICY_ID_RE.findall(text)
        elif spec.evidence_parser == "table_names":
            m = _TABLE_MISSING_RE.search(text)
            if m:
                values = [v.strip() for v in m.group(1).split(",") if v.strip()]
        elif spec.evidence_parser == "wan_iface_services":
            values = [
                f"{name} ({' '.join(s.strip() for s in svcs.split(',') if s.strip())})"
                for name, svcs in _WAN_IFACE_EXPOSED_RE.findall(text)
            ]
        # dedupe, preserving evidence order
        out[spec.name] = list(dict.fromkeys(values))
    return out


def _validate_param_value(spec: ManualParam, value: str) -> None:
    """Reject values that could escape the rendered command block."""
    if "\n" in value or "\r" in value:
        raise ManualParameterError(f"Invalid value for {spec.label}: line breaks are not allowed")
    if spec.input_type == "number" and not re.fullmatch(r"\d+", value):
        raise ManualParameterError(f"Invalid value for {spec.label}: '{value}' is not a number")


_MULTI_SPLIT_RE = re.compile(r"[,\s]+")


def _substitute(commands: List[str], resolved: Dict[str, str]) -> List[str]:
    rendered: List[str] = []
    for line in commands:
        out = line
        for name, val in resolved.items():
            out = out.replace("{" + name + "}", val)
        rendered.append(out)
    return rendered


def render_manual_command_blocks(
    check_id: str, parameters: Dict[str, str]
) -> List[Tuple[Optional[str], List[str]]]:
    """
    Render a manual remediation's command block(s), substituting ``{PARAM}``
    tokens with the provided values (falling back to each parameter's default).

    For a template with a ``multi`` parameter (e.g. POLICY_ID on the
    policy-profile checks) the value is a comma/space-separated list and the
    block is rendered once per value; the return is ``[(target, commands), ...]``
    where ``target`` is that value. Templates without a multi parameter return a
    single ``(None, commands)`` entry.

    Raises :class:`ManualParameterError` if a required parameter is missing or a
    value is malformed. Values are inserted verbatim — the catalog quotes
    name/string fields where FortiOS requires it, so callers pass raw values.
    """
    rem = get_manual_remediation(check_id)
    params = dict(parameters or {})

    multi_spec = next((s for s in rem.parameters if s.multi), None)

    resolved: Dict[str, str] = {}
    missing: List[str] = []
    for spec in rem.parameters:
        if spec is multi_spec:
            continue
        val = params.get(spec.name)
        if val is None or str(val).strip() == "":
            if spec.default is not None:
                val = spec.default
            elif spec.required:
                missing.append(spec.label)
                continue
            else:
                val = ""
        val = str(val).strip()
        if val:
            _validate_param_value(spec, val)
        resolved[spec.name] = val

    if missing:
        raise ManualParameterError(
            "Missing required parameter(s): " + ", ".join(missing)
        )

    if multi_spec is None:
        return [(None, _substitute(rem.commands, resolved))]

    raw = str(params.get(multi_spec.name) or "").strip()
    # Numeric targets (policy IDs) split on commas/whitespace; string targets
    # (zone names may contain spaces) split on commas only.
    if multi_spec.input_type == "number":
        targets = [v for v in _MULTI_SPLIT_RE.split(raw) if v]
    else:
        targets = [v.strip() for v in raw.split(",") if v.strip()]
    if not targets:
        raise ManualParameterError(
            f"Missing required parameter(s): {multi_spec.label} (select at least one)"
        )
    blocks: List[Tuple[Optional[str], List[str]]] = []
    for target in list(dict.fromkeys(targets)):
        _validate_param_value(multi_spec, target)
        blocks.append((target, _substitute(rem.commands, {**resolved, multi_spec.name: target})))
    return blocks


def render_manual_commands(check_id: str, parameters: Dict[str, str]) -> List[str]:
    """Flattened form of :func:`render_manual_command_blocks` (all blocks
    concatenated in order) — for callers that only need the command list."""
    rendered: List[str] = []
    for _target, cmds in render_manual_command_blocks(check_id, parameters):
        rendered.extend(cmds)
    return rendered


def redact_manual_secret_values(text: str, check_id: str, parameters: Dict[str, str]) -> str:
    """
    Redact the literal values of secret parameters from ``text`` (echoed commands
    or device output), in addition to the generic ``redact_fortigate_secrets``
    pass. Guards against a password surviving in the echoed rendered command.
    """
    if not text:
        return text
    rem = MANUAL_REMEDIATION_TEMPLATES.get(check_id)
    if not rem:
        return text
    out = text
    for spec in rem.parameters:
        if not spec.secret:
            continue
        val = (parameters or {}).get(spec.name)
        if val and str(val).strip():
            out = out.replace(str(val).strip(), "<REDACTED>")
    return out
