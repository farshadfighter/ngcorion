"""
Sophos Firewall remediation through the XML API ("SFOS:" statements, see
edit.py): the current object is read, only the named fields change, and it
is sent back with Set operation="update". Each fix is verified by running
its rule again on a fresh collection.

Changes that can cut off access - device access on the WAN zone, TLS for
syslog - need confirmation. Multi-factor authentication, certificates,
ports, rules' IPS policies, SNMP, syslog servers and backups need choices
only the administrator can make and stay as guidance.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from . import rules as R

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))
TEMPLATES.param(ParamMeta(
    name="LOCKOUT_ATTEMPTS", input_type="number", label="Failed logins before blocking",
    description="Unsuccessful administrator logins from one address before it is blocked (1-5).", required=True,
    min_value=1, max_value=5, placeholder="5"))
TEMPLATES.param(ParamMeta(
    name="MIN_PASSWORD_LENGTH", input_type="number", label="Minimum administrator password length",
    description="Characters an administrator password needs at least (12-20).", required=True,
    min_value=12, max_value=20, placeholder="14"))

WAN = "SFOS:zone type=WAN "
_ACCESS_WARNING = ("Applies to the WAN zone. If this server reaches the firewall's API through the WAN, the API "
                   "connection is cut too - make sure it comes from a LAN or management zone, or through a VPN.")


def _add(sec, description, statements, warning=None, params=()):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"SOPHOS-{sec}", description=description, statements=statements,
        verify_statements=[f"SFOS:check SOPHOS-{sec}"], parameters=list(params), warning=warning))


_add("1.1", "Turn off web admin (HTTPS) and SSH on the WAN zone",
     [WAN + "ApplianceAccess/AdminServices/HTTPS=Disable ApplianceAccess/AdminServices/SSH=Disable"],
     warning="Administrators can no longer manage the firewall from the internet. " + _ACCESS_WARNING,
     params=["CONFIRM"])
_add("1.2", "Turn off the user portal on the WAN zone", [WAN + "ApplianceAccess/OtherServices/UserPortal=Disable"],
     warning="Remote users can no longer reach the user portal (VPN client downloads, password changes) from the "
             "internet.", params=["CONFIRM"])
_add("1.3", "Turn off SNMP, DNS, web proxy, routing, SMTP relay and captive portal on the WAN zone",
     [WAN + "ApplianceAccess/OtherServices/SNMP=Disable ApplianceAccess/NetworkServices/DNS=Disable "
            "ApplianceAccess/OtherServices/WebProxy=Disable ApplianceAccess/OtherServices/DynamicRouting=Disable "
            "ApplianceAccess/OtherServices/SMTPRelay=Disable ApplianceAccess/AuthenticationServices/CaptivePortal=Disable"],
     warning="Monitoring, routing peers or mail relays that use these services from the WAN stop working.",
     params=["CONFIRM"])
_add("1.5", "Log out idle administrator sessions after 10 minutes",
     ["SFOS:set AdminSettings LoginSecurity LogoutSession=10"])
_add("1.6", "Block administrator logins after repeated failures",
     ["SFOS:set AdminSettings LoginSecurity BlockLogin=Enable BlockLoginSettings/UnsucccessfulAttempt={LOCKOUT_ATTEMPTS} "
      "BlockLoginSettings/Duration=10 BlockLoginSettings/ForMinutes=15"],
     warning="An address with too many failed logins within 10 minutes is blocked for 15 minutes.",
     params=["LOCKOUT_ATTEMPTS"])
_add("1.7", "Require complex administrator passwords",
     ["SFOS:set AdminSettings PasswordComplexitySettings PasswordComplexityCheck=Enable "
      "PasswordComplexity/MinimumPasswordLength=Enable PasswordComplexity/MinimumPasswordLengthValue={MIN_PASSWORD_LENGTH} "
      "PasswordComplexity/IncludeAlphabeticCharacters=Enable PasswordComplexity/IncludeNumericCharacter=Enable "
      "PasswordComplexity/IncludeSpecialCharacter=Enable"],
     warning="Applies to new and changed administrator passwords; existing passwords keep working.",
     params=["MIN_PASSWORD_LENGTH"])
_add("1.8", "Show the login disclaimer", ["SFOS:set AdminSettings LoginDisclaimer .=Enable"])
_add("2.1", "Install hotfixes automatically", ["SFOS:set Hotfix - AllowAutoInstallOfHotFixes=Enable"])
_add("2.2", "Update protection patterns automatically every 15 minutes",
     ["SFOS:set PatternDownload - AutoUpdate=On 'Interval=Every 15 minutes'"])
_add("3.2", "Send syslog over TLS", ["SFOS:each SyslogServers EnableSecureConnection=Enable"],
     warning="Every syslog collector must accept TLS on its port; collectors that do not stop receiving logs.",
     params=["CONFIRM"])
_add("3.4", "Log traffic on every allow rule", ["SFOS:rules-log"],
     warning="Log volume grows with the traffic those rules allow.")
_add("4.3", "Turn on Advanced Threat Protection", ["SFOS:set ATP - ThreatProtectionStatus=Enable"])

_GUIDANCE = {
    "1.4": "Administration > Device access > Local service ACL exception: remove WAN rules for HTTPS/SSH or limit "
           "them to fixed management hosts.",
    "1.9": "Authentication > One-time password: enable OTP for web admin after issuing tokens to every administrator.",
    "3.1": "System services > Log settings: add a syslog server (TLS, port 6514 where the collector supports it).",
    "4.1": "Replace any-to-any allow rules with rules naming zones, networks and services.",
    "4.2": "Select an IPS policy on each rule that allows traffic from the WAN.",
    "4.5": "Administration > SNMP: remove v1/v2c communities; add SNMPv3 users with SHA and AES.",
    "5.1": "Backup & firmware > Backup and restore: schedule backups with an encryption password.",
    "5.2": "Send scheduled backups by FTP or email to storage outside the firewall.",
}
for _r in R.all_rules():
    if _r.id not in TEMPLATES.templates:
        TEMPLATES.manual(_r.id, _GUIDANCE.get(_r.section, _r.remediation))
