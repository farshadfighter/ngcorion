"""
Windows DNS Server remediation.

Server-wide settings are changed with the DnsServer cmdlets and verified by
reading them back. Zone-wide fixes act on every zone that fails the check,
and those with side effects for clients (zone transfers, dynamic updates,
DNSSEC signing, the socket pool restart) need an explicit confirmation.
Host and procedural items (static addressing, file permissions, roles, key
handling) stay manual.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from .collect import DNS_PARAMS

TEMPLATES = TemplateSet()
_CONFIRM = "CONFIRM"
TEMPLATES.param(ParamMeta(
    name=_CONFIRM, input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))

_I = "Import-Module DnsServer; "
_PRIMARY = ("Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsAutoCreated "
            "-and $_.ZoneName -ne 'TrustAnchors' }")


def _ok(cond: str) -> str:
    return _I + f"if ({cond}) {{ 'PASS' }} else {{ 'FAIL' }}"


def _add(rid, description, statements, verify, warning=None, confirm=False, restart=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"DNS-{rid}", description=description, statements=[_I + s for s in statements],
        verify_statements=verify, parameters=[_CONFIRM] if confirm else [], warning=warning,
        requires_restart=restart))


_add("AC-1", "Restrict zone transfers (none for AD-integrated zones, name servers only otherwise)",
     [f"{_PRIMARY} | Where-Object {{ $_.SecureSecondaries -eq 'TransferAnyServer' }} | ForEach-Object {{ "
      "if ($_.IsDsIntegrated) { Set-DnsServerPrimaryZone -Name $_.ZoneName -SecureSecondaries NoTransfer } "
      "else { Set-DnsServerPrimaryZone -Name $_.ZoneName -SecureSecondaries TransferToZoneNameServer } }"],
     [_ok(f"-not @({_PRIMARY} | Where-Object {{ $_.SecureSecondaries -eq 'TransferAnyServer' }})")],
     warning="Secondary servers that are not listed as name servers of a zone stop receiving its transfers.",
     confirm=True)
_add("AC-2", "Allow only secure dynamic updates",
     [f"{_PRIMARY} | Where-Object {{ $_.DynamicUpdate -eq 'NonsecureAndSecure' }} | ForEach-Object {{ "
      "if ($_.IsDsIntegrated) { Set-DnsServerPrimaryZone -Name $_.ZoneName -DynamicUpdate Secure } "
      "else { Set-DnsServerPrimaryZone -Name $_.ZoneName -DynamicUpdate None } }"],
     [_ok(f"-not @({_PRIMARY} | Where-Object {{ $_.DynamicUpdate -eq 'NonsecureAndSecure' }})")],
     warning="Clients and DHCP servers that register without domain credentials can no longer update their records.",
     confirm=True)
TEMPLATES.add(HardeningTemplate(
    check_id="DNS-AU-1", description="Enable the DNS Server audit event log",
    statements=["wevtutil sl Microsoft-Windows-DNSServer/Audit /e:true"],
    verify_statements=["if ((Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Audit').IsEnabled) { 'PASS' } else { 'FAIL' }"]))
TEMPLATES.add(HardeningTemplate(
    check_id="DNS-AU-2", description="Set the DNS Server event log to 32 MB",
    statements=["wevtutil sl \"DNS Server\" /ms:33554432"],
    verify_statements=["if ((Get-WinEvent -ListLog 'DNS Server').MaximumSizeInBytes -ge 33554432) { 'PASS' } else { 'FAIL' }"]))
_add("AU-3", "Log errors, warnings and informational events",
     ["Set-DnsServerDiagnostics -EventLogLevel 4"],
     [_ok("(Get-DnsServerDiagnostics).EventLogLevel -eq 4")])
_add("CM-2", "Stop using root hints when forwarding",
     ["Set-DnsServerForwarder -UseRootHint $false"],
     [_ok("-not (Get-DnsServerForwarder).UseRootHint")],
     warning="If every forwarder is down, names outside your zones stop resolving instead of falling back to the root servers.")
_add("CM-4", "Raise the DNS socket pool to 10000 ports",
     [f"if (-not (Test-Path -LiteralPath '{DNS_PARAMS}')) {{ New-Item -Path '{DNS_PARAMS}' -Force | Out-Null }}; "
      f"Set-ItemProperty -LiteralPath '{DNS_PARAMS}' -Name SocketPoolSize -Value 10000 -Type DWord -Force; "
      "Restart-Service DNS"],
     [f"if ((Get-ItemProperty -LiteralPath '{DNS_PARAMS}' -Name SocketPoolSize).SocketPoolSize -ge 2500) {{ 'PASS' }} else {{ 'FAIL' }}"],
     warning="Restarts the DNS Server service: name resolution from this server pauses for a few seconds.",
     confirm=True)
_add("CM-5", "Set DNS cache locking to 100%", ["Set-DnsServerCache -LockingPercent 100"],
     [_ok("(Get-DnsServerCache).LockingPercent -eq 100")])
_add("CM-6", "Enable cache pollution protection", ["Set-DnsServerCache -EnablePollutionProtection $true"],
     [_ok("(Get-DnsServerCache).EnablePollutionProtection")])
_add("CM-7", "Enable the global query block list with wpad and isatap",
     ["$l = @(@((Get-DnsServerGlobalQueryBlockList).List) + 'wpad', 'isatap' | Where-Object { $_ } | Select-Object -Unique); "
      "Set-DnsServerGlobalQueryBlockList -Enable $true -List $l"],
     [_ok("$g = Get-DnsServerGlobalQueryBlockList; $g.Enable -and ($g.List -contains 'wpad') -and ($g.List -contains 'isatap')")],
     warning="Clients that find their web proxy through a 'wpad' DNS name stop finding it.")
_add("CM-8", "Enable response rate limiting", ["Set-DnsServerResponseRateLimiting -Mode Enable -Force"],
     [_ok("[string](Get-DnsServerResponseRateLimiting).Mode -eq 'Enable'")],
     warning="Clients sending very high query rates (some load testers, misconfigured resolvers) get truncated or dropped answers.")
_add("CM-9", "Return only secure responses from recursion", ["Set-DnsServerRecursion -SecureResponse $true"],
     [_ok("(Get-DnsServerRecursion).SecureResponse")])
_add("CM-10", "Limit cached records to one day", ["Set-DnsServerCache -MaxTtl 1.00:00:00"],
     [_ok("(Get-DnsServerCache).MaxTtl.TotalSeconds -le 86400")])
TEMPLATES.add(HardeningTemplate(
    check_id="DNS-CM-13", description="Start the DNS Server service and set it to start automatically",
    statements=["Set-Service -Name DNS -StartupType Automatic; Start-Service -Name DNS"],
    verify_statements=["$s = Get-Service DNS; if ($s.Status -eq 'Running' -and [string]$s.StartType -eq 'Automatic') { 'PASS' } else { 'FAIL' }"]))
_add("SC-1", "Sign every unsigned primary forward zone with the default DNSSEC parameters (NSEC3, RSA/SHA-256)",
     [f"{_PRIMARY} | Where-Object {{ -not $_.IsReverseLookupZone -and -not $_.IsSigned }} | "
      "ForEach-Object { Invoke-DnsServerZoneSign -ZoneName $_.ZoneName -SignWithDefault -Force }"],
     [_ok(f"-not @({_PRIMARY} | Where-Object {{ -not $_.IsReverseLookupZone -and -not $_.IsSigned }})")],
     warning=("Run it on the zone's key master. Delegated zones need their new DS records added at the parent, "
              "and validating resolvers reject the zone if keys are later lost or rolled incorrectly."),
     confirm=True)
TEMPLATES.add(HardeningTemplate(
    check_id="DNS-SC-5", description="Make the DNS server return DNSSEC records",
    statements=["dnscmd /config /enablednssec 1"],
    verify_statements=["Import-Module DnsServer; if ((Get-DnsServerSetting -All).EnableDnsSec) { 'PASS' } else { 'FAIL' }"]))

for _rid, _desc in {
    "AC-3": "Remove write access to %SystemRoot%\\System32\\dns from everyone but SYSTEM, Administrators and DnsAdmins.",
    "CM-1": "Assign static IP addresses to the DNS server's interfaces.",
    "CM-3": "Add a second forwarder (Set-DnsServerForwarder -IPAddress <a>,<b>).",
    "CM-11": "Move the DNS role to Windows Server 2016 or later.",
    "CM-12": "Move unrelated roles off the DNS server.",
    "SC-2": "Unsign the zone and sign it again with NSEC3.",
    "SC-3": "Replace weak keys: re-sign with RSA/SHA-256 (KSK 2048, ZSK 1024+) or ECDSA.",
    "SC-4": "Enable automatic rollover on each signing key.",
}.items():
    TEMPLATES.manual(f"DNS-{_rid}", _desc)
for _n in range(1, 9):
    TEMPLATES.manual(f"DNS-PR-{_n}", "Procedural requirement: verify and document it; nothing to change on the server.")
