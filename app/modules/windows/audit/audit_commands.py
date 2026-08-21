"""
Windows Server Audit Commands (PowerShell)

Read-only PowerShell scripts for collecting CIS Windows Server 2025 Benchmark
compliance data via WinRM. Every command is a ``Get-*`` / ``secedit /export`` /
``auditpol /get`` — the audit path never writes to the target.

Each command produces parseable output (JSON / CSV / secedit INF text) and is
wrapped so a single failure does not block the whole collection. The section
names line up 1:1 with the parsers in ``rules.py``:

    OS_VERSION        -> _detect_version / _detect_gate
    DOMAIN_ROLE       -> is_domain_controller (MS vs DC scope)
    SECURITY_POLICY   -> [System Access]  (Section 1)
    USER_RIGHTS       -> [Privilege Rights] (Section 2.2)
    AUDIT_POLICY      -> auditpol CSV       (Section 17)
    REGISTRY          -> {path: {named props only}} (Section 2.3 / 18)
    FIREWALL_PROFILES -> Get-NetFirewallProfile (Section 9)
    LOCAL_USERS       -> Guest account status (2.3.1.1)
"""

from typing import Dict

from .rules import get_registry_properties


def _registry_collection_script() -> str:
    """
    Build the REGISTRY collection PowerShell from the (path -> property names)
    map the rule engine reads (rules.get_registry_properties). Emits a hashtable
    of {full_path: <json string of the requested properties>} so rules._reg can
    look up any (path, property) pair. -LiteralPath avoids wildcard/bracket
    surprises.

    Only the named values are read. Fetching whole keys used to sweep up
    neighbouring secrets — Winlogon is audited for AutoAdminLogon and also holds
    DefaultPassword/DefaultUserName in cleartext when autologon is configured,
    which then landed in audit_sessions.turbo_dump.

    The spec travels as a here-string (one "path=prop|prop" line each) rather
    than a PowerShell hashtable literal: same data, ~1KB less quoting overhead
    on a script that is already a few KB.
    """
    spec_lines = [
        f"{path}={'|'.join(props)}"
        for path, props in get_registry_properties().items()
    ]
    spec = "\n".join(spec_lines)
    return (
        "$spec = @'\n"
        f"{spec}\n"
        "'@\n"
        "$result = @{}; "
        "foreach ($line in ($spec -split \"`r?`n\")) { "
        "    if (-not $line.Trim()) { continue } "
        "    $i = $line.IndexOf('='); "
        "    if ($i -lt 1) { continue } "
        "    $p = $line.Substring(0, $i); "
        "    $names = $line.Substring($i + 1) -split '\\|'; "
        "    try { "
        "        if (Test-Path -LiteralPath $p) { "
        "            $props = Get-ItemProperty -LiteralPath $p -Name $names "
        "                -ErrorAction SilentlyContinue; "
        "            if ($props) { "
        "                $o = @{}; "
        "                foreach ($n in $names) { "
        "                    $pp = $props.PSObject.Properties[$n]; "
        "                    if ($pp) { $o[$n] = $pp.Value } "
        "                } "
        "                $result[$p] = ($o | ConvertTo-Json -Compress -Depth 3) "
        "            } "
        "        } "
        "    } catch {} "
        "} "
        "$result | ConvertTo-Json -Depth 4"
    )


def get_windows_audit_commands() -> Dict[str, str]:
    """Return a dict of section_name -> read-only PowerShell collection script."""
    commands: Dict[str, str] = {}

    # ---- OS Version / Build (version gate) -------------------------- #
    commands["OS_VERSION"] = (
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption, Version, BuildNumber, OSArchitecture | "
        "ConvertTo-Json -Compress"
    )

    # ---- Domain role (MS vs DC scope) ------------------------------- #
    commands["DOMAIN_ROLE"] = (
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object DomainRole, Domain, PartOfDomain | "
        "ConvertTo-Json -Compress"
    )

    # ---- Security Policy (secedit [System Access]) ------------------ #
    commands["SECURITY_POLICY"] = (
        "$secpolPath = \"$env:TEMP\\secpol_audit_$([guid]::NewGuid().ToString('N')).cfg\"; "
        "secedit /export /cfg $secpolPath /quiet 2>$null; "
        "if (Test-Path $secpolPath) { "
        "    Get-Content $secpolPath -Raw; "
        "    Remove-Item $secpolPath -Force "
        "} else { Write-Output 'SECEDIT_EXPORT_FAILED' }"
    )

    # ---- User Rights Assignment ([Privilege Rights]) ---------------- #
    commands["USER_RIGHTS"] = (
        "$secpolPath = \"$env:TEMP\\secpol_rights_$([guid]::NewGuid().ToString('N')).cfg\"; "
        "secedit /export /cfg $secpolPath /quiet 2>$null; "
        "if (Test-Path $secpolPath) { "
        "    $content = Get-Content $secpolPath -Raw; "
        "    $inSection = $false; $lines = @(); "
        "    foreach ($line in ($content -split \"`r?`n\")) { "
        "        if ($line -match '^\\[Privilege Rights\\]') { $inSection = $true; continue } "
        "        if ($line -match '^\\[' -and $inSection) { break } "
        "        if ($inSection -and $line.Trim()) { $lines += $line } "
        "    } "
        "    $lines -join \"`n\"; "
        "    Remove-Item $secpolPath -Force "
        "} else { Write-Output 'SECEDIT_EXPORT_FAILED' }"
    )

    # ---- Advanced Audit Policy (auditpol CSV) ----------------------- #
    commands["AUDIT_POLICY"] = "auditpol /get /category:* /r"

    # ---- Registry (Section 2.3 / 18) -------------------------------- #
    commands["REGISTRY"] = _registry_collection_script()

    # ---- Firewall Profiles (Section 9) ------------------------------ #
    # Every flag here is a uint16 enum (GpoBoolean: True/False/NotConfigured),
    # not a boolean — see MSFT_NetFirewallProfile. ConvertTo-Json serialises an
    # enum as its *integer*, and the published class documents no ValueMap, so
    # a disabled profile arrived as some non-zero number and read as "on".
    # Casting to [string] emits the member name ("True"/"False"/"NotConfigured",
    # "Block"/"Allow"), which is unambiguous whatever the numbering is.
    _enum_fields = [
        "Enabled", "DefaultInboundAction", "DefaultOutboundAction",
        "NotifyOnListen", "AllowLocalFirewallRules", "AllowLocalIPsecRules",
        "LogAllowed", "LogBlocked",
        # uint64: MAXUINT64 means "Not Configured", so keep it exact.
        "LogMaxSizeKilobytes",
    ]
    _projection = ", ".join(
        ["Name"]
        + [f"@{{n='{f}';e={{[string]$_.{f}}}}}" for f in _enum_fields]
        + ["LogFileName"]
    )
    commands["FIREWALL_PROFILES"] = (
        f"Get-NetFirewallProfile -All | Select-Object {_projection} | "
        "ConvertTo-Json -Compress"
    )

    # ---- Local Users (Guest account status, 2.3.1.1) --------------- #
    commands["LOCAL_USERS"] = (
        "Get-LocalUser | Select-Object Name, Enabled, SID | ConvertTo-Json -Compress"
    )

    return commands
