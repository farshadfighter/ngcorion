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
    REGISTRY          -> {path: {props}}    (Section 2.3 / 18)
    FIREWALL_PROFILES -> Get-NetFirewallProfile (Section 9)
    LOCAL_USERS       -> Guest account status (2.3.1.1)
"""

from typing import Dict

from .rules import get_registry_paths


def _registry_collection_script() -> str:
    """
    Build the REGISTRY collection PowerShell from the single list of paths the
    rule engine reads (rules.get_registry_paths). Emits a hashtable of
    {full_path: <json string of properties>} so rules._reg can look up any
    (path, property) pair. -LiteralPath avoids wildcard/bracket surprises.
    """
    paths = get_registry_paths()
    # Single-quote each path; none contain a single quote.
    ps_array = ", ".join("'" + p.replace("'", "''") + "'" for p in paths)
    return (
        f"$paths = @({ps_array}); "
        "$result = @{}; "
        "foreach ($p in $paths) { "
        "    try { "
        "        if (Test-Path -LiteralPath $p) { "
        "            $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue; "
        "            if ($props) { "
        "                $result[$p] = ($props | Select-Object * -ExcludeProperty PS* | "
        "                    ConvertTo-Json -Compress -Depth 3) "
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
    commands["FIREWALL_PROFILES"] = (
        "Get-NetFirewallProfile -All | "
        "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, "
        "NotifyOnListen, AllowLocalFirewallRules, AllowLocalIPsecRules, "
        "LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes | "
        "ConvertTo-Json -Compress"
    )

    # ---- Local Users (Guest account status, 2.3.1.1) --------------- #
    commands["LOCAL_USERS"] = (
        "Get-LocalUser | Select-Object Name, Enabled, SID | ConvertTo-Json -Compress"
    )

    return commands
