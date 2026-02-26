"""
Windows Server Audit Commands (PowerShell)

PowerShell scripts for collecting CIS Benchmark compliance data from
Windows Server instances via WinRM. Each command produces parseable
output (JSON, CSV, or structured text).

Commands are grouped by CIS section and wrapped in try/catch blocks
so one failure does not block the entire collection.
"""

from typing import Dict


def get_windows_audit_commands() -> Dict[str, str]:
    """
    Return a dict of section_name -> PowerShell script for audit data collection.

    Each script is designed to produce parseable output. JSON is preferred
    where possible; CSV for tools like auditpol that natively support it.
    """
    commands: Dict[str, str] = {}

    # ---- OS Version / Build ----------------------------------------- #
    commands["OS_VERSION"] = (
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption, Version, BuildNumber, OSArchitecture | "
        "ConvertTo-Json -Compress"
    )

    # ---- Security Policy (secedit export) --------------------------- #
    # secedit exports to a file; we read it back and delete it
    commands["SECURITY_POLICY"] = (
        "$secpolPath = \"$env:TEMP\\secpol_audit_$([guid]::NewGuid().ToString('N')).cfg\"; "
        "secedit /export /cfg $secpolPath /quiet 2>$null; "
        "if (Test-Path $secpolPath) { "
        "    Get-Content $secpolPath -Raw; "
        "    Remove-Item $secpolPath -Force "
        "} else { "
        "    Write-Output 'SECEDIT_EXPORT_FAILED' "
        "}"
    )

    # ---- Advanced Audit Policy (auditpol CSV) ----------------------- #
    commands["AUDIT_POLICY"] = "auditpol /get /category:* /r"

    # ---- User Rights Assignment ------------------------------------- #
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
        "} else { "
        "    Write-Output 'SECEDIT_EXPORT_FAILED' "
        "}"
    )

    # ---- Registry: SYSTEM hive (LSA, network, session security) ----- #
    commands["REGISTRY_SYSTEM"] = (
        "$paths = @("
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel', "
        "    'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' "
        "); "
        "$result = @{}; "
        "foreach ($p in $paths) { "
        "    try { "
        "        if (Test-Path $p) { "
        "            $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue; "
        "            $result[$p] = $props | Select-Object * -ExcludeProperty PS* | "
        "                ConvertTo-Json -Compress -Depth 2 "
        "        } "
        "    } catch {} "
        "} "
        "$result | ConvertTo-Json -Depth 3"
    )

    # ---- Registry: SOFTWARE hive (Admin Templates / Policies) ------- #
    commands["REGISTRY_SOFTWARE"] = (
        "$paths = @("
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation', "
        "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', "
        "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile', "
        "    'HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' "
        "); "
        "$result = @{}; "
        "foreach ($p in $paths) { "
        "    try { "
        "        if (Test-Path $p) { "
        "            $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue; "
        "            $result[$p] = $props | Select-Object * -ExcludeProperty PS* | "
        "                ConvertTo-Json -Compress -Depth 2 "
        "        } "
        "    } catch {} "
        "} "
        "$result | ConvertTo-Json -Depth 3"
    )

    # ---- Services --------------------------------------------------- #
    commands["SERVICES"] = (
        "Get-Service | Select-Object Name, DisplayName, Status, StartType | "
        "ConvertTo-Json -Compress"
    )

    # ---- Firewall Profiles ------------------------------------------ #
    commands["FIREWALL_PROFILES"] = (
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, "
        "LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes | "
        "ConvertTo-Json -Compress"
    )

    # ---- Windows Features (Server only) ----------------------------- #
    commands["WINDOWS_FEATURES"] = (
        "try { "
        "    Get-WindowsFeature | Where-Object { $_.Installed -eq $true } | "
        "    Select-Object Name, DisplayName | ConvertTo-Json -Compress "
        "} catch { "
        "    Write-Output 'GET_WINDOWSFEATURE_NOT_AVAILABLE' "
        "}"
    )

    # ---- Local Users ------------------------------------------------ #
    commands["LOCAL_USERS"] = (
        "Get-LocalUser | Select-Object Name, Enabled, "
        "PasswordRequired, PasswordLastSet, LastLogon, "
        "AccountExpires, SID | ConvertTo-Json -Compress"
    )

    # ---- LSA Protection --------------------------------------------- #
    commands["LSA_PROTECTION"] = (
        "try { "
        "    $lsa = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "        -ErrorAction SilentlyContinue; "
        "    $lsa | Select-Object RunAsPPL, LimitBlankPasswordUse, "
        "        NoLMHash, RestrictAnonymous, RestrictAnonymousSAM, "
        "        EveryoneIncludesAnonymous, ForceGuest, SCENoApplyLegacyAuditPolicy, "
        "        DisableDomainCreds, LmCompatibilityLevel, "
        "        RestrictRemoteSAM | ConvertTo-Json -Compress "
        "} catch { Write-Output '{}' }"
    )

    # ---- Remote Desktop Settings ------------------------------------ #
    commands["REMOTE_DESKTOP"] = (
        "$rdp = @{}; "
        "try { "
        "    $ts = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
        "        -ErrorAction SilentlyContinue; "
        "    $rdp['fDenyTSConnections'] = $ts.fDenyTSConnections; "
        "    $rdp['fSingleSessionPerUser'] = $ts.fSingleSessionPerUser; "
        "    $sec = Get-ItemProperty -Path "
        "        'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "        -ErrorAction SilentlyContinue; "
        "    $rdp['UserAuthentication'] = $sec.UserAuthentication; "
        "    $rdp['SecurityLayer'] = $sec.SecurityLayer; "
        "    $rdp['MinEncryptionLevel'] = $sec.MinEncryptionLevel "
        "} catch {} "
        "$rdp | ConvertTo-Json -Compress"
    )

    # ---- WDigest Authentication ------------------------------------- #
    commands["WDIGEST"] = (
        "try { "
        "    $wd = Get-ItemProperty -Path "
        "        'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "        -ErrorAction SilentlyContinue; "
        "    $wd | Select-Object UseLogonCredential | ConvertTo-Json -Compress "
        "} catch { Write-Output '{\"UseLogonCredential\": null}' }"
    )

    # ---- Installed Hotfixes ----------------------------------------- #
    commands["HOTFIXES"] = (
        "Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | "
        "Select-Object -First 20 HotFixID, Description, InstalledOn | "
        "ConvertTo-Json -Compress"
    )

    # ---- Windows Defender Status ------------------------------------ #
    commands["DEFENDER_STATUS"] = (
        "try { "
        "    Get-MpComputerStatus | Select-Object AMServiceEnabled, "
        "        AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, "
        "        IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, "
        "        RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | "
        "    ConvertTo-Json -Compress "
        "} catch { Write-Output 'DEFENDER_NOT_AVAILABLE' }"
    )

    # ---- BitLocker Volumes ------------------------------------------ #
    commands["BITLOCKER"] = (
        "try { "
        "    Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, "
        "        ProtectionStatus, EncryptionMethod, EncryptionPercentage | "
        "    ConvertTo-Json -Compress "
        "} catch { Write-Output 'BITLOCKER_NOT_AVAILABLE' }"
    )

    # ---- SMBv1 Status ----------------------------------------------- #
    commands["SMBV1_STATUS"] = (
        "try { "
        "    $smb = Get-SmbServerConfiguration | "
        "        Select-Object EnableSMB1Protocol, EnableSMB2Protocol; "
        "    $feature = $null; "
        "    try { $feature = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
        "        -ErrorAction SilentlyContinue).State } catch {} "
        "    @{ 'EnableSMB1Protocol' = $smb.EnableSMB1Protocol; "
        "       'EnableSMB2Protocol' = $smb.EnableSMB2Protocol; "
        "       'SMB1FeatureState' = $feature } | ConvertTo-Json -Compress "
        "} catch { Write-Output '{}' }"
    )

    # ---- PowerShell v2 Feature State -------------------------------- #
    commands["POWERSHELL_V2"] = (
        "try { "
        "    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 "
        "        -ErrorAction SilentlyContinue; "
        "    @{ 'FeatureName' = $ps2.FeatureName; 'State' = [string]$ps2.State } | "
        "        ConvertTo-Json -Compress "
        "} catch { "
        "    try { "
        "        $ps2 = Get-WindowsFeature PowerShell-V2 -ErrorAction SilentlyContinue; "
        "        @{ 'FeatureName' = 'PowerShell-V2'; 'Installed' = $ps2.Installed } | "
        "            ConvertTo-Json -Compress "
        "    } catch { Write-Output '{}' } "
        "}"
    )

    # ---- Credential Guard ------------------------------------------- #
    commands["CREDENTIAL_GUARD"] = (
        "try { "
        "    $dg = Get-CimInstance -ClassName Win32_DeviceGuard "
        "        -Namespace root\\Microsoft\\Windows\\DeviceGuard "
        "        -ErrorAction SilentlyContinue; "
        "    $dg | Select-Object SecurityServicesConfigured, SecurityServicesRunning, "
        "        VirtualizationBasedSecurityStatus | ConvertTo-Json -Compress "
        "} catch { Write-Output '{}' }"
    )

    # ---- Network Profile Settings ----------------------------------- #
    commands["NETWORK_PROFILES"] = (
        "Get-NetConnectionProfile | Select-Object Name, NetworkCategory, "
        "InterfaceAlias | ConvertTo-Json -Compress"
    )

    # ---- Scheduled Tasks (non-Microsoft) ---------------------------- #
    commands["SCHEDULED_TASKS"] = (
        "Get-ScheduledTask | Where-Object { $_.Author -notlike 'Microsoft*' -and "
        "$_.Author -ne $null -and $_.State -eq 'Ready' } | "
        "Select-Object TaskName, Author, State -First 50 | ConvertTo-Json -Compress"
    )

    # ---- UAC Settings ----------------------------------------------- #
    commands["UAC_SETTINGS"] = (
        "try { "
        "    $uac = Get-ItemProperty -Path "
        "        'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "        -ErrorAction SilentlyContinue; "
        "    $uac | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, "
        "        ConsentPromptBehaviorUser, EnableInstallerDetection, "
        "        EnableSecureUIAPaths, EnableVirtualization, "
        "        PromptOnSecureDesktop, FilterAdministratorToken, "
        "        ValidateAdminCodeSignatures, EnableUIADesktopToggle, "
        "        LegalNoticeCaption, LegalNoticeText, "
        "        DontDisplayLastUserName, InactivityTimeoutSecs | "
        "    ConvertTo-Json -Compress "
        "} catch { Write-Output '{}' }"
    )

    return commands
