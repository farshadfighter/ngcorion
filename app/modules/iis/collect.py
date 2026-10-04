"""
Read-only collection for an IIS 10 audit, over WinRM.

Configuration is read with the WebAdministration module at the three levels
the benchmark talks about: applicationHost (MACHINE/WEBROOT/APPHOST), the
root web.config (MACHINE/WEBROOT) and machine.config (MACHINE), and the
effective values of each site, so a site's own web.config counts. Values
come back as strings; "N/A" means the section does not exist (the module
behind it is not installed). SCHANNEL is read with the .NET registry API
because cipher key names contain "/". Site content, credentials stored in
configuration and machine keys are never read - only whether they exist.
"""

from typing import Dict

from app.modules.benchmark.rules import assemble
from app.modules.benchmark.winps import guarded
from app.modules.windows.audit.audit_commands import get_windows_audit_commands

A = "MACHINE/WEBROOT/APPHOST"
W = "MACHINE/WEBROOT"
M = "MACHINE"

_V = (
    "Import-Module WebAdministration; "
    "function V($path, $filter, $name) { try { $p = Get-WebConfigurationProperty -PSPath $path -Filter $filter "
    "  -Name $name -ErrorAction Stop; if ($null -eq $p) { $null } elseif ($p.PSObject.Properties['Value']) "
    "  { [string]$p.Value } else { [string]$p } } catch { 'N/A' } }; "
    "function E($path, $filter) { try { [bool](Get-WebConfiguration -PSPath $path -Filter $filter -ErrorAction Stop) } "
    "  catch { $false } }; "
)

# key -> (level, filter, attribute)
SERVER_VALUES = {
    "DirBrowse": (A, "system.webServer/directoryBrowse", "enabled"),
    "AnonymousUser": (A, "system.webServer/security/authentication/anonymousAuthentication", "userName"),
    "BasicAuth": (A, "system.webServer/security/authentication/basicAuthentication", "enabled"),
    "AccessSslFlags": (A, "system.webServer/security/access", "sslFlags"),
    "ErrorMode": (A, "system.webServer/httpErrors", "errorMode"),
    "MaxContentLength": (A, "system.webServer/security/requestFiltering/requestLimits", "maxAllowedContentLength"),
    "MaxUrl": (A, "system.webServer/security/requestFiltering/requestLimits", "maxUrl"),
    "MaxQueryString": (A, "system.webServer/security/requestFiltering/requestLimits", "maxQueryString"),
    "AllowHighBit": (A, "system.webServer/security/requestFiltering", "allowHighBitCharacters"),
    "AllowDoubleEscaping": (A, "system.webServer/security/requestFiltering", "allowDoubleEscaping"),
    "RemoveServerHeader": (A, "system.webServer/security/requestFiltering", "removeServerHeader"),
    "AllowUnlistedExt": (A, "system.webServer/security/requestFiltering/fileExtensions", "allowUnlisted"),
    "TraceVerbAllowed": (A, "system.webServer/security/requestFiltering/verbs/add[@verb='TRACE']", "allowed"),
    "HandlersAccessPolicy": (A, "system.webServer/handlers", "accessPolicy"),
    "NotListedIsapis": (A, "system.webServer/security/isapiCgiRestriction", "notListedIsapisAllowed"),
    "NotListedCgis": (A, "system.webServer/security/isapiCgiRestriction", "notListedCgisAllowed"),
    "DynIpConcurrent": (A, "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests", "enabled"),
    "DynIpRate": (A, "system.webServer/security/dynamicIpSecurity/denyByRequestRate", "enabled"),
    "LogDirectory": (A, "system.applicationHost/sites/siteDefaults/logFile", "directory"),
    "LogTarget": (A, "system.applicationHost/sites/siteDefaults/logFile", "logTargetW3C"),
    "FtpControlChannel": (A, "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl", "controlChannelPolicy"),
    "FtpDataChannel": (A, "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl", "dataChannelPolicy"),
    "FtpDenyByFailure": (A, "system.ftpServer/security/authentication/denyByFailure", "enabled"),
    "Retail": (M, "system.web/deployment", "retail"),
    "Debug": (W, "system.web/compilation", "debug"),
    "CustomErrors": (W, "system.web/customErrors", "mode"),
    "Trace": (W, "system.web/trace", "enabled"),
    "SessionCookieless": (W, "system.web/sessionState", "cookieless"),
    "HttpOnlyCookies": (W, "system.web/httpCookies", "httpOnlyCookies"),
    "MachineKeyValidation": (W, "system.web/machineKey", "validation"),
    "TrustLevel": (W, "system.web/trust", "level"),
    "FormsRequireSsl": (W, "system.web/authentication/forms", "requireSSL"),
    "FormsCookieless": (W, "system.web/authentication/forms", "cookieless"),
    "FormsProtection": (W, "system.web/authentication/forms", "protection"),
    "PasswordFormat": (W, "system.web/authentication/forms/credentials", "passwordFormat"),
}
SERVER_EXISTS = {
    "XPoweredByHeader": (A, "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"),
    "HstsHeader": (A, "system.webServer/httpProtocol/customHeaders/add[@name='Strict-Transport-Security']"),
    "AuthorizationAllowAll": (A, "system.webServer/security/authorization/add[@users='*' and @accessType='Allow']"),
    "FormsCredentialUsers": (W, "system.web/authentication/forms/credentials/user"),
}


def _server_script() -> str:
    parts = [f"{k} = V '{lvl}' \"{flt}\" '{attr}'" for k, (lvl, flt, attr) in SERVER_VALUES.items()]
    parts += [f"{k} = E '{lvl}' \"{flt}\"" for k, (lvl, flt) in SERVER_EXISTS.items()]
    return _V + "[pscustomobject]@{ " + "; ".join(parts) + " } | ConvertTo-Json -Compress"


IIS_SITES = _V + (
    "$sites = @(Get-Website | ForEach-Object { $n = $_.Name; $p = \"IIS:\\Sites\\$n\"; "
    "  [pscustomobject]@{ Name = $n; State = [string]$_.State; "
    "    PhysicalPath = [Environment]::ExpandEnvironmentVariables($_.PhysicalPath); AppPool = $_.ApplicationPool; "
    "    Bindings = @($_.Bindings.Collection | ForEach-Object { [pscustomobject]@{ Protocol = $_.protocol; "
    "      Info = $_.bindingInformation } }); "
    "    DirBrowse = V $p 'system.webServer/directoryBrowse' 'enabled'; ErrorMode = V $p 'system.webServer/httpErrors' 'errorMode'; "
    "    Debug = V $p 'system.web/compilation' 'debug'; CustomErrors = V $p 'system.web/customErrors' 'mode'; "
    "    Trace = V $p 'system.web/trace' 'enabled'; "
    "    Hsts = V 'MACHINE/WEBROOT/APPHOST' \"system.applicationHost/sites/site[@name='$n']/hsts\" 'enabled' } }); "
    "$pools = @(Get-ChildItem IIS:\\AppPools | ForEach-Object { [pscustomobject]@{ Name = $_.Name; "
    "  Identity = [string]$_.processModel.identityType; State = [string]$_.State } }); "
    "[pscustomobject]@{ Sites = $sites; Pools = $pools } | ConvertTo-Json -Depth 5 -Compress"
)

IIS_HOST = (
    "$v = Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\InetStp' -ErrorAction Stop; "
    "$f = @{}; foreach ($n in 'Web-DAV-Publishing', 'Web-Ftp-Server', 'Web-IP-Security', 'Web-Asp-Net45') { "
    "  $f[$n] = [bool](Get-WindowsFeature -Name $n).Installed }; "
    "[pscustomobject]@{ IisVersion = \"$($v.MajorVersion).$($v.MinorVersion)\"; SystemDrive = $env:SystemDrive; "
    "  Features = $f } | ConvertTo-Json -Depth 3 -Compress"
)

SCHANNEL_BASE = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
SCHANNEL_KEYS = (
    "Protocols\\SSL 2.0\\Server", "Protocols\\SSL 3.0\\Server", "Protocols\\TLS 1.0\\Server",
    "Protocols\\TLS 1.1\\Server", "Protocols\\TLS 1.2\\Server",
    "Ciphers\\NULL", "Ciphers\\DES 56/56", "Ciphers\\RC4 40/128", "Ciphers\\RC4 56/128", "Ciphers\\RC4 64/128",
    "Ciphers\\RC4 128/128", "Ciphers\\Triple DES 168", "Ciphers\\AES 128/128", "Ciphers\\AES 256/256",
)

SCHANNEL = (
    f"$base = '{SCHANNEL_BASE}'; $hk = [Microsoft.Win32.Registry]::LocalMachine; $out = [ordered]@{{}}; "
    "foreach ($k in @(" + ", ".join(f"'{k}'" for k in SCHANNEL_KEYS) + ")) { "
    "  $key = $hk.OpenSubKey(\"$base\\$k\"); "
    "  if ($key) { $o = @{}; foreach ($n in $key.GetValueNames()) { $val = $key.GetValue($n); "
    "    $o[$n] = if ($val -is [int]) { [int64]([uint32]('0x{0:X8}' -f $val)) } else { $val } }; "
    "    $out[$k] = $o; $key.Close() } else { $out[$k] = $null } }; "
    "$out | ConvertTo-Json -Compress"
)

HOST_SECTIONS = ("OS_VERSION",)


def iis_commands() -> Dict[str, str]:
    win = get_windows_audit_commands()
    cmds = {name: win[name] for name in HOST_SECTIONS}
    cmds.update({
        "IIS_SERVER": guarded(_server_script()),
        "IIS_SITES": guarded(IIS_SITES),
        "IIS_HOST": guarded(IIS_HOST),
        "SCHANNEL": guarded(SCHANNEL),
    })
    return cmds


def collect(conn) -> str:
    return assemble({name: conn.run(script) for name, script in iis_commands().items()})
