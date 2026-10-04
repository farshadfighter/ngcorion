"""
IIS 10 remediation.

Configuration fixes write to applicationHost.config, the root web.config or
machine.config through the WebAdministration cmdlets and are verified by
reading the effective value back - a site whose own web.config overrides
the value still fails verification, which is the truth. SCHANNEL fixes
write the registry with the .NET API (cipher names contain "/") and take
effect after a restart. Changes that can break clients or applications
(TLS 1.0/1.1, AES-128, HSTS, request limits, non-ASCII URLs, pool
identities, WebDAV removal, machine key) need an explicit confirmation.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from .collect import A, M, SCHANNEL_BASE, W

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))

_I = "Import-Module WebAdministration; "


def _get(level, flt, attr):
    return f"(Get-WebConfigurationProperty -PSPath '{level}' -Filter \"{flt}\" -Name '{attr}').Value"


def _set(level, flt, attr, value):
    return f"Set-WebConfigurationProperty -PSPath '{level}' -Filter \"{flt}\" -Name '{attr}' -Value {value}"


def _add(sec, description, statements, verify_cond, warning=None, confirm=False, restart=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"IIS-{sec}", description=description, statements=[_I + s for s in statements],
        verify_statements=[_I + f"if ({verify_cond}) {{ 'PASS' }} else {{ 'FAIL' }}"],
        parameters=["CONFIRM"] if confirm else [], warning=warning, requires_restart=restart))


def _value(sec, description, level, flt, attr, value, cond, warning=None, confirm=False):
    _add(sec, description, [_set(level, flt, attr, value)], cond.replace("$v", f"({_get(level, flt, attr)})"),
         warning=warning, confirm=confirm)


def _site_wide(sec, description, flt, attr, value, bad_cond):
    """Server value, plus a location entry for every site; verified on each
    site's effective configuration."""
    _add(sec, description,
         [_set(A, flt, attr, value) + "; Get-Website | ForEach-Object { "
          f"Set-WebConfigurationProperty -PSPath '{A}' -Location $_.Name -Filter \"{flt}\" -Name '{attr}' -Value {value} }}"],
         f"-not @(Get-Website | Where-Object {{ $v = (Get-WebConfigurationProperty -PSPath \"IIS:\\Sites\\$($_.Name)\" "
         f"-Filter \"{flt}\" -Name '{attr}').Value; {bad_cond} }}) -and -not $($v = {_get(A, flt, attr)}; {bad_cond})")


def _web_value(sec, description, flt, attr, value, bad_cond):
    """Root web.config value (ASP.NET), verified at the server and every site."""
    _add(sec, description, [_set(W, flt, attr, value)],
         f"-not @(Get-Website | Where-Object {{ $v = (Get-WebConfigurationProperty -PSPath \"IIS:\\Sites\\$($_.Name)\" "
         f"-Filter \"{flt}\" -Name '{attr}').Value; {bad_cond} }}) -and -not $($v = {_get(W, flt, attr)}; {bad_cond})")


# 1 Basic configuration
_site_wide("1.3", "Disable directory browsing", "system.webServer/directoryBrowse", "enabled", "$false", "[string]$v -eq 'True'")
_add("1.4", "Run every application pool as ApplicationPoolIdentity",
     ["Get-ChildItem IIS:\\AppPools | Where-Object { $_.processModel.identityType -ne 'ApplicationPoolIdentity' } | "
      "ForEach-Object { Set-ItemProperty \"IIS:\\AppPools\\$($_.Name)\" -Name processModel.identityType -Value ApplicationPoolIdentity }"],
     "-not @(Get-ChildItem IIS:\\AppPools | Where-Object { $_.processModel.identityType -ne 'ApplicationPoolIdentity' })",
     warning="Applications that reach databases or shares with the pool's service account lose that access.", confirm=True)
_value("1.6", "Use the application pool identity for anonymous users", A,
       "system.webServer/security/authentication/anonymousAuthentication", "userName", "''", "[string]$v -eq ''",
       warning="Content readable only by IUSR becomes unreadable until the pool identities are granted access.", confirm=True)
_add("1.7", "Remove the WebDAV Publishing feature",
     ["Uninstall-WindowsFeature -Name Web-DAV-Publishing | Out-Null"],
     "-not (Get-WindowsFeature -Name Web-DAV-Publishing).Installed",
     warning="Applications publishing over WebDAV stop working.", confirm=True)

# 2 Authentication
_value("2.3", "Require SSL for forms authentication", W, "system.web/authentication/forms", "requireSSL", "$true", "[string]$v -eq 'True'",
       warning="Forms logins over plain HTTP stop working.")
_value("2.4", "Use cookies for forms authentication", W, "system.web/authentication/forms", "cookieless", "UseCookies", "[string]$v -eq 'UseCookies'")
_value("2.5", "Protect forms authentication cookies (encryption and validation)", W, "system.web/authentication/forms",
       "protection", "All", "[string]$v -eq 'All'")
_value("2.6", "Require SSL for the server (basic authentication over TLS only)", A, "system.webServer/security/access",
       "sslFlags", "Ssl", "[string]$v -match 'Ssl'",
       warning="Every site then refuses plain HTTP requests.", confirm=True)

# 3 ASP.NET
_value("3.1", "Set deployment retail in machine.config", M, "system.web/deployment", "retail", "$true", "[string]$v -eq 'True'")
_web_value("3.2", "Turn ASP.NET debug off", "system.web/compilation", "debug", "$false", "[string]$v -eq 'True'")
_web_value("3.3", "Use custom errors for remote clients", "system.web/customErrors", "mode", "RemoteOnly", "[string]$v -eq 'Off'")
_site_wide("3.4", "Show detailed IIS errors only locally", "system.webServer/httpErrors", "errorMode", "DetailedLocalOnly",
           "[string]$v -eq 'Detailed'")
_web_value("3.5", "Turn ASP.NET tracing off", "system.web/trace", "enabled", "$false", "[string]$v -eq 'True'")
_value("3.6", "Keep session IDs in cookies", W, "system.web/sessionState", "cookieless", "UseCookies", "[string]$v -eq 'UseCookies'")
_value("3.7", "Set HttpOnly on ASP.NET cookies", W, "system.web/httpCookies", "httpOnlyCookies", "$true", "[string]$v -eq 'True'")
_value("3.8", "Validate machine keys with HMACSHA256", W, "system.web/machineKey", "validation", "HMACSHA256",
       "[string]$v -match '^HMACSHA(256|384|512)$'",
       warning="Existing authentication tickets and view state become invalid; users sign in again. "
               "Web farms must change every node together.", confirm=True)
_add("3.10", "Remove the X-Powered-By header",
     [f"Remove-WebConfigurationProperty -PSPath '{A}' -Filter system.webServer/httpProtocol/customHeaders -Name . "
      "-AtElement @{name='X-Powered-By'} -ErrorAction SilentlyContinue"],
     f"-not (Get-WebConfiguration -PSPath '{A}' -Filter \"system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']\")")
_value("3.11", "Remove the Server header", A, "system.webServer/security/requestFiltering", "removeServerHeader", "$true",
       "[string]$v -eq 'True'")

# 4 Request filtering
_RL = "system.webServer/security/requestFiltering/requestLimits"
_value("4.1", "Limit request bodies to 30 MB", A, _RL, "maxAllowedContentLength", "30000000", "[int64]$v -le 30000000",
       warning="Uploads larger than 30 MB are rejected.", confirm=True)
_value("4.2", "Limit URLs to 4096 characters", A, _RL, "maxUrl", "4096", "[int64]$v -le 4096")
_value("4.3", "Limit query strings to 2048 characters", A, _RL, "maxQueryString", "2048", "[int64]$v -le 2048",
       warning="Requests with longer query strings are rejected (some reporting tools and SSO flows use long ones).", confirm=True)
_value("4.4", "Reject non-ASCII characters in URLs", A, "system.webServer/security/requestFiltering", "allowHighBitCharacters",
       "$false", "[string]$v -eq 'False'",
       warning="URLs containing non-ASCII characters (Persian page names, for example) are rejected.", confirm=True)
_value("4.5", "Reject double-encoded requests", A, "system.webServer/security/requestFiltering", "allowDoubleEscaping",
       "$false", "[string]$v -eq 'False'")
_add("4.6", "Deny the HTTP TRACE verb",
     [f"$f = 'system.webServer/security/requestFiltering/verbs'; "
      f"if (Get-WebConfiguration -PSPath '{A}' -Filter \"$f/add[@verb='TRACE']\") {{ "
      f"Set-WebConfigurationProperty -PSPath '{A}' -Filter \"$f/add[@verb='TRACE']\" -Name allowed -Value $false }} "
      f"else {{ Add-WebConfigurationProperty -PSPath '{A}' -Filter $f -Name . -Value @{{verb='TRACE'; allowed='False'}} }}"],
     f"[string]{_get(A, 'system.webServer/security/requestFiltering/verbs/add[@verb=' + chr(39) + 'TRACE' + chr(39) + ']', 'allowed')} -eq 'False'")
_value("4.8", "Grant handlers Read and Script only", A, "system.webServer/handlers", "accessPolicy", "'Read,Script'",
       "-not ([string]$v -match 'Write' -and [string]$v -match 'Script|Execute')")
_value("4.9", "Deny ISAPI modules that are not listed", A, "system.webServer/security/isapiCgiRestriction",
       "notListedIsapisAllowed", "$false", "[string]$v -eq 'False'")
_value("4.10", "Deny CGI programs that are not listed", A, "system.webServer/security/isapiCgiRestriction",
       "notListedCgisAllowed", "$false", "[string]$v -eq 'False'")
_add("4.11", "Enable dynamic IP restrictions (concurrent requests and request rate)",
     [_set(A, "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests", "enabled", "$true") + "; " +
      _set(A, "system.webServer/security/dynamicIpSecurity/denyByRequestRate", "enabled", "$true")],
     f"[string]{_get(A, 'system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests', 'enabled')} -eq 'True'",
     warning="Many clients behind one NAT address can be throttled. Needs the IP and Domain Restrictions feature.",
     confirm=True)

# 5 Logging
_value("5.3", "Log to file and ETW", A, "system.applicationHost/sites/siteDefaults/logFile", "logTargetW3C", "'File,ETW'",
       "[string]$v -match 'ETW'")

# 6 FTP
_add("6.1", "Require SSL on FTP control and data channels",
     [_set(A, "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl", "controlChannelPolicy", "SslRequire") + "; " +
      _set(A, "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl", "dataChannelPolicy", "SslRequire")],
     f"[string]{_get(A, 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl', 'controlChannelPolicy')} -eq 'SslRequire'",
     warning="FTP clients without FTPS can no longer connect.", confirm=True)
_value("6.2", "Enable FTP logon attempt restrictions", A, "system.ftpServer/security/authentication/denyByFailure",
       "enabled", "$true", "[string]$v -eq 'True'")

# 7 Transport encryption
_add("7.1", "Enable HSTS (one year) on every HTTPS site",
     ["Get-Website | Where-Object { $_.Bindings.Collection.protocol -contains 'https' } | ForEach-Object { "
      f"$f = \"system.applicationHost/sites/site[@name='$($_.Name)']/hsts\"; "
      f"Set-WebConfigurationProperty -PSPath '{A}' -Filter $f -Name enabled -Value $true; "
      f"Set-WebConfigurationProperty -PSPath '{A}' -Filter $f -Name max-age -Value 31536000 }}"],
     "-not @(Get-Website | Where-Object { $_.Bindings.Collection.protocol -contains 'https' } | Where-Object { "
     f"[string](Get-WebConfigurationProperty -PSPath '{A}' -Filter \"system.applicationHost/sites/site[@name='$($_.Name)']/hsts\" "
     "-Name enabled).Value -ne 'True' })",
     warning="Browsers then refuse plain HTTP to these host names for a year. Needs IIS 10 version 1709 or later.",
     confirm=True)


def _reg(key, values):
    sets = "; ".join(f"$k.SetValue('{n}', {v}, [Microsoft.Win32.RegistryValueKind]::DWord)" for n, v in values.items())
    return (f"$k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('{SCHANNEL_BASE}\\{key}'); {sets}; $k.Close()")


def _reg_ok(key, cond):
    return (f"$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('{SCHANNEL_BASE}\\{key}'); "
            f"if ($k -and ({cond})) {{ 'PASS' }} else {{ 'FAIL' }}")


def _schannel(sec, description, key, values, cond, warning=None, confirm=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"IIS-{sec}", description=description, statements=[_reg(key, values)],
        verify_statements=[_reg_ok(key, cond)], requires_restart=True,
        parameters=["CONFIRM"] if confirm else [], warning=warning))


for _sec, _p, _confirm in (("7.2", "SSL 2.0", False), ("7.3", "SSL 3.0", False), ("7.4", "TLS 1.0", True), ("7.5", "TLS 1.1", True)):
    _schannel(_sec, f"Disable {_p} for the server", f"Protocols\\{_p}\\Server", {"Enabled": 0, "DisabledByDefault": 1},
              "$k.GetValue('Enabled') -eq 0 -and $k.GetValue('DisabledByDefault') -eq 1",
              warning=(f"Clients that only speak {_p} (old Windows, Java 6/7, embedded devices) can no longer connect. "
                       "Takes effect after a restart.") if _confirm else "Takes effect after a restart.",
              confirm=_confirm)
_schannel("7.6", "Enable TLS 1.2 for the server", "Protocols\\TLS 1.2\\Server", {"Enabled": 1, "DisabledByDefault": 0},
          "$k.GetValue('Enabled') -ne 0 -and $k.GetValue('DisabledByDefault') -eq 0", warning="Takes effect after a restart.")
for _sec, _c in (("7.7", "NULL"), ("7.8", "DES 56/56"), ("7.9", "RC4 40/128"), ("7.10", "RC4 56/128"),
                 ("7.11", "RC4 64/128"), ("7.12", "RC4 128/128"), ("7.15", "Triple DES 168")):
    _schannel(_sec, f"Disable the {_c} cipher", f"Ciphers\\{_c}", {"Enabled": 0}, "$k.GetValue('Enabled') -eq 0",
              warning="Takes effect after a restart.")
_schannel("7.13", "Disable the AES 128/128 cipher", "Ciphers\\AES 128/128", {"Enabled": 0}, "$k.GetValue('Enabled') -eq 0",
          warning="Removes the AES-128 suites many clients prefer; clients without AES-256 suites fail. Takes effect after a restart.",
          confirm=True)
_schannel("7.14", "Enable the AES 256/256 cipher", "Ciphers\\AES 256/256", {"Enabled": -1}, "$k.GetValue('Enabled') -ne 0",
          warning="Takes effect after a restart.")

for _sec, _desc in {
    "1.1": "Move site content to a non-system volume and update the sites' physical paths.",
    "1.2": "Add host names to the bindings that have none.",
    "1.5": "Create an application pool per site.",
    "2.1": "Replace the server-wide 'Allow All Users' rule with per-site rules.",
    "2.2": "Require authentication on sensitive application paths.",
    "2.7": "Hash or remove credentials stored in web.config.",
    "2.8": "Move users out of <credentials> into a membership store.",
    "3.9": "Lower the .NET trust level where applications allow it.",
    "4.7": "List the extensions each application serves, then deny unlisted ones.",
    "5.1": "Move the default log directory to a non-system volume (siteDefaults/logFile directory).",
    "5.2": "Add the log fields incident response needs.",
    "7.16": "Configure the SSL Cipher Suite Order policy.",
}.items():
    TEMPLATES.manual(f"IIS-{_sec}", _desc)
