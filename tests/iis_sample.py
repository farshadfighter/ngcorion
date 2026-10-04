"""
Sample collector output of a Windows Server 2022 web server running IIS 10
(WEB01, a domain member), in the shape the IIS collection scripts print.
Built here, not captured: two sites on D:, the Default Web Site still on
C: with directory browsing on, one shared pool, one pool running as
LocalSystem, debug on in a site's web.config, default request limits, TLS
1.0 still enabled, RC4 disabled, HSTS on one of the two HTTPS sites.
"""
import copy
import json

SERVER = {
    "DirBrowse": "False", "AnonymousUser": "IUSR", "BasicAuth": "False", "AccessSslFlags": "",
    "ErrorMode": "DetailedLocalOnly", "MaxContentLength": "30000000", "MaxUrl": "4096", "MaxQueryString": "2048",
    "AllowHighBit": "True", "AllowDoubleEscaping": "False", "RemoveServerHeader": "False",
    "AllowUnlistedExt": "True", "TraceVerbAllowed": "N/A", "HandlersAccessPolicy": "Read, Script",
    "NotListedIsapis": "False", "NotListedCgis": "False", "DynIpConcurrent": "False", "DynIpRate": "False",
    "LogDirectory": "%SystemDrive%\\inetpub\\logs\\LogFiles", "LogTarget": "File",
    "FtpControlChannel": "N/A", "FtpDataChannel": "N/A", "FtpDenyByFailure": "N/A",
    "Retail": "False", "Debug": "False", "CustomErrors": "RemoteOnly", "Trace": "False",
    "SessionCookieless": "UseCookies", "HttpOnlyCookies": "False", "MachineKeyValidation": "HMACSHA256",
    "TrustLevel": "Full", "FormsRequireSsl": "False", "FormsCookieless": "UseDeviceProfile",
    "FormsProtection": "All", "PasswordFormat": "SHA1",
    "XPoweredByHeader": True, "HstsHeader": False, "AuthorizationAllowAll": True, "FormsCredentialUsers": False,
}


def _site(name, path, pool, bindings, **cfg):
    base = {"Name": name, "State": "Started", "PhysicalPath": path, "AppPool": pool,
            "Bindings": [{"Protocol": p, "Info": i} for p, i in bindings],
            "DirBrowse": "False", "ErrorMode": "DetailedLocalOnly", "Debug": "False",
            "CustomErrors": "RemoteOnly", "Trace": "False", "Hsts": "False"}
    base.update(cfg)
    return base


DATA = {
    "OS_VERSION": {"Caption": "Microsoft Windows Server 2022 Standard", "Version": "10.0.20348",
                   "BuildNumber": "20348", "OSArchitecture": "64-bit"},
    "IIS_SERVER": SERVER,
    "IIS_SITES": {
        "Sites": [
            _site("Default Web Site", "C:\\inetpub\\wwwroot", "DefaultAppPool", [("http", "*:80:")],
                  DirBrowse="True"),
            _site("portal", "D:\\sites\\portal", "portal", [("https", "*:443:portal.corp.example.com"),
                                                             ("http", "*:80:portal.corp.example.com")],
                  Hsts="True"),
            _site("intranet", "D:\\sites\\intranet", "DefaultAppPool", [("https", "*:443:intranet.corp.example.com")],
                  Debug="True"),
        ],
        "Pools": [
            {"Name": "DefaultAppPool", "Identity": "ApplicationPoolIdentity", "State": "Started"},
            {"Name": "portal", "Identity": "LocalSystem", "State": "Started"},
        ],
    },
    "IIS_HOST": {"IisVersion": "10.0", "SystemDrive": "C:",
                 "Features": {"Web-DAV-Publishing": False, "Web-Ftp-Server": False,
                              "Web-IP-Security": False, "Web-Asp-Net45": True}},
    "SCHANNEL": {
        "Protocols\\SSL 2.0\\Server": {"Enabled": 0, "DisabledByDefault": 1},
        "Protocols\\SSL 3.0\\Server": {"Enabled": 0, "DisabledByDefault": 1},
        "Protocols\\TLS 1.0\\Server": None,
        "Protocols\\TLS 1.1\\Server": {"Enabled": 0, "DisabledByDefault": 1},
        "Protocols\\TLS 1.2\\Server": {"Enabled": 1, "DisabledByDefault": 0},
        "Ciphers\\NULL": {"Enabled": 0},
        "Ciphers\\DES 56/56": None,
        "Ciphers\\RC4 40/128": {"Enabled": 0}, "Ciphers\\RC4 56/128": {"Enabled": 0},
        "Ciphers\\RC4 64/128": {"Enabled": 0}, "Ciphers\\RC4 128/128": {"Enabled": 0},
        "Ciphers\\Triple DES 168": None, "Ciphers\\AES 128/128": None,
        "Ciphers\\AES 256/256": {"Enabled": 4294967295},
    },
}


def sections(**changes):
    data = copy.deepcopy(DATA)
    data.update(changes)
    return {k: json.dumps(v, separators=(",", ":")) for k, v in data.items()}


def dump(**changes):
    from app.modules.benchmark.rules import assemble
    return assemble(sections(**changes))


def with_(section, **fields):
    data = copy.deepcopy(DATA[section])
    data.update(fields)
    return data
