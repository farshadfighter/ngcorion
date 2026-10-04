"""
IIS 10 rules after the CIS Microsoft IIS 10 Benchmark: 1 basic
configuration, 2 authentication and authorisation, 3 ASP.NET, 4 request
filtering, 5 logging, 6 FTP, 7 transport encryption (SCHANNEL).

Numbering follows the benchmark's sections; it was written from the
benchmark's content rather than copied from a specific edition, so item
numbers can differ slightly from the edition in use. Checks that the
benchmark makes per site are evaluated on every site's effective
configuration (its own web.config included).
"""

import re
from typing import Any, Dict, List, Optional

from app.modules.benchmark.rules import BenchmarkRule, as_list, json_section, section
from app.modules.windows.audit import rules as W

JSON_SECTIONS = frozenset({"OS_VERSION", "IIS_SERVER", "IIS_SITES", "IIS_HOST", "SCHANNEL"})
STRONG_MACHINE_KEY = ("HMACSHA256", "HMACSHA384", "HMACSHA512")
LOW_TRUST = ("Medium", "Low", "Minimal")


def server(d: str) -> Dict[str, Any]:
    v = json_section(d, "IIS_SERVER")
    return v if isinstance(v, dict) else {}


def sites(d: str) -> List[Dict[str, Any]]:
    v = json_section(d, "IIS_SITES")
    return [s for s in as_list((v or {}).get("Sites")) if isinstance(s, dict)] if isinstance(v, dict) else []


def pools(d: str) -> List[Dict[str, Any]]:
    v = json_section(d, "IIS_SITES")
    return [p for p in as_list((v or {}).get("Pools")) if isinstance(p, dict)] if isinstance(v, dict) else []


def host(d: str) -> Dict[str, Any]:
    v = json_section(d, "IIS_HOST")
    return v if isinstance(v, dict) else {}


def feature(d: str, name: str) -> bool:
    return bool((host(d).get("Features") or {}).get(name))


def schannel(d: str, key: str) -> Optional[Dict[str, Any]]:
    v = json_section(d, "SCHANNEL")
    return (v or {}).get(key) if isinstance(v, dict) else None


def true(v) -> bool:
    return str(v).strip().lower() == "true"


def false(v) -> bool:
    return str(v).strip().lower() == "false"


def num(v) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _names(items, limit=20) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def https_sites(d):
    return [s for s in sites(d) if any(b.get("Protocol") == "https" for b in as_list(s.get("Bindings")))]


def _no_host(binding) -> bool:
    info = str(binding.get("Info") or "")
    return binding.get("Protocol") in ("http", "https") and info.rsplit(":", 1)[-1] == ""


def _on_system_drive(path: str, d: str) -> bool:
    drive = str(host(d).get("SystemDrive") or "C:").upper()
    p = str(path or "")
    return p.upper().startswith(drive) or p.upper().startswith("%SYSTEMDRIVE%")


# SCHANNEL ───────────────────────────────────────────────────────────────────

def protocol_disabled(d, name) -> bool:
    k = schannel(d, f"Protocols\\{name}\\Server") or {}
    return k.get("Enabled") == 0 and k.get("DisabledByDefault") == 1


def protocol_enabled(d, name) -> bool:
    k = schannel(d, f"Protocols\\{name}\\Server") or {}
    return k.get("Enabled") not in (None, 0) and k.get("DisabledByDefault") == 0


def cipher_disabled(d, name) -> bool:
    return (schannel(d, f"Ciphers\\{name}") or {}).get("Enabled") == 0


def cipher_enabled(d, name) -> bool:
    return (schannel(d, f"Ciphers\\{name}") or {}).get("Enabled") not in (None, 0)


def _sch_ev(*keys):
    return lambda d: "; ".join(f"{k}: {schannel(d, k)}" for k in keys) + " (absent = Windows default)"


# rule builders ──────────────────────────────────────────────────────────────

def _rule(rules, sec, title, severity, check, evidence, remediation, sections, level="L1",
          manual=False, unavailable=None):
    rules.append(BenchmarkRule(
        id=f"IIS-{sec}", section=sec, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation, description=title,
        manual=manual, data_sections=list(sections), source="CIS", unavailable_fn=unavailable))


def _manual(rules, sec, title, severity, guidance, level="L1"):
    _rule(rules, sec, title, severity, lambda d: False, lambda d: f"Manual verification: {guidance}",
          guidance, [], level=level, manual=True)


def _server_value(rules, sec, title, severity, key, ok, remediation, level="L1"):
    _rule(rules, sec, title, severity, lambda d: ok(server(d).get(key)),
          lambda d: f"{key} = {server(d).get(key)!r}", remediation, ["IIS_SERVER"], level=level,
          unavailable=lambda d: f"{key}: the section is not available on this server"
          if server(d).get(key) == "N/A" else None)


def _server_and_sites(rules, sec, title, severity, key, bad, remediation, level="L1"):
    """A value checked at the server and in every site's effective configuration."""
    def offenders(d):
        out = []
        if bad(server(d).get(key)):
            out.append(f"server ({server(d).get(key)})")
        out += [f"{s.get('Name')} ({s.get(key)})" for s in sites(d) if bad(s.get(key))]
        return out
    _rule(rules, sec, title, severity, lambda d: not offenders(d),
          lambda d: f"{key} not compliant at: " + _names(offenders(d)), remediation,
          ["IIS_SERVER", "IIS_SITES"], level=level)


def build_rules() -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    S, ST, H = ["IIS_SERVER"], ["IIS_SITES"], ["IIS_HOST"]

    # 1 Basic configuration ───────────────────────────────────────────────
    _rule(r, "1.1", "Ensure 'web content' is on a non-system partition", "medium",
          lambda d: not [s for s in sites(d) if _on_system_drive(s.get("PhysicalPath"), d)],
          lambda d: "Sites on the system drive: " + _names(
              f"{s['Name']} ({s.get('PhysicalPath')})" for s in sites(d) if _on_system_drive(s.get("PhysicalPath"), d)),
          "Move site content to a separate data volume and update each site's physical path.", ST + H)
    _rule(r, "1.2", "Ensure 'host headers' are on all sites", "low",
          lambda d: not [s for s in sites(d) if any(_no_host(b) for b in as_list(s.get("Bindings")))],
          lambda d: "Bindings without a host name: " + _names(
              f"{s['Name']} {b.get('Protocol')} {b.get('Info')}" for s in sites(d)
              for b in as_list(s.get("Bindings")) if _no_host(b)),
          "Give every http/https binding a host name.", ST)
    _server_and_sites(r, "1.3", "Ensure 'directory browsing' is set to Disabled", "medium", "DirBrowse", true,
                      "Disable directory browsing at the server and in every site.")
    _rule(r, "1.4", "Ensure 'application pool identity' is configured for all application pools", "medium",
          lambda d: all(p.get("Identity") == "ApplicationPoolIdentity" for p in pools(d)),
          lambda d: "Pools with another identity: " + _names(
              f"{p['Name']} ({p.get('Identity')})" for p in pools(d) if p.get("Identity") != "ApplicationPoolIdentity"),
          "Set processModel.identityType to ApplicationPoolIdentity.", ST)
    _rule(r, "1.5", "Ensure 'unique application pools' is set for sites", "medium",
          lambda d: len({s.get("AppPool") for s in sites(d)}) == len(sites(d)),
          lambda d: "Pools shared by several sites: " + _names(sorted(
              {s.get("AppPool") for s in sites(d) if [x.get("AppPool") for x in sites(d)].count(s.get("AppPool")) > 1})),
          "Give each site its own application pool.", ST)
    _server_value(r, "1.6", "Ensure 'application pool identity' is configured for anonymous user identity", "medium",
                  "AnonymousUser", lambda v: v == "", "Set the anonymous user identity to the application pool identity (userName \"\").")
    _rule(r, "1.7", "Ensure WebDav feature is disabled", "medium",
          lambda d: not feature(d, "Web-DAV-Publishing"),
          lambda d: f"Web-DAV-Publishing installed = {feature(d, 'Web-DAV-Publishing')}",
          "Uninstall-WindowsFeature Web-DAV-Publishing", H)

    # 2 Authentication and authorisation ──────────────────────────────────
    _rule(r, "2.1", "Ensure 'global authorization rule' is set to restrict access", "medium",
          lambda d: server(d).get("AuthorizationAllowAll") is False,
          lambda d: f"Server-level 'Allow All Users' rule present = {server(d).get('AuthorizationAllowAll')}",
          "Replace the server-wide 'Allow All Users' rule with rules for the roles that need access, set per site.", S)
    _manual(r, "2.2", "Ensure access to sensitive site features is restricted to authenticated principals only",
            "high", "Require authentication on administrative and sensitive paths of each application.")
    _server_value(r, "2.3", "Ensure 'forms authentication' requires SSL", "medium", "FormsRequireSsl", true,
                  "Set system.web/authentication/forms requireSSL = true.")
    _server_value(r, "2.4", "Ensure 'forms authentication' is set to use cookies", "medium", "FormsCookieless",
                  lambda v: v == "UseCookies", "Set system.web/authentication/forms cookieless = UseCookies.")
    _server_value(r, "2.5", "Ensure 'cookie protection mode' is configured for forms authentication", "medium",
                  "FormsProtection", lambda v: v == "All", "Set system.web/authentication/forms protection = All.")
    _rule(r, "2.6", "Ensure transport layer security for 'basic authentication' is configured", "high",
          lambda d: not true(server(d).get("BasicAuth")) or "Ssl" in str(server(d).get("AccessSslFlags") or ""),
          lambda d: f"Basic authentication = {server(d).get('BasicAuth')}, sslFlags = {server(d).get('AccessSslFlags')!r}",
          "Require SSL wherever basic authentication is enabled.", S)
    _server_value(r, "2.7", "Ensure 'passwordFormat' is not set to clear", "high", "PasswordFormat",
                  lambda v: v != "Clear", "Set system.web/authentication/forms/credentials passwordFormat to SHA1 or remove the credentials.")
    _rule(r, "2.8", "Ensure 'credentials' are not stored in configuration files", "high",
          lambda d: server(d).get("FormsCredentialUsers") is False,
          lambda d: f"Users stored in <credentials> = {server(d).get('FormsCredentialUsers')}",
          "Move users out of system.web/authentication/forms/credentials into a membership store.", S)

    # 3 ASP.NET ───────────────────────────────────────────────────────────
    _server_value(r, "3.1", "Ensure 'deployment method retail' is set", "medium", "Retail", true,
                  "Set <deployment retail=\"true\" /> in machine.config.")
    _server_and_sites(r, "3.2", "Ensure 'debug' is turned off", "medium", "Debug", true,
                      "Set system.web/compilation debug = false at the server and in every site.")
    _server_and_sites(r, "3.3", "Ensure custom error messages are not off", "medium", "CustomErrors",
                      lambda v: v == "Off", "Set system.web/customErrors mode to RemoteOnly or On.")
    _server_and_sites(r, "3.4", "Ensure IIS HTTP detailed errors are hidden from displaying remotely", "medium",
                      "ErrorMode", lambda v: v == "Detailed", "Set system.webServer/httpErrors errorMode to DetailedLocalOnly or Custom.")
    _server_and_sites(r, "3.5", "Ensure ASP.NET stack tracing is not enabled", "medium", "Trace", true,
                      "Set system.web/trace enabled = false.")
    _server_value(r, "3.6", "Ensure 'httpcookie' mode is configured for session state", "medium", "SessionCookieless",
                  lambda v: v == "UseCookies", "Set system.web/sessionState cookieless = UseCookies.")
    _server_value(r, "3.7", "Ensure 'cookies' are set with HttpOnly attribute", "medium", "HttpOnlyCookies", true,
                  "Set system.web/httpCookies httpOnlyCookies = true.")
    _server_value(r, "3.8", "Ensure 'MachineKey validation method - .Net 4.5' is configured", "medium",
                  "MachineKeyValidation", lambda v: v in STRONG_MACHINE_KEY, "Set system.web/machineKey validation = HMACSHA256.")
    _server_value(r, "3.9", "Ensure global .NET trust level is configured", "medium", "TrustLevel",
                  lambda v: v in LOW_TRUST, "Set system.web/trust level to Medium (or lower) where applications allow it.", level="L2")
    _server_value(r, "3.10", "Ensure X-Powered-By Header is removed", "low", "XPoweredByHeader",
                  lambda v: v is False, "Remove the X-Powered-By custom header.")
    _server_value(r, "3.11", "Ensure Server Header is removed", "low", "RemoveServerHeader", true,
                  "Set system.webServer/security/requestFiltering removeServerHeader = true.")

    # 4 Request filtering ─────────────────────────────────────────────────
    _server_value(r, "4.1", "Ensure 'maxAllowedContentLength' is configured", "medium", "MaxContentLength",
                  lambda v: num(v) is not None and num(v) <= 30000000, "Set requestLimits maxAllowedContentLength to 30000000 or less.", level="L2")
    _server_value(r, "4.2", "Ensure 'maxURL request filter' is configured", "medium", "MaxUrl",
                  lambda v: num(v) is not None and num(v) <= 4096, "Set requestLimits maxUrl to 4096 or less.", level="L2")
    _server_value(r, "4.3", "Ensure 'MaxQueryString request filter' is configured", "medium", "MaxQueryString",
                  lambda v: num(v) is not None and num(v) <= 2048, "Set requestLimits maxQueryString to 2048 or less.", level="L2")
    _server_value(r, "4.4", "Ensure non-ASCII characters in URLs are not allowed", "medium", "AllowHighBit", false,
                  "Set requestFiltering allowHighBitCharacters = false.", level="L2")
    _server_value(r, "4.5", "Ensure Double-Encoded requests will be rejected", "medium", "AllowDoubleEscaping", false,
                  "Set requestFiltering allowDoubleEscaping = false.")
    _rule(r, "4.6", "Ensure 'HTTP Trace Method' is disabled", "medium",
          lambda d: false(server(d).get("TraceVerbAllowed")),
          lambda d: f"TRACE verb rule: allowed = {server(d).get('TraceVerbAllowed')!r} (N/A = no rule)",
          "Add a request-filtering verb rule TRACE allowed=false.", S)
    _server_value(r, "4.7", "Ensure Unlisted File Extensions are not allowed", "medium", "AllowUnlistedExt", false,
                  "Set fileExtensions allowUnlisted = false and list the extensions each application serves.", level="L2")
    _rule(r, "4.8", "Ensure Handler is not granted Write and Script/Execute", "high",
          lambda d: not ("Write" in str(server(d).get("HandlersAccessPolicy") or "") and re.search(
              r"Script|Execute", str(server(d).get("HandlersAccessPolicy") or ""))),
          lambda d: f"handlers accessPolicy = {server(d).get('HandlersAccessPolicy')!r}",
          "Set system.webServer/handlers accessPolicy to Read, Script.", S)
    _server_value(r, "4.9", "Ensure 'notListedIsapisAllowed' is set to false", "high", "NotListedIsapis", false,
                  "Set isapiCgiRestriction notListedIsapisAllowed = false.")
    _server_value(r, "4.10", "Ensure 'notListedCgisAllowed' is set to false", "high", "NotListedCgis", false,
                  "Set isapiCgiRestriction notListedCgisAllowed = false.")
    _rule(r, "4.11", "Ensure 'Dynamic IP Address Restrictions' is enabled", "medium",
          lambda d: true(server(d).get("DynIpConcurrent")) or true(server(d).get("DynIpRate")),
          lambda d: (f"IP and Domain Restrictions installed = {feature(d, 'Web-IP-Security')}; denyByConcurrentRequests = "
                     f"{server(d).get('DynIpConcurrent')}, denyByRequestRate = {server(d).get('DynIpRate')}"),
          "Install Web-IP-Security and enable denyByConcurrentRequests / denyByRequestRate.", S + H, level="L2")

    # 5 Logging ───────────────────────────────────────────────────────────
    _rule(r, "5.1", "Ensure Default IIS web log location is moved", "low",
          lambda d: not _on_system_drive(server(d).get("LogDirectory"), d),
          lambda d: f"Default log directory = {server(d).get('LogDirectory')}",
          "Point siteDefaults/logFile directory to a non-system volume.", S + H)
    _manual(r, "5.2", "Ensure Advanced IIS logging is enabled", "low",
            "Log the fields incident response needs (client IP, user, status, bytes, user agent, X-Forwarded-For).")
    _server_value(r, "5.3", "Ensure 'ETW Logging' is enabled", "low", "LogTarget",
                  lambda v: "ETW" in str(v or ""), "Set siteDefaults/logFile logTargetW3C = File,ETW.")

    # 6 FTP ───────────────────────────────────────────────────────────────
    _rule(r, "6.1", "Ensure FTP requests are encrypted", "high",
          lambda d: not feature(d, "Web-Ftp-Server") or (
              server(d).get("FtpControlChannel") == "SslRequire" and server(d).get("FtpDataChannel") == "SslRequire"),
          lambda d: (f"FTP installed = {feature(d, 'Web-Ftp-Server')}; control = {server(d).get('FtpControlChannel')}, "
                     f"data = {server(d).get('FtpDataChannel')}"),
          "Require SSL on the FTP control and data channels.", S + H)
    _rule(r, "6.2", "Ensure FTP Logon attempt restrictions is enabled", "medium",
          lambda d: not feature(d, "Web-Ftp-Server") or true(server(d).get("FtpDenyByFailure")),
          lambda d: f"FTP installed = {feature(d, 'Web-Ftp-Server')}; denyByFailure = {server(d).get('FtpDenyByFailure')}",
          "Enable FTP logon attempt restrictions (denyByFailure).", S + H)

    # 7 Transport encryption ──────────────────────────────────────────────
    _rule(r, "7.1", "Ensure HSTS Header is set", "medium",
          lambda d: server(d).get("HstsHeader") is True or all(true(s.get("Hsts")) for s in https_sites(d)),
          lambda d: "HTTPS sites without HSTS: " + _names(s["Name"] for s in https_sites(d) if not true(s.get("Hsts"))),
          "Enable HSTS on every HTTPS site (max-age 31536000).", S + ST, level="L2")
    for sec, proto, sev in (("7.2", "SSL 2.0", "high"), ("7.3", "SSL 3.0", "high"),
                            ("7.4", "TLS 1.0", "medium"), ("7.5", "TLS 1.1", "medium")):
        _rule(r, sec, f"Ensure {proto} is disabled", sev,
              (lambda d, p=proto: protocol_disabled(d, p)), _sch_ev(f"Protocols\\{proto}\\Server"),
              f"Set SCHANNEL\\Protocols\\{proto}\\Server Enabled=0 and DisabledByDefault=1.", ["SCHANNEL"])
    _rule(r, "7.6", "Ensure TLS 1.2 is enabled", "high", lambda d: protocol_enabled(d, "TLS 1.2"),
          _sch_ev("Protocols\\TLS 1.2\\Server"),
          "Set SCHANNEL\\Protocols\\TLS 1.2\\Server Enabled=1 and DisabledByDefault=0.", ["SCHANNEL"])
    for sec, ciph, sev, lvl in (("7.7", "NULL", "high", "L1"), ("7.8", "DES 56/56", "high", "L1"),
                                ("7.9", "RC4 40/128", "high", "L1"), ("7.10", "RC4 56/128", "high", "L1"),
                                ("7.11", "RC4 64/128", "high", "L1"), ("7.12", "RC4 128/128", "high", "L1"),
                                ("7.13", "AES 128/128", "low", "L2"), ("7.15", "Triple DES 168", "medium", "L1")):
        _rule(r, sec, f"Ensure {ciph} Cipher Suites is disabled", sev,
              (lambda d, c=ciph: cipher_disabled(d, c)), _sch_ev(f"Ciphers\\{ciph}"),
              f"Set SCHANNEL\\Ciphers\\{ciph} Enabled=0.", ["SCHANNEL"], level=lvl)
    _rule(r, "7.14", "Ensure AES 256/256 Cipher Suite is enabled", "medium",
          lambda d: cipher_enabled(d, "AES 256/256"), _sch_ev("Ciphers\\AES 256/256"),
          "Set SCHANNEL\\Ciphers\\AES 256/256 Enabled=0xffffffff.", ["SCHANNEL"])
    _manual(r, "7.16", "Ensure TLS Cipher Suite ordering is configured", "medium",
            "Order suites with ECDHE and AES-GCM first (Group Policy: SSL Cipher Suite Order).")
    r.sort(key=lambda x: tuple(int(p) for p in x.section.split(".")))
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    raw = section(dump, "IIS_SERVER")
    if raw.startswith("PS_ERROR") and ("WebAdministration" in raw or "InetStp" in raw):
        raise ValueError("IIS is not installed on this host (the WebAdministration module is missing).")
    host_raw = section(dump, "IIS_HOST")
    if host_raw.startswith("PS_ERROR") and "InetStp" in host_raw:
        raise ValueError("IIS is not installed on this host.")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    return f"IIS {host(dump).get('IisVersion')} on Windows Server {W._detect_version(dump)}, {len(sites(dump))} sites"
