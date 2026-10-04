"""
nginx rules after the CIS NGINX Benchmark: 1 installation and updates,
2 basic configuration (modules, account, permissions, network, information
disclosure), 3 logging, 4 TLS, 5 request filtering and limits, 6 mandatory
access control.

Settings are judged as nginx applies them: per server block (and per
location where a location can override), with inheritance from the levels
above, so a value set in http and overridden in one server is reported for
that server. Item numbers follow the benchmark's content rather than a
specific edition's PDF and can differ slightly from the edition in use.
"""

import re
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

from app.modules.benchmark.rules import BenchmarkRule, section

from .collect import NOT_INSTALLED, compiled
from .conf import Config, Directive, effective, effective_value, is_ssl, listens, server_label

NOLOGIN_SHELLS = ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false")
SAFE_REFERRER = ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin")
HSTS_MIN = 15768000          # six months
TIMEOUT_MAX = 10


# ── data access ──────────────────────────────────────────────────────────

@lru_cache(maxsize=16)
def _config(text: str) -> Config:
    return Config(text)


def config_error(d) -> Optional[str]:
    """The error when nginx -t refused the configuration, else None (the audit stops: an unloadable
    configuration cannot be judged).
    """
    text = section(d, "NGINX_T")
    m = re.search(r"nginx: \[emerg\][^\n]*", text)
    if m or "test failed" in text:
        return m.group(0) if m else "nginx -t failed"
    return None


def cfg(d) -> Config:
    return _config(section(d, "NGINX_T"))


def version(d) -> Tuple[int, ...]:
    m = re.search(r"nginx version: nginx/(\d+)\.(\d+)\.(\d+)", section(d, "NGINX_VERSION"))
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def version_text(d) -> str:
    m = re.search(r"nginx version: (\S+)(?: \(([^)]*)\))?", section(d, "NGINX_VERSION"))
    return f"{m.group(1)}{' (' + m.group(2) + ')' if m.group(2) else ''}" if m else "unknown"


def built_with(d, module: str) -> bool:
    return f"--with-{module}" in section(d, "NGINX_VERSION")


def _rows(d, name) -> List[List[str]]:
    return [ln.split("|") for ln in section(d, name).splitlines() if ln.count("|") >= 4]


def files(d) -> List[Tuple[str, str, int, str, str]]:
    """(owner, group, mode, type, path), symbolic links left out."""
    out = []
    for r in _rows(d, "FILES"):
        if r[3] != "symbolic link":
            out.append((r[0], r[1], int(r[2], 8) if r[2].isdigit() else 0, r[3], r[4]))
    return out


def paths(d) -> Dict[str, Tuple[str, str, int, str]]:
    """Owner, group, mode and type of every file and directory the configuration names (PATHS section).
    """
    out = {}
    for r in _rows(d, "PATHS"):
        out[r[4]] = (r[0], r[1], int(r[2], 8) if r[2].isdigit() else -1, r[3])
    return out


def account(d) -> Dict[str, str]:
    """The worker account from /etc/passwd (name, uid, gid, home, shell) and whether it exists."""
    text = section(d, "ACCOUNT")
    out = {"exists": "NO_ACCOUNT" not in text}
    for line in text.splitlines():
        if line.count(":") >= 6 and not line.startswith(("shadow=", "groups=")):
            f = line.split(":")
            out.update(name=f[0], uid=f[2], gid=f[3], home=f[5], shell=f[6])
        elif line.startswith("shadow="):
            out["shadow"] = line[7:]
        elif line.startswith("groups="):
            out["groups"] = line[7:]
    return out


def procs(d) -> List[Dict[str, str]]:
    """nginx processes with their uid, parent and security context."""
    out = []
    for r in _rows(d, "PROCS"):
        out.append({"pid": r[0], "uid": r[1], "ppid": r[2], "cmd": r[3], "context": r[4] if len(r) > 4 else ""})
    return out


def worker_user(d) -> str:
    return (cfg(d).main_value("user") or "nobody").split()[0]


def _names(items, limit=12) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _seconds(value: Optional[str]) -> Optional[float]:
    """nginx time value ("10", "10s", "1m", "500ms") in seconds."""
    if value is None:
        return None
    m = re.fullmatch(r"(\d+)(ms|s|m|h|d)?", value.strip())
    if not m:
        return None
    n = int(m.group(1))
    return n * {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, None: 1}[m.group(2)]


def servers(d) -> List[Directive]:
    return cfg(d).servers()


def ssl_servers(d) -> List[Directive]:
    return [s for s in servers(d) if is_ssl(s)]


def scopes(d) -> List[Tuple[str, Directive]]:
    """Each server block and each location in it, labelled."""
    out = []
    for s in servers(d):
        out.append((server_label(s), s))
        for loc in Config.locations(s):
            out.append((f"{server_label(s)} location {' '.join(loc.args)}", loc))
    return out


def headers(block: Directive) -> Dict[str, str]:
    """add_header in force in a block: {lower-case name: value}."""
    return {h.args[0].lower(): (h.args[1] if len(h.args) > 1 else "") for h in effective(block, "add_header") if h.args}


def array_values(block: Directive, name: str) -> List[str]:
    return [h.args[0].lower() for h in effective(block, name) if h.args]


def proxied(d) -> List[Tuple[str, Directive]]:
    return [(label, b) for label, b in scopes(d) if b.direct("proxy_pass")]


# ── rule builders ────────────────────────────────────────────────────────

def _rule(rules, sec, title, severity, check, evidence, remediation, sections=("NGINX_T",), level="L1",
          manual=False):
    rules.append(BenchmarkRule(
        id=f"NGINX-{sec}", section=sec, title=title, severity=severity, level=level, check_fn=check,
        evidence_fn=evidence, remediation=remediation, description=title, manual=manual,
        data_sections=list(sections), source="CIS"))


def _manual(rules, sec, title, severity, guidance, evidence=None, sections=("NGINX_T",), level="L1"):
    _rule(rules, sec, title, severity, lambda d: False, evidence or (lambda d: "Review the configuration."),
          guidance, sections, level=level, manual=True)


def _per_scope(rules, sec, title, severity, bad_fn, what, remediation, *, scope="servers", level="L1", empty_ok=True,
               empty_note="no server blocks", with_dump=False, sections=("NGINX_T",)):
    """A rule that fails for every server (or SSL server / proxied location /
    location) where bad_fn(block) - bad_fn(block, dump) with with_dump -
    returns a reason."""
    def items(d):
        """The blocks a per-block rule examines (TLS servers, proxied locations, every level, servers).
        """
        if scope == "ssl":
            return [(server_label(s), s) for s in ssl_servers(d)]
        if scope == "proxied":
            return proxied(d)
        if scope == "scopes":
            return scopes(d)
        return [(server_label(s), s) for s in servers(d)]

    def offenders(d):
        """"label (reason)" of every block that fails the rule."""
        out = []
        for label, block in items(d):
            reason = bad_fn(block, d) if with_dump else bad_fn(block)
            if reason:
                out.append(f"{label} ({reason})")
        return out

    def check(d):
        return (empty_ok or bool(items(d))) and not offenders(d)

    def evidence(d):
        """"N of M compliant" plus the offenders."""
        n = len(items(d))
        if not n:
            return f"{what}: {empty_note}"
        bad = offenders(d)
        return f"{what}: {n - len(bad)} of {n} compliant" + (f"; not compliant: {_names(bad)}" if bad else "")

    _rule(rules, sec, title, severity, check, evidence, remediation, sections, level=level)


def _timeout_rule(rules, sec, title, names, default, remediation):
    def bad(block):
        """The timeouts of a block that are missing, zero or longer than TIMEOUT_MAX seconds."""
        reasons = []
        for name in names:
            raw = effective_value(block, name)
            secs = _seconds((raw or default).split()[0])
            if secs is None or secs <= 0 or secs > TIMEOUT_MAX:
                reasons.append(f"{name} {raw or default + ' (default)'}")
        return ", ".join(reasons)
    _per_scope(rules, sec, title, "medium", bad, " / ".join(names), remediation)


def _header_rule(rules, sec, title, severity, name, ok, what, remediation, scope="scopes", level="L1"):
    def bad(block):
        """Why the header is wrong at this level (missing, or a value the rule does not accept), else
        None.
        """
        value = headers(block).get(name.lower())
        if value is None:
            return "not set"
        return None if ok(value) else f"{value}"
    _per_scope(rules, sec, title, severity, bad, what, remediation, scope=scope, level=level,
               empty_note="no HTTPS servers" if scope == "ssl" else "no server blocks")


def build_rules() -> List[BenchmarkRule]:
    """Every rule of the module, in CIS NGINX Benchmark order."""
    r: List[BenchmarkRule] = []
    V = ("NGINX_VERSION",)

    # 1 Installation and updates ───────────────────────────────────────────
    _rule(r, "1.1.1", "Ensure NGINX is installed", "medium", lambda d: version(d) > (0, 0, 0),
          lambda d: version_text(d), "Install nginx from the distribution or nginx.org packages.", V)
    _manual(r, "1.2.1", "Ensure package manager repositories are properly configured", "medium",
            "Install nginx from the distribution or the official nginx.org repository with its signing key.",
            lambda d: "packages: " + section(d, "PACKAGE").replace("\n", "; "), ("PACKAGE",))
    _manual(r, "1.2.2", "Ensure the latest software package is installed", "high",
            "Update nginx to the current release of its branch.",
            lambda d: f"running {version_text(d)}", V)

    # 2.1 Modules ─────────────────────────────────────────────────────────
    def modules(d):
        built = re.findall(r"--with-([\w-]+?)_module(?:=dynamic)?", section(d, "NGINX_VERSION"))
        loaded = [x.args[0].rsplit("/", 1)[-1] for x in cfg(d).main("load_module") if x.args]
        return built, loaded
    _manual(r, "2.1.1", "Ensure only required modules are installed", "medium",
            "Build or install nginx with only the modules the sites use; remove unused load_module lines.",
            lambda d: f"compiled in: {_names(modules(d)[0], 40)}; loaded: {_names(modules(d)[1])}", V + ("NGINX_T",))
    _rule(r, "2.1.2", "Ensure HTTP WebDAV module is not installed", "medium",
          lambda d: not built_with(d, "http_dav_module"),
          lambda d: ("built with http_dav_module" if built_with(d, "http_dav_module") else "not built with http_dav_module")
          + f"; dav_methods used in: {_names(server_label(x) for x in servers(d) if any(l.name == 'dav_methods' and l.args != ['off'] for l in x.walk()))}",
          "Use an nginx build without --with-http_dav_module (the stock distribution and nginx.org builds include "
          "it; until then make sure no dav_methods directive is enabled).", V + ("NGINX_T",), level="L2")

    def gzip_on(d):
        return [f"{x.name} {' '.join(x.args)} ({x.file}:{x.line})" for x in cfg(d).all()
                if x.name in ("gzip", "gzip_static") and x.args and x.args[0] in ("on", "always")]
    _rule(r, "2.1.3", "Ensure modules with gzip functionality are disabled", "medium", lambda d: not gzip_on(d),
          lambda d: "gzip enabled at: " + _names(gzip_on(d)),
          "Set gzip off (compression of responses with secrets allows BREACH-style attacks).", level="L2")

    def autoindex_on(d):
        return [f"{x.file}:{x.line}" for x in cfg(d).all("autoindex") if x.args[:1] == ["on"]]
    _rule(r, "2.1.4", "Ensure the autoindex module is disabled", "medium", lambda d: not autoindex_on(d),
          lambda d: "autoindex on at: " + _names(autoindex_on(d)), "Remove 'autoindex on' (directory listings).")

    # 2.2 Account ─────────────────────────────────────────────────────────
    def account_problems(d):
        """What is wrong with the worker account: running as root, missing, a login shell, no lock.
        """
        a, user = account(d), worker_user(d)
        out = []
        if user == "root" or a.get("uid") == "0":
            out.append("workers run as root")
        if not a["exists"]:
            out.append(f"account {user} does not exist")
        if user == "nobody":
            out.append("nobody is shared, not dedicated")
        uids = {p["uid"] for p in procs(d) if "worker process" in p["cmd"]}
        if a.get("uid") and uids and uids != {a["uid"]}:
            out.append(f"workers run with uid {_names(sorted(uids))}")
        return out
    _rule(r, "2.2.1", "Ensure that NGINX is run using a non-privileged, dedicated service account", "high",
          lambda d: not account_problems(d),
          lambda d: f"user {worker_user(d)} (uid {account(d).get('uid', '?')})"
          + (f": {'; '.join(account_problems(d))}" if account_problems(d) else ""),
          "Create a dedicated system account for nginx and name it in the user directive.", ("NGINX_T", "ACCOUNT"))
    _rule(r, "2.2.2", "Ensure the NGINX service account is locked", "medium",
          lambda d: account(d).get("shadow", "") in ("!", "*"),
          lambda d: f"{worker_user(d)}: password " + ({"!": "locked", "*": "locked (no password)"}.get(
              account(d).get("shadow", ""), "not locked" if account(d).get("shadow") else "unknown")),
          "passwd -l <nginx user>", ("NGINX_T", "ACCOUNT"))
    _rule(r, "2.2.3", "Ensure the NGINX service account has an invalid shell", "medium",
          lambda d: account(d).get("shell") in NOLOGIN_SHELLS,
          lambda d: f"{worker_user(d)}: shell {account(d).get('shell', 'unknown')}",
          "usermod -s /sbin/nologin <nginx user>", ("NGINX_T", "ACCOUNT"))

    # 2.3 Permissions ─────────────────────────────────────────────────────
    def not_root_owned(d):
        return [p for o, g, _m, _t, p in files(d) if o != "root" or g != "root"]
    _rule(r, "2.3.1", "Ensure NGINX directories and files are owned by root", "medium", lambda d: not not_root_owned(d),
          lambda d: f"{len(files(d))} entries under /etc/nginx; not root:root: {_names(not_root_owned(d))}",
          "chown -R root:root /etc/nginx", ("FILES",))

    def loose(d):
        """Configuration files and directories writable by group/others or files readable by others.
        """
        out = []
        for _o, _g, mode, kind, p in files(d):
            if kind == "directory" and mode & 0o022:
                out.append(f"{p} ({mode:o})")
            elif kind != "directory" and mode & 0o117:
                out.append(f"{p} ({mode:o})")
        return out
    _rule(r, "2.3.2", "Ensure access to NGINX directories and files is restricted", "medium", lambda d: not loose(d),
          lambda d: "too open (directories writable by group/others, files readable by others or executable): "
          + _names(loose(d)),
          "find /etc/nginx -type d -exec chmod go-w {} +; find /etc/nginx -type f -exec chmod ug-x,o-rwx {} +",
          ("FILES",))

    def pid_file(d):
        v = section(d, "NGINX_VERSION")
        path = cfg(d).main_value("pid") or compiled(v, "pid-path") or "/run/nginx.pid"
        return path, paths(d).get(path)
    _rule(r, "2.3.3", "Ensure the NGINX process ID (PID) file is secured", "medium",
          lambda d: pid_file(d)[1] is not None and pid_file(d)[1][3] != "missing" and pid_file(d)[1][0] == "root"
          and pid_file(d)[1][1] == "root" and not pid_file(d)[1][2] & 0o133,
          lambda d: f"{pid_file(d)[0]}: " + (f"{pid_file(d)[1][0]}:{pid_file(d)[1][1]} {pid_file(d)[1][2]:o}"
                                              if pid_file(d)[1] and pid_file(d)[1][3] != "missing" else "missing"),
          "chown root:root <pid file>; chmod u-x,go-wx <pid file>", ("NGINX_T", "PATHS"))

    def core_dir(d):
        """The working_directory (core dumps) and what is wrong with it."""
        wd = cfg(d).main_value("working_directory")
        if not wd:
            return None, []
        info = paths(d).get(wd)
        problems = []
        if not info or info[3] == "missing":
            problems.append("does not exist")
        else:
            if info[0] != "root":
                problems.append(f"owner {info[0]}")
            if info[2] & 0o007:
                problems.append(f"mode {info[2]:o}")
        roots = [x.args[0] for x in cfg(d).all("root") if x.args]
        if any(wd.rstrip("/").startswith(rt.rstrip("/")) for rt in roots):
            problems.append("inside a document root")
        return wd, problems
    _rule(r, "2.3.4", "Ensure the core dump directory is secured", "low", lambda d: not core_dir(d)[1],
          lambda d: (f"working_directory {core_dir(d)[0]}: " + (", ".join(core_dir(d)[1]) or "secured"))
          if core_dir(d)[0] else "working_directory not set (no core dump directory configured)",
          "Keep working_directory outside document roots, owned by root, not accessible to others.",
          ("NGINX_T", "PATHS"))

    # 2.4 Network ─────────────────────────────────────────────────────────
    _manual(r, "2.4.1", "Ensure NGINX only listens for network connections on authorized ports", "medium",
            "Review the listen directives; remove listeners that are not needed.",
            lambda d: "listening on: " + _names(sorted({k for s in servers(d) for k, _p in listens(s)})))

    def catchall_missing(d):
        """Listen addresses without a default server that rejects unknown hosts."""
        groups: Dict[str, List[Directive]] = {}
        for s in servers(d):
            for key, params in listens(s):
                groups.setdefault(key, [])
                if "default_server" in params or "default" in params:
                    groups[key].insert(0, s)
                else:
                    groups[key].append(s)
        out = []
        for key, members in groups.items():
            first = members[0]
            rejects = any(x.name == "return" and x.args and x.args[0] in ("444", "400", "403", "404")
                          for x in first.direct("return")) or effective_value(first, "ssl_reject_handshake") == "on"
            if not rejects:
                out.append(f"{key} -> {server_label(first)}")
        return out
    _rule(r, "2.4.2", "Ensure requests for unknown host names are rejected", "medium",
          lambda d: not catchall_missing(d),
          lambda d: "listeners whose default server answers unknown host names: " + _names(catchall_missing(d)),
          "Add a default_server for each listener that returns 444 (ssl_reject_handshake on for TLS).")
    _timeout_rule(r, "2.4.3", "Ensure keepalive_timeout is 10 seconds or less, but not 0", ("keepalive_timeout",), "75",
                  "keepalive_timeout 10;")
    _timeout_rule(r, "2.4.4", "Ensure send_timeout is set to 10 seconds or less, but not 0", ("send_timeout",), "60",
                  "send_timeout 10;")

    # 2.5 Information disclosure ──────────────────────────────────────────
    _per_scope(r, "2.5.1", "Ensure server_tokens directive is set to `off`", "medium",
               lambda b: None if effective_value(b, "server_tokens", "on") == "off"
               else f"server_tokens {effective_value(b, 'server_tokens') or 'on (default)'}",
               "server_tokens", "server_tokens off;", scope="scopes")
    _rule(r, "2.5.2", "Ensure default error and index.html pages do not reference NGINX", "low",
          lambda d: not [ln for ln in section(d, "PAGES").splitlines() if ln.startswith("/")],
          lambda d: "pages mentioning nginx: " + _names(ln for ln in section(d, "PAGES").splitlines() if ln.startswith("/")),
          "Replace the stock index and 50x pages with pages that do not name the server software.", ("PAGES",))

    def no_hidden_guard(d):
        """Servers without a location that denies hidden files (/.git, /.env)."""
        out = []
        for s in servers(d):
            guarded = any(loc.args[:1] in (["~"], ["~*"]) and "/\\." in " ".join(loc.args)
                          and any(x.name in ("deny", "return") for x in loc.children or []) for loc in Config.locations(s))
            if not guarded:
                out.append(server_label(s))
        return out
    _manual(r, "2.5.3", "Ensure hidden file serving is disabled", "medium",
            "Add location ~ /\\. { deny all; return 404; } (allow /.well-known/acme-challenge if needed).",
            lambda d: "servers without a hidden-file location: " + _names(no_hidden_guard(d)))
    _per_scope(r, "2.5.4", "Ensure the NGINX reverse proxy does not enable information disclosure", "medium",
               lambda b: ", ".join(f"{h} not hidden" for h in ("X-Powered-By", "Server")
                                   if h.lower() not in array_values(b, "proxy_hide_header")) or None,
               "proxied locations hiding X-Powered-By and Server",
               "proxy_hide_header X-Powered-By; proxy_hide_header Server;", scope="proxied",
               empty_note="no proxied locations")

    # 3 Logging ───────────────────────────────────────────────────────────
    _manual(r, "3.1", "Ensure detailed logging is enabled", "medium",
            "Define a log_format with the client address, user, time, request, status, size, referrer and user agent.",
            lambda d: "log_format: " + _names(x.args[0] for x in cfg(d).all("log_format") if x.args))

    def access_off(d):
        return [f"{x.file}:{x.line}" for x in cfg(d).all("access_log")
                if x.args[:1] == ["off"] and x.context() in ("http", "server")]
    _rule(r, "3.2", "Ensure access logging is enabled", "medium", lambda d: not access_off(d),
          lambda d: "access_log off at http/server level: " + _names(access_off(d)),
          "Remove 'access_log off' from http and server blocks.")

    def error_logs(d):
        return [x.args for x in cfg(d).main("error_log") if x.args]
    _rule(r, "3.3", "Ensure error logging is enabled and set to the info logging level", "medium",
          lambda d: bool(error_logs(d)) and all(len(a) > 1 and a[1] in ("info", "debug") for a in error_logs(d)),
          lambda d: "error_log: " + (_names(" ".join(a) + ("" if len(a) > 1 else " (level error by default)")
                                            for a in error_logs(d)) if error_logs(d) else "not set at main level"),
          "error_log /var/log/nginx/error.log info;")

    def logrotate(d):
        """What is missing from the nginx logrotate configuration."""
        text = section(d, "LOGROTATE")
        problems = []
        if "NO_LOGROTATE_FILE" in text:
            problems.append("no /etc/logrotate.d/nginx")
        elif not re.search(r"^\s*rotate\s+\d+", text, re.M):
            problems.append("no rotate count")
        if "### logrotate missing" in text:
            problems.append("logrotate is not installed")
        return problems
    _rule(r, "3.4", "Ensure log files are rotated", "medium", lambda d: not logrotate(d),
          lambda d: "; ".join(logrotate(d)) or "rotation: " + " ".join(
              ln.strip() for ln in section(d, "LOGROTATE").splitlines()
              if re.match(r"\s*(daily|weekly|monthly|rotate)\b", ln)),
          "Rotate /var/log/nginx/*.log with logrotate (weekly, 13 rotations).", ("LOGROTATE",))

    def to_syslog(d, name):
        return [" ".join(x.args) for x in cfg(d).all(name) if x.args and x.args[0].startswith("syslog:")]
    _manual(r, "3.5", "Ensure error logs are sent to a remote syslog server", "low",
            "error_log syslog:server=<collector>:514 info;",
            lambda d: "error_log to syslog: " + _names(to_syslog(d, "error_log")), level="L2")
    _manual(r, "3.6", "Ensure access logs are sent to a remote syslog server", "low",
            "access_log syslog:server=<collector>:514,facility=local7,tag=nginx,severity=info combined;",
            lambda d: "access_log to syslog: " + _names(to_syslog(d, "access_log")), level="L2")
    _per_scope(r, "3.7", "Ensure proxies pass source IP information", "medium",
               lambda b: ", ".join(f"{h} not passed" for h in ("X-Real-IP", "X-Forwarded-For")
                                   if h.lower() not in array_values(b, "proxy_set_header")) or None,
               "proxied locations passing X-Real-IP and X-Forwarded-For",
               "proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
               scope="proxied", empty_note="no proxied locations")

    # 4 TLS ───────────────────────────────────────────────────────────────
    def plain_servers(d):
        """Plain-HTTP servers that do not redirect to HTTPS."""
        out = []
        for s in servers(d):
            if is_ssl(s):
                continue
            redirects = any(x.args[:1] in (["301"], ["302"], ["307"], ["308"]) and len(x.args) > 1
                            and x.args[1].startswith("https://") for x in s.direct("return"))
            if not redirects:
                out.append(server_label(s))
        return out
    _manual(r, "4.1.1", "Ensure HTTP is redirected to HTTPS", "high",
            "In each plain-HTTP server: return 301 https://$host$request_uri;",
            lambda d: "HTTP servers without a redirect to HTTPS: " + _names(plain_servers(d)))
    _manual(r, "4.1.2", "Ensure a trusted certificate and trust chain is installed", "high",
            "Use certificates issued by a trusted CA, with the full chain in ssl_certificate.",
            lambda d: "certificates: " + _names(sorted({x.args[0] for x in cfg(d).all("ssl_certificate") if x.args})))

    def key_problems(d):
        """Private key files that are missing, not owned by root, or readable by group/others."""
        out = []
        for key in sorted({x.args[0] for x in cfg(d).all("ssl_certificate_key") if x.args and "$" not in x.args[0]}):
            info = paths(d).get(key)
            if not info or info[3] == "missing":
                out.append(f"{key} (missing)")
            elif info[0] != "root" or info[2] & 0o077:
                out.append(f"{key} ({info[0]}:{info[1]} {info[2]:o})")
        return out
    _rule(r, "4.1.3", "Ensure private key permissions are restricted", "high", lambda d: not key_problems(d),
          lambda d: f"{len({x.args[0] for x in cfg(d).all('ssl_certificate_key') if x.args})} private keys; "
          f"too open: {_names(key_problems(d))}", "chown root:root <key>; chmod 400 <key>", ("NGINX_T", "PATHS"))

    def default_protocols(d):
        return "TLSv1.2 TLSv1.3" if version(d) >= (1, 23, 4) else "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"

    def bad_protocols(block, d):
        value = effective_value(block, "ssl_protocols") or default_protocols(d) + " (default)"
        weak = [p for p in value.split() if p in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")]
        return f"{value}" if weak else None
    _per_scope(r, "4.1.4", "Ensure only modern TLS protocols are used", "high", bad_protocols,
               "HTTPS servers using only TLS 1.2/1.3", "ssl_protocols TLSv1.2 TLSv1.3;", scope="ssl",
               empty_note="no HTTPS servers", with_dump=True, sections=("NGINX_T", "NGINX_VERSION"))
    _manual(r, "4.1.5", "Disable weak ciphers", "high",
            "ssl_ciphers with AEAD ciphers only (Mozilla intermediate profile); ssl_prefer_server_ciphers per profile.",
            lambda d: "ssl_ciphers: " + _names(sorted({effective_value(s, 'ssl_ciphers') or 'default'
                                                       for s in ssl_servers(d)})))
    _per_scope(r, "4.1.6", "Ensure custom Diffie-Hellman parameters are used", "medium",
               lambda b: None if effective_value(b, "ssl_dhparam") else "ssl_dhparam not set",
               "HTTPS servers with ssl_dhparam", "openssl dhparam -out /etc/nginx/dhparam.pem 2048; ssl_dhparam ...;",
               scope="ssl", level="L2", empty_note="no HTTPS servers")
    _per_scope(r, "4.1.7", "Ensure Online Certificate Status Protocol (OCSP) stapling is enabled", "low",
               lambda b: ", ".join(f"{n} {effective_value(b, n) or 'off (default)'}"
                                   for n in ("ssl_stapling", "ssl_stapling_verify") if effective_value(b, n) != "on") or None,
               "HTTPS servers with OCSP stapling", "ssl_stapling on; ssl_stapling_verify on;", scope="ssl",
               empty_note="no HTTPS servers")

    def hsts_ok(value):
        m = re.search(r"max-age=(\d+)", value)
        return bool(m) and int(m.group(1)) >= HSTS_MIN
    _header_rule(r, "4.1.8", "Ensure HTTP Strict Transport Security (HSTS) is enabled", "high",
                 "Strict-Transport-Security", hsts_ok, "HTTPS servers sending HSTS with max-age >= 15768000",
                 'add_header Strict-Transport-Security "max-age=31536000" always;', scope="ssl")
    _manual(r, "4.1.9", "Ensure upstream server traffic is authenticated with a client certificate", "medium",
            "proxy_ssl_certificate and proxy_ssl_certificate_key for HTTPS upstreams.",
            lambda d: "proxy_ssl_certificate: " + _names(x.args[0] for x in cfg(d).all("proxy_ssl_certificate") if x.args),
            level="L2")
    _manual(r, "4.1.10", "Ensure the upstream traffic server certificate is trusted", "medium",
            "proxy_ssl_verify on; proxy_ssl_trusted_certificate <CA bundle>;",
            lambda d: "proxy_ssl_verify on in: " + _names(f"{x.file}:{x.line}" for x in cfg(d).all("proxy_ssl_verify")
                                                         if x.args[:1] == ["on"]), level="L2")
    _manual(r, "4.1.11", "Ensure your domain is preloaded", "low",
            "Add includeSubDomains; preload to HSTS and submit the domain to hstspreload.org.", level="L2")
    _per_scope(r, "4.1.12", "Ensure session resumption is disabled to enable perfect forward security", "medium",
               lambda b: None if effective_value(b, "ssl_session_tickets", "on") == "off"
               else f"ssl_session_tickets {effective_value(b, 'ssl_session_tickets') or 'on (default)'}",
               "HTTPS servers with session tickets off", "ssl_session_tickets off;", scope="ssl",
               empty_note="no HTTPS servers")
    _per_scope(r, "4.1.13", "Ensure HTTP/2.0 is used", "low",
               lambda b: None if (effective_value(b, "http2") == "on"
                                  or any("http2" in p for _k, p in listens(b))) else "HTTP/2 not enabled",
               "HTTPS servers with HTTP/2", "http2 on; (nginx 1.25.1+) or listen 443 ssl http2;", scope="ssl",
               empty_note="no HTTPS servers")
    _manual(r, "4.1.14", "Ensure only Perfect Forward Secrecy Ciphers are Leveraged", "medium",
            "Use ECDHE/DHE key exchange ciphers only.",
            lambda d: "ssl_ciphers: " + _names(sorted({effective_value(s, 'ssl_ciphers') or 'default'
                                                       for s in ssl_servers(d)})))

    # 5 Request filtering and limits ──────────────────────────────────────
    _manual(r, "5.1.1", "Ensure allow and deny filters limit access to specific IP addresses", "medium",
            "Restrict administrative locations with allow <network>; deny all;",
            lambda d: "locations with allow/deny: " + _names(label for label, b in scopes(d) if b.direct("deny")))
    _manual(r, "5.1.2", "Ensure only approved HTTP methods are allowed", "medium",
            "if ($request_method !~ ^(GET|HEAD|POST)$) { return 444; } or limit_except in each location.",
            lambda d: "servers restricting methods: " + _names(
                server_label(s) for s in servers(d)
                if any(x.name in ("limit_except",) or (x.name == "if" and "$request_method" in " ".join(x.args))
                       for x in s.walk())))
    _timeout_rule(r, "5.2.1", "Ensure timeout values for reading the client header and body are set correctly",
                  ("client_body_timeout", "client_header_timeout"), "60",
                  "client_body_timeout 10; client_header_timeout 10;")

    def body_size(block):
        """Why the request body limit is wrong (unset or unlimited), else None."""
        v = effective_value(block, "client_max_body_size")
        if v is None:
            return "not set (1m default)"
        return "0 (unlimited)" if v.strip() in ("0", "0k", "0m", "0K", "0M") else None
    _per_scope(r, "5.2.2", "Ensure the maximum request body size is set correctly", "medium", body_size,
               "client_max_body_size set and not 0", "client_max_body_size 100K; (or the size the sites need)",
               scope="scopes")
    _per_scope(r, "5.2.3", "Ensure the maximum buffer size for URIs is defined", "low",
               lambda b: None if effective_value(b, "large_client_header_buffers") else "not set (4 8k default)",
               "large_client_header_buffers set", "large_client_header_buffers 2 1k;")
    _per_scope(r, "5.2.4", "Ensure the number of connections per IP address is limited", "medium",
               lambda b: None if effective(b, "limit_conn") else "no limit_conn",
               "servers limiting connections per address",
               "limit_conn_zone $binary_remote_addr zone=limitperip:10m; limit_conn limitperip 10;", level="L2")
    _per_scope(r, "5.2.5", "Ensure rate limits by IP address are set", "medium",
               lambda b: None if effective(b, "limit_req") else "no limit_req", "servers rate-limiting requests",
               "limit_req_zone $binary_remote_addr zone=ratelimit:10m rate=5r/s; limit_req zone=ratelimit burst=10 nodelay;",
               level="L2")
    _header_rule(r, "5.3.1", "Ensure X-Content-Type-Options header is configured and enabled", "medium",
                 "X-Content-Type-Options", lambda v: v.strip("\"'").lower() == "nosniff",
                 "servers and locations sending X-Content-Type-Options nosniff",
                 'add_header X-Content-Type-Options "nosniff" always;')
    _header_rule(r, "5.3.2", "Ensure that Content Security Policy (CSP) is enabled and configured properly", "medium",
                 "Content-Security-Policy", lambda v: bool(v.strip("\"' ")),
                 "servers and locations sending a Content-Security-Policy",
                 "add_header Content-Security-Policy \"default-src 'self'\" always;", level="L2")
    _header_rule(r, "5.3.3", "Ensure the Referrer Policy is enabled and configured properly", "low", "Referrer-Policy",
                 lambda v: v.strip("\"'").lower() in SAFE_REFERRER,
                 "servers and locations sending a strict Referrer-Policy", 'add_header Referrer-Policy "no-referrer";')

    # 6 Mandatory access control ──────────────────────────────────────────
    def mac(d):
        """(SELinux mode, AppArmor state, security contexts of the nginx processes)."""
        text = section(d, "MAC")
        selinux = re.search(r"selinux=(\S+)", text)
        apparmor = re.search(r"apparmor=(\S+)", text)
        contexts = {p["context"] for p in procs(d) if p["context"]}
        return (selinux.group(1) if selinux else "absent", apparmor.group(1) if apparmor else "absent", contexts)

    def confined(d):
        """Whether nginx runs confined by SELinux (httpd_t) or an enforcing AppArmor profile."""
        selinux, _apparmor, contexts = mac(d)
        if selinux == "Enforcing":
            return any(":httpd_t:" in c for c in contexts) or not contexts
        return any(c and c not in ("unconfined", "kernel") and "(enforce)" in c for c in contexts)
    _rule(r, "6.1", "Ensure a mandatory access control profile confines NGINX (SELinux or AppArmor)", "medium",
          confined,
          lambda d: f"SELinux {mac(d)[0]}, AppArmor {mac(d)[1]}, nginx process contexts: {_names(sorted(mac(d)[2]))}",
          "Run nginx under SELinux (httpd_t, enforcing) or an enforcing AppArmor profile.", ("MAC", "PROCS"),
          level="L2")

    r.sort(key=lambda x: tuple(int(p) for p in x.section.split(".")))
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    """The rules for this host. Raises when nginx is not installed or its configuration does not load,
    so the session fails with that reason instead of a list of false findings.
    """
    v = section(dump, "NGINX_VERSION")
    if not v or NOT_INSTALLED in v:
        raise ValueError("nginx is not installed on this host (nginx -V did not answer).")
    error = config_error(dump)
    if error:
        raise ValueError(f"The nginx configuration does not load, so it cannot be audited: {error}")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    c = cfg(dump)
    ssl = len([s for s in c.servers() if is_ssl(s)])
    return f"{version_text(dump)}, {len(c.servers())} server blocks ({ssl} HTTPS), {len(c.files)} config files"
