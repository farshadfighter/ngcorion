"""
Read-only collection for an nginx audit over SSH (root via sudo).

The configuration comes from `nginx -T` - every file nginx itself read, in
order - so includes, sites-enabled/ and conf.d/ are seen as nginx sees
them. A second pass, driven by that configuration, reads the worker
account, ownership and modes of the files it names (PID file, keys,
certificates), and the default pages under its document roots.

Before storage the stock MIME type list is dropped and values that can
hold secrets (Authorization and token headers, fastcgi/uwsgi parameters,
secure_link secrets) are masked. Private keys are only stat'ed, never read;
of /etc/shadow only whether the account is locked is read.
"""

import re
import shlex
from typing import Dict, List, Optional

from app.modules.benchmark.rules import assemble

from .conf import Config, ParseError, split_dump

NOT_INSTALLED = "NOT_INSTALLED"

COMMANDS: Dict[str, str] = {
    "NGINX_VERSION": f"command -v nginx >/dev/null 2>&1 || {{ echo {NOT_INSTALLED}; exit 0; }}; nginx -V 2>&1",
    "NGINX_T": "nginx -T 2>&1; true",
    # nginx processes from /proc (minimal images have no ps): pid|uid|ppid|cmdline|security context
    "PROCS": ("for p in /proc/[0-9]*; do [ \"$(cat $p/comm 2>/dev/null)\" = nginx ] || continue; "
              "echo \"${p#/proc/}|$(awk '/^Uid:/{print $2}' $p/status)|$(awk '/^PPid:/{print $2}' $p/status)|"
              "$(tr '\\0' ' ' < $p/cmdline)|$(tr -d '\\0' < $p/attr/current 2>/dev/null)\"; done; echo END"),
    "FILES": ("find /etc/nginx -xdev \\( -type f -o -type d -o -type l \\) -exec stat -c '%U|%G|%a|%F|%n' {} + "
              "2>/dev/null | head -n 3000; echo END"),
    "LOGROTATE": ("if [ -f /etc/logrotate.d/nginx ]; then cat /etc/logrotate.d/nginx; else echo NO_LOGROTATE_FILE; fi; "
                  "command -v logrotate >/dev/null 2>&1 && echo '### logrotate installed' || echo '### logrotate missing'"),
    "MAC": ("echo \"selinux=$(getenforce 2>/dev/null || echo absent)\"; "
            "echo \"apparmor=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)\""),
    "PACKAGE": ("{ dpkg-query -W -f '${db:Status-Abbrev} ${Package} ${Version}\\n' 'nginx*' 2>/dev/null | "
                "awk '$1 == \"ii\" { print $2 \" \" $3 }'; rpm -q nginx 2>/dev/null; } | grep . || "
                "echo 'not from a package'"),
}


def account_command(user: str) -> str:
    """The worker account: passwd line, and from /etc/shadow only the first
    character of the password field (! or * = locked)."""
    u = shlex.quote(user)
    return (f"getent passwd {u} || echo NO_ACCOUNT; "
            f"echo \"shadow=$(awk -F: -v u={u} '$1==u {{print substr($2,1,1)}}' /etc/shadow 2>/dev/null)\"; "
            f"echo \"groups=$(id -Gn {u} 2>/dev/null)\"")


def paths_command(paths: List[str]) -> str:
    quoted = " ".join(shlex.quote(p) for p in paths)
    return (f"for f in {quoted}; do stat -L -c '%U|%G|%a|%F|%n' \"$f\" 2>/dev/null || echo \"missing|||missing|$f\"; "
            "done; echo END")


def pages_command(roots: List[str]) -> str:
    quoted = " ".join(shlex.quote(r) for r in roots)
    return (f"for d in {quoted}; do for f in index.html index.htm index.nginx-debian.html 50x.html; do "
            "[ -f \"$d/$f\" ] && grep -qi nginx \"$d/$f\" && echo \"$d/$f\"; done; done; echo END")


# ── what to store ────────────────────────────────────────────────────────

_SECRET_ARGS = re.compile(
    r"^(\s*(?:proxy_set_header|grpc_set_header|add_header|more_set_headers|fastcgi_param|uwsgi_param|scgi_param|"
    r"set|env)\s+[\"']?[$\w.-]*(?:auth|token|secret|passw|pwd|api[_-]?key|cookie|credential|session)[\w.-]*[\"']?\s+)"
    r"([^;]*)(;)", re.I | re.M)
_SECRET_DIRECTIVES = re.compile(r"^(\s*(?:secure_link_secret|secure_link_md5)\s+)([^;]*)(;)", re.I | re.M)


def redact(text: str) -> str:
    text = _SECRET_ARGS.sub(lambda m: f"{m.group(1)}\"***\"{m.group(3)}", text)
    return _SECRET_DIRECTIVES.sub(lambda m: f"{m.group(1)}\"***\"{m.group(3)}", text)


def slim(dump_t: str) -> str:
    """Drop the MIME type list (a hundred lines nobody audits)."""
    out, skip = [], False
    for line in dump_t.splitlines():
        if line.startswith("# configuration file "):
            skip = line.rstrip(":").endswith("mime.types")
            out.append(line)
            if skip:
                out += ["types {", "    # (MIME type list omitted)", "}"]
            continue
        if not skip:
            out.append(line)
    return "\n".join(out)


def compiled(version_text: str, name: str) -> Optional[str]:
    m = re.search(rf"--{name}=(\S+)", version_text)
    return m.group(1) if m else None


def config_paths(cfg: Config, version_text: str) -> List[str]:
    """Files whose ownership and modes the rules look at."""
    paths = [cfg.main_value("pid") or compiled(version_text, "pid-path") or "/run/nginx.pid"]
    for name in ("ssl_certificate_key", "ssl_certificate", "ssl_dhparam", "ssl_trusted_certificate"):
        paths += [d.args[0] for d in cfg.all(name) if d.args and "$" not in d.args[0]]
    wd = cfg.main_value("working_directory")
    if wd:
        paths.append(wd)
    return list(dict.fromkeys(paths))


def document_roots(cfg: Config) -> List[str]:
    roots = [d.args[0] for d in cfg.all("root") if d.args and "$" not in d.args[0]]
    return list(dict.fromkeys(roots + ["/usr/share/nginx/html", "/var/www/html"]))


def second_pass(cfg: Config, version_text: str) -> Dict[str, str]:
    return {"ACCOUNT": account_command(cfg.main_value("user", "nobody").split()[0]),
            "PATHS": paths_command(config_paths(cfg, version_text)),
            "PAGES": pages_command(document_roots(cfg))}


def collect(conn) -> str:
    """Collect the nginx audit dump: version, the full configuration (nginx -T, secrets redacted,
    comments stripped), then the account, file permissions, log pages and processes the
    configuration points to. A host without nginx yields a dump saying so.
    """
    version = conn.run(COMMANDS["NGINX_VERSION"])
    if NOT_INSTALLED in version or "nginx version" not in version:
        return assemble({"NGINX_VERSION": NOT_INSTALLED})
    out = {"NGINX_VERSION": version, "NGINX_T": redact(slim(conn.run(COMMANDS["NGINX_T"])))}
    try:
        cfg = Config(out["NGINX_T"]) if split_dump(out["NGINX_T"]) else None
    except ParseError:
        cfg = None
    if cfg is not None:
        out.update({name: conn.run(script) for name, script in second_pass(cfg, version).items()})
    out.update({name: conn.run(script) for name, script in COMMANDS.items() if name not in out})
    return assemble(out)
