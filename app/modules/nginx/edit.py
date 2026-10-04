"""
Configuration changes for nginx hardening, made the way an administrator
would: on the files nginx actually reads, directive by directive.

A hardening statement starting with "NGX:" is an edit, for example

    NGX:set http server_tokens off
    NGX:array add_header X-Content-Type-Options nosniff always
    NGX:check NGINX-2.5.1

Each edit reads the live configuration (`nginx -T` and the files it
lists), comments out or rewrites only whole-line directives (anything else
is refused), inserts new directives at the top of the right block, then
backs the changed files up to /var/backups/ngcorion-nginx/, writes them,
and runs `nginx -t`. If the test fails every file is put back and the error
is reported; otherwise nginx is reloaded. "NGX:check" re-collects and
evaluates the benchmark rule, so verification is the audit itself.

File contents travel on the SSH channel's stdin, never on a command line.
"""

import re
import shlex
import time
from typing import Callable, Dict, List, Optional, Tuple

from .conf import Config, Directive, effective_value, is_ssl, listens, parse_file

PREFIX = "NGX:"
BACKUP_ROOT = "/var/backups/ngcorion-nginx"
MARK = "----- ngcorion file content -----"
TAG = "# disabled by ngcorion:"

CSP_POLICIES = {
    "default-src-self": "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
    "default-src-self-no-framing": "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
}


class EditError(RuntimeError):
    """A configuration edit could not be made safely; nothing was changed (or the change was rolled
    back).
    """
    pass


def render(name: str, args: List[str]) -> str:
    """One directive as configuration text, quoting arguments that contain spaces or special
    characters.
    """
    out = [name]
    for a in args:
        if a == "" or re.search(r"[\s;{}#\"']", a):
            out.append('"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"')
        else:
            out.append(a)
    return " ".join(out) + ";"


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


class Editor:
    """One edit session over the live configuration."""

    def __init__(self, conn):
        self.conn = conn
        dump = conn.execute("nginx -T 2>&1")
        if "test failed" in dump or "[emerg]" in dump:
            raise EditError("the current configuration does not load: "
                            + next((ln for ln in dump.splitlines() if "[emerg]" in ln), "nginx -t failed"))
        self.cfg = Config(dump)
        self.version = tuple(int(x) for x in re.search(r"nginx/(\d+)\.(\d+)\.(\d+)",
                                                         conn.execute("nginx -v 2>&1")).groups())
        self.original: Dict[str, str] = {}
        for path, dumped in self.cfg.files.items():
            text = conn.execute(f"cat {shlex.quote(path)}")
            if text == "(ok)":
                text = ""
            if text.rstrip("\n") != dumped.rstrip("\n"):
                raise EditError(f"{path} changed since nginx loaded it; reload nginx and try again")
            self.original[path] = text
        self.ops: Dict[str, List[Tuple[int, int, str, List[str]]]] = {}

    # ── recorded operations, applied bottom-up at commit ──
    def _op(self, path, line, order, kind, lines=()):
        self.ops.setdefault(path, []).append((line, order, kind, list(lines)))

    def _line(self, path, n) -> str:
        return self.original[path].split("\n")[n - 1]

    def _single_line(self, d: Directive) -> str:
        if d.is_block or d.line != d.end_line:
            raise EditError(f"{d.file}:{d.line}: '{d.name}' spans several lines; change it by hand")
        text = self._line(d.file, d.line)
        parsed = parse_file(text, d.file)
        if len(parsed) != 1 or parsed[0].name != d.name:
            raise EditError(f"{d.file}:{d.line}: '{d.name}' shares its line with other directives; change it by hand")
        return text

    def comment(self, d: Directive):
        text = self._single_line(d)
        self._op(d.file, d.line, 0, "replace", [f"{_indent(text)}{TAG} {text.strip()}"])

    def replace(self, d: Directive, args: List[str]):
        text = self._single_line(d)
        self._op(d.file, d.line, 0, "replace", [_indent(text) + render(d.name, args)])

    def insert_top(self, block: Directive, lines: List[str]):
        """Insert lines right after the block's opening brace."""
        brace = self._line(block.file, block.end_line)
        if not brace.split("#", 1)[0].rstrip().endswith("{"):
            raise EditError(f"{block.file}:{block.end_line}: the '{block.name}' block does not open at the end of "
                            "a line; change it by hand")
        first = next((c for c in block.children or [] if c.file == block.file), None)
        indent = _indent(self._line(block.file, first.line)) if first else _indent(brace) + "    "
        self._op(block.file, block.end_line, 1, "after", [indent + ln if ln else ln for ln in lines])

    def insert_before(self, d: Directive, lines: List[str]):
        indent = _indent(self._line(d.file, d.line))
        self._op(d.file, d.line, 2, "before", [indent + ln for ln in lines])

    def http(self) -> Directive:
        """The http block; editing requires one."""
        h = self.cfg.http()
        if h is None:
            raise EditError("the configuration has no http block")
        return h

    # ── edits ──
    def set(self, ctx: str, name: str, args: List[str], top_only: bool = False) -> str:
        """Make `name args` the value at a level: rewrite the existing directive(s) there, comment out
        conflicting ones below (top_only keeps lower levels), or add it when absent.
        """
        if ctx == "main":
            targets = self.cfg.main(name)
        else:
            h = self.http()
            targets = h.direct(name) if top_only else [x for x in h.walk() if x.name == name]
        if len(targets) == 1 and targets[0].args == args and targets[0].context() == ctx:
            return f"{name} already {' '.join(args)}"
        for d in targets:
            self.comment(d)
        if ctx == "main":
            self.insert_before(self.http(), [render(name, args)])
        else:
            self.insert_top(self.http(), [render(name, args)])
        return f"{render(name, args)} set in {ctx}; {len(targets)} earlier setting(s) disabled"

    def array(self, name: str, args: List[str]) -> str:
        """Array directives (add_header, proxy_set_header, proxy_hide_header):
        a block that sets any of them does not inherit the others, so the
        directive goes into http and into every block with its own."""
        key = args[0].lower()
        h = self.http()
        blocks = [h] + [b for b in h.walk() if b.is_block and b.direct(name)]
        changed = 0
        for b in blocks:
            same = [x for x in b.direct(name) if x.args and x.args[0].lower() == key]
            if len(same) == 1 and same[0].args == args:
                continue
            for x in same:
                self.comment(x)
            self.insert_top(b, [render(name, args)])
            changed += 1
        return f"{render(name, args)} in {changed} block(s)"

    def comment_matching(self, name: str, value: str, levels: Optional[List[str]] = None) -> str:
        """Comment out every `name value ...` directive (optionally only at some levels), for example
        "autoindex on".
        """
        targets = [x for x in self.http().walk() if x.name == name and x.args[:1] == [value]
                   and (not levels or x.context() in levels)]
        for d in targets:
            self.comment(d)
        return f"{len(targets)} '{name} {value}' disabled"

    def add(self, name: str, args: List[str], match: Optional[str] = None) -> str:
        """Add an http-level directive (for an array directive such as add_header, alongside the
        others), replacing one that matches `match`.
        """
        h = self.http()
        same = [x for x in h.direct(name) if (match and any(a.startswith(match) for a in x.args))
                or (not match and x.args == args)]
        if len(same) == 1 and same[0].args == args:
            return f"{render(name, args)} already present"
        for x in same:
            self.comment(x)
        self.insert_top(h, [render(name, args)])
        return f"{render(name, args)} added to http"

    def error_level(self, level: str) -> str:
        """Set the level of every main-level error_log, adding one when none exists."""
        logs = self.cfg.main("error_log")
        if not logs:
            self.insert_before(self.http(), [render("error_log", ["/var/log/nginx/error.log", level])])
            return f"error_log /var/log/nginx/error.log {level} added"
        for d in logs:
            if d.args[1:2] != [level]:
                self.replace(d, [d.args[0], level])
        return f"error_log level {level} on {len(logs)} log(s)"

    def catchall(self) -> str:
        """Add a default server for every listen address that has none, which closes requests with an
        unknown Host (444; TLS handshake rejected).
        """
        groups: Dict[str, List[Tuple[Directive, List[str]]]] = {}
        for s in self.cfg.servers():
            for key, params in listens(s):
                groups.setdefault(key, []).append((s, params))
        listen_lines, ssl_needed, taken = [], False, []
        for key, members in groups.items():
            if key.startswith("unix:"):
                continue
            default = next((s for s, p in members if "default_server" in p or "default" in p), members[0][0])
            rejects = any(x.args[:1] in (["444"], ["400"], ["403"], ["404"]) for x in default.direct("return")) \
                or effective_value(default, "ssl_reject_handshake") == "on"
            if rejects:
                continue
            ssl = any("ssl" in p for _s, p in members)
            ssl_needed |= ssl
            addr = key[2:] if key.startswith("*:") else key
            listen_lines.append(render("listen", [addr] + (["ssl"] if ssl else []) + ["default_server"]))
            taken.append(key)
        if not taken:
            return "every listener already rejects unknown host names"
        if ssl_needed and self.version < (1, 19, 4):
            raise EditError("rejecting unknown names on TLS listeners needs nginx 1.19.4+ (ssl_reject_handshake)")
        for s in self.cfg.servers():
            for d in s.direct("listen"):
                key = listens(_wrap(d))[0][0]
                if key in taken and ("default_server" in d.args or "default" in d.args):
                    self.replace(d, [a for a in d.args if a not in ("default_server", "default")])
        # No server_name: a default server answers whatever no other server
        # names, and "_" would clash with distribution default sites.
        body = ["server {"] + ["    " + ln for ln in listen_lines]
        if ssl_needed:
            body.append("    ssl_reject_handshake on;")
        body += ["    return 444;", "}", ""]
        self.insert_top(self.http(), ["# Added by ngcorion: reject requests for unknown host names (CIS NGINX 2.4.2)"]
                        + body)
        return f"catch-all default server added for {', '.join(taken)}"

    def http2(self) -> str:
        """Turn on HTTP/2 for TLS servers: "http2 on" on nginx 1.25.1 and later, the listen parameter
        before that.
        """
        changed = 0
        for s in self.cfg.servers():
            if not is_ssl(s) or effective_value(s, "http2") == "on" or any("http2" in p for _k, p in listens(s)):
                continue
            if self.version >= (1, 25, 1):
                for x in s.direct("http2"):
                    self.comment(x)
                self.insert_top(s, [render("http2", ["on"])])
            else:
                for d in s.direct("listen"):
                    if "ssl" in d.args and "http2" not in d.args:
                        self.replace(d, d.args + ["http2"])
            changed += 1
        return f"HTTP/2 enabled on {changed} HTTPS server(s)"

    # ── apply ──
    def commit(self) -> str:
        """Apply the collected edits: back up the touched files, write them, run nginx -t, and restore
        the backup if the test fails. Returns what changed.
        """
        if not self.ops:
            return "no change needed"
        new: Dict[str, str] = {}
        for path, ops in self.ops.items():
            lines = self.original[path].split("\n")
            # A file included in several places yields the same edit more than once.
            unique = list({(o[0], o[1], o[2], tuple(o[3])): o for o in ops}.values())
            for line, _order, kind, payload in sorted(unique, key=lambda o: (o[0], -o[1]), reverse=True):
                if kind == "replace":
                    lines[line - 1:line] = payload
                elif kind == "after":
                    lines[line:line] = payload
                elif kind == "before":
                    lines[line - 1:line - 1] = payload
            new[path] = "\n".join(lines)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = f"{BACKUP_ROOT}/{stamp}-{int(time.time() * 1000) % 100000}"
        self.conn.execute(f"mkdir -p {shlex.quote(backup)} && chmod 700 {shlex.quote(BACKUP_ROOT)} && "
                          + " && ".join(f"mkdir -p {shlex.quote(backup + p.rsplit('/', 1)[0])} && "
                                        f"cp -p {shlex.quote(p)} {shlex.quote(backup + p)}" for p in new))
        written = []
        try:
            for path, text in new.items():
                self.conn.write(path, text)
                written.append(path)
            test = self.conn.run("nginx -t 2>&1")
            if "successful" not in test:
                raise EditError("nginx -t rejected the change: "
                                + next((ln for ln in test.splitlines() if "[emerg]" in ln), test.strip()[-200:]))
        except Exception:
            for path in written:
                self.conn.write(path, self.original[path])
            raise
        return f"backup in {backup}; " + self.reload()

    def reload(self) -> str:
        """Reload nginx after a successful test; when nginx is not running (container without systemd),
        the configuration simply applies at the next start.
        """
        out = self.conn.run("nginx -s reload 2>&1")
        if out.startswith(("CMD_ERROR", "SSH_ERROR")):
            running = self.conn.run("for p in /proc/[0-9]*; do [ \"$(cat $p/comm 2>/dev/null)\" = nginx ] && "
                                    "echo yes && break; done; true").strip()
            if running == "yes":
                raise EditError(f"configuration written and tested, but nginx -s reload failed: {out[:200]}")
            return "nginx is not running; the change applies when it starts"
        return "nginx reloaded"


def _wrap(listen: Directive) -> Directive:
    return Directive("server", [], listen.file, listen.line, listen.line, children=[listen])


# ── statement handling ───────────────────────────────────────────────────

def _flag(args: List[str], name: str) -> Tuple[List[str], Optional[str]]:
    for a in args:
        if a.startswith(f"--{name}="):
            return [x for x in args if x != a], a.split("=", 1)[1]
        if a == f"--{name}":
            return [x for x in args if x != a], ""
    return args, None


def run_statement(conn, statement: str, check: Callable[[str], str]) -> str:
    """Execute one NGX: statement (set, array, comment, add, error-level, catchall, http2, csp, check)
    against a freshly collected configuration.
    """
    words = shlex.split(statement[len(PREFIX):])
    if not words:
        raise EditError("empty nginx edit")
    op, args = words[0], words[1:]
    if op == "check":
        return check(args[0])
    editor = Editor(conn)
    if op == "set":
        args, top = _flag(args, "top-only")
        result = editor.set(args[0], args[1], args[2:], top_only=top is not None)
    elif op == "array":
        result = editor.array(args[0], args[1:])
    elif op == "comment":
        args, levels = _flag(args, "levels")
        result = editor.comment_matching(args[0], args[1], levels.split(",") if levels else None)
    elif op == "add":
        args, match = _flag(args, "match")
        result = editor.add(args[0], args[1:], match)
    elif op == "error-level":
        result = editor.error_level(args[0])
    elif op == "catchall":
        result = editor.catchall()
    elif op == "http2":
        result = editor.http2()
    elif op == "csp":
        if args[0] not in CSP_POLICIES:
            raise EditError(f"unknown policy {args[0]}")
        result = editor.array("add_header", ["Content-Security-Policy", CSP_POLICIES[args[0]], "always"])
    else:
        raise EditError(f"unknown nginx edit '{op}'")
    return f"{result}; {editor.commit()}"


class NginxConnection:
    """The SSH connection plus nginx edits: "NGX:" statements are handled
    here, everything else runs as root through the shell connection.

    `writer(path, content)` replaces a file's content as root without the
    content appearing on a command line."""

    def __init__(self, shell, writer: Callable[[str, str], None]):
        self._shell = shell
        self._writer = writer
        self.ip = getattr(shell, "ip", None)

    def run(self, script: str) -> str:
        """Run a collection command, or an NGX: statement; an edit error comes back as CMD_ERROR text
        so the fix is reported as failed.
        """
        if not script.startswith(PREFIX):
            return self._shell.run(script)
        try:
            return run_statement(self, script, self.check)
        except Exception as exc:  # noqa: BLE001 - reported like a failed command
            return f"CMD_ERROR: {str(exc)[:300]}"

    def execute(self, script: str) -> str:
        if not script.startswith(PREFIX):
            return self._shell.execute(script)
        return run_statement(self, script, self.check)

    def write(self, path: str, content: str) -> None:
        self._writer(path, content)

    def check(self, rule_id: str) -> str:
        """Verify a fix by collecting again and evaluating the rule: "PASS: ..." or "FAIL: ..."."""
        from app.modules.benchmark.rules import evaluate
        from . import rules as R
        from .collect import collect
        dump = collect(self)
        rule = next((r for r in R.rules_for(dump) if r.id == rule_id), None)
        if rule is None:
            raise EditError(f"unknown rule {rule_id}")
        finding = evaluate(dump, [rule])["findings"][0]
        verdict = "PASS" if finding["status"] == "pass" else "FAIL"
        return f"{verdict}: {finding['evidence']}"


def stdin_write_script(path: str) -> str:
    """Shell script that writes what follows MARK on stdin to `path`
    (in place, so the file keeps its owner and mode). Lines before MARK - a
    sudo password sudo did not ask for - are dropped."""
    return (f"t=$(mktemp) || exit 1; awk -v m={shlex.quote(MARK)} 'f {{ print }} $0 == m {{ f = 1 }}' > \"$t\" && "
            f"cat \"$t\" > {shlex.quote(path)}; rc=$?; rm -f \"$t\"; exit $rc")
