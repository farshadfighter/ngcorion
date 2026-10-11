"""
nginx module (CIS NGINX Benchmark).

The rules run on output captured from two real servers:
tests/mock_data/nginx/nginx1_27_official_image_dump.txt (the nginx.org
image, nginx 1.27.5) and nginx1_24_ubuntu2404_dump.txt (Ubuntu 24.04's nginx
1.24.0 with a TLS shop site: proxy_pass with an Authorization header, its
own add_header, autoindex on a download folder, a world-readable key).

The configuration editor ("NGX:" statements) is tested on an in-memory
host that answers nginx -T / nginx -t like nginx, and TestLive runs
collection and every automated fix on a real nginx container when
NGCORION_NGINX_CONTAINER names one (skipped otherwise).
"""
import os
import re
import shlex
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset, AuditResult, User
from app.models.asset_types import AssetType
from app.models.audit import CheckStatus, DeviceType
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.connectors import NginxConnector
from app.modules.benchmark.hardening_service import BenchmarkHardeningService, run_template
from app.modules.benchmark.rules import evaluate, section
from app.modules.benchmark.templates import PLACEHOLDER_RE
from app.modules.nginx import rules as R
from app.modules.nginx.collect import COMMANDS, collect, redact, second_pass, slim
from app.modules.nginx.conf import Config, ParseError, effective_value, listens, parse_file, split_dump, tokenize
from app.modules.nginx.edit import MARK, EditError, NginxConnection, stdin_write_script
from app.modules.nginx.hardening import TEMPLATES
from app.modules.nginx.spec import SPEC

sys.path.insert(0, str(Path(__file__).parent))
from benchmark_fakes import FakeHost, install  # noqa: E402

MOCK = Path(__file__).parent / "mock_data" / "nginx"
OFFICIAL = (MOCK / "nginx1_27_official_image_dump.txt").read_text()
UBUNTU = (MOCK / "nginx1_24_ubuntu2404_dump.txt").read_text()
PARAMS = {"CONFIRM": "yes", "MAX_BODY_SIZE": "10m", "HEADER_BUFFERS": "4 8k", "CONN_PER_IP": "20", "REQ_RATE": "10",
          "REQ_BURST": "20", "CSP_POLICY": "default-src-self", "REFERRER_POLICY": "strict-origin-when-cross-origin"}


def run(d):
    report = evaluate(d, R.rules_for(d))
    return report, {f["id"]: f["status"] for f in report["findings"]}


def evidence(d, rid):
    return next(f["evidence"] for f in run(d)[0]["findings"] if f["id"] == rid)


def dump_of(files):
    """nginx -T output for {path: content} (first file = nginx.conf)."""
    out = ["nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
           "nginx: configuration file /etc/nginx/nginx.conf test is successful"]
    for path, text in files.items():
        out += [f"# configuration file {path}:", text]
    return "\n".join(out)


# ── parser ───────────────────────────────────────────────────────────────

class TestParser:
    def test_tokens(self):
        toks = [t for t, _ln, _q in tokenize('add_header X "a; b" always; # c\nset $x "${y}z";\nreturn 200 \'{}\';')]
        assert toks == ["add_header", "X", "a; b", "always", ";", "set", "$x", "${y}z", ";", "return", "200", "{}", ";"]

    def test_blocks_lines_and_lua(self):
        text = "http {\n  server {\n    listen 80;\n    content_by_lua_block {\n      ngx.say('}')\n    }\n  }\n}\n"
        root = parse_file(text, "/x.conf")
        server = root[0].children[0]
        assert (server.line, server.end_line, server.close_line) == (2, 2, 7)
        assert [c.name for c in server.children] == ["listen", "content_by_lua_block"]

    @pytest.mark.parametrize("text", ["server { listen 80;", "listen 80", "}", "a 'b;"])
    def test_errors(self, text):
        with pytest.raises(ParseError):
            parse_file(text, "/x.conf")

    def test_includes_and_inheritance(self):
        cfg = Config(dump_of({
            "/etc/nginx/nginx.conf": "http {\n  server_tokens off;\n  include conf.d/*.conf;\n  include /etc/nginx/sites/b;\n}",
            "/etc/nginx/conf.d/b.conf": "server { listen 443 ssl; server_tokens on; location / { } }",
            "/etc/nginx/conf.d/a.conf": "server { listen 10.0.0.1:8080 default_server; }",
            "/etc/nginx/sites/b": "server { server_name b; }",
        }))
        servers = cfg.servers()
        assert [s.file for s in servers] == ["/etc/nginx/conf.d/a.conf", "/etc/nginx/conf.d/b.conf", "/etc/nginx/sites/b"]
        assert [effective_value(s, "server_tokens") for s in servers] == ["off", "on", "off"]
        loc = Config.locations(servers[1])[0]
        assert effective_value(loc, "server_tokens") == "on" and loc.under("http")
        assert listens(servers[0]) == [("10.0.0.1:8080", ["default_server"])]
        assert listens(servers[1]) == [("*:443", ["ssl"])] and listens(servers[2]) == [("*:80", [])]

    def test_real_configs(self):
        cfg = Config(section(UBUNTU, "NGINX_T"))
        assert list(cfg.files) == ["/etc/nginx/nginx.conf", "/etc/nginx/mime.types", "/etc/nginx/sites-enabled/default",
                                   "/etc/nginx/sites-enabled/shop.conf"]
        assert [s.file.rsplit("/", 1)[-1] for s in cfg.servers()] == ["default", "shop.conf", "shop.conf"]


# ── rules on the real captures ───────────────────────────────────────────

class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 54
        assert sum(r.manual for r in rules) == 17

    def test_official_image(self):
        report, _ = run(OFFICIAL)
        assert report["summary"]["error_checks"] == 0
        assert (report["summary"]["passed_scored"], report["summary"]["failed_scored"]) == (19, 18)
        assert R.describe(OFFICIAL) == "nginx/1.27.5, 1 server blocks (0 HTTPS), 3 config files"

    def test_ubuntu(self):
        report, _ = run(UBUNTU)
        assert report["summary"]["error_checks"] == 0
        assert (report["summary"]["passed_scored"], report["summary"]["failed_scored"]) == (9, 28)
        assert R.describe(UBUNTU) == "nginx/1.24.0 (Ubuntu), 3 server blocks (1 HTTPS), 4 config files"

    @pytest.mark.parametrize("rid, official, ubuntu", [
        ("2.1.2", "fail", "fail"), ("2.1.3", "pass", "fail"), ("2.1.4", "pass", "fail"), ("2.2.1", "pass", "pass"),
        ("2.2.3", "pass", "pass"), ("2.3.2", "fail", "fail"), ("2.4.2", "fail", "fail"), ("2.4.3", "fail", "fail"),
        ("2.5.1", "fail", "fail"), ("2.5.2", "fail", "fail"), ("2.5.4", "pass", "fail"), ("3.3", "fail", "fail"),
        ("3.4", "fail", "pass"), ("3.7", "pass", "fail"), ("4.1.3", "pass", "fail"), ("4.1.4", "pass", "fail"),
        ("4.1.8", "pass", "fail"), ("4.1.13", "pass", "fail"), ("5.2.2", "fail", "fail"), ("5.3.1", "fail", "fail"),
        ("6.1", "fail", "fail"), ("4.1.1", "skipped", "skipped"),
    ])
    def test_verdicts(self, rid, official, ubuntu):
        assert run(OFFICIAL)[1][f"NGINX-{rid}"] == official
        assert run(UBUNTU)[1][f"NGINX-{rid}"] == ubuntu

    def test_evidence(self):
        assert evidence(UBUNTU, "NGINX-4.1.4").endswith("shop.example.com:443 (TLSv1 TLSv1.1 TLSv1.2 TLSv1.3)")
        assert evidence(UBUNTU, "NGINX-4.1.3") == "1 private keys; too open: /etc/nginx/ssl/shop.key (root:root 644)"
        assert evidence(UBUNTU, "NGINX-2.1.4") == "autoindex on at: /etc/nginx/sites-enabled/shop.conf:28"
        assert evidence(UBUNTU, "NGINX-2.4.2") == ("listeners whose default server answers unknown host names: "
                                                   "*:80 -> _:80, *:443 -> shop.example.com:443")
        assert "shop.example.com:443 (keepalive_timeout 75)" in evidence(UBUNTU, "NGINX-2.4.3")
        assert evidence(OFFICIAL, "NGINX-3.4") == "logrotate is not installed"
        assert evidence(OFFICIAL, "NGINX-4.1.8").endswith("no HTTPS servers")
        assert "location / (X-Real-IP not passed" in evidence(UBUNTU, "NGINX-3.7")

    def test_header_inheritance(self):
        # The shop server sets its own add_header: headers from http do not reach it.
        t = section(UBUNTU, "NGINX_T").replace("http {\n", "http {\n\tadd_header X-Content-Type-Options nosniff always;\n", 1)
        d = UBUNTU.replace(section(UBUNTU, "NGINX_T"), t)
        ev = evidence(d, "NGINX-5.3.1")
        assert "shop.example.com:443 (not set)" in ev and "_:80 (" not in ev

    def test_not_installed_and_broken_config(self):
        with pytest.raises(ValueError, match="not installed"):
            R.rules_for("===SECTION:NGINX_VERSION===\nNOT_INSTALLED")
        broken = UBUNTU.replace(section(UBUNTU, "NGINX_T"),
                                'nginx: [emerg] unknown directive "servr" in /etc/nginx/sites-enabled/shop.conf:5\n'
                                "nginx: configuration file /etc/nginx/nginx.conf test failed")
        with pytest.raises(ValueError, match="unknown directive"):
            R.rules_for(broken)


class TestPrivacy:
    def test_secrets_masked(self):
        assert "shop-internal-token" not in UBUNTU and 'proxy_set_header Authorization "***";' in UBUNTU
        text = ("fastcgi_param DB_PASSWORD hunter2;\n  proxy_set_header X-Api-Key 'k-123';\nsecure_link_secret s3cr3t;\n"
                "proxy_set_header Host $host;\nset $session_token abc;")
        out = redact(text)
        for secret in ("hunter2", "k-123", "s3cr3t", "abc"):
            assert secret not in out
        assert "proxy_set_header Host $host;" in out

    def test_mime_types_dropped(self):
        assert "vnd.ms-excel" not in UBUNTU and "(MIME type list omitted)" in UBUNTU
        assert slim("# configuration file /etc/nginx/mime.types:\ntypes {\n  text/html html;\n}\n"
                    "# configuration file /x:\nx;").splitlines()[-1] == "x;"

    def test_keys_and_shadow_not_read(self):
        assert "PRIVATE KEY" not in UBUNTU and re.search(r"^shadow=[!*]$", section(UBUNTU, "ACCOUNT"), re.M)
        assert "/etc/shadow" in second_pass(Config(section(UBUNTU, "NGINX_T")), "")["ACCOUNT"]
        assert "substr($2,1,1)" in second_pass(Config(section(UBUNTU, "NGINX_T")), "")["ACCOUNT"]


# ── the configuration editor ─────────────────────────────────────────────

class FakeNginx:
    """A host for the editor: nginx -T/-t/-v/-s and cat over in-memory files."""

    def __init__(self, files, version="1.24.0", reject=None):
        self.files, self.version, self.reject, self.ip = dict(files), version, reject, "10.0.0.9"
        self.reloads, self.commands = 0, []

    def _test(self):
        try:
            Config(dump_of(self.files))
        except ParseError as exc:
            return f"nginx: [emerg] {exc}\nnginx: configuration file /etc/nginx/nginx.conf test failed"
        if self.reject and any(self.reject in t for t in self.files.values()):
            return f'nginx: [emerg] unknown directive "{self.reject}"\nnginx: configuration file test failed'
        return "nginx: the configuration file syntax is ok\nnginx: configuration file test is successful"

    def run(self, script):
        self.commands.append(script)
        if script == "nginx -t 2>&1":
            out = self._test()
            return out if "successful" in out else "CMD_ERROR: exit 1: " + out.splitlines()[0]
        if script == "nginx -s reload 2>&1":
            self.reloads += 1
            return "(no output)"
        return self.execute(script)

    def execute(self, script):
        self.commands.append(script)
        if script == "nginx -T 2>&1":
            return dump_of(self.files)
        if script == "nginx -v 2>&1":
            return f"nginx version: nginx/{self.version}"
        if script.startswith("cat "):
            return self.files[shlex.split(script)[1]]
        if script.startswith("mkdir -p /var/backups/ngcorion-nginx/"):
            return "(ok)"
        raise AssertionError(f"unexpected command {script}")

    def write(self, path, content):
        self.files[path] = content


def edited(files, statement, **kw):
    host = FakeNginx(files, **kw)
    conn = NginxConnection(host, host.write)
    return host, conn, conn.execute(statement)


UB_FILES = {"/etc/nginx/nginx.conf": "user www-data;\nerror_log /var/log/nginx/error.log;\nevents {\n}\n\nhttp {\n"
                                     "\tkeepalive_timeout 65;\n\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n"
                                     "\tinclude /etc/nginx/sites-enabled/*;\n}\n",
            "/etc/nginx/sites-enabled/shop": "server {\n    listen 443 ssl;\n    server_name shop;\n"
                                             "    keepalive_timeout 75;\n    add_header X-Frame-Options SAMEORIGIN;\n"
                                             "    location / {\n        proxy_pass http://app;\n"
                                             "        proxy_set_header Host $host;\n    }\n}\n",
            "/etc/nginx/sites-enabled/default": "server {\n    listen 80 default_server;\n    server_name _;\n"
                                                "    root /var/www/html;\n}\n"}


class TestEditor:
    def test_set_replaces_lower_levels(self):
        host, _conn, out = edited(UB_FILES, "NGX:set http keepalive_timeout 10")
        main, shop = host.files["/etc/nginx/nginx.conf"], host.files["/etc/nginx/sites-enabled/shop"]
        assert "http {\n\tkeepalive_timeout 10;\n\t# disabled by ngcorion: keepalive_timeout 65;" in main
        assert "    # disabled by ngcorion: keepalive_timeout 75;" in shop
        assert "2 earlier setting(s) disabled" in out and "nginx reloaded" in out and host.reloads == 1
        assert any(c.startswith("mkdir -p /var/backups/ngcorion-nginx/") and "cp -p" in c for c in host.commands)
        # Again: nothing to change.
        host2, _c, out2 = edited(host.files, "NGX:set http keepalive_timeout 10")
        assert "already" in out2 and host2.files == host.files and host2.reloads == 0

    def test_top_only_keeps_site_values(self):
        files = dict(UB_FILES)
        files["/etc/nginx/sites-enabled/shop"] = files["/etc/nginx/sites-enabled/shop"].replace(
            "    location / {", "    client_max_body_size 50m;\n    location / {")
        host, _c, _o = edited(files, "NGX:set http client_max_body_size 10m --top-only")
        assert "client_max_body_size 50m;" in host.files["/etc/nginx/sites-enabled/shop"]
        assert "\tclient_max_body_size 10m;" in host.files["/etc/nginx/nginx.conf"]

    def test_array_reaches_blocks_with_their_own(self):
        host, _c, out = edited(UB_FILES, "NGX:array add_header X-Content-Type-Options nosniff always")
        assert "add_header X-Content-Type-Options nosniff always;" in host.files["/etc/nginx/nginx.conf"]
        shop = host.files["/etc/nginx/sites-enabled/shop"]
        assert shop.index("add_header X-Content-Type-Options nosniff always;") < shop.index("listen 443 ssl;")
        assert "in 2 block(s)" in out
        host, _c, _o = edited(UB_FILES, "NGX:array proxy_set_header X-Real-IP $remote_addr")
        assert "        proxy_set_header X-Real-IP $remote_addr;\n        proxy_pass" in \
            host.files["/etc/nginx/sites-enabled/shop"]

    def test_rollback_when_nginx_rejects(self):
        host, conn, _ = edited(UB_FILES, "NGX:set http server_tokens off")
        before = dict(host.files)
        host.reject = "bogus_directive"
        with pytest.raises(EditError, match="nginx -t rejected"):
            conn.execute("NGX:set http bogus_directive on")
        assert host.files == before

    def test_refuses_multiline_and_shared_lines(self):
        files = dict(UB_FILES)
        files["/etc/nginx/nginx.conf"] = files["/etc/nginx/nginx.conf"].replace(
            "\tkeepalive_timeout 65;", "\tkeepalive_timeout\n\t\t65;")
        host = FakeNginx(files)
        with pytest.raises(EditError, match="spans several lines"):
            NginxConnection(host, host.write).execute("NGX:set http keepalive_timeout 10")
        assert host.files == files
        files["/etc/nginx/nginx.conf"] = UB_FILES["/etc/nginx/nginx.conf"].replace(
            "\tkeepalive_timeout 65;", "\tkeepalive_timeout 65; sendfile on;")
        host = FakeNginx(files)
        with pytest.raises(EditError, match="shares its line"):
            NginxConnection(host, host.write).execute("NGX:set http keepalive_timeout 10")

    def test_run_reports_errors_as_cmd_error(self):
        host = FakeNginx({"/etc/nginx/nginx.conf": "events {}\n"})
        assert NginxConnection(host, host.write).run("NGX:set http server_tokens off").startswith(
            "CMD_ERROR: the configuration has no http block")

    def test_file_changed_since_load(self):
        host = FakeNginx(UB_FILES)
        conn = NginxConnection(host, host.write)
        real_execute = host.execute
        host.execute = lambda s: real_execute(s) + "\n# edited" if s.startswith("cat /etc/nginx/nginx.conf") else real_execute(s)
        with pytest.raises(EditError, match="changed since nginx loaded it"):
            conn.execute("NGX:set http server_tokens off")

    def test_catchall(self):
        host, _c, out = edited(UB_FILES, "NGX:catchall")
        main = host.files["/etc/nginx/nginx.conf"]
        assert "listen 80 default_server;" in main and "listen 443 ssl default_server;" in main
        assert "ssl_reject_handshake on;" in main and "return 444;" in main
        assert "    listen 80;\n" in host.files["/etc/nginx/sites-enabled/default"]
        assert "*:80" in out and "*:443" in out
        _h, _c, again = edited(host.files, "NGX:catchall")
        assert again.startswith("every listener already rejects")

    def test_error_level_http2_add(self):
        host, _c, _o = edited(UB_FILES, "NGX:error-level info")
        assert "error_log /var/log/nginx/error.log info;" in host.files["/etc/nginx/nginx.conf"]
        host, _c, _o = edited(UB_FILES, "NGX:http2", version="1.24.0")
        assert "listen 443 ssl http2;" in host.files["/etc/nginx/sites-enabled/shop"]
        host, _c, _o = edited(UB_FILES, "NGX:http2", version="1.27.5")
        assert "    http2 on;" in host.files["/etc/nginx/sites-enabled/shop"]
        host, _c, _o = edited(UB_FILES, "NGX:add limit_req_zone $binary_remote_addr zone=ngcorion_req:10m rate=5r/s "
                                        "--match=zone=ngcorion_req:")
        host2, _c, _o = edited(host.files, "NGX:add limit_req_zone $binary_remote_addr zone=ngcorion_req:10m rate=9r/s "
                                           "--match=zone=ngcorion_req:")
        main = host2.files["/etc/nginx/nginx.conf"]
        assert "rate=9r/s;" in main and "# disabled by ngcorion: limit_req_zone" in main

    def test_write_script_keeps_content_off_the_command_line(self):
        script = stdin_write_script("/etc/nginx/sites-enabled/shop")
        assert MARK in script and "proxy_pass" not in script
        sh = shutil.which("sh")
        target = Path(os.environ.get("TMPDIR", "/tmp")) / f"ngcorion-write-{os.getpid()}"
        target.write_text("old\n")
        subprocess.run([sh, "-c", stdin_write_script(str(target))], input=f"sudo-pw\n{MARK}\nnew line 1\nnew 2\n",
                       text=True, check=True)
        assert target.read_text() == "new line 1\nnew 2\n"
        target.unlink()


# ── templates ────────────────────────────────────────────────────────────

class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}
        auto = [cid for cid, t in TEMPLATES.templates.items() if not t.manual_only]
        assert len(auto) == 32
        for cid in auto:
            assert TEMPLATES.templates[cid].verify_statements == [f"NGX:check {cid}"]

    def test_parameters(self):
        for rid in ("2.1.3", "2.1.4", "2.3.2", "2.4.2", "2.5.2", "4.1.4", "4.1.8"):
            assert TEMPLATES.missing(f"NGINX-{rid}", {}) == ["CONFIRM"], rid
        assert TEMPLATES.missing("NGINX-5.3.2", {}) == ["CSP_POLICY", "CONFIRM"]
        assert TEMPLATES.missing("NGINX-5.2.5", {}) == ["REQ_RATE", "REQ_BURST"]
        for cid, t in TEMPLATES.templates.items():
            leftovers = {m for s in t.statements + t.verify_statements for m in PLACEHOLDER_RE.findall(s)}
            assert leftovers <= {"{" + p + "}" for p in t.parameters}, cid

    @pytest.mark.parametrize("cid, name, value", [
        ("NGINX-5.2.2", "MAX_BODY_SIZE", "10m; evil"), ("NGINX-5.2.2", "MAX_BODY_SIZE", "0"),
        ("NGINX-5.2.3", "HEADER_BUFFERS", "4 8k;"), ("NGINX-5.3.2", "CSP_POLICY", "default-src *"),
        ("NGINX-5.3.3", "REFERRER_POLICY", "unsafe-url"), ("NGINX-5.2.4", "CONN_PER_IP", "0"),
    ])
    def test_unsafe_values_rejected(self, cid, name, value):
        assert TEMPLATES.validate(cid, {name: value})

    def test_statements_parse(self):
        sh = [shutil.which("busybox"), "sh"] if shutil.which("busybox") else ["sh"]
        for cid in TEMPLATES.templates:
            for s in TEMPLATES.statements(cid, PARAMS):
                if s.startswith("NGX:"):
                    assert shlex.split(s[4:])[0] in ("set", "array", "comment", "add", "error-level", "catchall",
                                                     "http2", "csp"), s
                else:
                    assert subprocess.run(sh + ["-n", "-c", s]).returncode == 0, s
        for script in COMMANDS.values():
            assert subprocess.run(sh + ["-n", "-c", script]).returncode == 0, script


# ── the connector ────────────────────────────────────────────────────────

class _Runner:
    as_root = False

    def __init__(self, **kw):
        self.kw, self.ip, self.inputs, self.sudo_password = kw, kw["ip"], [], kw.get("sudo_password") or kw["password"]

    def connect(self):
        pass

    def send_command_with_status(self, command, use_sudo=False, timeout=60):
        return "", 0

    def run_with_input(self, command, data, timeout=120):
        self.inputs.append((command, data))
        return "", 0

    def disconnect(self):
        pass


def test_connector_writes_through_stdin(monkeypatch):
    import app.modules.linux.common.fast_ssh_runner as m
    made = []
    monkeypatch.setattr(m, "HardeningSSHRunner", lambda **kw: made.append(_Runner(**kw)) or made[-1])
    with NginxConnector().open("10.0.0.5", {"ssh_username": "ops", "ssh_password": "Ssh-Pass-1"}) as conn:
        assert isinstance(conn, NginxConnection)
        conn.write("/etc/nginx/nginx.conf", "user www-data;\nhttp {}\n")
    command, data = made[0].inputs[0]
    assert command.startswith("sudo -S -p '' sh -c ") and "www-data" not in command and "Ssh-Pass-1" not in command
    assert data == f"Ssh-Pass-1\n{MARK}\nuser www-data;\nhttp {{}}\n"
    with NginxConnector().open("10.0.0.5", {"ssh_username": "root", "ssh_password": "Root-1"}) as conn:
        conn.write("/etc/nginx/nginx.conf", "x;\n")
    command, data = made[1].inputs[0]
    assert command.startswith("sh -c ") and data == f"{MARK}\nx;\n"


# ── through the engine and the database ─────────────────────────────────

def fake_host(dump):
    sections = {name: section(dump, name) for name in re.findall(r"===SECTION:(\w+)===", dump)}
    commands = dict(COMMANDS)
    commands.update(second_pass(Config(sections["NGINX_T"]), sections["NGINX_VERSION"]))
    return FakeHost(commands, sections, TEMPLATES, ip="10.10.0.60")


@pytest.fixture
def ctx(monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="nginx-tester", email="nginx-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="Web Server (nginx test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="WEB02", asset_type_id=t.id, ip_address="10.10.0.60", os_name="Ubuntu 24.04")
    db.add(a)
    db.flush()
    host = install(monkeypatch, fake_host(UBUNTU), connector_key="ssh_nginx", password_field="ssh_password",
                   password="Ssh-Pass-1")
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a, host
    finally:
        db.close()
        trans.rollback()
        connection.close()


CREDS = {"ssh_username": "ops", "ssh_password": "Ssh-Pass-1"}


def test_audit_then_fix(ctx):
    db, user, asset, host = ctx
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
    assert session.status == "completed" and session.device_type == DeviceType.NGINX
    assert session.passed_checks == 9 and session.failed_checks == 28
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
        {"check_id": "NGINX-2.5.1", "parameters": {}}, {"check_id": "NGINX-4.1.4", "parameters": {"CONFIRM": "yes"}},
        {"check_id": "NGINX-5.2.2", "parameters": {"MAX_BODY_SIZE": "10m"}}, {"check_id": "NGINX-6.1", "parameters": {}}])
    assert out["successful"] == 3 and out["failed"] == 1
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["NGINX-2.5.1"] == rows["NGINX-4.1.4"] == rows["NGINX-5.2.2"] == CheckStatus.PASS
    assert rows["NGINX-6.1"] == CheckStatus.FAIL


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.benchmark.registry import spec_map
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    assert spec_map()["nginx"] is SPEC
    t = target_for_device_type("nginx")
    assert t.category == "web" and t.connects_via == "SSH"
    assert {f.name for f in get_family(DeviceType.NGINX).credential_fields} >= {"ssh_username", "sudo_password"}
    assert "nginx" in SUPPORTED_TECHNOLOGIES and REQUIRED_PARAMS["nginx"] == {"ssh_username", "ssh_password"}

    def asset(name, os_name, type_name="Server"):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("lb01", "Ubuntu 24.04", "NGINX Reverse Proxy")) == "nginx"
    assert infer_device_family(asset("web01", "Ubuntu 24.04", "Apache Web Server")) == "apache"
    assert family_matches("linux", "nginx")  # a Linux host may run nginx


# ── live: a real nginx in a container ───────────────────────────────────

CONTAINER = os.environ.get("NGCORION_NGINX_CONTAINER")


@contextmanager
def live_connection():
    from test_mysql import DockerShell
    shell = DockerShell(CONTAINER)

    def write(path, content):
        out, rc = shell._runner.run_with_input(stdin_write_script(path), f"{MARK}\n{content}")
        if rc:
            raise RuntimeError(out)
    yield NginxConnection(shell, write)


@pytest.mark.skipif(not CONTAINER, reason="set NGCORION_NGINX_CONTAINER to an nginx container to run")
class TestLive:
    def test_collect_fix_and_rollback(self):
        with live_connection() as conn:
            before = run(collect(conn))[1]
            results = {cid: run_template(SPEC, conn, cid, PARAMS) for cid, t in TEMPLATES.templates.items()
                       if not t.manual_only}
            failed = {cid: r["error_message"] for cid, r in results.items() if not r["success"]}
            # logrotate is missing from minimal images: that fix refuses.
            assert set(failed) <= {"NGINX-3.4"}, failed
            after = run(collect(conn))[1]
            assert all(after[cid] == "pass" for cid in results if cid not in failed)
            assert before != after
            config = split_dump(conn.execute("nginx -T 2>&1"))
            with pytest.raises(EditError, match="nginx -t rejected"):
                conn.execute("NGX:set http ngcorion_no_such_directive on")
            assert split_dump(conn.execute("nginx -T 2>&1")) == config
