"""
MySQL 8 module (CIS Oracle MySQL Community Server 8.0).

The rules run on output captured from a real MySQL 8.0.46 server (the
official image, tests/mock_data/mysql/mysql8_0_46_dump.txt) with typical
problems added: an application account with ALL ON *.* from '%', a
replication account from '%', a test schema, an anonymous account,
local_infile on, a backup password in an option file and a
.mysql_history file. Also: the password channel to the mysql client, the
tolerated-error SQL prefix, the connector's login probe, and the audit ->
fix flow through the engine against a simulated host.

TestLive runs collection and fixes against a real MySQL container and is
skipped unless NGCORION_MYSQL_CONTAINER names one (root password in
NGCORION_MYSQL_ROOT_PASSWORD).
"""
import json
import os
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
from app.modules.benchmark import connectors
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.connectors import MySQLConnection, mysql_client_script, split_sql
from app.modules.benchmark.hardening_service import BenchmarkHardeningService, run_template
from app.modules.benchmark.rules import assemble, evaluate, section
from app.modules.benchmark.templates import PLACEHOLDER_RE
from app.modules.mysql import rules as R
from app.modules.mysql.collect import collect, mysql_commands, redact_option_files
from app.modules.mysql.hardening import TEMPLATES
from app.modules.mysql.spec import SPEC

sys.path.insert(0, str(Path(__file__).parent))
from benchmark_fakes import FakeHost, install  # noqa: E402

DUMP = (Path(__file__).parent / "mock_data" / "mysql" / "mysql8_0_46_dump.txt").read_text()


def sections(dump=DUMP):
    out, name = {}, None
    for line in dump.split("\n"):
        if line.startswith("===SECTION:") and line.endswith("==="):
            name = line[11:-3]
            out[name] = []
        elif name:
            out[name].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def changed(**new):
    s = sections()
    s.update({k: v if isinstance(v, str) else json.dumps(v) for k, v in new.items()})
    return assemble(s)


def run(dump=DUMP):
    report = evaluate(dump, R.rules_for(dump), R.JSON_SECTIONS)
    return report, {f["id"]: f["status"] for f in report["findings"]}


def evidence(dump, rid):
    return next(f["evidence"] for f in run(dump)[0]["findings"] if f["id"] == rid)


def mysql_vars(**fields):
    v = json.loads(sections()["MYSQL_VARS"])
    v.update(fields)
    return v


class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 74
        assert sum(r.manual for r in rules) == 21

    def test_real_capture(self):
        report, _ = run()
        assert report["summary"]["error_checks"] == 0
        assert (report["summary"]["passed_scored"], report["summary"]["failed_scored"]) == (26, 27)
        assert R.describe(DUMP) == "MySQL 8.0.46, 9 accounts, 2 application schemas"

    @pytest.mark.parametrize("rid, expected", [
        ("MYSQL-1.1", "pass"), ("MYSQL-1.2", "pass"), ("MYSQL-1.3", "fail"), ("MYSQL-1.5", "fail"),
        ("MYSQL-2.1.5", "pass"), ("MYSQL-2.6", "fail"), ("MYSQL-3.1", "fail"), ("MYSQL-3.2", "pass"),
        ("MYSQL-3.7", "fail"), ("MYSQL-3.8", "fail"), ("MYSQL-4.2", "fail"), ("MYSQL-4.4", "fail"),
        ("MYSQL-4.6", "pass"), ("MYSQL-4.8", "pass"), ("MYSQL-4.9", "fail"), ("MYSQL-5.1", "fail"),
        ("MYSQL-5.2", "fail"), ("MYSQL-7.1", "pass"), ("MYSQL-7.2", "fail"), ("MYSQL-7.3", "fail"),
        ("MYSQL-7.6", "fail"), ("MYSQL-7.7", "fail"), ("MYSQL-8.1", "fail"), ("MYSQL-8.4", "pass"),
        ("MYSQL-9.2", "pass"), ("MYSQL-9.4", "pass"), ("MYSQL-9.5", "fail"),
    ])
    def test_verdicts(self, rid, expected):
        assert run()[1][rid] == expected

    def test_local_root_is_administrative(self):
        ev = evidence(DUMP, "MYSQL-5.2")
        assert "'shop_app'@'%'" in ev and "'root'@'%'" in ev and "'root'@'localhost'" not in ev

    def test_replication_accounts(self):
        ev = evidence(DUMP, "MYSQL-9.5")
        assert "'repl'@'%'" in ev and "shop_app" not in ev and "'root'@'%'" not in ev

    def test_password_in_option_file_is_found_but_not_kept(self):
        assert "backup.cnf" in evidence(DUMP, "MYSQL-7.2")
        assert "Backup-Secret-9" not in DUMP and "password=***" in DUMP

    def test_tls_and_password_policy(self):
        _, st = run(changed(MYSQL_VARS=mysql_vars(tls_version="TLSv1.1,TLSv1.2", require_secure_transport="ON")))
        assert st["MYSQL-8.4"] == "fail" and st["MYSQL-8.1"] == "pass"
        v = mysql_vars(**{"validate_password.length": "14", "validate_password.mixed_case_count": "1",
                          "validate_password.number_count": "1", "validate_password.special_char_count": "1",
                          "validate_password.policy": "MEDIUM"})
        assert run(changed(MYSQL_VARS=v))[1]["MYSQL-7.5"] == "pass"

    def test_startup_options(self):
        d = changed(MYSQLD_PROC="mysql|/usr/sbin/mysqld --skip-grant-tables --allow-suspicious-udfs\nEND")
        _, st = run(d)
        assert st["MYSQL-4.5"] == st["MYSQL-4.3"] == "fail"
        d = changed(MYSQLD_PROC="root|/usr/sbin/mysqld\nEND")
        assert run(d)[1]["MYSQL-1.2"] == "fail"

    def test_replica_without_certificate_check(self):
        d = changed(MYSQL_REPLICATION=[{"channel": "", "host": "10.0.0.5", "user": "repl", "ssl_allowed": "YES",
                                        "ssl_verify_server_cert": "NO"}])
        assert run(d)[1]["MYSQL-9.2"] == "fail"

    def test_not_mysql_8(self):
        with pytest.raises(ValueError, match="MySQL 8"):
            R.rules_for(changed(MYSQL_VERSION="5.7.44"))
        with pytest.raises(ValueError, match="could not be queried"):
            R.rules_for(changed(MYSQL_VERSION="CMD_ERROR: exit 1: ERROR 1045 (28000): Access denied"))


class TestPrivacy:
    def test_no_password_or_hash_is_stored(self):
        for secret in ("App-Pass-1", "Rep-Pass-1", "Repl-Pass-1", "Root-Pass-1", "Backup-Secret-9", "$A$005$"):
            assert secret not in DUMP

    def test_collection_never_selects_password_hashes(self):
        sql = " ".join(mysql_commands().values())
        assert "authentication_string <> ''" in sql
        assert "'authentication_string', authentication_string" not in sql

    def test_redact_option_files(self):
        text = "[client]\nuser=a\npassword = s3cr3t\nssl-key-password=k3y\n[mysqld]\npassword=\n"
        out = redact_option_files(text)
        assert "s3cr3t" not in out and "k3y" not in out and "password = ***" in out and "password=\n" in out


class TestPasswordChannel:
    @pytest.mark.parametrize("pw", ['plain', 'a\\b"c', "x'y", "both\"'q", "sp ace $HOME `id`"])
    def test_password_never_in_the_script(self, pw):
        script, data = mysql_client_script("SELECT 1", "audit", 3306, pw)
        assert pw not in script and data.endswith("\n")
        assert ("MYSQL_PWD" in script) == ('"' in pw and "'" in pw)

    def test_user_and_sql_are_quoted(self):
        script, _ = mysql_client_script("SELECT 'x'; DROP TABLE t", "o'brien", 3307, "pw")
        assert "-P 3307" in script and "'o'\"'\"'brien'" in script

    def test_tolerated_error_codes(self):
        assert split_sql("SQL:SELECT 1") == ("SELECT 1", ())
        assert split_sql("SQL[ok=3529,1007]:INSTALL X") == ("INSTALL X", ("3529", "1007"))
        assert split_sql("echo hi") == (None, ())

    def _conn(self, outputs):
        class Runner:
            def run_with_input(self, command, data, timeout=120):
                assert "Secret" not in command
                return outputs.pop(0)

        class Shell:
            ip, _runner = "10.0.0.7", Runner()
        return MySQLConnection(Shell(), "root", 3306, "Secret-1")

    def test_tolerated_error_passes_others_raise(self):
        conn = self._conn([("ERROR 3529 (HY000) at line 1: Cannot load component", 1),
                           ("ERROR 1045 (28000): Access denied", 1)])
        assert "tolerated" in conn.execute("SQL[ok=3529]:INSTALL COMPONENT 'x'")
        with pytest.raises(RuntimeError, match="Access denied"):
            conn.execute("SQL[ok=3529]:SELECT 1")

    def test_login_probe(self, monkeypatch):
        replies = []

        @contextmanager
        def fake_ssh_open(self, ip, creds):
            class Runner:
                def run_with_input(self, command, data, timeout=120):
                    return replies.pop(0)

            class Shell:
                _runner = Runner()
            Shell.ip = ip
            yield Shell()
        monkeypatch.setattr(connectors.SSHConnector, "open", fake_ssh_open)
        creds = {"ssh_username": "u", "ssh_password": "p", "mysql_password": "m"}
        c = connectors.get_connector("ssh_mysql")
        replies.append(("ERROR 1045 (28000): Access denied for user 'root'@'127.0.0.1'", 1))
        with pytest.raises(PermissionError, match="MySQL login rejected"):
            with c.open("10.0.0.7", creds):
                pass
        replies.append(("sh: 1: mysql: not found", 127))
        with pytest.raises(ConnectionError, match="not installed"):
            with c.open("10.0.0.7", creds):
                pass
        replies.append(("1\n", 0))
        with c.open("10.0.0.7", creds) as conn:
            assert isinstance(conn, MySQLConnection)
        with pytest.raises(PermissionError, match="line break"):
            with c.open("10.0.0.7", dict(creds, mysql_password="a\nb")):
                pass


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}
        assert len([t for t in TEMPLATES.templates.values() if not t.manual_only]) == 23

    def test_parameters(self):
        for rid in ("MYSQL-2.6", "MYSQL-4.2", "MYSQL-4.4", "MYSQL-4.9", "MYSQL-7.5", "MYSQL-7.7", "MYSQL-8.1",
                    "MYSQL-8.4", "MYSQL-1.5"):
            assert TEMPLATES.missing(rid, {}) == ["CONFIRM"], rid
        assert TEMPLATES.missing("MYSQL-8.3", {}) == ["MAX_USER_CONN"]
        for cid, t in TEMPLATES.templates.items():
            leftovers = {m for s in t.statements + t.verify_statements for m in PLACEHOLDER_RE.findall(s)}
            assert leftovers <= {"{" + p + "}" for p in t.parameters}, cid

    def test_settings_use_set_persist(self):
        for rid in ("MYSQL-2.6", "MYSQL-4.4", "MYSQL-6.3", "MYSQL-7.4", "MYSQL-8.1", "MYSQL-8.4"):
            assert "SET PERSIST" in TEMPLATES.templates[rid].statements[0]


@pytest.fixture
def ctx(monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="mysql-tester", email="mysql-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="MySQL Server (test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="DB01", asset_type_id=t.id, ip_address="10.10.0.33", os_name="Oracle Linux 9")
    db.add(a)
    db.flush()
    host = install(monkeypatch, FakeHost(mysql_commands(), sections(), TEMPLATES, ip=a.ip_address),
                   connector_key="ssh_mysql", password_field="mysql_password", password="Db-Pass-1")
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a, host
    finally:
        db.close()
        trans.rollback()
        connection.close()


CREDS = {"ssh_username": "dba", "ssh_password": "Ssh-Pass-1", "mysql_username": "root", "mysql_password": "Db-Pass-1"}


def test_audit_then_fix(ctx):
    db, user, asset, host = ctx
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
    assert session.status == "completed" and session.device_type == DeviceType.MYSQL
    assert session.passed_checks == 26 and session.failed_checks == 27
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
        {"check_id": "MYSQL-4.4", "parameters": {"CONFIRM": "yes"}}, {"check_id": "MYSQL-3.1", "parameters": {}},
        {"check_id": "MYSQL-8.3", "parameters": {"MAX_USER_CONN": "200"}}, {"check_id": "MYSQL-7.6", "parameters": {}}])
    assert out["successful"] == 3 and out["failed"] == 1
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["MYSQL-4.4"] == rows["MYSQL-3.1"] == rows["MYSQL-8.3"] == CheckStatus.PASS
    assert rows["MYSQL-7.6"] == CheckStatus.FAIL


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    t = target_for_device_type("mysql")
    assert t.category == "databases" and t.connects_via == "SSH + MySQL login"
    fam = get_family(DeviceType.MYSQL)
    assert {f.name for f in fam.credential_fields} >= {"ssh_username", "sudo_password", "mysql_username", "mysql_password"}
    assert "mysql" in SUPPORTED_TECHNOLOGIES and REQUIRED_PARAMS["mysql"] == {"ssh_username", "ssh_password", "mysql_password"}

    def asset(name, os_name, type_name):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("db01", "Ubuntu 24.04", "MySQL Server")) == "mysql"
    assert infer_device_family(asset("sql01", "Windows Server 2022", "SQL Server")) == "mssql"
    assert family_matches("linux", "mysql")  # a Linux host may run MySQL


# ── live: a real MySQL server in a container ────────────────────────────

CONTAINER = os.environ.get("NGCORION_MYSQL_CONTAINER")


class _DockerRunner:
    def __init__(self, c):
        self.c, self.ip = c, c

    def run_with_input(self, command, data, timeout=120):
        p = subprocess.run(["docker", "exec", "-i", self.c, "sh", "-c", command], input=data, capture_output=True,
                           text=True, timeout=timeout)
        return p.stdout + (("\n" + p.stderr) if p.stderr.strip() else ""), p.returncode


class DockerShell:
    """The SSH connection's contract, run in the container as root."""

    def __init__(self, c):
        self.ip, self._runner = c, _DockerRunner(c)

    def run(self, script):
        out, rc = self._runner.run_with_input(script, "")
        if rc:
            return f"CMD_ERROR: exit {rc}: {out.strip().splitlines()[-1] if out.strip() else ''}"
        return out if out.strip() else "(no output)"

    def execute(self, script):
        out, rc = self._runner.run_with_input(script, "")
        if rc:
            raise RuntimeError(out.strip().splitlines()[-1] if out.strip() else f"exit {rc}")
        return out if out.strip() else "(ok)"


def live_connection():
    return MySQLConnection(DockerShell(CONTAINER), "root", 3306, os.environ.get("NGCORION_MYSQL_ROOT_PASSWORD", ""))


@pytest.mark.skipif(not CONTAINER, reason="set NGCORION_MYSQL_CONTAINER to a MySQL 8 container to run")
class TestLive:
    def test_collect_and_fix(self):
        conn = live_connection()
        dump = collect(conn)
        report, st = run(dump)
        assert report["summary"]["error_checks"] == 0
        before = conn.run("SQL:SELECT @@global.log_error_verbosity").strip()
        try:
            conn.execute("SQL:SET PERSIST log_error_verbosity = 3")
            assert run_template(SPEC, conn, "MYSQL-6.3", {})["success"]
            assert conn.run("SQL:SELECT @@global.log_error_verbosity").strip() == "2"
            assert run_template(SPEC, conn, "MYSQL-7.5", {"CONFIRM": "yes"})["success"]
            # Idempotent: the component is already installed the second time.
            assert run_template(SPEC, conn, "MYSQL-7.5", {"CONFIRM": "yes"})["success"]
        finally:
            conn.execute(f"SQL:SET PERSIST log_error_verbosity = {before}")
