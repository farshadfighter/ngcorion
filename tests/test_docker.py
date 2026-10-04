"""
Docker module (CIS Docker Benchmark).

The rules run on output captured from a real Docker Engine 29.3.1 host
(Ubuntu 24.04, tests/mock_data/docker/docker29_ubuntu24_dump.txt) with two
containers: ngt-app started with the benchmark's runtime options and ngt-web
started privileged, root, with /etc mounted and a port on 0.0.0.0. Edge
cases change single sections of that capture. The SSH connector is tested
against a stub runner; the audit -> fix flow runs through the engine against
a simulated host.

TestLive runs the real collection and real fixes on the local Docker daemon
(as root, without SSH) and is skipped unless NGCORION_DOCKER_LIVE=1.
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset, AuditResult, User
from app.models.asset_types import AssetType
from app.models.audit import CheckStatus, DeviceType
from app.modules.benchmark import connectors
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.hardening_service import BenchmarkHardeningService, run_template
from app.modules.benchmark.rules import assemble, evaluate, section
from app.modules.benchmark.templates import PLACEHOLDER_RE
from app.modules.docker import rules as R
from app.modules.docker.collect import NO_DOCKER, collect, docker_commands, slim_containers
from app.modules.docker.hardening import TEMPLATES, daemon_json_edit
from app.modules.docker.spec import SPEC, redact

sys.path.insert(0, str(Path(__file__).parent))
from benchmark_fakes import FakeHost, install  # noqa: E402

DUMP = (Path(__file__).parent / "mock_data" / "docker" / "docker29_ubuntu24_dump.txt").read_text()


def sections(dump=DUMP):
    out, name = {}, None
    for line in dump.split("\n"):
        m = re.match(r"^===SECTION:(\w+)===$", line)
        if m:
            name = m.group(1)
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
    report, _ = run(dump)
    return next(f["evidence"] for f in report["findings"] if f["id"] == rid)


def containers():
    return json.loads(sections()["CONTAINERS"])


def info(**fields):
    data = json.loads(sections()["DOCKER_INFO"])
    data.update(fields)
    return data


class TestRules:
    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 108
        assert sum(r.manual for r in rules) == 22
        assert all(r.source == "CIS" for r in rules)
        counts = {}
        for r in rules:
            counts[r.section.split(".")[0]] = counts.get(r.section.split(".")[0], 0) + 1
        assert counts == {"1": 20, "2": 18, "3": 24, "4": 12, "5": 32, "6": 2}

    def test_real_capture_evaluates_without_errors(self):
        report, st = run()
        assert report["summary"]["error_checks"] == 0
        assert report["summary"]["passed_scored"] == 55 and report["summary"]["failed_scored"] == 31

    @pytest.mark.parametrize("rid, expected", [
        ("DKR-1.1.1", "pass"), ("DKR-1.1.3", "fail"), ("DKR-1.1.8", "pass"), ("DKR-2.2", "fail"),
        ("DKR-2.3", "pass"), ("DKR-2.5", "pass"), ("DKR-2.7", "pass"), ("DKR-2.9", "fail"), ("DKR-2.15", "fail"),
        ("DKR-2.16", "fail"), ("DKR-3.2", "pass"), ("DKR-3.15", "pass"), ("DKR-3.16", "pass"), ("DKR-4.1", "fail"),
        ("DKR-4.5", "fail"), ("DKR-4.6", "fail"), ("DKR-4.9", "pass"), ("DKR-5.1", "pass"), ("DKR-5.4", "pass"),
        ("DKR-5.5", "fail"), ("DKR-5.6", "fail"), ("DKR-5.13", "fail"), ("DKR-5.14", "fail"), ("DKR-5.15", "pass"),
        ("DKR-5.26", "fail"), ("DKR-5.30", "fail"), ("DKR-5.32", "pass"), ("DKR-6.1", "skipped"),
    ])
    def test_real_capture_verdicts(self, rid, expected):
        assert run()[1][rid] == expected

    def test_only_the_insecure_container_is_named(self):
        for rid in ("DKR-5.5", "DKR-5.6", "DKR-5.11", "DKR-5.13", "DKR-5.26", "DKR-5.29"):
            ev = evidence(DUMP, rid)
            assert "ngt-web" in ev and "ngt-app" not in ev, rid

    def test_no_running_containers(self):
        _, st = run(changed(CONTAINERS="[]", CONTAINER_PROCS="NONE"))
        runtime = [r.id for r in R.all_rules() if r.section.startswith("5.") and not r.manual and r.id != "DKR-5.1"]
        assert all(st[rid] == "pass" for rid in runtime)

    def test_docker_missing_is_refused(self):
        with pytest.raises(ValueError, match="Docker is not installed"):
            R.rules_for(assemble({"DOCKER_VERSION": NO_DOCKER}))

    def test_daemon_down_is_refused(self):
        with pytest.raises(ValueError, match="not running"):
            R.rules_for(changed(DOCKER_VERSION="CMD_ERROR: exit 1: Cannot connect to the Docker daemon"))

    def test_icc_configured_but_not_in_effect(self):
        d = changed(DAEMON_JSON={"icc": False})
        assert run(d)[1]["DKR-2.2"] == "fail" and "not yet in effect" in evidence(d, "DKR-2.2")
        nets = sections()["NETWORKS"].replace('enable_icc":"true"', 'enable_icc":"false"')
        assert run(changed(NETWORKS=nets))[1]["DKR-2.2"] == "pass"

    def test_tcp_listener_needs_tls(self):
        d = changed(DOCKERD_ARGS="/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375")
        assert run(d)[1]["DKR-2.7"] == "fail"
        d = changed(DOCKERD_ARGS="/usr/bin/dockerd -H tcp://0.0.0.0:2376 --tlsverify --tlscacert=/etc/docker/ca.pem "
                                 "--tlscert=/etc/docker/cert.pem --tlskey=/etc/docker/key.pem")
        assert run(d)[1]["DKR-2.7"] == "pass"

    def test_setting_from_the_command_line(self):
        d = changed(DOCKERD_ARGS="/usr/bin/dockerd --userland-proxy=false --no-new-privileges")
        _, st = run(d)
        assert st["DKR-2.16"] == "pass" and st["DKR-2.14"] == "pass" and st["DKR-5.26"] == "pass"

    def test_insecure_registry_from_docker_info(self):
        reg = info()["RegistryConfig"]
        reg["InsecureRegistryCIDRs"] = ["127.0.0.0/8", "10.0.0.0/8"]
        assert run(changed(DOCKER_INFO=info(RegistryConfig=reg)))[1]["DKR-2.5"] == "fail"

    def test_audit_rules(self):
        rules = ("-w /usr/bin/dockerd -p rwxa -k docker\n"
                 "-a always,exit -F path=/usr/bin/runc -F perm=rwxa -F key=docker\n"
                 "-w /var/lib/docker -p rwxa -k docker")
        _, st = run(changed(AUDIT_RULES=rules))
        assert st["DKR-1.1.3"] == st["DKR-1.1.18"] == st["DKR-1.1.5"] == "pass"
        assert st["DKR-1.1.6"] == "fail"
        assert "auditd is not installed" in evidence(DUMP, "DKR-1.1.3")

    def test_file_modes(self):
        files = sections()["FILES"].replace("/var/run/docker.sock|root|docker|660", "/var/run/docker.sock|root|docker|666")
        assert run(changed(FILES=files))[1]["DKR-3.16"] == "fail"
        files = sections()["FILES"].replace("/var/run/docker.sock|root|docker|660", "/var/run/docker.sock|root|docker|600")
        assert run(changed(FILES=files))[1]["DKR-3.16"] == "pass"
        files = sections()["FILES"] + "\ntlskey|/etc/docker/key.pem|root|root|644|regular file"
        _, st = run(changed(FILES=files))
        assert st["DKR-3.13"] == "pass" and st["DKR-3.14"] == "fail"

    def test_sshd_in_a_container(self):
        procs = sections()["CONTAINER_PROCS"].replace("### d4c15d2fb28c\nsleep", "### d4c15d2fb28c\nsshd\nsleep")
        assert "ngt-web" in evidence(changed(CONTAINER_PROCS=procs), "DKR-5.7")

    def test_dangerous_capabilities(self):
        cs = containers()
        cs[0]["HostConfig"]["CapAdd"] = ["NET_BIND_SERVICE"]
        assert run(changed(CONTAINERS=cs))[1]["DKR-5.4"] == "pass"
        cs[0]["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
        assert run(changed(CONTAINERS=cs))[1]["DKR-5.4"] == "fail"

    def test_docker_socket_mount(self):
        cs = containers()
        cs[0]["Mounts"] = [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock",
                            "RW": True, "Propagation": "rprivate"}]
        assert run(changed(CONTAINERS=cs))[1]["DKR-5.32"] == "fail"

    def test_build_history_heuristics(self):
        assert not R._uses_add(["ADD file:4b03b5f551e3fbdf47ec609712007327828f7530cc3455c43bbcdcaf449a75a9 in / "])
        assert not R._uses_add(["ADD alpine-minirootfs-3.20.3-x86_64.tar.gz / # buildkit"])
        assert R._uses_add(["ADD https://example.com/app.tar.gz /opt/ # buildkit"])
        assert R._update_alone(["RUN /bin/sh -c apt-get update"])
        assert not R._update_alone(["RUN /bin/sh -c apt-get update && apt-get install -y curl"])

    def test_describe(self):
        assert R.describe(DUMP) == "Docker Engine 29.3.1 on Ubuntu 24.04.4 LTS, 2 running containers"


class TestPrivacy:
    def test_container_environment_is_not_kept(self):
        raw = json.dumps([{"Id": "abc", "Name": "/db", "Config": {"Image": "postgres:16", "User": "",
                           "Env": ["POSTGRES_PASSWORD=hunter2"], "Labels": {"secret": "x"}},
                           "HostConfig": {"Privileged": False}, "Mounts": [], "State": {},
                           "NetworkSettings": {"Ports": {}, "Networks": {"bridge": {}}}}])
        out = slim_containers(raw)
        assert "hunter2" not in out and "Env" not in out and json.loads(out)[0]["Image"] == "postgres:16"

    def test_redact(self):
        text = ("RUN |1 DB_PASSWORD=hunter2 /bin/sh -c ./setup\n"
                '"HttpProxy":"http://alice:s3cret@proxy.corp:3128"')
        out = redact(text)
        assert "hunter2" not in out and "s3cret" not in out and "DB_PASSWORD=***" in out

    def test_collection_never_runs_inside_containers(self):
        text = " ".join(docker_commands().values())
        assert "docker exec" not in text and "docker run" not in text


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}
        assert len([t for t in TEMPLATES.templates.values() if not t.manual_only]) == 50

    @pytest.mark.parametrize("rid", ["DKR-2.2", "DKR-2.4", "DKR-2.5", "DKR-2.9", "DKR-2.14", "DKR-4.5"])
    def test_disruptive_changes_need_confirmation(self, rid):
        assert TEMPLATES.missing(rid, {}) == ["CONFIRM"]

    def test_no_shell_text_reads_as_a_parameter(self):
        for cid, t in TEMPLATES.templates.items():
            assert not [m for s in t.statements + t.verify_statements for m in PLACEHOLDER_RE.findall(s)], cid

    def test_runtime_findings_are_guidance_only(self):
        assert all(TEMPLATES.templates[r.id].manual_only for r in R.all_rules() if r.section.startswith("5."))

    def test_daemon_json_edit_is_valid_python(self):
        stmt = daemon_json_edit({"icc": False}, remove=["debug"], flags=["icc"])
        code = stmt.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        compile(code, "daemon_json_edit", "exec")
        assert "--icc([= ]|$)" in stmt and "dockerd --validate" in stmt

    def test_live_restore_refuses_swarm(self):
        assert "swarm mode" in TEMPLATES.templates["DKR-2.15"].statements[0]

    def test_daemon_json_edit_on_a_local_file(self, tmp_path):
        """The merge itself, run with a real python3 on a copy of the file."""
        stmt = daemon_json_edit({"icc": False}, remove=["insecure-registries"])
        code = stmt.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        target = tmp_path / "daemon.json"
        target.write_text(json.dumps({"log-driver": "json-file", "insecure-registries": ["10.0.0.5:5000"]}))
        code = code.replace("/etc/docker/daemon.json", str(target))
        subprocess.run([sys.executable, "-c", code], check=True)
        merged = json.loads((tmp_path / "daemon.json.ngcorion-new").read_text())
        assert merged == {"log-driver": "json-file", "icc": False}


class _Runner:
    """Stub of HardeningSSHRunner: answers by command."""
    def __init__(self, sudo_ok=True, fail_connect=None):
        self.ip, self.sudo_ok, self.fail_connect, self.sent = "10.0.0.9", sudo_ok, fail_connect, []

    def connect(self):
        if self.fail_connect:
            raise self.fail_connect

    def disconnect(self):
        pass

    def send_command_with_status(self, command, use_sudo=False, timeout=30):
        self.sent.append(command)
        if command == "true":
            return ("", 0) if self.sudo_ok else ("Sorry, user bob is not in the sudoers file", 1)
        if "exit 3" in command:
            return ("boom: something failed", 3)
        return ("hello", 0)

    def run_with_status(self, command, timeout=30):
        self.sent.append(command)
        return ("root-out", 0)


class TestSSHConnector:
    CREDS = {"ssh_username": "bob", "ssh_password": "pw", "ssh_port": 22}

    def _open(self, monkeypatch, runner, creds=None):
        import app.modules.linux.common.fast_ssh_runner as fsr
        monkeypatch.setattr(fsr, "HardeningSSHRunner", lambda **kw: runner)
        return connectors.get_connector("ssh").open("10.0.0.9", creds or self.CREDS)

    def test_scripts_run_under_sudo(self, monkeypatch):
        runner = _Runner()
        with self._open(monkeypatch, runner) as conn:
            assert conn.run("echo hi") == "hello"
            assert conn.run("exit 3").startswith("CMD_ERROR: exit 3: boom")
            with pytest.raises(RuntimeError, match="boom"):
                conn.execute("exit 3")
        assert runner.sent[-1].startswith("sh -c ")

    def test_root_login_skips_sudo(self, monkeypatch):
        runner = _Runner(sudo_ok=False)
        with self._open(monkeypatch, runner, dict(self.CREDS, ssh_username="root")) as conn:
            assert conn.run("id") == "root-out"

    def test_sudo_refused(self, monkeypatch):
        with pytest.raises(PermissionError, match="sudo was refused"):
            with self._open(monkeypatch, _Runner(sudo_ok=False)):
                pass

    def test_connection_errors(self, monkeypatch):
        from app.core.ssh_exceptions import SSHAuthenticationError, SSHNetworkError
        with pytest.raises(PermissionError):
            with self._open(monkeypatch, _Runner(fail_connect=SSHAuthenticationError("10.0.0.9"))):
                pass
        with pytest.raises(ConnectionError):
            with self._open(monkeypatch, _Runner(fail_connect=SSHNetworkError("10.0.0.9"))):
                pass

    def test_fields(self):
        c = connectors.get_connector("ssh")
        assert set(c.request_fields) == {"ssh_username", "ssh_password", "ssh_port", "sudo_password"}
        assert c.required_for_schedule == {"ssh_username", "ssh_password"}


@pytest.fixture
def ctx(monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="docker-tester", email="docker-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="Docker Host (test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="DOCK01", asset_type_id=t.id, ip_address="10.10.0.20", os_name="Ubuntu 24.04")
    db.add(a)
    db.flush()
    host = install(monkeypatch, FakeHost(docker_commands(), sections(), TEMPLATES, ip=a.ip_address),
                   connector_key="ssh", password_field="ssh_password", password="Dock-Pass-1")
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a, host
    finally:
        db.close()
        trans.rollback()
        connection.close()


CREDS = {"ssh_username": "dockadmin", "ssh_password": "Dock-Pass-1", "ssh_port": 22}


def test_audit_then_fix(ctx):
    db, user, asset, host = ctx
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
    assert session.status == "completed" and session.device_type == DeviceType.DOCKER
    assert session.passed_checks == 55 and session.failed_checks == 31
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
        {"check_id": "DKR-2.15", "parameters": {}}, {"check_id": "DKR-2.16", "parameters": {}},
        {"check_id": "DKR-2.2", "parameters": {}}, {"check_id": "DKR-5.5", "parameters": {}}])
    assert out["successful"] == 2 and out["failed"] == 2
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["DKR-2.15"] == rows["DKR-2.16"] == CheckStatus.PASS
    assert rows["DKR-2.2"] == rows["DKR-5.5"] == CheckStatus.FAIL


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    t = target_for_device_type("docker")
    assert t.icon == "container" and t.category == "platforms" and t.connects_via == "SSH"
    fam = get_family(DeviceType.DOCKER)
    assert fam.capabilities.backup and {f.name for f in fam.credential_fields} >= {"ssh_username", "sudo_password"}
    assert "docker" in SUPPORTED_TECHNOLOGIES and REQUIRED_PARAMS["docker"] == {"ssh_username", "ssh_password"}

    def asset(name, os_name, type_name):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("dock01", "Ubuntu 24.04", "Docker Host")) == "docker"
    assert family_matches("docker", "linux") and family_matches("linux", "docker")
    assert not family_matches("windows", "docker")


# ── live: real Docker on this machine ───────────────────────────────────

LIVE = os.environ.get("NGCORION_DOCKER_LIVE") == "1"


class LocalConnection:
    """The SSH connection's contract, run locally as root."""
    ip = "127.0.0.1"

    def _x(self, script):
        p = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=120)
        return p.stdout + (("\n" + p.stderr) if p.stderr.strip() else ""), p.returncode

    def run(self, script):
        out, rc = self._x(script)
        if rc:
            return f"CMD_ERROR: exit {rc}: {out.strip().splitlines()[-1] if out.strip() else ''}"
        return out if out.strip() else "(no output)"

    def execute(self, script):
        out, rc = self._x(script)
        if rc:
            raise RuntimeError(out.strip().splitlines()[-1] if out.strip() else f"exit {rc}")
        return out if out.strip() else "(ok)"


@pytest.mark.skipif(not LIVE, reason="set NGCORION_DOCKER_LIVE=1 to run against the local Docker daemon (root)")
class TestLive:
    def test_collect_and_evaluate(self):
        dump = redact(collect(LocalConnection()))
        report, st = run(dump)
        assert report["summary"]["error_checks"] == 0
        assert section(dump, "DOCKER_INFO").startswith("{")
        assert "Env" not in section(dump, "CONTAINERS")

    def test_fixes_on_the_local_daemon(self, tmp_path):
        conn = LocalConnection()
        daemon_json = Path("/etc/docker/daemon.json")
        saved = daemon_json.read_text() if daemon_json.exists() else None
        default = Path("/etc/default/docker")
        mode = default.stat().st_mode & 0o7777 if default.exists() else None
        ct = Path("/etc/profile.d/docker-content-trust.sh")
        try:
            if default.exists():
                default.chmod(0o666)
            assert run_template(SPEC, conn, "DKR-2.18", {})["success"]
            assert run_template(SPEC, conn, "DKR-2.15", {})["success"]
            assert json.loads(daemon_json.read_text())["live-restore"] is True
            if default.exists():
                assert run_template(SPEC, conn, "DKR-3.20", {})["success"]
                assert default.stat().st_mode & 0o7777 == 0o644
            assert run_template(SPEC, conn, "DKR-4.5", {"CONFIRM": "yes"})["success"]
            assert run(redact(collect(conn)))[1]["DKR-2.15"] == "pass"
        finally:
            # A reload without the file keeps the reloaded values: put
            # live-restore back explicitly, reload, then restore the file.
            restored = json.loads(saved) if saved else {}
            restored.setdefault("live-restore", False)
            daemon_json.write_text(json.dumps(restored))
            subprocess.run("kill -HUP $(pidof dockerd); sleep 1", shell=True)
            if saved is None:
                daemon_json.unlink(missing_ok=True)
            else:
                daemon_json.write_text(saved)
            Path("/etc/docker/daemon.json.ngcorion-orig").unlink(missing_ok=True)
            if mode is not None:
                default.chmod(mode)
            ct.unlink(missing_ok=True)
