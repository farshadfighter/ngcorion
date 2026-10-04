"""
Kubernetes module (CIS Kubernetes Benchmark, kubeadm).

Node rules run on sections captured from a real kubeadm v1.32.2
control-plane node (kind); cluster rules (section 5) on kubectl JSON built in
tests/k8s_sample.py, passed through the module's own reduction. Also: the
text editors the fixes run on the node (manifest and kubelet config), the
fail-closed behaviour when kubectl cannot reach the API, and the audit ->
fix flow through the engine against a simulated host.

TestLive runs collection and fixes against a real kind node container and
is skipped unless NGCORION_K8S_NODE names one (e.g. ngk-control-plane).
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine as db_engine
from app.models import Asset, AuditResult, User
from app.models.asset_types import AssetType
from app.models.audit import CheckStatus, DeviceType
from app.modules.benchmark.audit_service import BenchmarkAuditService
from app.modules.benchmark.hardening_service import BenchmarkHardeningService, run_template
from app.modules.benchmark.rules import assemble, evaluate, section
from app.modules.benchmark.templates import PLACEHOLDER_RE
from app.modules.kubernetes import hardening as H
from app.modules.kubernetes import rules as R
from app.modules.kubernetes.collect import NO_KUBERNETES, collect, kubernetes_commands
from app.modules.kubernetes.hardening import TEMPLATES
from app.modules.kubernetes.spec import SPEC

sys.path.insert(0, str(Path(__file__).parent))
import k8s_sample as S  # noqa: E402
from benchmark_fakes import FakeHost, install  # noqa: E402


def run(dump):
    report = evaluate(dump, R.rules_for(dump), R.JSON_SECTIONS)
    return report, {f["id"]: f["status"] for f in report["findings"]}


def evidence(dump, rid):
    return next(f["evidence"] for f in run(dump)[0]["findings"] if f["id"] == rid)


DUMP = S.dump()


class TestNodeCapture:
    """The real kubeadm node, as captured (the API server was not running)."""

    def test_rule_set(self):
        rules = R.all_rules()
        assert len({r.id for r in rules}) == len(rules) == 130
        assert sum(r.manual for r in rules) == 15
        sections = [tuple(int(p) for p in r.section.split(".")) for r in rules]
        assert sections == sorted(sections)

    def test_cluster_checks_are_not_evaluated_without_the_api(self):
        report, st = run(S.NODE_DUMP)
        errors = [rid for rid, s in st.items() if s == "error"]
        assert errors and all(e.startswith(("K8S-5.", "K8S-4.3.1")) for e in errors)
        assert "connection" in evidence(S.NODE_DUMP, "K8S-5.1.1").lower()

    @pytest.mark.parametrize("rid, expected", [
        ("K8S-1.1.1", "pass"), ("K8S-1.1.12", "fail"), ("K8S-1.1.13", "pass"), ("K8S-1.1.20", "fail"),
        ("K8S-1.1.21", "pass"), ("K8S-1.2.1", "fail"), ("K8S-1.2.6", "pass"), ("K8S-1.2.8", "pass"),
        ("K8S-1.2.14", "pass"), ("K8S-1.2.15", "fail"), ("K8S-1.2.16", "fail"), ("K8S-1.2.21", "pass"),
        ("K8S-1.2.27", "fail"), ("K8S-1.3.3", "pass"), ("K8S-1.3.7", "pass"), ("K8S-1.4.1", "fail"),
        ("K8S-2.2", "pass"), ("K8S-2.5", "pass"), ("K8S-3.2.1", "fail"), ("K8S-4.1.1", "fail"),
        ("K8S-4.1.5", "pass"), ("K8S-4.1.9", "fail"), ("K8S-4.2.1", "pass"), ("K8S-4.2.2", "pass"),
        ("K8S-4.2.4", "pass"), ("K8S-4.2.5", "pass"), ("K8S-4.2.10", "pass"), ("K8S-4.2.13", "fail"),
    ])
    def test_verdicts(self, rid, expected):
        assert run(S.NODE_DUMP)[1][rid] == expected

    def test_settings_come_from_the_manifest_when_not_running(self):
        assert "static pod manifest" in evidence(S.NODE_DUMP, "K8S-1.2.15")
        assert R.describe(S.NODE_DUMP) == "Kubernetes v1.32.2 control-plane node ngk-control-plane"

    def test_running_process_wins_over_the_manifest(self):
        procs = section(S.NODE_DUMP, "PROCS").replace(
            "### kube-scheduler\n", "### kube-scheduler\n/usr/local/bin/kube-scheduler --profiling=false --bind-address=0.0.0.0\n")
        d = S.dump()
        d = d.replace(section(d, "PROCS"), procs)
        _, st = run(d)
        assert st["K8S-1.4.1"] == "pass" and st["K8S-1.4.2"] == "fail"

    def test_kubeadm_zero_idle_timeout_is_the_default(self):
        """kubeadm writes streamingConnectionIdleTimeout: 0s; the kubelet reads it as 4h."""
        assert "0s" in section(S.NODE_DUMP, "KUBELET_CONFIG")
        assert "default" in evidence(S.NODE_DUMP, "K8S-4.2.5")

    def test_worker_node_gets_node_and_cluster_rules(self):
        d = DUMP.replace("control_plane=yes", "control_plane=no")
        ids = {r.id for r in R.rules_for(d)}
        assert not any(i.startswith(("K8S-1.", "K8S-2.", "K8S-3.")) for i in ids)
        assert "K8S-4.2.1" in ids and "K8S-5.1.1" in ids

    def test_not_kubernetes_is_refused(self):
        with pytest.raises(ValueError, match="not installed"):
            R.rules_for(assemble({"NODE": NO_KUBERNETES}))


class TestCluster:
    @pytest.mark.parametrize("rid, expected", [
        ("K8S-4.3.1", "fail"), ("K8S-5.1.1", "fail"), ("K8S-5.1.2", "fail"), ("K8S-5.1.3", "fail"),
        ("K8S-5.1.5", "fail"), ("K8S-5.1.8", "pass"), ("K8S-5.1.10", "fail"), ("K8S-5.1.11", "pass"),
        ("K8S-5.1.12", "pass"), ("K8S-5.2.1", "pass"), ("K8S-5.2.2", "fail"), ("K8S-5.2.3", "fail"),
        ("K8S-5.2.4", "pass"), ("K8S-5.2.12", "fail"), ("K8S-5.2.13", "fail"), ("K8S-5.3.2", "fail"),
        ("K8S-5.4.1", "fail"), ("K8S-5.7.2", "fail"), ("K8S-5.7.4", "fail"),
    ])
    def test_verdicts(self, rid, expected):
        assert run(DUMP)[1][rid] == expected

    def test_default_admin_groups_are_not_findings(self):
        ev = evidence(DUMP, "K8S-5.1.1")
        assert "alice@corp.example.com" in ev and "system:masters" not in ev and "kubeadm:cluster-admins" not in ev

    def test_builtin_roles_are_not_findings(self):
        ev = evidence(DUMP, "K8S-5.1.2")
        assert "ci-deployer" in ev and "system:node" not in ev and "admin" not in ev.replace("ci-deployer", "")

    def test_kube_system_pods_are_left_out(self):
        assert "kube-apiserver" not in evidence(DUMP, "K8S-5.2.5")
        assert "monitoring/node-exporter" in evidence(DUMP, "K8S-5.2.5")

    def test_namespaces_with_network_policies(self):
        ev = evidence(DUMP, "K8S-5.3.2")
        assert "monitoring" in ev and "default" in ev and "shop" not in ev and "kube-system" not in ev

    def test_no_kube_proxy_is_not_a_finding(self):
        assert run(S.dump(K8S_PROXY_CONFIG="NONE"))[1]["K8S-4.3.1"] == "pass"

    def test_unreadable_kube_proxy_config_is_an_error(self):
        assert run(S.NODE_DUMP)[1]["K8S-4.3.1"] == "error"


class TestPrivacy:
    def test_secret_values_never_reach_the_dump(self):
        for value in ("tok-9f8e7d6c5b4a", "hunter2", "last-applied-configuration", "LOG_LEVEL"):
            assert value not in DUMP
        pods = json.loads(section(DUMP, "K8S_PODS"))
        debug = next(p for p in pods if p["name"] == "debug")
        assert debug["containers"][0]["secretEnv"] == ["DB_PASSWORD"]
        assert debug["containers"][0]["secretEnvFrom"] == ["legacy-creds"]

    def test_secrets_are_never_listed(self):
        text = " ".join(kubernetes_commands().values())
        assert not re.search(r"get[^|;]*\bsecrets?\b", text)

    def test_encryption_keys_never_leave_the_node(self):
        assert "grep -oE" in kubernetes_commands()["ENCRYPTION"]


class TestTemplates:
    def test_every_rule_has_a_template(self):
        assert set(TEMPLATES.templates) == {r.id for r in R.all_rules()}
        assert len([t for t in TEMPLATES.templates.values() if not t.manual_only]) == 49

    def test_parameters(self):
        assert TEMPLATES.missing("K8S-1.2.11", {}) == ["CONFIRM"]
        assert TEMPLATES.missing("K8S-1.3.1", {}) == ["GC_THRESHOLD"]
        assert TEMPLATES.missing("K8S-4.2.13", {}) == ["PIDS_LIMIT"]
        assert TEMPLATES.missing("K8S-5.1.5", {}) == ["CONFIRM"]
        for cid, t in TEMPLATES.templates.items():
            leftovers = {m for s in t.statements + t.verify_statements for m in PLACEHOLDER_RE.findall(s)}
            assert leftovers <= {"{" + p + "}" for p in t.parameters}, cid

    def test_manifest_backups_stay_out_of_the_manifest_directory(self):
        assert "/etc/kubernetes/ngcorion-backup" in H.MANIFEST_EDIT
        assert "manifests" not in H.MANIFEST_EDIT

    def _apiserver_manifest(self, tmp_path):
        text = section(S.NODE_DUMP, "MANIFESTS").split("### kube-apiserver\n", 1)[1].split("\n### ", 1)[0]
        path = tmp_path / "kube-apiserver.yaml"
        path.write_text(text)
        return path

    def _edit(self, tmp_path, path, *argv):
        code = H.MANIFEST_EDIT.replace("/etc/kubernetes/ngcorion-backup", str(tmp_path / "backup"))
        subprocess.run([sys.executable, "-c", code, str(path), "kube-apiserver", *argv], check=True)
        return R.yaml.safe_load(path.read_text())["spec"]["containers"][0]["command"]

    def test_manifest_edit_on_the_real_manifest(self, tmp_path):
        path = self._apiserver_manifest(tmp_path)
        cmd = self._edit(tmp_path, path, "profiling", "set", "false")
        assert "--profiling=false" in cmd and cmd[0] == "kube-apiserver"
        cmd = self._edit(tmp_path, path, "enable-admission-plugins", "add", "AlwaysPullImages")
        assert "--enable-admission-plugins=NodeRestriction,AlwaysPullImages" in cmd
        cmd = self._edit(tmp_path, path, "enable-admission-plugins", "remove", "NodeRestriction")
        assert "--enable-admission-plugins=AlwaysPullImages" in cmd
        cmd = self._edit(tmp_path, path, "enable-admission-plugins", "remove", "AlwaysPullImages")
        assert not [c for c in cmd if c.startswith("--enable-admission-plugins")]
        backups = sorted(p.name for p in (tmp_path / "backup").iterdir())
        assert len(backups) == 5 and "kube-apiserver.yaml.orig" in backups

    def test_kubelet_config_edit(self, tmp_path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(section(S.NODE_DUMP, "KUBELET_CONFIG").split("\n", 1)[1])
        for key, value in (("readOnlyPort", "0"), ("podPidsLimit", "4096"), ("readOnlyPort", "0")):
            subprocess.run([sys.executable, "-c", H.KUBELET_EDIT, str(cfg), key, value], check=True)
        data = R.yaml.safe_load(cfg.read_text())
        assert data["podPidsLimit"] == 4096 and data["readOnlyPort"] == 0
        assert data["authentication"]["anonymous"]["enabled"] is False
        assert cfg.read_text().count("readOnlyPort:") == 1
        assert (tmp_path / "config.yaml.ngcorion-orig").exists()

    def test_default_service_account_fix_fails_closed(self, tmp_path):
        """With the API unreachable, the verification must print FAIL, never PASS."""
        fake = tmp_path / "kubectl"
        fake.write_text("#!/bin/sh\necho 'connection refused' >&2\nexit 1\n")
        fake.chmod(0o755)
        env = dict(os.environ, PATH=f"{tmp_path}:{os.environ['PATH']}")
        verify = TEMPLATES.templates["K8S-5.1.5"].verify_statements[0]
        out = subprocess.run(["sh", "-c", verify], capture_output=True, text=True, env=env).stdout
        assert out.strip() == "FAIL"


class TestEngine:
    def test_failed_statement_is_never_a_success(self):
        """A fix whose statement failed is not applied, even if verification reads PASS."""
        class Conn:
            def execute(self, script):
                if "PASS" in script:
                    return "PASS"
                raise RuntimeError("--icc is set on the dockerd command line")
        from app.modules.docker.spec import SPEC as DOCKER
        r = run_template(DOCKER, Conn(), "DKR-2.16", {})
        assert r["success"] is False and "command line" in r["error_message"]


@pytest.fixture
def ctx(monkeypatch):
    connection = db_engine.connect()
    trans = connection.begin()
    db = Session(bind=connection, join_transaction_mode="create_savepoint")
    u = User(username="k8s-tester", email="k8s-tester@example.com", hashed_password="x", role="admin")
    t = AssetType(type_name="Kubernetes Node (test)", category="server")
    db.add_all([u, t])
    db.flush()
    a = Asset(asset_name="K8S-CP1", asset_type_id=t.id, ip_address="10.10.0.30", os_name="Ubuntu 24.04")
    db.add(a)
    db.flush()
    host = install(monkeypatch, FakeHost(kubernetes_commands(), S.sections(), TEMPLATES, ip=a.ip_address),
                   connector_key="ssh", password_field="ssh_password", password="K8s-Pass-1")
    monkeypatch.setattr(SPEC, "save_software", None)
    try:
        yield db, u, a, host
    finally:
        db.close()
        trans.rollback()
        connection.close()


CREDS = {"ssh_username": "k8sadmin", "ssh_password": "K8s-Pass-1", "ssh_port": 22}


def test_audit_then_fix(ctx):
    db, user, asset, host = ctx
    session = BenchmarkAuditService(SPEC).execute(db, asset.id, user.id, dict(CREDS))
    assert session.status == "completed" and session.device_type == DeviceType.KUBERNETES
    assert session.error_checks == 0
    out = BenchmarkHardeningService(SPEC).batch_execute_selected(db, session.id, asset.id, dict(CREDS), [
        {"check_id": "K8S-1.2.15", "parameters": {}}, {"check_id": "K8S-4.1.9", "parameters": {}},
        {"check_id": "K8S-4.2.13", "parameters": {"PIDS_LIMIT": "4096"}}, {"check_id": "K8S-1.3.1", "parameters": {}}])
    assert out["successful"] == 3 and out["failed"] == 1
    rows = {r.check_number: r.status for r in db.query(AuditResult).filter_by(session_id=session.id)}
    assert rows["K8S-1.2.15"] == rows["K8S-4.1.9"] == rows["K8S-4.2.13"] == CheckStatus.PASS
    assert rows["K8S-1.3.1"] == CheckStatus.FAIL


def test_integration_and_classification():
    from app.core.target_catalog import target_for_device_type
    from app.modules.hardening.harden_all.families import get_family
    from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
    from app.utils.device_classification import family_matches, infer_device_family
    t = target_for_device_type("kubernetes")
    assert t.icon == "cluster" and t.category == "platforms"
    assert get_family(DeviceType.KUBERNETES).capabilities.backup
    assert "kubernetes" in SUPPORTED_TECHNOLOGIES and REQUIRED_PARAMS["kubernetes"] == {"ssh_username", "ssh_password"}

    def asset(name, os_name, type_name):
        return type("A", (), {"manufacturer": None, "os_name": os_name, "os_version": "", "model": None,
                              "asset_name": name, "asset_type": type("T", (), {"type_name": type_name})()})()
    assert infer_device_family(asset("k8s-cp1", "Ubuntu 24.04", "Kubernetes Node")) == "kubernetes"
    assert infer_device_family(asset("node3", "Ubuntu 24.04", "Docker host, kubelet")) == "kubernetes"
    assert family_matches("kubernetes", "linux") and family_matches("linux", "kubernetes")


# ── live: a real kubeadm node (kind) ────────────────────────────────────

NODE_CONTAINER = os.environ.get("NGCORION_K8S_NODE")


class DockerExecConnection:
    """The SSH connection's contract, run in a kind node container as root."""
    ip = "kind"

    def _x(self, script):
        p = subprocess.run(["docker", "exec", NODE_CONTAINER, "sh", "-c", script], capture_output=True, text=True,
                           timeout=180)
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


@pytest.mark.skipif(not NODE_CONTAINER, reason="set NGCORION_K8S_NODE to a kind node container to run")
class TestLive:
    def test_collect_and_fix(self):
        conn = DockerExecConnection()
        dump = collect(conn)
        report, st = run(dump)
        assert st["K8S-1.1.1"] in ("pass", "fail") and R.node(dump).get("control_plane") == "yes"
        cfg = "/var/lib/kubelet/config.yaml"
        mode = conn.run(f"stat -c %a {cfg}").strip()
        try:
            conn.execute(f"chmod 644 {cfg}")
            assert run_template(SPEC, conn, "K8S-4.1.9", {})["success"]
            assert conn.run(f"stat -c %a {cfg}").strip() == "600"
            assert run_template(SPEC, conn, "K8S-5.1.5", {"CONFIRM": "yes"})["success"] is (
                not section(dump, "K8S_RBAC").startswith("CMD_ERROR"))
        finally:
            conn.execute(f"chmod {mode} {cfg}")
