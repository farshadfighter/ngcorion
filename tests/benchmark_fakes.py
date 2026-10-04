"""
A simulated host for benchmark-module tests: answers each collection
script with a prepared section, and applies fixes - a template's
statements mark its check fixed, its verification then prints PASS.
"""
from contextlib import contextmanager

from app.modules.benchmark import connectors


class FakeHost:
    def __init__(self, commands, sections, templates, ip="10.0.0.1"):
        self.sections = dict(sections)
        self.by_script = {script: name for name, script in commands.items()}
        self.templates = templates
        self.applied = set()
        self.executed = []
        self.ip = ip

    def run(self, script):
        name = self.by_script.get(script)
        return self.sections.get(name, "(no output)") if name else "(no output)"

    _run_ps = run

    def execute(self, script):
        self.executed.append(script)
        ts = self.templates
        for cid in ts.templates:
            params = {p.name: (p.options[0] if p.options else "x") for p in ts.params_for(cid)}
            if script in ts.statements(cid, params):
                self.applied.add(cid)
                return "(ok)"
            if script in ts.verify_statements(cid, params):
                return "PASS" if cid in self.applied else "FAIL"
        return "(ok)"


def install(monkeypatch, host, connector_key="winrm", password_field="windows_password", password="Corp-Pass-1"):
    base = type(connectors.CONNECTORS[connector_key])

    class _Connector(base):
        @contextmanager
        def open(self, ip, creds):
            if creds.get(password_field) != password:
                raise PermissionError("auth failed")
            yield host

    monkeypatch.setitem(connectors.CONNECTORS, connector_key, _Connector())
    return host
