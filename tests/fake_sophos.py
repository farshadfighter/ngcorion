"""
A simulated Sophos Firewall XML API for tests and screenshots: HTTPS with a
self-signed certificate on /webconsole/APIController, answering the
"reqxml" form field the way SFOS does (Response/Login/status, entity
elements with transactionid, "No. of records Zero.", Status codes 200,
500, 532, 534). Get returns the stored objects; Set operation="update"
replaces a named object (Name / RuleName) or, for single objects such as
AdminSettings, the sections sent. Fields the stored object does not have
are refused (code 500), as the firewall refuses elements its firmware does
not know.

No Sophos device is available to the test suite; the element names follow
Sophos's API reference and SDK (tests/sophos_sample.py).
"""

import copy
import shutil
import ssl
import subprocess
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree as ET

import sophos_sample as S

SINGLETONS = {"AdminSettings", "OTPSettings", "AdminAuthentication", "Hotfix", "PatternDownload", "Notification",
              "SNMPAgentConfiguration", "ATP", "BackupRestore", "Time"}


def _known(stored: ET.Element, sent: ET.Element) -> bool:
    for child in sent:
        match = stored.find(child.tag)
        if match is None or not _known(match, child):
            return False
    return True


class FakeSophos:
    def __init__(self, username=S.USERNAME, password=S.PASSWORD, api_version=S.API_VERSION):
        self.username, self.password, self.api_version = username, password, api_version
        self.state = {name: [ET.fromstring(x) for x in xs] for name, xs in S.ENTITIES.items()}
        self.mode = "ok"            # "api-disabled" / "ip-not-allowed"
        self.requests = []
        self.sets = []
        self._dir = tempfile.mkdtemp(prefix="fake-sophos-")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj",
                        "/CN=fw01.corp.example.com", "-keyout", f"{self._dir}/k.pem", "-out", f"{self._dir}/c.pem"],
                       check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{self._dir}/c.pem", f"{self._dir}/k.pem")
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                fake.requests.append((self.path, self.raw_requestline))
                reqxml = urllib.parse.parse_qs(body).get("reqxml", [""])[0]
                if self.path != "/webconsole/APIController" or not reqxml:
                    self.send_response(404)
                    self.end_headers()
                    return
                out = fake.answer(reqxml).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_GET(self):
                self.send_response(405)
                self.end_headers()

        class Server(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass        # clients that drop the TLS connection (a pin mismatch) are expected

        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self._dir, ignore_errors=True)

    # ── the API ──
    def answer(self, reqxml: str) -> str:
        head = f'<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="{self.api_version}" IPS_CAT_VER="1">'
        if self.mode == "api-disabled":
            return head + '<Status code="532">API operations are not allowed. Enable API configuration.</Status></Response>'
        if self.mode == "ip-not-allowed":
            return head + '<Status code="534">API operations are not allowed from the requester IP address.</Status></Response>'
        req = ET.fromstring(reqxml)
        ok = req.findtext("Login/Username") == self.username and req.findtext("Login/Password") == self.password
        if not ok:
            return head + "<Login><status>Authentication Failure</status></Login></Response>"
        parts = [head, "<Login><status>Authentication Successful</status></Login>"]
        for get in req.findall("Get"):
            for ask in get:
                found = self.state.get(ask.tag)
                if found is None:
                    parts.append(f'<{ask.tag} transactionid=""><Status code="541">Operation not supported.</Status></{ask.tag}>')
                elif not found:
                    parts.append(f'<{ask.tag} transactionid=""><Status>No. of records Zero.</Status></{ask.tag}>')
                else:
                    parts += [ET.tostring(el, encoding="unicode") for el in found]
        for st in req.findall("Set"):
            for sent in st:
                parts.append(self._set(sent))
        return "".join(parts) + "</Response>"

    def _set(self, sent: ET.Element) -> str:
        name = sent.tag
        ok = f'<{name} transactionid=""><Status code="200">Configuration applied successfully.</Status></{name}>'
        bad = f'<{name} transactionid=""><Status code="500">Operation failed. Invalid or unknown element.</Status></{name}>'
        stored = self.state.get(name)
        if stored is None:
            return bad
        self.sets.append(ET.tostring(sent, encoding="unicode"))
        if name in SINGLETONS:
            target = stored[0]
            if not _known(target, sent):
                return bad
            for part in sent:
                old = target.find(part.tag)
                target.insert(list(target).index(old), copy.deepcopy(part))
                target.remove(old)
            return ok
        key = "RuleName" if name == "LocalServiceACL" else "Name"
        for i, obj in enumerate(stored):
            if obj.findtext(key) == sent.findtext(key):
                if not _known(obj, sent):
                    return bad
                new = copy.deepcopy(sent)
                new.set("transactionid", "")
                stored[i] = new
                return ok
        return f'<{name} transactionid=""><Status code="500">Operation failed. Entity not found.</Status></{name}>'
