"""
Sophos Firewall (SFOS) XML API client.

Every request is an XML document POSTed in the "reqxml" form field to
https://<firewall>:<port>/webconsole/APIController, with a Login block.
The API must be enabled on the firewall (Backup & firmware > API) and the
ngcorion server's address listed as an allowed IP.

The TLS certificate is pinned on first use (app/core/tls_pins.py) and checked
on the open connection before the request - with the password - is sent.
The password is sent in the request body only, never in a URL.
"""

import http.client
import logging
import re
import urllib.parse
from typing import List, Optional, Tuple
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from app.core import tls_pins

logger = logging.getLogger(__name__)

API_PATH = "/webconsole/APIController"


class SophosAPIError(RuntimeError):
    pass


def parse_xml(text: str) -> ET.Element:
    """Parse a device response; DTDs and entity declarations are refused
    (no entity expansion attacks from a hostile device)."""
    head = text[:4096].upper()
    if "<!DOCTYPE" in head or "<!ENTITY" in head:
        raise SophosAPIError("the firewall answered with a DTD; refusing to parse it")
    try:
        return ET.fromstring(text.strip().encode())
    except ET.ParseError as exc:
        raise SophosAPIError(f"the firewall answered with invalid XML: {exc}") from exc


def to_text(el: ET.Element) -> str:
    return ET.tostring(el, encoding="unicode")


def sfos_version(api_version: str) -> str:
    """APIVersion "2000.1" -> "20.0", "1905.1" -> "19.5", "2150.1" -> "21.5"."""
    m = re.match(r"^(\d{2})(\d{2})", api_version or "")
    if not m:
        return "unknown"
    minor = int(m.group(2))
    return f"{int(m.group(1))}.{minor // 10 if minor % 10 == 0 else minor}"


class SophosAPI:
    def __init__(self, host: str, port: int, username: str, password: str, timeout: int = 60):
        self.host, self.port, self.timeout = host, int(port), timeout
        self._login = (f"<Login><Username>{escape(username)}</Username>"
                       f"<Password>{escape(password)}</Password></Login>")
        self.api_version = ""

    def _post(self, body: str) -> ET.Element:
        reqxml = f"<Request>{self._login}{body}</Request>"
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                           context=tls_pins.unverified_context())
        try:
            try:
                conn.connect()
            except OSError as exc:
                raise ConnectionError(f"cannot reach {self.host}:{self.port}: {exc}") from exc
            tls_pins.check(self.host, self.port, conn.sock.getpeercert(binary_form=True))
            conn.request("POST", API_PATH, body=urllib.parse.urlencode({"reqxml": reqxml}),
                         headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/xml"})
            resp = conn.getresponse()
            text = resp.read().decode("utf-8", "replace")
        finally:
            conn.close()
        if resp.status != 200:
            raise ConnectionError(f"the firewall answered HTTP {resp.status} on {API_PATH}")
        root = parse_xml(text)
        if root.tag != "Response":
            raise SophosAPIError(f"unexpected answer <{root.tag}>")
        self.api_version = root.get("APIVersion", self.api_version)
        status = root.find("Status")
        if status is not None and status.get("code", "").strip() in ("532", "534"):
            # 532: API access not enabled; 534: this address is not allowed.
            raise PermissionError(f"Sophos API refused the request: {(status.text or '').strip()}")
        login = root.findtext("Login/status") or ""
        if "Failure" in login:
            raise PermissionError("Sophos API login failed (check the API user's name and password)")
        return root

    def login(self) -> str:
        self._post("")
        return self.api_version

    def get(self, entity: str) -> List[ET.Element]:
        root = self._post(f"<Get><{entity}/></Get>")
        found = root.findall(entity)
        if len(found) == 1:
            status = found[0].find("Status")
            if status is not None and len(found[0]) == 1:
                text = (status.text or "").strip()
                if "records Zero" in text:
                    return []
                raise SophosAPIError(f"Get {entity}: {status.get('code', '')} {text}".strip())
        return found

    def set(self, element: ET.Element, operation: str = "update") -> str:
        name = element.tag
        root = self._post(f'<Set operation="{operation}">{to_text(element)}</Set>')
        answer = root.find(name)
        status = answer.find("Status") if answer is not None else root.find("Status")
        if status is None:
            raise SophosAPIError(f"Set {name}: no status in the answer")
        code, text = status.get("code", ""), (status.text or "").strip()
        if not code.startswith("2"):
            raise SophosAPIError(f"Set {name} refused: {code} {text}")
        return text


def strip_transaction(el: ET.Element) -> ET.Element:
    """A copy of a Get answer element that can be sent back in a Set."""
    copy = ET.fromstring(to_text(el))
    copy.attrib.pop("transactionid", None)
    return copy


def child_path(el: ET.Element, path: str, create: bool = True) -> Optional[ET.Element]:
    """el/path ("A/B/C"), creating missing elements when asked."""
    node = el
    for part in path.split("/"):
        nxt = node.find(part)
        if nxt is None:
            if not create:
                return None
            nxt = ET.SubElement(node, part)
        node = nxt
    return node


def split_assignment(text: str) -> Tuple[str, str]:
    if "=" not in text:
        raise SophosAPIError(f"expected path=value, got {text!r}")
    path, value = text.split("=", 1)
    return path.strip("/"), value
