"""
How a benchmark module reaches its target.

A connector turns the credentials from a request into an open connection with
two calls:

    run(script)      audit path: never raises, returns the output or an
                     "<KIND>_ERROR: ..." marker the rule engine reports as
                     "not evaluated"
    execute(script)  hardening path: returns the output, raises on failure so
                     a fix is never reported as applied when it was not

Opening a connection raises PermissionError for rejected credentials and
ConnectionError when the host cannot be reached; the routers turn those into
401 / 503 the same way the older modules do. Credentials are used for the one
connection and never stored.
"""

import logging
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Tuple

from pydantic import Field

from app.core.config import settings
from app.modules.hardening.harden_all.contract import CredentialField
from app.modules.windows.winrm_endpoint import DEFAULT_WINRM_PORT

logger = logging.getLogger(__name__)


class Connector:
    """Base class. Subclasses fill in the field sets and open()."""

    key: str = ""
    # pydantic field definitions merged into the execute / execute-single bodies
    request_fields: Dict[str, Tuple[Any, Any]] = {}
    # what the Harden All credentials step renders
    credential_fields: List[CredentialField] = []
    # names a scheduled audit must carry (stored encrypted by scheduling)
    required_for_schedule: frozenset = frozenset()

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]) -> Iterator[Any]:  # pragma: no cover - abstract
        raise NotImplementedError
        yield

    def port_of(self, creds: Dict[str, Any]) -> Optional[int]:
        return None


# ── WinRM (Windows Server roles: AD, DNS, DHCP, IIS) ───────────────────────

class WinRMConnection:
    """One WinRM session. Wraps the Windows hardening executor, which already
    has the connect/retry/auth handling the Windows module relies on."""

    def __init__(self, executor):
        self._ex = executor
        self.ip = executor.ip

    def execute(self, script: str) -> str:
        return self._ex._execute(script)

    def run(self, script: str) -> str:
        try:
            out = self._ex._execute(script)
        except Exception as exc:  # noqa: BLE001 - reported per section
            return f"PS_ERROR: {str(exc)[:300]}"
        return "(no output)" if out == "(ok)" else out

    # The software inventory hook calls client._run_ps(...)
    _run_ps = run


class WinRMConnector(Connector):
    key = "winrm"
    request_fields = {
        "windows_username": (str, Field(..., min_length=1, description="Windows admin account (DOMAIN\\user), not stored")),
        "windows_password": (str, Field(..., min_length=1, description="Password, not stored")),
        "winrm_port": (int, Field(DEFAULT_WINRM_PORT, ge=1, le=65535, description="5985 HTTP / 5986 HTTPS")),
        "transport": (str, Field("ntlm", pattern="^(ntlm|kerberos|credssp|basic)$")),
        "verify_ssl": (Optional[bool], Field(None, description="Validate the WinRM TLS certificate (server default when omitted)")),
    }
    credential_fields = [
        CredentialField(name="windows_username", label="Windows Username", type="text", required=True),
        CredentialField(name="windows_password", label="Windows Password", type="password", required=True),
        CredentialField(name="winrm_port", label="WinRM Port", type="number", default=str(DEFAULT_WINRM_PORT)),
        CredentialField(name="transport", label="Transport", type="select", default="ntlm",
                        options=["ntlm", "kerberos", "credssp", "basic"]),
    ]
    required_for_schedule = frozenset({"windows_username", "windows_password"})

    def port_of(self, creds):
        return int(creds.get("winrm_port") or DEFAULT_WINRM_PORT)

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]):
        from app.modules.windows.hardening.winrm_executor import WindowsWinRMExecutor
        verify = creds.get("verify_ssl")
        executor = WindowsWinRMExecutor(
            ip=ip,
            username=creds["windows_username"],
            password=creds["windows_password"],
            port=self.port_of(creds),
            transport=creds.get("transport") or "ntlm",
            verify_ssl=settings.WINRM_VERIFY_SSL if verify is None else bool(verify),
            # Directory queries over a large domain can take a while.
            timeout=120,
        )
        with executor:
            yield WinRMConnection(executor)


CONNECTORS: Dict[str, Connector] = {"winrm": WinRMConnector()}


def get_connector(key: str) -> Connector:
    return CONNECTORS[key]


def register_connector(connector: Connector) -> None:
    CONNECTORS[connector.key] = connector
