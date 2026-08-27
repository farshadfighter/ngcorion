"""The default WinRM port for Windows Server auditing and hardening is 5985.

5985 is the plaintext listener Windows enables by default; 5986 is the optional
HTTPS one. Both clients used to hardcode ``https://`` regardless of the port, so
the default and the scheme have to be asserted together — a 5985 default paired
with an https:// URL is not a working default.
"""

import inspect
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from app.modules.windows.winrm_endpoint import (
    DEFAULT_WINRM_PORT,
    WINRM_HTTP_PORT,
    WINRM_HTTPS_PORT,
    winrm_endpoint,
    winrm_use_ssl,
)


def test_default_port_is_5985():
    assert DEFAULT_WINRM_PORT == 5985
    assert WINRM_HTTP_PORT == 5985
    assert WINRM_HTTPS_PORT == 5986


@pytest.mark.parametrize("port,expected", [
    (5985, False),
    (5986, True),
    (15986, True),   # a custom HTTPS listener stays on TLS
    (443, True),
])
def test_scheme_follows_the_port(port, expected):
    assert winrm_use_ssl(port) is expected


def test_endpoint_urls():
    assert winrm_endpoint("10.0.0.1", 5985) == "http://10.0.0.1:5985/wsman"
    assert winrm_endpoint("10.0.0.1", 5986) == "https://10.0.0.1:5986/wsman"


def test_explicit_https_on_5986_still_works():
    """5986 must remain selectable — this change moved the default, not the
    capability."""
    from app.modules.windows.audit.winrm_client import WindowsWinRMClient

    client = WindowsWinRMClient("10.0.0.1", "u", "p", port=5986)
    assert client.port == 5986
    assert winrm_endpoint(client.ip, client.port).startswith("https://")


# ----------------------------------------------------------------------
# Every entry point that carries its own default
# ----------------------------------------------------------------------

def _default_of(func, name: str):
    return inspect.signature(func).parameters[name].default


def test_client_defaults():
    from app.modules.windows.audit.winrm_client import WindowsWinRMClient
    from app.modules.windows.hardening.winrm_executor import (
        WindowsHardeningBatchExecutor,
        WindowsWinRMExecutor,
    )

    assert _default_of(WindowsWinRMClient.__init__, "port") == 5985
    assert _default_of(WindowsWinRMExecutor.__init__, "port") == 5985
    assert _default_of(WindowsHardeningBatchExecutor.__init__, "port") == 5985


def test_service_defaults():
    from app.modules.windows.audit.service import WindowsAuditService
    from app.modules.windows.hardening import service as hardening_service

    for name, func in inspect.getmembers(
        WindowsAuditService, predicate=inspect.isfunction
    ):
        params = inspect.signature(func).parameters
        if "winrm_port" in params and params["winrm_port"].default is not inspect.Parameter.empty:
            assert params["winrm_port"].default == 5985, name

    for name, func in inspect.getmembers(
        hardening_service, predicate=inspect.isfunction
    ):
        params = inspect.signature(func).parameters
        if "winrm_port" in params and params["winrm_port"].default is not inspect.Parameter.empty:
            assert params["winrm_port"].default == 5985, name


def test_request_schema_defaults():
    """Both the audit request and the hardening fix request carry the default
    into the OpenAPI schema the UI reads."""
    from app.modules.windows.audit.router import WindowsAuditRequest
    from app.modules.windows.hardening.router import SingleFixRequest

    assert SingleFixRequest.model_fields["winrm_port"].default == 5985
    assert WindowsAuditRequest.model_fields["winrm_port"].default == 5985


def test_harden_all_credential_field_default():
    """The Harden-All credential form advertises the same default."""
    from app.modules.hardening.harden_all import families

    fields = [
        field
        for spec in families._build_registry().values()
        for field in getattr(spec, "credential_fields", []) or []
        if getattr(field, "name", None) == "winrm_port"
    ]
    assert fields, "no winrm_port credential field found"
    assert all(f.default == "5985" for f in fields)
