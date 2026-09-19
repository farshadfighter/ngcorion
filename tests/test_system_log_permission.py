"""System Log is a grantable permission, and the login-log API enforces it.

Two halves had drifted: ModuleEnum carried LOGS and the frontend route already
gated on it, but the User Management permission picker never offered it — so it
could not be granted — and /api/logs/* had no dependency at all, so login
history (usernames, source IPs) was readable by anyone who could reach the
endpoint.
"""

import inspect
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from app.models.user_permission import ModuleEnum, get_all_modules
from app.modules.logs import router as logs_router
from app.schemas.user import get_available_modules

FRONTEND_MODULES = (
    PROJECT_ROOT / "front/src/components/UserManagement/permissionModules.js"
)


def test_logs_is_a_module():
    assert ModuleEnum.LOGS.value == "logs"
    assert "logs" in get_all_modules()


def test_every_module_is_offered_to_the_permission_ui():
    """get_available_modules() is what User Management lists; a module missing
    from it can never be granted."""
    offered = {module.name for module in get_available_modules()}
    assert offered == set(get_all_modules())
    assert "logs" in offered
    assert "system_config" in offered


def test_every_module_has_a_description():
    for module in get_available_modules():
        assert module.description
        assert module.description != module.name or module.name == module.name


# Backend modules deliberately absent from the picker: they exist in
# ModuleEnum (so require_permission-style checks *could* reference them) but
# are gated some other way, so offering a checkbox for them would be a dead
# control - toggling it would change nothing.
#   deployment: gated by require_admin_or_manager (role), not per-user
#   permission - see app/modules/deployment/router.py.
_MODULES_INTENTIONALLY_NOT_IN_PICKER = {"deployment"}


def test_frontend_permission_list_matches_the_backend():
    """The picker is a hardcoded list in the SPA; it drifting from ModuleEnum is
    exactly what hid System Log. Modules in _MODULES_INTENTIONALLY_NOT_IN_PICKER
    are the one allowed kind of drift - everything else must match exactly."""
    source = FRONTEND_MODULES.read_text()
    names = set(re.findall(r'\{\s*name:\s*"([a-z_]+)"', source))
    expected = set(get_all_modules()) - _MODULES_INTENTIONALLY_NOT_IN_PICKER
    assert names == expected, (
        f"frontend-only: {sorted(names - expected)}; "
        f"backend-only: {sorted(expected - names)}"
    )


# ----------------------------------------------------------------------
# API enforcement
# ----------------------------------------------------------------------

def _dependency_modules(func) -> list:
    """The (module, action) pairs of every require_permission on a route.

    require_permission returns a closure, so the arguments are read off its
    cell contents rather than the function object.
    """
    found = []
    for param in inspect.signature(func).parameters.values():
        dependency = getattr(param.default, "dependency", None)
        if dependency is None or not dependency.__closure__:
            continue
        cells = [cell.cell_contents for cell in dependency.__closure__]
        strings = [c for c in cells if isinstance(c, str)]
        if len(strings) == 2:
            found.append(tuple(strings))
    return found


@pytest.mark.parametrize("route_name", [
    "get_all_logs", "get_user_logs", "get_login_stats",
])
def test_login_log_routes_require_logs_read(route_name):
    func = getattr(logs_router, route_name)
    assert ("LOGS", "read") in _dependency_modules(func), (
        f"{route_name} does not require LOGS read"
    )


def test_no_login_log_route_is_unguarded():
    """Catches a route added later without a permission dependency."""
    unguarded = []
    for route in logs_router.router.routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None:
            continue
        if not _dependency_modules(endpoint):
            unguarded.append(route.path)
    assert unguarded == []
