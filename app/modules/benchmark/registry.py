"""Every benchmark module, for the places that list device families
(main.py routers, Harden All, scheduling, reports, logs)."""

from typing import Dict, List, Optional

from .spec import ModuleSpec


def specs() -> List[ModuleSpec]:
    from app.modules.active_directory.spec import SPEC as active_directory
    from app.modules.dhcp_server.spec import SPEC as dhcp_server
    from app.modules.dns_server.spec import SPEC as dns_server
    return [active_directory, dns_server, dhcp_server]


def spec_map() -> Dict[str, ModuleSpec]:
    return {s.key: s for s in specs()}


def spec_for(key: str) -> Optional[ModuleSpec]:
    return spec_map().get(key)


def keys() -> List[str]:
    return [s.key for s in specs()]
