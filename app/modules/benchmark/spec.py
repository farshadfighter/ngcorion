"""What a benchmark module declares about itself."""

from dataclasses import dataclass, field
from typing import Any, Callable, FrozenSet, List, Optional

from app.models.audit import DeviceType

from .rules import BenchmarkRule
from .templates import TemplateSet


def _identity(text: str) -> str:
    return text


@dataclass
class ModuleSpec:
    key: str                     # DeviceType value and API path segment
    label: str                   # "Active Directory"
    device_type: DeviceType
    log_module: str              # system log module name, "active_directory_cis"
    connector: str               # app.modules.benchmark.connectors key
    benchmark: str               # what the rules follow, for API docs and logs

    # conn -> dump string (sections)
    collect: Callable[[Any], str]
    # dump -> the rules that apply to this target (version / role detected)
    rules_for: Callable[[str], List[BenchmarkRule]]
    # every rule the module knows, for report texts and the supported list
    all_rules: Callable[[], List[BenchmarkRule]]
    templates: TemplateSet

    json_sections: FrozenSet[str] = frozenset()
    redact: Callable[[str], str] = _identity
    # dump -> short description of what was found ("Windows Server 2022, DC")
    describe: Optional[Callable[[str], str]] = None

    # Software inventory on the audit connection (optional, never fails an audit)
    collect_software: Optional[Callable[[Any], Any]] = None
    save_software: Optional[Callable[..., Any]] = None

    # conn -> text snapshot taken before hardening when a backup is requested
    backup: Optional[Callable[[Any], str]] = None
    backup_device_type: Optional[str] = None

    tags_audit: List[str] = field(default_factory=list)
    tags_hardening: List[str] = field(default_factory=list)
