"""
Why a CIS check matters and how to fix it, from the rule catalogs of the
audit modules (the audit results keep only the check number).

The catalogs are built once per process. A check that no catalog knows has
no text; the report then shows a dash.
"""
import logging
from functools import lru_cache
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

Text = Tuple[Optional[str], Optional[str]]          # (rationale, remediation)


def _add(out: Dict[str, Text], rule, *keys) -> None:
    rationale = getattr(rule, "rationale", None) or getattr(rule, "description", None)
    remediation = getattr(rule, "remediation", None)
    for k in keys:
        if k:
            out.setdefault(str(k), (rationale, remediation))


def _cisco(out):
    from app.modules.cisco.audit.rules import build_all_cisco_cis_rules, build_cis_benchmark_rules
    for r in list(build_cis_benchmark_rules()) + list(build_all_cisco_cis_rules()):
        _add(out, r, r.id, r.id.removeprefix("CIS-"))


def _linux(out):
    from app.modules.linux.audit.rules import get_linux_rule_catalog
    for r in get_linux_rule_catalog().values():
        _add(out, r, r.id, getattr(r, "cis_section", None))


def _windows(out):
    from app.modules.windows.audit.rules import build_all_windows_cis_rules
    for r in build_all_windows_cis_rules():
        _add(out, r, r.id, getattr(r, "section", None))


def _apache(out):
    from app.modules.apache.audit.rules import build_apache_cis_rules
    for r in build_apache_cis_rules():
        _add(out, r, r.id, getattr(r, "cis_section", None))


def _mongodb(out):
    from app.modules.mongodb.audit.rules import build_all_mongodb_cis_rules
    for r in build_all_mongodb_cis_rules():
        _add(out, r, r.id, getattr(r, "section", None))


def _mssql(out):
    from app.modules.mssql.audit.rules import build_all_mssql_cis_rules
    for r in build_all_mssql_cis_rules():
        _add(out, r, r.id, getattr(r, "section", None))


def _fortinet(out):
    from app.modules.fortinet.audit.cis_map import get_benchmark_catalog
    for c in get_benchmark_catalog().get("controls") or []:
        text = (None, c.get("remediation"))
        for k in (c.get("control_id"), c.get("section")):
            if k:
                out.setdefault(str(k), text)


LOADERS = {"cisco": _cisco, "linux": _linux, "windows": _windows, "apache": _apache, "mongodb": _mongodb,
           "mssql": _mssql, "fortinet": _fortinet}


def _benchmark_loader(key: str):
    """Benchmark modules (app/modules/benchmark/registry.py) carry their own catalog."""
    from app.modules.benchmark.registry import spec_for
    spec = spec_for(key)
    if spec is None:
        return None

    def load(out):
        for r in spec.all_rules():
            _add(out, r, r.id)
    return load


@lru_cache(maxsize=None)
def catalog(device_type: str) -> Dict[str, Text]:
    out: Dict[str, Text] = {}
    loader = LOADERS.get(device_type) or _benchmark_loader(device_type)
    if loader:
        try:
            loader(out)
        except Exception:  # noqa: BLE001 - a broken catalog leaves the column empty, not the report
            logger.exception("[reports] could not load the %s rule catalog", device_type)
    return out


def text_for(device_type, check_number: Optional[str]) -> Text:
    raw = str(device_type.value if hasattr(device_type, "value") else device_type or "").lower()
    if not check_number:
        return None, None
    return catalog(raw).get(check_number) or catalog(raw).get(check_number.split(" ")[0]) or (None, None)
