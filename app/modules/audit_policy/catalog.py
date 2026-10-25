"""
The checks of every benchmark, from the audit modules' own rule catalogs, so a policy rule can be set
for any of the 17 families before any of its assets has been audited.

The check number is the one an audit writes into audit_results.check_number (the policy matches on
it): the rule ID for most modules (LNX-L1-1.1.1.1, WIN-2025-1.1.1, DKR-1.1.1, ...), the control ID for
FortiGate (FG-BL-043), and for Cisco the IDs of both rule sets an audit may run (CIS-1.1.1, IOS-L1-0010).

Built once per process per family. A catalog that cannot be loaded gives no checks (the audited ones are
still offered) rather than an error.
"""
import logging
from functools import lru_cache
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def _rows(rules, number=lambda r: r.id) -> List[Dict]:
    return [{"check_number": str(number(r)), "title": getattr(r, "title", None),
             "severity": (getattr(r, "severity", None) or "").lower() or None,
             "level": (getattr(r, "level", None) or "").upper() or None} for r in rules]


def _cisco():
    from app.modules.cisco.audit.rules import build_all_cisco_cis_rules, build_cis_benchmark_rules
    return _rows(list(build_cis_benchmark_rules()) + list(build_all_cisco_cis_rules()))


def _linux():
    from app.modules.linux.audit.rules import get_linux_rule_catalog
    return _rows(get_linux_rule_catalog().values())


def _windows():
    # every server version's rule set (2016 to 2025) uses these IDs
    from app.modules.windows.audit.rules import build_all_windows_cis_rules
    return _rows(build_all_windows_cis_rules())


def _fortinet():
    from app.modules.fortinet.audit.rules import get_fortinet_controls
    return _rows(get_fortinet_controls())


def _apache():
    from app.modules.apache.audit.rules import build_apache_cis_rules
    return _rows(build_apache_cis_rules())


def _mongodb():
    from app.modules.mongodb.audit.rules import build_all_mongodb_cis_rules
    return _rows(build_all_mongodb_cis_rules())


def _mssql():
    from app.modules.mssql.audit.rules import build_all_mssql_cis_rules
    return _rows(build_all_mssql_cis_rules())


LOADERS = {"cisco": _cisco, "linux": _linux, "windows": _windows, "fortinet": _fortinet, "apache": _apache,
           "mongodb": _mongodb, "mssql": _mssql}


def _benchmark_module(key: str) -> Optional[List[Dict]]:
    """The benchmark modules (app/modules/benchmark/registry.py) carry their catalog in their spec."""
    from app.modules.benchmark.registry import spec_for
    spec = spec_for(key)
    return _rows(spec.all_rules()) if spec is not None else None


@lru_cache(maxsize=None)
def _catalog(benchmark: str) -> tuple:
    try:
        loader = LOADERS.get(benchmark)
        rows = loader() if loader else (_benchmark_module(benchmark) or [])
    except Exception:  # noqa: BLE001 - a broken catalog leaves only the audited checks, not an error
        logger.exception("[audit_policy] could not load the %s rule catalog", benchmark)
        rows = []
    seen, out = set(), []
    for r in rows:
        if r["check_number"] and r["check_number"] not in seen:
            seen.add(r["check_number"])
            out.append(r)
    return tuple(out)


def checks(benchmark: str) -> List[Dict]:
    """Every check of a benchmark: check_number, title, severity (lower case), level (L1, L2, ...)."""
    return [dict(r) for r in _catalog(benchmark)]


def find(benchmark: str, check_number: str) -> Optional[Dict]:
    """One check of a benchmark's catalog, or None."""
    return next((dict(r) for r in _catalog(benchmark) if r["check_number"] == check_number), None)
