"""
Benchmark rules, the collection dump they read, and compliance scoring.

A collection is one text dump split into named sections:

    ===SECTION:OS_VERSION===
    {"Caption": "...", "BuildNumber": "20348"}
    ===SECTION:AD_DOMAIN===
    ...

Each rule reads one or more sections. When none of a rule's sections came
back, the rule is reported as ERROR (not evaluated) rather than scored, so a
failed command never reads as compliant or as a finding. Manual rules are
reported and never scored. The scoring is the one the Windows module uses,
so compliance means the same thing across modules.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1, "info": 0}
DEFAULT_SEVERITY_WEIGHT = 1


@dataclass
class BenchmarkRule:
    id: str                       # "AD-CIS-2.3.5.3", "AD-DOM-1.1"
    section: str                  # benchmark numbering, "2.3.5.3"
    title: str
    severity: str                 # high / medium / low / info
    level: str                    # L1 / L2 / INFO
    check_fn: Callable[[str], bool]
    evidence_fn: Callable[[str], str]
    remediation: str
    description: str = ""
    manual: bool = False
    scope: str = "all"
    data_sections: List[str] = field(default_factory=list)
    # Where the control comes from, shown in reports: "CIS", "DISA STIG",
    # "Microsoft", "Vendor", or "Beyond CIS" for the extra checks a module adds.
    source: str = "CIS"
    # Optional: a reason this rule cannot be judged on this dump even though
    # its sections came back (one group of several could not be read, ...).
    unavailable_fn: Optional[Callable[[str], Optional[str]]] = None


# ── Dump sections ──────────────────────────────────────────────────────────

_SECTION_RE_CACHE: Dict[str, "re.Pattern"] = {}


def section(dump: str, name: str) -> str:
    """Text of one section, or "" when it is absent."""
    pattern = _SECTION_RE_CACHE.get(name)
    if pattern is None:
        pattern = re.compile(
            r"===SECTION:" + re.escape(name) + r"===\n(.*?)(?=\n===SECTION:|\Z)", re.S)
        _SECTION_RE_CACHE[name] = pattern
    m = pattern.search(dump or "")
    return m.group(1).strip() if m else ""


def parse_json(text: str) -> Any:
    text = (text or "").strip()
    if not text or text[0] not in "[{\"0123456789-tfn":
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def json_section(dump: str, name: str) -> Any:
    return parse_json(section(dump, name))


def as_list(value: Any) -> List[Any]:
    """ConvertTo-Json writes a one-item array as the bare item."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def assemble(sections: Dict[str, str]) -> str:
    parts = []
    for key, content in sections.items():
        parts.append(f"===SECTION:{key}===")
        parts.append(content if content not in (None, "") else "(empty)")
    return "\n".join(parts)


FAILURE_PREFIXES = ("PS_ERROR", "CMD_ERROR", "COLLECTION_ERROR", "SSH_ERROR", "API_ERROR")
EMPTY_MARKERS = ("", "(no output)", "(empty)", "SECEDIT_EXPORT_FAILED")


def section_failure(dump: str, name: str, json_sections: Iterable[str] = ()) -> Optional[str]:
    """A short reason when a section is unusable, else None."""
    content = section(dump, name).strip()
    if content in EMPTY_MARKERS:
        return f"{name} was not collected"
    if content.startswith(FAILURE_PREFIXES):
        return f"{name} collection failed: {content.splitlines()[0][:160]}"
    if "SECEDIT_EXPORT_FAILED" in content:
        return f"{name} collection failed: secedit /export returned no policy file"
    if name in set(json_sections) and parse_json(content) is None:
        return f"{name} returned unparseable output: {content.splitlines()[0][:160]}"
    return None


def rule_data_failure(dump: str, rule, json_sections: Iterable[str] = ()) -> Optional[str]:
    """A reason when none of a rule's sections is usable (one is enough)."""
    names = list(getattr(rule, "data_sections", None) or [])
    if not names:
        return None
    reasons = []
    for name in names:
        reason = section_failure(dump, name, json_sections)
        if reason is None:
            return None
        reasons.append(reason)
    return "; ".join(reasons)


# ── Scoring ────────────────────────────────────────────────────────────────

def evaluate(dump: str, rules: List[Any], json_sections: Iterable[str] = ()) -> Dict[str, Any]:
    """Evaluate rules against a dump. Same report shape as the Windows engine."""
    json_sections = frozenset(json_sections)
    findings = []
    passed_scored = failed_scored = manual_checks = error_checks = 0
    total_weight = passed_weight = 0

    def _evidence(rule):
        try:
            return str(rule.evidence_fn(dump))
        except Exception:
            return "(evidence extraction failed)"

    for rule in rules:
        base = {
            "id": rule.id, "title": rule.title, "description": rule.description or rule.title,
            "section": rule.section, "severity": rule.severity, "level": rule.level,
            "remediation": rule.remediation, "source": getattr(rule, "source", "CIS"),
        }
        if rule.manual:
            manual_checks += 1
            findings.append({**base, "compliant": False, "manual": True, "error": False,
                             "status": "skipped",
                             "evidence": (f"SKIPPED — manual verification required. {rule.remediation}\n\n"
                                          f"Collected evidence:\n{_evidence(rule)}")[:1000]})
            continue

        failure = rule_data_failure(dump, rule, json_sections)
        if not failure and getattr(rule, "unavailable_fn", None):
            try:
                failure = rule.unavailable_fn(dump)
            except Exception:  # noqa: BLE001
                failure = None
        if failure:
            error_checks += 1
            findings.append({**base, "compliant": False, "manual": False, "error": True,
                             "status": "error",
                             "evidence": (f"ERROR — not evaluated: {failure}. "
                                          "Re-run the audit with an account that can read this data.")[:1000]})
            continue

        try:
            compliant = bool(rule.check_fn(dump))
        except Exception:
            compliant = False
        weight = SEVERITY_WEIGHTS.get(rule.severity, DEFAULT_SEVERITY_WEIGHT)
        if rule.level != "INFO":
            total_weight += weight
            if compliant:
                passed_scored += 1
                passed_weight += weight
            else:
                failed_scored += 1
        findings.append({**base, "compliant": compliant, "manual": False, "error": False,
                         "status": "pass" if compliant else "fail",
                         "evidence": _evidence(rule)})

    total = passed_scored + failed_scored
    return {
        "summary": {
            "total_rules_scored": total,
            "manual_checks": manual_checks,
            "error_checks": error_checks,
            "passed_scored": passed_scored,
            "failed_scored": failed_scored,
            "compliance_pct": round(100.0 * passed_scored / total, 2) if total else 0.0,
            "weighted_compliance_pct": round(100.0 * passed_weight / total_weight, 2) if total_weight else 0.0,
        },
        "findings": findings,
    }


def filter_by_profile(rules: List[Any], profile: str) -> List[Any]:
    """L1 keeps level-1 (and INFO) rules; FULL keeps everything."""
    if (profile or "FULL").upper() == "L1":
        return [r for r in rules if r.level in ("L1", "INFO")]
    return list(rules)
