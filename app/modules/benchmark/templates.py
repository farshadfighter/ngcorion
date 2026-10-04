"""
Remediation templates and their parameters.

A template is the list of statements that fixes one check, plus statements
that print PASS or FAIL afterwards. A fix only counts when verification
prints PASS (and no FAIL): a statement that ran without error is not proof
the setting took. {PARAM} placeholders are filled from user input that has
been validated against the parameter's metadata first.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.hardening_param_security import ParameterSecurityError

PLACEHOLDER_RE = re.compile(r"\{[A-Z][A-Z0-9_]*\}")

# Characters that would break out of the quoted contexts templates substitute
# into, or start a shell/PowerShell sub-expression.
UNSAFE_TEXT_CHARS = ("'", '"', "`", "$", ";", "|", "&", "<", ">", "\n", "\r", "{", "}", "\\")


@dataclass
class ParamMeta:
    name: str
    input_type: str            # text / number / select
    label: str
    description: str
    required: bool = True
    default: Optional[str] = None
    placeholder: Optional[str] = None
    validation: Optional[str] = None   # regex a text value must match in full
    options: Optional[List[str]] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None


@dataclass
class HardeningTemplate:
    check_id: str
    description: str
    statements: List[str]
    verify_statements: List[str] = field(default_factory=list)
    requires_restart: bool = False
    manual_only: bool = False
    parameters: List[str] = field(default_factory=list)
    # Shown before the fix runs: side effects the operator must accept
    # ("cannot be undone", "restarts the service", ...).
    warning: Optional[str] = None


class TemplateSet:
    """The templates and parameters of one module."""

    def __init__(self):
        self.templates: Dict[str, HardeningTemplate] = {}
        self.params: Dict[str, ParamMeta] = {}

    # ── registration ──
    def add(self, template: HardeningTemplate) -> HardeningTemplate:
        self.templates[template.check_id] = template
        return template

    def manual(self, check_id: str, description: str) -> HardeningTemplate:
        return self.add(HardeningTemplate(check_id=check_id, description=description,
                                          statements=[], manual_only=True))

    def param(self, meta: ParamMeta) -> ParamMeta:
        self.params[meta.name] = meta
        return meta

    # ── lookup ──
    def get(self, check_id: str) -> Optional[HardeningTemplate]:
        return self.templates.get(check_id)

    def supported(self) -> List[str]:
        return sorted(self.templates)

    def params_for(self, check_id: str) -> List[ParamMeta]:
        t = self.get(check_id)
        if not t:
            return []
        return [self.params[n] for n in t.parameters if n in self.params]

    def has_fix(self, check_id: str) -> bool:
        t = self.get(check_id)
        return bool(t and not t.manual_only)

    def auto_fixable(self, check_id: str) -> bool:
        if not self.has_fix(check_id):
            return False
        return all(p.default is not None for p in self.params_for(check_id))

    def defaults(self, check_id: str) -> Dict[str, str]:
        return {p.name: p.default for p in self.params_for(check_id) if p.default is not None}

    def merged(self, check_id: str, parameters: Optional[Dict[str, Any]]) -> Dict[str, str]:
        """Defaults under the caller's values; empty strings do not override."""
        out = dict(self.defaults(check_id))
        for k, v in (parameters or {}).items():
            if v is not None and str(v).strip() != "":
                out[k] = str(v)
        return out

    def categorize(self, check_ids: List[str]) -> Dict[str, List[str]]:
        auto, needs, unsupported = [], [], []
        for cid in check_ids:
            if not self.has_fix(cid):
                unsupported.append(cid)
            elif self.auto_fixable(cid):
                auto.append(cid)
            else:
                needs.append(cid)
        return {"auto_fixable": auto, "needs_params": needs, "not_supported": unsupported}

    def aggregate(self, check_ids: List[str]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for cid in check_ids:
            for p in self.params_for(cid):
                if p.name not in out:
                    out[p.name] = {
                        "type": p.input_type, "label": p.label, "description": p.description,
                        "required": p.required and p.default is None, "default": p.default,
                        "placeholder": p.placeholder, "validation": p.validation,
                        "options": p.options, "min_value": p.min_value, "max_value": p.max_value,
                        "checks": [cid],
                    }
                elif cid not in out[p.name]["checks"]:
                    out[p.name]["checks"].append(cid)
        return out

    def missing(self, check_id: str, parameters: Optional[Dict[str, Any]]) -> List[str]:
        """Required parameters with no default that the caller left empty -
        including confirmation gates that never appear in a statement."""
        merged = self.merged(check_id, parameters)
        return [p.name for p in self.params_for(check_id)
                if p.required and p.default is None and not merged.get(p.name)]

    # ── validation + substitution ──
    def validate(self, check_id: str, parameters: Dict[str, str]) -> Optional[str]:
        allowed = {p.name: p for p in self.params_for(check_id)}
        for name, value in parameters.items():
            meta = allowed.get(name)
            if meta is None:
                # Unknown names are never substituted; ignore them.
                continue
            value = str(value)
            if meta.options:
                if value not in meta.options:
                    return f"Parameter {name}: value '{value}' not in {meta.options}"
                continue
            if meta.input_type == "number":
                try:
                    number = int(value)
                except ValueError:
                    return f"Parameter {name}: '{value}' is not a number"
                if meta.min_value is not None and number < meta.min_value:
                    return f"Parameter {name}: {number} is below the minimum {meta.min_value}"
                if meta.max_value is not None and number > meta.max_value:
                    return f"Parameter {name}: {number} is above the maximum {meta.max_value}"
                continue
            for bad in UNSAFE_TEXT_CHARS:
                if bad in value:
                    return f"Parameter {name} contains unsupported character {bad!r}"
            if meta.validation and not re.fullmatch(meta.validation, value):
                return f"Parameter {name}: '{value}' is not in the expected format"
        return None

    def _render(self, statements: List[str], check_id: str, parameters: Optional[Dict[str, Any]]) -> List[str]:
        params = self.merged(check_id, parameters)
        error = self.validate(check_id, params)
        if error:
            raise ParameterSecurityError(error)
        names = {p.name for p in self.params_for(check_id)}
        out = []
        for stmt in statements:
            for name in names:
                if name in params:
                    stmt = stmt.replace("{" + name + "}", params[name])
            out.append(stmt)
        return out

    def statements(self, check_id: str, parameters: Optional[Dict[str, Any]] = None) -> List[str]:
        t = self.get(check_id)
        return self._render(t.statements, check_id, parameters) if t else []

    def verify_statements(self, check_id: str, parameters: Optional[Dict[str, Any]] = None) -> List[str]:
        t = self.get(check_id)
        return self._render(t.verify_statements, check_id, parameters) if t else []
