"""
Every English string the report module translates, found by reading its
source: literals passed to tr(...), and the titles, hints and labels of the
templates, sections, options and lookup tables. tests/test_reports.py checks
each one has a Persian entry in locale/fa.json.
"""
import ast
from pathlib import Path
from typing import Set

HERE = Path(__file__).parent


def _literal(node) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def collect() -> Set[str]:
    from app.modules.reports import service, templates
    from app.modules.reports.i18n import Tr
    found: Set[str] = set()
    for path in HERE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name in ("tr", "Tr") or (isinstance(f, ast.Call) and getattr(f.func, "id", None) == "Tr"):
                text = _literal(node.args[0])
                if text:
                    found.add(text)
    for t in list(templates.TEMPLATES.values()) + list(templates.PLANNED):
        found.update([t.title, t.description])
        for s in t.sections:
            found.add(s.title)
            if s.hint:
                found.add(s.hint)
        for o in t.options:
            found.add(o.label)
            found.update(label for _, label in o.choices)
    found.update(label for _, label in templates.GROUPS)
    found.update(label for _, label in templates.FACTORS)
    found.update(label for _, label, _ in templates.LEVELS)
    found.update(service.MODULE_LABELS.values())
    found.update(["Critical", "High", "Medium", "Low", "Info", "Informational", "Public", "Internal", "Confidential"])
    Tr  # noqa: B018 - imported for its side-effect-free name
    return found
