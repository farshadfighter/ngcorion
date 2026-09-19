"""
Architecture Validation Rule Engine

Rules are declarative YAML documents (rules/*.yaml): each rule is a boolean
"condition" expression evaluated against a per-asset context dict. Conditions
are parsed and evaluated through a restricted AST walker - never eval()/exec()
- so a rule file can only read names already present in the context and
combine them with boolean/comparison operators, not run arbitrary code.
"""
import ast
import operator
from pathlib import Path
from typing import Any, Optional

import yaml

RULES_DIR = Path(__file__).parent / "rules"

_COMPARATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}


class RuleConditionError(ValueError):
    """A rule's condition uses syntax or a name this evaluator doesn't support."""


def _eval_node(node: ast.AST, context: dict) -> Any:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, context)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in context:
            raise RuleConditionError(f"Unknown name in condition: {node.id!r}")
        return context[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, context)
    if isinstance(node, ast.BoolOp):
        # Short-circuit, like Python's own `and`/`or`: a rule such as
        # "days_since_audit is not None and days_since_audit > 90" relies on
        # the second operand never being evaluated when the first is False.
        if isinstance(node.op, ast.And):
            result = True
            for value in node.values:
                result = _eval_node(value, context)
                if not result:
                    return result
            return result
        if isinstance(node.op, ast.Or):
            result = False
            for value in node.values:
                result = _eval_node(value, context)
                if result:
                    return result
            return result
        raise RuleConditionError("Unsupported boolean operator")
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, context)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval_node(comparator, context)
            fn = _COMPARATORS.get(type(op))
            if fn is None:
                raise RuleConditionError(f"Unsupported comparison operator: {type(op).__name__}")
            if not fn(left, right):
                return False
            left = right
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_eval_node(e, context) for e in node.elts]
    raise RuleConditionError(f"Unsupported expression: {type(node).__name__}")


def evaluate_condition(expression: str, context: dict) -> bool:
    """Evaluate one rule's boolean `condition` string against a context dict."""
    tree = ast.parse(expression, mode="eval")
    return bool(_eval_node(tree, context))


def load_rules() -> list[dict]:
    """Load every rule from rules/*.yaml, sorted by code."""
    rules = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        content = yaml.safe_load(path.read_text()) or []
        rules.extend(content)
    rules.sort(key=lambda r: r["code"])
    return rules


def run_rules(context: dict, rules: Optional[list[dict]] = None) -> list[dict]:
    """Return every rule whose condition is true for this context."""
    if rules is None:
        rules = load_rules()
    findings = []
    for rule in rules:
        try:
            if evaluate_condition(rule["condition"], context):
                findings.append(rule)
        except RuleConditionError:
            # A rule referencing a name this context doesn't provide is a
            # rule-authoring bug, not a reason to fail the whole run.
            continue
    return findings
