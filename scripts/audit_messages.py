"""The sentences NGCorion writes into its audit trail, found in the source.

The audit trail stores what happened in English (detail of audit_logs, message of login_logs);
the UI translates it at display time (front/src/i18n/backendText.js, tb()). This walks app/ for
every call that writes one of those rows and returns the literal sentences it passes:

    "Account is inactive"                        -> fixed sentence, translated by exact match
    f"Login successful (role={user.role.value})" -> template "Login successful (role={{role}})"

A detail built elsewhere (a variable, a join) cannot be read here; such calls are returned as
"dynamic" with their location so a test can keep that list from growing unnoticed.

Run it to print what it finds:  python scripts/audit_messages.py
"""
from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Writers of audit rows: the argument that carries the sentence, by keyword and by position.
WRITERS = {
    "log_action": ("detail", 8),
    "log_user_action": ("detail", 4),
    "log_asset_action": ("detail", 4),
    "log_discovery_action": ("detail", 3),
    "log_login_attempt": ("message", 5),
}


@dataclass(frozen=True)
class Found:
    kind: str  # "fixed", "template" or "dynamic"
    text: str  # the sentence, or the source of a dynamic argument
    where: str  # path:line


def _placeholder(node: ast.expr, taken: set[str]) -> str:
    """A readable name for an f-string value: user.role.value -> role, len(rows) -> rows."""
    name = "value"
    if isinstance(node, ast.Call) and node.args:
        node = node.args[0]
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts = [p for p in parts if p not in ("value", "self")]
    if parts:
        name = parts[0].lower()
    base, i = name, 2
    while name in taken:
        name, i = f"{base}{i}", i + 1
    taken.add(name)
    return name


def _texts(node: ast.expr, taken: set[str]) -> list[str] | None:
    """Every sentence an expression can produce, values as {{placeholders}}; None when it is not
    written out in the source. "a" if x else "b", "x" + ("y" if z else "") and f-strings combine."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        # each branch names its values afresh: "Exported {{rows}} events" / "Exported {{rows}} sign-ins"
        body, orelse = _texts(node.body, set(taken)), _texts(node.orelse, set(taken))
        return body + orelse if body is not None and orelse is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _texts(node.left, taken), _texts(node.right, taken)
        return [a + b for a in left for b in right] if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        out = [""]
        for part in node.values:
            if isinstance(part, ast.Constant):
                options = [str(part.value)]
            else:
                inner = part.value
                options = _texts(inner, taken) if isinstance(inner, (ast.IfExp, ast.BinOp)) else None
                if options is None or any("{{" in o for o in options) and not isinstance(inner, ast.IfExp):
                    options = ["{{" + _placeholder(inner, taken) + "}}"]
            out = [a + b for a in out for b in options]
        return out
    return None


def _assigned(fn: ast.AST | None, name: str) -> ast.expr | None:
    """The value of a local variable assigned exactly once in the function (detail = f"..." before the
    row it describes is deleted)."""
    if fn is None:
        return None
    values = [n.value for n in ast.walk(fn) if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    return values[0] if len(values) == 1 else None


def _sentences(node: ast.expr, fn: ast.AST | None = None) -> list[tuple[str, str]] | None:
    if isinstance(node, ast.Name):
        node = _assigned(fn, node.id) or node
    texts = _texts(node, set())
    if texts is None:
        return None
    return [("template" if "{{" in t else "fixed", t) for t in dict.fromkeys(texts) if t]


def _name(call: ast.Call) -> str | None:
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)


def _argument(call: ast.Call, keyword: str, position: int) -> ast.expr | None:
    for k in call.keywords:
        if k.arg == keyword:
            return k.value
    if len(call.args) > position and not any(isinstance(a, ast.Starred) for a in call.args):
        return call.args[position]
    return None


def _passed_through(arg: ast.expr) -> str | None:
    """The parameter a wrapper hands on unchanged: detail, detail[:500], str(detail)[:500]."""
    while True:
        if isinstance(arg, ast.Subscript):
            arg = arg.value
        elif isinstance(arg, ast.Call) and getattr(arg.func, "id", None) == "str" and len(arg.args) == 1:
            arg = arg.args[0]
        else:
            break
    return arg.id if isinstance(arg, ast.Name) else None


def _writers(tree: ast.AST) -> tuple[dict[str, tuple[str, int]], set[int]]:
    """The global writers plus this file's own wrappers (def _log(db, user, action, detail): log_action(...,
    detail=detail)): calls to a wrapper are where the sentence really is. Also returns the writer calls
    inside those wrappers, which carry only the parameter."""
    writers = dict(WRITERS)
    inside: set[int] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fn.name in WRITERS:  # log_user_action(...) and friends: their callers are already writers
            inside.update(id(c) for c in ast.walk(fn) if isinstance(c, ast.Call) and _name(c) in WRITERS)
            continue
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        for call in ast.walk(fn):
            if isinstance(call, ast.Call) and _name(call) in WRITERS:
                arg = _argument(call, *WRITERS[_name(call)])
                through = _passed_through(arg) if arg is not None else None
                if through in params:
                    writers[fn.name] = (through, params.index(through))
                    inside.add(id(call))
    return writers, inside


def find(root: Path = ROOT) -> list[Found]:
    found: list[Found] = []
    for path in sorted((root / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(root).as_posix()
        writers, inside = _writers(tree)
        enclosing = {id(c): fn for fn in ast.walk(tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                     for c in ast.walk(fn) if isinstance(c, ast.Call)}
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or _name(call) not in writers or id(call) in inside:
                continue
            keyword, position = writers[_name(call)]
            arg = _argument(call, keyword, position)
            if arg is None or (isinstance(arg, ast.Constant) and arg.value is None):
                continue
            where = f"{rel}:{call.lineno}"
            got = _sentences(arg, enclosing.get(id(call)))
            if got is None:
                found.append(Found("dynamic", ast.unparse(arg), where))
            for kind, text in got or []:
                found.append(Found(kind, text, where))
    return found


def is_sentence(text: str) -> bool:
    """Words for a reader, not a record of values: "Deleted rule '{{name}}'" is translated,
    "{{code}} {{template}}" and "rows={{rows}}; filters=..." are shown as they are."""
    rest = re.sub(r"\{\{\w+\}\}", " ", text)
    rest = re.sub(r"\b\w+=\S*", " ", rest)
    return re.search(r"[A-Za-z]{2,}", rest) is not None


if __name__ == "__main__":
    for f in find():
        mark = "" if f.kind == "dynamic" or is_sentence(f.text) else "  (data)"
        print(f"{f.kind:8} {f.where:55} {f.text}{mark}")
    sys.exit(0)
