"""
Every `python -m app....` command the documentation gives must still run in the production image,
where scripts/compile_app.py turns modules into native extensions: `python -m` needs a code object,
which a compiled module does not have, so each one has to be in RUN_AS_MAIN (kept as source).
"""
import ast
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import compile_app  # noqa: E402

DOCS = [*(ROOT / "docs").rglob("*.md"), ROOT / "README.md"]


def _entry_file(module: str) -> str:
    """The file `python -m module` runs: the module itself, or a package's __main__.py."""
    spec = importlib.util.find_spec(module)
    origin = Path(spec.origin)
    if origin.name == "__init__.py":
        origin = origin.with_name("__main__.py")
    return origin.relative_to(ROOT).as_posix()


def test_documented_entry_points_stay_source():
    commands = {m for doc in DOCS for m in re.findall(r"python -m (app(?:\.\w+)+)", doc.read_text(encoding="utf-8"))}
    assert commands, "no python -m command found in the docs: the pattern is out of date"
    for module in sorted(commands):
        entry = _entry_file(module)
        assert entry in compile_app.RUN_AS_MAIN, f"{module} ({entry}) would be compiled and fail under python -m"


def test_entry_points_exist_and_are_not_licensing_code():
    for entry in compile_app.RUN_AS_MAIN:
        assert (ROOT / entry).is_file(), entry
    assert not compile_app.MUST_COMPILE & compile_app.RUN_AS_MAIN


def _model_classes(tree):
    """The classes of a module that are Pydantic models: BaseModel subclasses, and subclasses of those."""
    models, changed = set(), True
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    while changed:
        changed = False
        for c in classes:
            names = {b.id if isinstance(b, ast.Name) else getattr(b, "attr", None) for b in c.bases}
            if c.name not in models and (names & ({"BaseModel"} | models)):
                models.add(c.name)
                changed = True
    return [c for c in classes if c.name in models]


def test_compiled_pydantic_models_have_no_plain_methods():
    """A plain method of a Pydantic model becomes a compiled function, which Pydantic takes for a field
    without annotation and refuses at import: the production image then fails to start. Put the logic
    in a module-level function, a property or a validator, or keep the module as source."""
    keep = compile_app.KEEP_AS_SOURCE | compile_app.RUN_AS_MAIN
    wrong = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if path.name == "__init__.py" or rel in keep:
            continue
        for cls in _model_classes(ast.parse(path.read_text(encoding="utf-8"))):
            for node in cls.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.decorator_list \
                        and not node.name.startswith("__"):
                    wrong.append(f"{rel}: {cls.name}.{node.name}")
    assert not wrong, wrong
