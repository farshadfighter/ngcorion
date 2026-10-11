"""
Every `python -m app....` command the documentation gives must still run in the production image,
where scripts/compile_app.py turns modules into native extensions: `python -m` needs a code object,
which a compiled module does not have, so each one has to be in RUN_AS_MAIN (kept as source).
"""
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
