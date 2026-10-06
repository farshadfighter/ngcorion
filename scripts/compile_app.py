"""
Compile the NGCorion backend (the `app` package) to native extension modules.

Used by Dockerfile.ngcorion when it builds the production image: every
module under app/ becomes a compiled .so and its .py source is removed from
the image, so the code that enforces licensing and quotas (the license client
and middleware, main.py, the routers with their quota dependencies) cannot be
read or edited in place. Package __init__.py files stay as source; they only
mark packages. So do the few modules in KEEP_AS_SOURCE (below).

This raises the bar, it is not encryption: someone with root on the machine
can still observe the program while it runs. It is meant to stop a casual
edit of a .py file from switching the licensing off.

    python scripts/compile_app.py [--keep-sources] [--jobs N] [ROOT]

ROOT is the directory that contains app/ (default: the current directory).
Behaviour must stay exactly that of the source: annotations are not used as
C types (annotation_typing=False) and functions stay introspectable
(binding=True) for FastAPI's signature inspection.

Needs Cython 3.2.x (3.3.0 crashes on `(x or {}).items()`) and setuptools, a C
compiler and the Python headers of the interpreter that will run the app.
"""
import argparse
import os
import sys
from pathlib import Path


# Pydantic models with plain methods (or a computed_field) cannot be compiled:
# Pydantic only recognises Python functions in a model's namespace, and a
# compiled method is not one. These modules hold request/response schemas,
# no licensing or permission logic.
KEEP_AS_SOURCE = {
    "app/modules/assets/schemas.py",
    "app/modules/hardening/schemas/base.py",
    "app/modules/shared/schemas/base.py",
}

# Must always be compiled: if one of these ever lands in KEEP_AS_SOURCE the
# build fails rather than shipping the licensing code as editable source.
MUST_COMPILE = {
    "app/main.py",
    "app/core/config.py",
    "app/core/dependencies.py",
    "app/core/license_client.py",
    "app/core/license_keys.py",
    "app/core/license_state.py",
    "app/core/license_token.py",
    "app/core/machine_fingerprint.py",
    "app/middleware/license_middleware.py",
    "app/modules/license/router.py",
}


def sources(root: Path):
    """Every module of the app package except package markers and KEEP_AS_SOURCE."""
    for path in sorted((root / "app").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if path.name != "__init__.py" and rel not in KEEP_AS_SOURCE:
            yield path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    parser.add_argument("--keep-sources", action="store_true",
                        help="keep the .py files next to the compiled modules (for testing)")
    args = parser.parse_args(argv)

    from Cython.Build import cythonize
    from setuptools import Distribution, Extension
    from setuptools.command.build_ext import build_ext

    root = Path(args.root).resolve()
    os.chdir(root)
    clash = MUST_COMPILE & KEEP_AS_SOURCE
    if clash:
        print("licensing modules may not stay source:", *sorted(clash), file=sys.stderr)
        return 1
    files = [p.relative_to(root) for p in sources(root)]
    absent = {m for m in MUST_COMPILE if Path(m) not in files}
    if absent:
        print("expected modules not found:", *sorted(absent), file=sys.stderr)
        return 1
    extensions = [
        Extension(".".join(f.with_suffix("").parts), [str(f)]) for f in files
    ]
    compiled = cythonize(
        extensions,
        nthreads=args.jobs,
        quiet=True,
        compiler_directives={
            "language_level": "3",
            "binding": True,
            "annotation_typing": False,
            "embedsignature": False,
            "always_allow_keywords": True,
        },
    )
    dist = Distribution({"ext_modules": compiled})
    cmd = build_ext(dist)
    cmd.inplace = True
    cmd.parallel = args.jobs
    cmd.ensure_finalized()
    cmd.run()

    missing = [f for f in files if not list(f.parent.glob(f.stem + ".*.so"))]
    if missing:
        print("not compiled:", *missing, sep="\n  ", file=sys.stderr)
        return 1
    for f in files:
        f.with_suffix(".c").unlink(missing_ok=True)
        if not args.keep_sources:
            f.unlink()
    # No symbol tables or debug information in what ships: smaller, and less
    # to read for anyone taking the modules apart.
    import subprocess
    sos = [str(p) for p in Path("app").rglob("*.so")]
    subprocess.run(["strip", "--strip-unneeded", *sos], check=True)
    for build in root.glob("build"):
        if build.is_dir():
            import shutil
            shutil.rmtree(build)
    print(f"compiled {len(files)} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
