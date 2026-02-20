"""
Nuitka entry point for the Netease backend server.

This file is passed to `nuitka` as the compilation target.
When running as a compiled standalone binary, it changes the working directory
to the binary's own directory so that .env, alembic.ini, and alembic/ are
resolved correctly by pydantic-settings and Alembic.
"""
import os
import sys
from pathlib import Path

# In Nuitka standalone mode, chdir to the binary's directory so that
# .env, alembic.ini, and alembic/ are found relative to CWD.
if "__compiled__" in dir():
    os.chdir(Path(sys.executable).parent)

import uvicorn
from app.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="info",
    )
