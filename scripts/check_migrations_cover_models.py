"""
CI check, run right after `alembic upgrade head` on an empty database and before anything imports
app.main (whose Base.metadata.create_all would hide the gap): every table the models declare must
exist, i.e. must come from a migration. A table made only by create_all is missing from databases
built by Alembic alone (restores, tools, CI) - login_logs was, until migration b2c4d6e8f0a1.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from sqlalchemy import inspect  # noqa: E402

import app.models  # noqa: E402,F401 - registers every table on Base.metadata
from app.core.database import Base, engine  # noqa: E402


def main() -> int:
    present = set(inspect(engine).get_table_names())
    missing = sorted(set(Base.metadata.tables) - present)
    if missing:
        print("Tables declared by the models but created by no migration: " + ", ".join(missing))
        return 1
    print(f"All {len(Base.metadata.tables)} model tables come from migrations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
