"""
Database configuration and session management.

Provides SQLAlchemy engine, session factory, and database dependency
for FastAPI endpoints.
"""
import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

logger = logging.getLogger(__name__)

# Create database engine with connection pooling
# pool_size: Number of permanent connections to keep
# max_overflow: Additional connections allowed beyond pool_size
# pool_pre_ping: Test connections before use (handles stale connections)
# pool_recycle: Recycle connections after N seconds (prevents timeout issues)
#
# Configuration adjusted for concurrent audit operations:
# - pool_size=20: Support up to 20 concurrent database connections
# - max_overflow=30: Allow up to 30 additional temporary connections under load
# - This allows ~50 concurrent operations before connection queueing
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=getattr(settings, 'DB_POOL_SIZE', 20),  # Increased from 5 for concurrent audits
    max_overflow=getattr(settings, 'DB_MAX_OVERFLOW', 30),  # Increased from 10
    pool_pre_ping=True,
    pool_recycle=3600,  # Recycle connections after 1 hour
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative base for ORM models
Base = declarative_base()


def get_db():
    """
    Dependency that provides a database session.

    Creates a new session for each request, yields it to the endpoint,
    and ensures it is closed after the request finishes.

    Usage:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_session_usable(db) -> None:
    """
    Recover a session that a failed flush left in pending-rollback state.

    Error handlers routinely run right after a DB error (a value too long for a
    column, a constraint violation). Without this rollback the next statement —
    the one writing the failure state, or the audit-log entry — raises
    PendingRollbackError, which replaces the real error in the HTTP 500 and
    loses the record of what happened.

    Rolls back only an already-doomed transaction, so calling it on the success
    path is a no-op.
    """
    try:
        if not db.is_active:
            db.rollback()
    except Exception as exc:  # noqa: BLE001 - recovery is best-effort
        logger.warning("rollback of the doomed session failed: %s", exc)
