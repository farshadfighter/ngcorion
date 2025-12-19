"""
Database configuration and session management.

Provides SQLAlchemy engine, session factory, and database dependency
for FastAPI endpoints.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

# Create database engine with connection pooling
# pool_size: Number of permanent connections to keep
# max_overflow: Additional connections allowed beyond pool_size
# pool_pre_ping: Test connections before use (handles stale connections)
# pool_recycle: Recycle connections after N seconds (prevents timeout issues)
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=5,
    max_overflow=10,
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