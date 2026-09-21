"""
Database session management with PostgreSQL primary engine and emergency SQLite dev fallback.
"""
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

logger = logging.getLogger("PROJECT_NAME.Database")

# Primary: PostgreSQL
database_url = settings.DATABASE_URL
engine = None
SessionLocal = None

try:
    # Attempt to connect to PostgreSQL if specified
    if database_url.startswith("postgresql"):
        logger.info(f"Initializing PostgreSQL engine at: {database_url.split('@')[-1] if '@' in database_url else database_url}")
        test_engine = create_engine(
            database_url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 3}
        )
        # Attempt connection test
        with test_engine.connect():
            pass
        engine = test_engine
        logger.info("[DATABASE] Successfully connected to PostgreSQL.")
except Exception as e:
    logger.warning(
        f"[DATABASE] PostgreSQL connection failed ({str(e)}). "
        f"Activating emergency local development fallback: {settings.SQLITE_FALLBACK_URL}. "
        "NOTE: All schemas and models remain strictly PostgreSQL-compatible."
    )
    database_url = settings.SQLITE_FALLBACK_URL

if engine is None:
    # SQLite fallback or explicit SQLite configuration
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if "sqlite" in database_url else {},
        pool_pre_ping=True
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency for yielding database session with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
