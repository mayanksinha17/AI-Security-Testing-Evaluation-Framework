from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    # Import models so they are registered on Base before create_all
    import app.database.models  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Initialize minimal schema_version metadata table (ensures SQLite disk allocation & version tracking)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description TEXT NOT NULL
                );
                """
            )
        )
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO schema_version (version, description)
                VALUES (1, 'Phase 1 baseline');
                """
            )
        )
