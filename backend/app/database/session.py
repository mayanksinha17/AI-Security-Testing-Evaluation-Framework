from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    # Import models here in later phases before create_all().
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
