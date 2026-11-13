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

        # Migrate security_audit_logs columns safely if missing
        try:
            table_info = conn.execute(text("PRAGMA table_info(security_audit_logs);")).fetchall()
            existing_cols = {row[1] for row in table_info}
            audit_cols = [
                ("security_component", "TEXT DEFAULT 'SecurityPipeline'"),
                ("tool_name", "TEXT DEFAULT 'N/A'"),
                ("execution_stage", "TEXT DEFAULT 'POST_MITIGATION'"),
                ("execution_status", "TEXT DEFAULT 'BLOCKED'"),
                ("authorization_decision", "TEXT DEFAULT 'BLOCKED'"),
            ]
            for col_name, col_def in audit_cols:
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE security_audit_logs ADD COLUMN {col_name} {col_def};"))
        except Exception:
            pass
