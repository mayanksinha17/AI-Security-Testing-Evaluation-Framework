from pathlib import Path
import sys
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.database.session import init_db


@pytest.fixture(scope="session", autouse=True)
def initialize_database():
    """Ensure database tables and schema migrations are initialized for all test sessions."""
    init_db()
