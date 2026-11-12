import sys
import os
import urllib.request
import json
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.database.session import init_db, engine
from sqlalchemy import text


def test_settings_and_cors_origins():
    print("[1/3] Testing Settings and CORS Configuration...")
    print(f"    App Name: {settings.app_name}")
    print(f"    App Env: {settings.app_env}")
    print(f"    Database URL: {settings.database_url}")
    print(f"    Frontend Origin: {settings.frontend_origin}")
    print(f"    Configured CORS Origins: {settings.cors_origins}")

    assert "http://localhost:5173" in settings.cors_origins, "localhost:5173 missing from cors_origins"
    assert "http://127.0.0.1:5173" in settings.cors_origins, "127.0.0.1:5173 missing from cors_origins"
    print("    PASSED: Settings and CORS origins verified.\n")


def test_sqlite_verification():
    print("[2/3] TASK 1: SQLite Verification & Persistence...")
    # 1. Run init_db (creates schema_version if not exists)
    init_db()

    # Verify schema_version table exists and has seed row
    with engine.connect() as conn:
        schema_rows = conn.execute(text("SELECT version, description, applied_at FROM schema_version;")).fetchall()
        print(f"    schema_version entries: {schema_rows}")
        assert len(schema_rows) >= 1, "schema_version table is empty"
        assert schema_rows[0][0] == 1, "Expected baseline version 1"

    # 2. Insert temporary test record
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS test_persistence (id INTEGER PRIMARY KEY, note TEXT);"))
        conn.execute(text("DELETE FROM test_persistence;"))
        conn.execute(text("INSERT INTO test_persistence (id, note) VALUES (42, 'sqlite_persists');"))
        print("    Inserted temporary record (id=42, note='sqlite_persists') into test_persistence")

    # 3. Close the database connection pool
    engine.dispose()
    print("    Closed database connection pool (engine.dispose())")

    # 4. Reopen database and verify record persists
    with engine.connect() as conn:
        result = conn.execute(text("SELECT note FROM test_persistence WHERE id = 42;")).fetchone()
        print(f"    Reopened database and fetched: {result}")
        assert result is not None and result[0] == "sqlite_persists", "Record did not persist across connection cycles!"

    # 5. Verify initialization is safe to run repeatedly (idempotency check)
    init_db()
    init_db()
    with engine.connect() as conn:
        schema_rows = conn.execute(text("SELECT version FROM schema_version;")).fetchall()
        assert len(schema_rows) == 1, f"Expected exactly 1 baseline version, found {len(schema_rows)}"
    print("    Verified init_db() is idempotent and safe to run repeatedly")

    # 6. Remove temporary test data after verification
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE test_persistence;"))
    print("    Cleaned up temporary test table test_persistence")

    # 7. Check database file existence and non-zero size
    db_candidates = [
        backend_dir / "ai_security_poc.db",
        Path.cwd() / "ai_security_poc.db",
    ]
    for db_path in db_candidates:
        if db_path.exists():
            size = db_path.stat().st_size
            print(f"    Database file verified at: {db_path} (size = {size} bytes)")
            assert size > 0, f"Database file {db_path} has 0 bytes!"

    print("    PASSED: SQLite initialization, non-zero file size, and persistence verified.\n")


def test_live_fastapi_endpoints_and_cors():
    print("[3/3] Testing Live FastAPI Endpoints & CORS on 127.0.0.1:8000...")
    base_url = "http://127.0.0.1:8000"

    # 1. Root endpoint
    with urllib.request.urlopen(f"{base_url}/", timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        print(f"    GET / -> Status: {resp.status}, Body: {data}")
        assert data.get("message") == "AI Security POC API is running"

    # 2. Health endpoint
    with urllib.request.urlopen(f"{base_url}/api/health", timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        print(f"    GET /api/health -> Status: {resp.status}, Body: {data}")
        assert data.get("status") == "ok"
        assert data.get("application") == "AI Security POC"
        assert "timestamp" in data

    # 3. CORS localhost:5173
    req = urllib.request.Request(f"{base_url}/api/health", headers={"Origin": "http://localhost:5173"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        allow_origin = resp.headers.get("Access-Control-Allow-Origin")
        print(f"    CORS localhost:5173 -> Access-Control-Allow-Origin: {allow_origin}")
        assert allow_origin == "http://localhost:5173"

    # 4. CORS 127.0.0.1:5173
    req = urllib.request.Request(f"{base_url}/api/health", headers={"Origin": "http://127.0.0.1:5173"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        allow_origin = resp.headers.get("Access-Control-Allow-Origin")
        print(f"    CORS 127.0.0.1:5173 -> Access-Control-Allow-Origin: {allow_origin}")
        assert allow_origin == "http://127.0.0.1:5173"

    # 5. OPTIONS preflight
    req = urllib.request.Request(
        f"{base_url}/api/health",
        method="OPTIONS",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        allow_origin = resp.headers.get("Access-Control-Allow-Origin")
        allow_methods = resp.headers.get("Access-Control-Allow-Methods")
        print(f"    CORS Preflight OPTIONS -> Allow-Origin: {allow_origin}, Allow-Methods: {allow_methods}")
        assert allow_origin == "http://localhost:5173"

    print("\n    PASSED: All FastAPI endpoints and CORS responses verified.\n")


if __name__ == "__main__":
    print("=" * 65)
    print("AI Security POC - Phase 1 Final Verification Suite")
    print("=" * 65 + "\n")
    test_settings_and_cors_origins()
    test_sqlite_verification()
    test_live_fastapi_endpoints_and_cors()
    print("=" * 65)
    print("ALL PHASE 1 FINAL VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)
