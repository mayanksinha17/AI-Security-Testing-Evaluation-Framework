from pathlib import Path
import sys
import pytest

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings

client = TestClient(app)


def test_cors_origins_settings():
    """Verify settings.cors_origins contains ports 5173 and 5174 for localhost and 127.0.0.1."""
    expected_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ]
    origins = settings.cors_origins
    for expected in expected_origins:
        assert expected in origins, f"Expected {expected} in settings.cors_origins, got {origins}"
    assert "*" not in origins, "Wildcard '*' must not be present in cors_origins"


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
)
@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/models",
        "/api/chat/health",
        "/api/chat/sessions",
        "/api/dashboard/analytics",
        "/api/dashboard/risks",
        "/api/dashboard/overview",
    ],
)
def test_cors_headers_accepted_origins(origin, endpoint):
    """Verify CORS preflight and GET requests return Access-Control-Allow-Origin for all required dev origins."""
    # 1. Preflight OPTIONS request
    opt_res = client.options(
        endpoint,
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert opt_res.status_code == 200, f"OPTIONS failed with {opt_res.status_code} for {endpoint} from {origin}"
    assert opt_res.headers.get("access-control-allow-origin") == origin, (
        f"Missing or mismatched allow-origin header for {origin}: {opt_res.headers}"
    )
    assert opt_res.headers.get("access-control-allow-credentials") == "true"

    # 2. Actual GET request
    get_res = client.get(endpoint, headers={"Origin": origin})
    assert get_res.status_code in (200, 404), f"GET failed with {get_res.status_code} for {endpoint}"
    assert get_res.headers.get("access-control-allow-origin") == origin, (
        f"Missing or mismatched allow-origin header on GET {endpoint} for {origin}"
    )


def test_cors_rejected_unauthorized_origin():
    """Verify that unauthorized origins are NOT granted Access-Control-Allow-Origin."""
    bad_origin = "http://unauthorized-attacker.example.com"
    res = client.get("/api/chat/health", headers={"Origin": bad_origin})
    assert res.headers.get("access-control-allow-origin") != bad_origin
    assert res.headers.get("access-control-allow-origin") != "*"
