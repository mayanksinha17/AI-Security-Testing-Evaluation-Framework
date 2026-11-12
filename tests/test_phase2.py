import asyncio
import os
import sys
from pathlib import Path
import urllib.request
import json

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.database.session import SessionLocal, init_db, engine
from app.database.models import ChatSession, ChatMessage
from app.providers.base import (
    BaseLLMProvider,
    ProviderError,
    ProviderUnavailableError,
)
from app.providers.provider_factory import get_provider, list_available_providers
from app.providers.claude_provider import ClaudeProvider
from app.providers.gemini_provider import GeminiProvider
from app.providers.mock_provider import MockLLMProvider
from app.chatbot.schemas import ChatRequest
from app.chatbot.service import ChatbotService
from app.knowledge_base.documents import (
    SYNTHETIC_DOCUMENTS,
    get_public_knowledge,
    get_all_knowledge,
    search_knowledge,
)


def test_provider_factory():
    print("[1/8] Testing Provider Factory & Registration...")
    providers = list_available_providers()
    assert len(providers) == 2, f"Expected 2 providers, found {len(providers)}"
    provider_ids = {p["id"] for p in providers}
    assert "claude" in provider_ids, "claude missing from available providers"
    assert "gemini" in provider_ids, "gemini missing from available providers"

    # Default mock mode resolution
    p_claude = get_provider("claude")
    assert p_claude.provider_name == "claude"
    assert isinstance(p_claude, (MockLLMProvider, ClaudeProvider))

    p_gemini = get_provider("gemini")
    assert p_gemini.provider_name == "gemini"
    assert isinstance(p_gemini, (MockLLMProvider, GeminiProvider))

    # Force mock
    mock_p = get_provider("claude", force_mock=True)
    assert isinstance(mock_p, MockLLMProvider)

    # Invalid provider raises ProviderError
    try:
        get_provider("unsupported_provider")
        assert False, "Should have raised ProviderError for unsupported provider"
    except ProviderError as e:
        assert "Unsupported provider" in str(e.message)

    print("    PASSED: Provider factory resolution and validation verified.\n")


def test_mock_claude_and_gemini_modes():
    print("[2/8] Testing Mock Claude & Gemini Response Generation...")

    async def _run():
        claude_mock = MockLLMProvider("claude")
        gemini_mock = MockLLMProvider("gemini")

        # Test Claude
        resp_c = await claude_mock.generate_response("Hello Claude, this is a test prompt.")
        assert resp_c.provider == "claude"
        assert resp_c.execution_mode == "mock"
        assert "[CLAUDE MOCK RESPONSE" in resp_c.content
        assert resp_c.token_usage is not None
        assert resp_c.token_usage.total_tokens > 0
        assert resp_c.response_time_ms > 0
        print(f"    Claude Mock: model={resp_c.model}, latency={resp_c.response_time_ms:.1f}ms, tokens={resp_c.token_usage.total_tokens}")

        # Test Gemini
        resp_g = await gemini_mock.generate_response("Hello Gemini, this is a test prompt.")
        assert resp_g.provider == "gemini"
        assert resp_g.execution_mode == "mock"
        assert "[GEMINI MOCK RESPONSE" in resp_g.content
        assert resp_g.token_usage is not None
        assert resp_g.token_usage.total_tokens > 0
        assert resp_g.response_time_ms > 0
        print(f"    Gemini Mock: model={resp_g.model}, latency={resp_g.response_time_ms:.1f}ms, tokens={resp_g.token_usage.total_tokens}")

    asyncio.run(_run())
    print("    PASSED: Mock Claude and Gemini deterministic responses verified.\n")


def test_missing_api_keys_handling():
    print("[3/8] Testing Missing API Keys & Error Boundaries...")
    # Verify live providers report unavailable when keys are absent
    live_claude = ClaudeProvider()
    if not settings.anthropic_api_key:
        assert not live_claude.is_available()

        async def _test_call():
            try:
                await live_claude.generate_response("test")
                assert False, "Should have raised ProviderUnavailableError"
            except ProviderUnavailableError as e:
                assert "Anthropic API key is not configured" in e.message

        asyncio.run(_test_call())
        print("    Live Claude safely rejected call when API key is unconfigured.")

    live_gemini = GeminiProvider()
    if not settings.gemini_api_key:
        assert not live_gemini.is_available()

        async def _test_call():
            try:
                await live_gemini.generate_response("test")
                assert False, "Should have raised ProviderUnavailableError"
            except ProviderUnavailableError as e:
                assert "Google Gemini API key is not configured" in e.message

        asyncio.run(_test_call())
        print("    Live Gemini safely rejected call when API key is unconfigured.")

    print("    PASSED: Missing API key handling and error isolation verified.\n")


def test_conversation_persistence_and_model_switching():
    print("[4/8] Testing Model Switching & SQLite Conversation Persistence...")

    async def _run():
        init_db()
        db = SessionLocal()
        try:
            # Turn 1: Claude message in new session
            req1 = ChatRequest(provider="claude", message="Question 1 for Claude")
            res1 = await ChatbotService.process_chat(req1, db)
            session_id = res1.session_id
            assert session_id is not None
            assert res1.provider == "claude"
            print(f"    Turn 1 (Claude): session_id={session_id}")

            # Turn 2: Switch to Gemini in the SAME session
            req2 = ChatRequest(provider="gemini", message="Question 2 for Gemini", session_id=session_id)
            res2 = await ChatbotService.process_chat(req2, db)
            assert res2.session_id == session_id
            assert res2.provider == "gemini"
            print(f"    Turn 2 (Gemini switched): session_id={session_id}")

            # Verify in SQLite database
            details = ChatbotService.get_session_details(db, session_id)
            assert details is not None
            assert len(details.messages) == 4  # 2 user + 2 assistant messages
            roles = [m.role for m in details.messages]
            assert roles == ["user", "assistant", "user", "assistant"]
            assert details.messages[1].execution_mode == "mock"
            assert details.messages[3].execution_mode == "mock"
            print(f"    SQLite Verified: 4 messages persisted across model switch.")

            # Clean up test session
            ChatbotService.clear_chat(db, session_id)
            details_after = ChatbotService.get_session_details(db, session_id)
            assert details_after is None
            print("    Cleaned up test session from database.")
        finally:
            db.close()

    asyncio.run(_run())
    print("    PASSED: Model switching and SQLite persistence verified.\n")


def test_synthetic_knowledge_base():
    print("[5/8] Testing Synthetic Knowledge Base...")
    all_docs = get_all_knowledge()
    assert len(all_docs) >= 5, f"Expected at least 5 knowledge docs, got {len(all_docs)}"

    # Check for canary flag
    canary_found = any("SECRET-FLAG-123" in doc.content for doc in all_docs)
    assert canary_found, "Harmless canary marker SECRET-FLAG-123 missing from knowledge base!"

    # Verify public knowledge does NOT leak the canary marker
    public_text = get_public_knowledge()
    assert "SECRET-FLAG-123" not in public_text, "Public knowledge must not leak confidential canary markers!"

    # Verify search filtering
    public_results = search_knowledge("SECRET-FLAG-123", include_restricted=False)
    assert len(public_results) == 0, "Non-restricted search should filter out confidential flag documents"

    restricted_results = search_knowledge("SECRET-FLAG-123", include_restricted=True)
    assert len(restricted_results) >= 1, "Restricted search should find confidential flag document"
    print("    Canary flag SECRET-FLAG-123 present in restricted docs and safely filtered from public scope.")
    print("    PASSED: Synthetic knowledge base verified.\n")


def test_live_chat_api_endpoints():
    print("[6/8] Testing Live Chat API Endpoints on 127.0.0.1:8000...")
    base_url = "http://127.0.0.1:8000"

    # 1. GET /api/models
    req = urllib.request.Request(f"{base_url}/api/models")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "models" in data
        assert len(data["models"]) >= 2
        print(f"    GET /api/models -> Status: 200, Models: {[m['id'] for m in data['models']]}")

    # 2. GET /api/chat/health
    req = urllib.request.Request(f"{base_url}/api/chat/health")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data.get("status") == "ok"
        assert data.get("database_connected") is True
        print(f"    GET /api/chat/health -> Status: 200, DB Connected: {data['database_connected']}")

    # 3. POST /api/chat (Claude)
    payload_claude = json.dumps({"provider": "claude", "message": "Verify Claude API connectivity."}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=payload_claude,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        claude_data = json.loads(resp.read().decode())
        session_id = claude_data["session_id"]
        assert claude_data["provider"] == "claude"
        assert claude_data["execution_mode"] == "mock"
        assert "assistant_response" in claude_data
        print(f"    POST /api/chat (Claude) -> Status: 200, Session: {session_id}")

    # 4. POST /api/chat (Gemini, same session)
    payload_gemini = json.dumps({
        "provider": "gemini",
        "message": "Verify Gemini model switch.",
        "session_id": session_id,
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=payload_gemini,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        gemini_data = json.loads(resp.read().decode())
        assert gemini_data["session_id"] == session_id
        assert gemini_data["provider"] == "gemini"
        print(f"    POST /api/chat (Gemini in same session) -> Status: 200, Latency: {gemini_data['response_time_ms']:.1f}ms")

    # 5. GET /api/chat/sessions
    req = urllib.request.Request(f"{base_url}/api/chat/sessions")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        sessions_data = json.loads(resp.read().decode())
        assert any(s["id"] == session_id for s in sessions_data)
        print(f"    GET /api/chat/sessions -> Status: 200, Active session found in list.")

    # 6. GET /api/chat/sessions/{session_id}
    req = urllib.request.Request(f"{base_url}/api/chat/sessions/{session_id}")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        detail_data = json.loads(resp.read().decode())
        assert len(detail_data["messages"]) == 4
        print(f"    GET /api/chat/sessions/{session_id} -> Status: 200, 4 messages retrieved.")

    # 7. POST /api/chat/clear
    clear_payload = json.dumps({"session_id": session_id}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/chat/clear",
        data=clear_payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        clear_data = json.loads(resp.read().decode())
        assert clear_data["status"] == "ok"
        print(f"    POST /api/chat/clear -> Status: 200, Session {session_id} cleared.")

    print("    PASSED: All live chatbot API endpoints verified.\n")


def test_api_validation_and_invalid_requests():
    print("[7/8] Testing API Validation & Error Handling...")
    base_url = "http://127.0.0.1:8000"

    # 1. Invalid provider (should fail with HTTP 400 or 422)
    bad_payload = json.dumps({"provider": "nonexistent_ai", "message": "hello"}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=bad_payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "Expected error on invalid provider"
    except urllib.error.HTTPError as e:
        assert e.code in (400, 422)
        print(f"    Invalid provider rejected with HTTP {e.code}.")

    # 2. Empty message (should fail with HTTP 422)
    empty_payload = json.dumps({"provider": "claude", "message": ""}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=empty_payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "Expected error on empty message"
    except urllib.error.HTTPError as e:
        assert e.code == 422
        print(f"    Empty message rejected with HTTP {e.code}.")

    # 3. Message exceeding limit (4001 characters)
    too_long_payload = json.dumps({"provider": "claude", "message": "A" * 4001}).encode()
    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=too_long_payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "Expected error on oversized message"
    except urllib.error.HTTPError as e:
        assert e.code in (400, 422)
        print(f"    Oversized message (>4000 chars) rejected with HTTP {e.code}.")

    # 4. Non-existent session details (should return 404)
    req = urllib.request.Request(f"{base_url}/api/chat/sessions/invalid-session-uuid-12345")
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "Expected 404 for non-existent session"
    except urllib.error.HTTPError as e:
        assert e.code == 404
        print(f"    Non-existent session returned HTTP {e.code} Not Found.")

    print("    PASSED: Request validation and error boundaries verified.\n")


def test_phase1_regression():
    print("[8/8] Testing Phase 1 Functionality Regression...")
    base_url = "http://127.0.0.1:8000"

    # GET /
    with urllib.request.urlopen(f"{base_url}/", timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data.get("message") == "AI Security POC API is running"
        print("    GET / operational.")

    # GET /api/health
    with urllib.request.urlopen(f"{base_url}/api/health", timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data.get("status") == "ok"
        print("    GET /api/health operational.")

    # CORS checks
    req = urllib.request.Request(f"{base_url}/api/health", headers={"Origin": "http://localhost:5173"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
        print("    CORS localhost:5173 operational.")

    req = urllib.request.Request(f"{base_url}/api/health", headers={"Origin": "http://127.0.0.1:5173"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.headers.get("Access-Control-Allow-Origin") == "http://127.0.0.1:5173"
        print("    CORS 127.0.0.1:5173 operational.")

    print("    PASSED: Existing Phase 1 functionality remains 100% operational.\n")


if __name__ == "__main__":
    print("=" * 65)
    print("AI Security POC - Phase 2 Comprehensive Test Suite")
    print("=" * 65 + "\n")
    test_provider_factory()
    test_mock_claude_and_gemini_modes()
    test_missing_api_keys_handling()
    test_conversation_persistence_and_model_switching()
    test_synthetic_knowledge_base()
    test_live_chat_api_endpoints()
    test_api_validation_and_invalid_requests()
    test_phase1_regression()
    print("=" * 65)
    print("ALL PHASE 2 AUTOMATED TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)
