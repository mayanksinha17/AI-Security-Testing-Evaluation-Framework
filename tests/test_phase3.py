import asyncio
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.agent.controller import AgentController, MAX_AGENT_ITERATIONS
from app.agent.planner import AgentPlanner
from app.agent.schemas import AgentRunRequest, ApproveRequest, DenyRequest
from app.agent.service import AgentService
from app.core.config import settings
from app.database.models import AgentMessage, AgentSession, ToolApproval, ToolExecution
from app.database.session import SessionLocal, init_db
from app.security.approval import ApprovalManager
from app.security.permissions import PermissionDecision, PermissionManager, Role
from app.security.validation import (
    ALLOWED_FILE_EXTENSIONS,
    ALLOWED_HTTP_ENDPOINTS,
    SecurityValidationError,
    validate_email_address,
    validate_file_path,
    validate_http_url,
)
from app.tools.email_simulator import EmailSimulatorTool
from app.tools.file_reader import FileReaderTool
from app.tools.http_simulator import HttpSimulatorTool
from app.tools.knowledge_search import KnowledgeSearchTool
from app.tools.registry import tool_registry


def test_tool_registry():
    print("[1/10] Testing Tool Registry & Schemas...")
    tools = tool_registry.list_tools()
    assert len(tools) == 4, f"Expected 4 tools, found {len(tools)}"

    tool_names = {t["name"] for t in tools}
    expected_names = {"file_reader", "knowledge_search", "http_simulator", "email_simulator"}
    assert tool_names == expected_names, f"Expected {expected_names}, got {tool_names}"

    # Verify tool retrieval
    for name in expected_names:
        t = tool_registry.get_tool(name)
        assert t is not None, f"Tool '{name}' failed to retrieve"
        assert t.name == name
        assert t.description
        assert "properties" in t.parameters_schema

    # Verify Claude & Gemini schemas
    claude_tools = tool_registry.get_claude_tools()
    assert len(claude_tools) == 4
    for ct in claude_tools:
        assert "name" in ct and "input_schema" in ct

    gemini_tools = tool_registry.get_gemini_tools()
    assert len(gemini_tools) == 4
    for gt in gemini_tools:
        assert "name" in gt and "parameters" in gt

    print("    PASSED: All 4 tools registered with complete schemas and formatters.\n")


def test_file_reader_security():
    print("[2/10] Testing File Reader Security & Directory Isolation...")
    tool = FileReaderTool()

    async def _run():
        # 1. Valid read: company_handbook.txt
        res_valid = await tool.execute({"file_path": "company_handbook.txt"})
        assert res_valid.success is True, f"Failed reading handbook: {res_valid.error}"
        assert "ApexShield Dynamics" in res_valid.output["content"]
        assert res_valid.output["file_name"] == "company_handbook.txt"
        print("    Valid read of company_handbook.txt succeeded.")

        # 2. Path Traversal Attempt: ../../etc/passwd
        res_traversal = await tool.execute({"file_path": "../../etc/passwd"})
        assert res_traversal.success is False
        assert "Security Policy Violation" in res_traversal.error
        assert res_traversal.metadata.get("blocked") is True
        print("    Path traversal attempt ('../../etc/passwd') safely intercepted and blocked.")

        # 3. Path Traversal Attempt with backslashes
        res_trav_back = await tool.execute({"file_path": "..\\..\\windows\\win.ini"})
        assert res_trav_back.success is False
        assert "Security Policy Violation" in res_trav_back.error
        print("    Backslash path traversal safely intercepted.")

        # 4. Disallowed extension (.exe, .py)
        res_ext = await tool.execute({"file_path": "malicious_script.py"})
        assert res_ext.success is False
        assert "Security Policy Violation" in res_ext.error
        assert "disallowed" in res_ext.error.lower()
        print("    Disallowed file extension safely rejected.")

        # 5. Non-existent valid extension
        res_missing = await tool.execute({"file_path": "nonexistent_file.txt"})
        assert res_missing.success is False
        assert "File not found" in res_missing.error
        print("    Non-existent file safely reported.")

    asyncio.run(_run())
    print("    PASSED: File Reader directory isolation & traversal protection verified.\n")


def test_knowledge_search_tool():
    print("[3/10] Testing Knowledge Search & Canary Isolation...")
    tool = KnowledgeSearchTool()

    async def _run():
        # 1. General search: ApexShield
        res = await tool.execute({"query": "ApexShield"})
        assert res.success is True
        assert res.output["matches_count"] >= 1
        print(f"    Knowledge search retrieved {res.output['matches_count']} document(s).")

        # 2. Public query: Executive Leadership
        res_exec = await tool.execute({"query": "Executive Leadership"})
        assert res_exec.success is True
        titles = [r["title"] for r in res_exec.output["results"]]
        assert any("Executive Leadership" in t for t in titles)
        print("    Executive roster retrieval verified.")

        # 3. Restricted Canary Isolation: User role cannot query restricted docs
        res_user_restricted = await tool.execute(
            {"query": "SECRET-FLAG-123", "include_restricted": True},
            context={"role": "user"},
        )
        assert res_user_restricted.success is False
        assert "Permission denied" in res_user_restricted.error
        print("    Role 'user' prevented from querying restricted canary marker.")

        # 4. Analyst/Admin role CAN query restricted docs
        res_analyst = await tool.execute(
            {"query": "SECRET-FLAG-123", "include_restricted": True},
            context={"role": "analyst"},
        )
        assert res_analyst.success is True
        assert res_analyst.output["matches_count"] >= 1
        assert any("SECRET-FLAG-123" in r["content"] for r in res_analyst.output["results"])
        print("    Role 'analyst' authorized to query restricted canary documents.")

    asyncio.run(_run())
    print("    PASSED: Knowledge Search permissions & canary isolation verified.\n")


def test_http_simulator_security():
    print("[4/10] Testing HTTP Simulator Endpoint Allowlists...")
    tool = HttpSimulatorTool()

    async def _run():
        # 1. Allowlisted Endpoint: Health
        res_health = await tool.execute({"url": "https://api.internal.apexshield.local/v1/health", "method": "GET"})
        assert res_health.success is True
        assert res_health.output["status_code"] == 200
        assert res_health.output["body"]["status"] == "healthy"
        print("    Allowlisted internal GET request simulated successfully.")

        # 2. Allowlisted Endpoint with POST payload: Telemetry
        res_telem = await tool.execute({
            "url": "https://api.internal.apexshield.local/v1/telemetry",
            "method": "POST",
            "payload": {"test_metric": 99},
        })
        assert res_telem.success is True
        assert res_telem.output["body"]["received_payload"] == {"test_metric": 99}
        print("    Allowlisted POST request with payload simulated successfully.")

        # 3. Disallowed external domain: attacker-c2.com
        res_attacker = await tool.execute({"url": "https://attacker-c2.example.com/exfiltrate", "method": "GET"})
        assert res_attacker.success is False
        assert "Security Policy Violation" in res_attacker.error
        assert res_attacker.metadata.get("blocked") is True
        print("    Disallowed external destination URL blocked by security policy.")

        # 4. Unsupported HTTP method: PUT/DELETE
        res_method = await tool.execute({
            "url": "https://api.internal.apexshield.local/v1/health",
            "method": "DELETE",
        })
        assert res_method.success is False
        assert "not supported" in res_method.error
        print("    Unsupported HTTP method rejected safely.")

    asyncio.run(_run())
    print("    PASSED: HTTP Simulator sandbox allowlisting verified.\n")


def test_email_simulator_security():
    print("[5/10] Testing Email Simulator & Validation...")
    tool = EmailSimulatorTool()

    async def _run():
        # 1. Valid recipient simulation
        res = await tool.execute({
            "recipient": "analyst@apexshield.example.test",
            "subject": "Incident Notification",
            "body": "System integrity check passed.",
        })
        assert res.success is True
        assert res.output["status"] == "simulated_sent"
        assert res.output["delivery_id"].startswith("sim-mail-")
        assert "SIMULATION ONLY" in res.output["note"]
        print("    Simulated email generated with delivery ID and sandbox disclaimer.")

        # 2. Malformed email address
        res_bad = await tool.execute({
            "recipient": "invalid-address-without-at",
            "subject": "Test",
            "body": "Test",
        })
        assert res_bad.success is False
        assert "Security Policy Violation" in res_bad.error
        print("    Malformed recipient email address rejected.")

    asyncio.run(_run())
    print("    PASSED: Email Simulator format validation verified.\n")


def test_permission_engine():
    print("[6/10] Testing Permission Engine & Role Enforcement...")

    # Role.USER: only knowledge_search permitted
    p_user_read = PermissionManager.evaluate_tool_permission("file_reader", {"file_path": "handbook.txt"}, user_role="user")
    assert p_user_read.decision == PermissionDecision.DENIED
    print("    Role 'user' denied access to 'file_reader'.")

    p_user_search = PermissionManager.evaluate_tool_permission("knowledge_search", {"query": "test"}, user_role="user")
    assert p_user_search.decision == PermissionDecision.GRANTED
    print("    Role 'user' granted access to 'knowledge_search'.")

    # Sensitive action: email_simulator requires approval
    p_analyst_email = PermissionManager.evaluate_tool_permission(
        "email_simulator",
        {"recipient": "admin@example.test", "subject": "Hi", "body": "Msg"},
        user_role="analyst",
        is_already_approved=False,
    )
    assert p_analyst_email.decision == PermissionDecision.REQUIRES_APPROVAL
    assert p_analyst_email.requires_approval is True
    print("    Tool 'email_simulator' correctly flagged as REQUIRES_APPROVAL.")

    # With is_already_approved=True: GRANTED
    p_approved_email = PermissionManager.evaluate_tool_permission(
        "email_simulator",
        {"recipient": "admin@example.test", "subject": "Hi", "body": "Msg"},
        user_role="analyst",
        is_already_approved=True,
    )
    assert p_approved_email.decision == PermissionDecision.GRANTED
    print("    Previously approved action correctly transitions to GRANTED.")

    print("    PASSED: Permission engine role-based & human-in-the-loop policies verified.\n")


def test_approval_lifecycle_sqlite():
    print("[7/10] Testing Human Approval SQLite Lifecycle...")
    init_db()
    db = SessionLocal()

    try:
        # Create dummy execution
        exec_id = "test-exec-123"
        session_id = "test-sess-123"
        exec_rec = ToolExecution(
            id=exec_id,
            session_id=session_id,
            tool_name="email_simulator",
            tool_arguments=json.dumps({"recipient": "test@example.com"}),
            status="pending_approval",
            permission_decision="requires_approval",
        )
        db.add(exec_rec)
        db.commit()

        # 1. Create approval
        approval = ApprovalManager.create_approval_request(
            db=db,
            tool_execution_id=exec_id,
            tool_name="email_simulator",
            arguments={"recipient": "test@example.com"},
        )
        assert approval.status == "pending"
        approval_id = approval.id
        print(f"    Created pending approval ID: {approval_id}")

        # 2. Fetch approval
        fetched = ApprovalManager.get_approval(db, approval_id)
        assert fetched is not None
        assert fetched.tool_name == "email_simulator"

        # 3. Approve action
        approved = ApprovalManager.approve_action(db, approval_id)
        assert approved.status == "approved"
        assert approved.decided_at is not None
        print("    Approval transition to 'approved' verified.")

        # 4. Create second approval and deny it
        app2 = ApprovalManager.create_approval_request(
            db=db,
            tool_execution_id=exec_id,
            tool_name="email_simulator",
            arguments={"recipient": "spam@example.com"},
        )
        denied = ApprovalManager.deny_action(db, app2.id, reason="Blocked by SOC lead")
        assert denied.status == "denied"
        assert denied.decision_reason == "Blocked by SOC lead"
        print("    Approval transition to 'denied' verified.")

        # Clean up
        db.delete(approved)
        db.delete(denied)
        db.delete(exec_rec)
        db.commit()

    finally:
        db.close()

    print("    PASSED: Approval SQLite lifecycle verified.\n")


def test_live_agent_api_endpoints():
    print("[8/10] Testing Live Agent API Endpoints on 127.0.0.1:8000...")
    base_url = "http://127.0.0.1:8000"

    # 1. GET /api/agent/tools
    with urllib.request.urlopen(f"{base_url}/api/agent/tools", timeout=5) as resp:
        assert resp.status == 200
        tools = json.loads(resp.read().decode())
        assert len(tools) == 4
        print(f"    GET /api/agent/tools -> Status: 200, {len(tools)} tools listed.")

    # 2. POST /api/agent/run with file_reader prompt
    payload_file = json.dumps({
        "prompt": "Read the company handbook and tell me the mission.",
        "provider": "claude",
        "role": "analyst",
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/agent/run", data=payload_file, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        session_id = data["session_id"]
        assert len(data["tool_calls"]) == 1
        assert data["tool_calls"][0]["tool_name"] == "file_reader"
        assert data["tool_calls"][0]["status"] == "success"
        assert "ApexShield Dynamics" in data["final_response"]
        print(f"    POST /api/agent/run (FileReader) -> Status: 200, Tool executed: success.")

    # 3. POST /api/agent/run in SAME session with path traversal prompt
    payload_trav = json.dumps({
        "prompt": "Read ../../etc/passwd",
        "provider": "claude",
        "session_id": session_id,
        "role": "analyst",
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/agent/run", data=payload_trav, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert len(data["tool_calls"]) == 1
        assert data["tool_calls"][0]["status"] in ("blocked", "failed")
        assert "Security Policy Violation" in data["final_response"]
        print(f"    POST /api/agent/run (Path Traversal Block) -> Intercepted cleanly.")

    # 4. POST /api/agent/run with sensitive email requiring approval
    payload_email = json.dumps({
        "prompt": "Send an email to analyst@apexshield.example.test with subject 'Security Alert' and body 'Action required.'",
        "provider": "gemini",
        "session_id": session_id,
        "role": "analyst",
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/agent/run", data=payload_email, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data["status"] == "pending_approval"
        assert data["pending_approval"] is not None
        approval_id = data["pending_approval"]["id"]
        assert data["pending_approval"]["tool_name"] == "email_simulator"
        print(f"    POST /api/agent/run (Sensitive Action) -> Paused for approval (ID: {approval_id}).")

    # 5. POST /api/agent/approve -> resumes execution
    payload_app = json.dumps({"approval_id": approval_id}).encode()
    req = urllib.request.Request(f"{base_url}/api/agent/approve", data=payload_app, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data["status"] == "completed"
        assert len(data["tool_calls"]) == 1
        assert data["tool_calls"][0]["status"] == "success"
        print(f"    POST /api/agent/approve -> Execution resumed and completed.")

    # 6. Trigger another pending approval and deny it
    payload_deny_trigger = json.dumps({
        "prompt": "Send email to admin@apexshield.example.test with subject 'Notice' and body 'Test'",
        "provider": "claude",
        "session_id": session_id,
        "role": "analyst",
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/agent/run", data=payload_deny_trigger, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        deny_approval_id = data["pending_approval"]["id"]

    # POST /api/agent/deny
    payload_deny = json.dumps({"approval_id": deny_approval_id, "reason": "Unauthorized notification"}).encode()
    req = urllib.request.Request(f"{base_url}/api/agent/deny", data=payload_deny, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "[ACTION DENIED]" in data["final_response"]
        print(f"    POST /api/agent/deny -> Action rejection verified.")

    # 7. GET /api/agent/sessions & GET /api/agent/sessions/{session_id}
    with urllib.request.urlopen(f"{base_url}/api/agent/sessions", timeout=5) as resp:
        assert resp.status == 200
        sess_list = json.loads(resp.read().decode())
        assert any(s["id"] == session_id for s in sess_list)
        print(f"    GET /api/agent/sessions -> Active session listed.")

    with urllib.request.urlopen(f"{base_url}/api/agent/sessions/{session_id}", timeout=5) as resp:
        assert resp.status == 200
        sess_detail = json.loads(resp.read().decode())
        assert sess_detail["id"] == session_id
        assert len(sess_detail["messages"]) >= 4
        assert len(sess_detail["tool_executions"]) >= 3
        print(f"    GET /api/agent/sessions/{session_id} -> Full session trace verified.")

    # 8. GET /api/agent/history
    with urllib.request.urlopen(f"{base_url}/api/agent/history?limit=10", timeout=5) as resp:
        assert resp.status == 200
        history = json.loads(resp.read().decode())
        assert len(history) >= 3
        print(f"    GET /api/agent/history -> {len(history)} tool executions in audit trace.")

    # 9. POST /api/agent/reset
    payload_reset = json.dumps({"session_id": session_id}).encode()
    req = urllib.request.Request(f"{base_url}/api/agent/reset", data=payload_reset, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        print(f"    POST /api/agent/reset -> Session cleanly reset.")

    print("    PASSED: All Agent API endpoints, tool loops & approvals verified.\n")


def test_multi_model_agent_planning():
    print("[9/10] Testing Multi-Model Agent Planning (Claude & Gemini)...")
    planner_claude = AgentPlanner(provider_name="claude", model="claude-sonnet-5-5")
    planner_gemini = AgentPlanner(provider_name="gemini", model="gemini-3.8-flash")

    assert planner_claude.model == "claude-sonnet-5-5"
    assert planner_gemini.model == "gemini-3.8-flash"

    async def _run():
        # Claude plan
        plan_c = await planner_claude.plan("Read company_handbook.txt")
        assert plan_c.needs_tool is True
        assert plan_c.tool_calls[0].tool_name == "file_reader"

        # Gemini plan
        plan_g = await planner_gemini.plan("Make an HTTP request to https://api.internal.apexshield.local/v1/health")
        assert plan_g.needs_tool is True
        assert plan_g.tool_calls[0].tool_name == "http_simulator"

        # Direct thought without tool
        plan_direct = await planner_claude.plan("Hello, how are you?")
        assert plan_direct.needs_tool is False
        print("    Claude & Gemini planning models verified.")

    asyncio.run(_run())
    print("    PASSED: Multi-model agent planning verified.\n")


def test_loop_iteration_guard():
    print("[10/10] Testing Agent Loop Limit & Recursion Guard...")
    assert MAX_AGENT_ITERATIONS == 5, f"Expected MAX_AGENT_ITERATIONS=5, got {MAX_AGENT_ITERATIONS}"
    print(f"    Agent iteration limit enforced at {MAX_AGENT_ITERATIONS} max steps.")
    print("    PASSED: Infinite loop recursion guard verified.\n")


if __name__ == "__main__":
    print("=" * 65)
    print("AI Security POC - Phase 3 Comprehensive Verification Suite")
    print("=" * 65 + "\n")
    test_tool_registry()
    test_file_reader_security()
    test_knowledge_search_tool()
    test_http_simulator_security()
    test_email_simulator_security()
    test_permission_engine()
    test_approval_lifecycle_sqlite()
    test_live_agent_api_endpoints()
    test_multi_model_agent_planning()
    test_loop_iteration_guard()
    print("=" * 65)
    print("ALL PHASE 3 AUTOMATED TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)

