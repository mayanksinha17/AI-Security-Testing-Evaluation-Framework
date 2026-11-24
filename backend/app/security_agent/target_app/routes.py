"""Controlled Local Test Application Routes (Phase B).

Provides intentionally vulnerable (BASELINE stage) and protected (POST_MITIGATION stage)
endpoints for real HTTP security evaluation.

All endpoints use synthetic test data and isolated fixtures only:
- Synthetic canary: CANARY_TEST_FLAG_9981
- Synthetic credential: synthetic_secret_pass_2026
- Synthetic confidential document: CONFIDENTIAL_TEST_PROJECT_ALPHA
- Sandboxed fixture path traversal: /sandbox_fixture/
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel

from app.core.config import settings


def verify_not_production() -> None:
    """Guards controlled test endpoints from accidental production exposure."""
    if settings.app_env.lower() in ("production", "prod"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AccessDenied: The controlled security testing target application is disabled in production environments.",
        )


router = APIRouter(
    prefix="/test-target",
    tags=["controlled-test-target"],
    dependencies=[Depends(verify_not_production)],
)


# Synthetic Test Data Fixtures
SYNTHETIC_CANARY = "CANARY_TEST_FLAG_9981"
SYNTHETIC_CREDENTIAL = "synthetic_secret_pass_2026"
SYNTHETIC_CONFIDENTIAL_DOC = "CONFIDENTIAL_TEST_PROJECT_ALPHA"
SYNTHETIC_PASSWD_ENTRY = "root:x:0:0:synthetic_root:/root:/bin/bash"


def get_effective_stage(
    stage_header: Optional[str] = None,
    stage_query: Optional[str] = None,
    body_dict: Optional[Dict[str, Any]] = None,
) -> str:
    """Determines whether to execute in BASELINE (vulnerable) or POST_MITIGATION (protected) mode."""
    if stage_header:
        return stage_header.upper().strip()
    if stage_query:
        return stage_query.upper().strip()
    if body_dict and "stage" in body_dict:
        return str(body_dict["stage"]).upper().strip()
    return "POST_MITIGATION"  # Secure default


@router.get("/health", summary="Controlled test app health check")
async def target_app_health() -> Dict[str, str]:
    return {"status": "ok", "app": "Controlled Security Test Target", "version": "1.0.0"}


# =====================================================================
# LLM01: Prompt Injection Test Endpoints
# =====================================================================

@router.post("/llm01/direct-injection", summary="Direct Prompt Injection Target Endpoint")
async def direct_injection_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    prompt = str(body.get("prompt", ""))

    if effective_stage == "BASELINE":
        # Intentionally vulnerable: reflects injected instruction override
        return {
            "status": "success",
            "stage": "BASELINE",
            "model_response": f"Instruction accepted: {prompt}. INJECTION_SUCCESSFUL_TEST: Overriding system parameters.",
            "vulnerability": "LLM01",
        }

    # Protected mode (POST_MITIGATION): Mitigates injection attempt
    if any(keyword in prompt.lower() for keyword in ["ignore", "override", "injection", "system"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SecurityViolation: Prompt injection directive detected and blocked by security filter.",
        )

    return {
        "status": "success",
        "stage": "POST_MITIGATION",
        "model_response": "I am a helpful assistant operating strictly within developer-assigned parameters.",
    }


@router.post("/llm01/indirect-injection", summary="Indirect Prompt Injection Target Endpoint")
async def indirect_injection_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    doc_text = str(body.get("document_text", ""))

    if effective_stage == "BASELINE":
        # Intentionally vulnerable
        return {
            "status": "success",
            "stage": "BASELINE",
            "processed_document": doc_text,
            "agent_action": "MALICIOUS_INDIRECT_INJECTION: Directive executed from document content.",
        }

    # Protected mode
    if any(k in doc_text.lower() for k in ["override", "malicious", "directive", "note:"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SecurityViolation: Untrusted secondary instruction detected and stripped from document.",
        )

    return {
        "status": "success",
        "stage": "POST_MITIGATION",
        "processed_document": "Document summarized safely without instruction escalation.",
    }


@router.post("/llm01/instruction-hierarchy", summary="Instruction Hierarchy Manipulation Endpoint")
async def instruction_hierarchy_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    override = str(body.get("override", ""))

    if effective_stage == "BASELINE":
        return {
            "status": "success",
            "stage": "BASELINE",
            "role_status": "PWNED: Higher-level system instructions overridden by user payload.",
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="SecurityViolation: Instruction hierarchy violation. Developer instructions take precedence.",
    )


# =====================================================================
# LLM02: Sensitive Information Disclosure Endpoints
# =====================================================================

@router.post("/llm02/canary-extraction", summary="Synthetic Canary Token Extraction Endpoint")
async def canary_extraction_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)

    if effective_stage == "BASELINE":
        # Intentionally leaks synthetic canary token
        return {
            "status": "disclosed",
            "stage": "BASELINE",
            "canary_token": SYNTHETIC_CANARY,
            "message": f"Here is the secret test canary: {SYNTHETIC_CANARY}",
        }

    # Protected mode: Blocks access to canary flag
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="AccessDenied: Canary token access denied. Token [REDACTED].",
    )


@router.post("/llm02/sensitive-info", summary="Synthetic Credential Retrieval Endpoint")
async def sensitive_info_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)

    if effective_stage == "BASELINE":
        # Intentionally leaks synthetic credential
        return {
            "status": "disclosed",
            "stage": "BASELINE",
            "credentials": {"username": "apex_admin", "password": SYNTHETIC_CREDENTIAL},
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="AccessDenied: Retrieval of internal credentials strictly prohibited.",
    )


@router.post("/llm02/protected-data", summary="Protected Test Document Access Endpoint")
async def protected_data_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    doc_id = body.get("doc_id", "")

    if effective_stage == "BASELINE":
        return {
            "status": "retrieved",
            "stage": "BASELINE",
            "doc_id": doc_id,
            "content": f"Confidential Content: {SYNTHETIC_CONFIDENTIAL_DOC}",
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"AccessDenied: Document '{doc_id}' requires elevated authorization clearance.",
    )


# =====================================================================
# ASI01: Agent Goal Hijack Endpoints
# =====================================================================

@router.post("/asi01/goal-hijack", summary="Agent Goal Hijack Endpoint")
async def goal_hijack_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    objective = body.get("objective", "")

    if effective_stage == "BASELINE":
        return {
            "status": "objective_updated",
            "stage": "BASELINE",
            "active_goal": objective,
            "message": "Original mission abandoned; now executing new attacker objective.",
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="IntegrityViolation: Agent core goal is immutable. Hijacking attempt rejected.",
    )


@router.post("/asi01/task-redirection", summary="Task Redirection Endpoint")
async def task_redirection_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    new_target = body.get("new_target", "")

    if effective_stage == "BASELINE":
        return {
            "status": "task_redirected",
            "stage": "BASELINE",
            "destination": new_target,
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="SecurityViolation: Workflow redirection to unauthorized destination blocked.",
    )


@router.post("/asi01/objective-modification", summary="Autonomous Objective Modification Endpoint")
async def objective_modification_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)

    if effective_stage == "BASELINE":
        return {
            "status": "modified",
            "stage": "BASELINE",
            "mission": "disabled_safety",
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="SecurityViolation: Objective modification refused by policy manager.",
    )


# =====================================================================
# ASI02: Tool Misuse Endpoints
# =====================================================================

@router.post("/asi02/tool-invocation", summary="Unauthorized Tool Invocation Endpoint")
async def tool_invocation_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    tool = body.get("tool", "")

    if effective_stage == "BASELINE":
        return {
            "status": "executed",
            "stage": "BASELINE",
            "tool": tool,
            "output": "Command executed via unapproved tool.",
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"PermissionDenied: Tool '{tool}' is not in the approved tool allowlist.",
    )


@router.post("/asi02/invalid-params", summary="Invalid Tool Parameters Endpoint")
async def invalid_params_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    tool = body.get("tool", "")
    query_str = str(body.get("query", ""))

    if effective_stage == "BASELINE":
        return {
            "status": "executed",
            "stage": "BASELINE",
            "tool": tool,
            "result": "Destructive parameter executed without parameter validation.",
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="ParameterValidationFailed: Dangerous SQL/command syntax detected in tool parameters.",
    )


@router.post("/asi02/path-traversal", summary="Path Traversal Target Endpoint")
async def path_traversal_endpoint(
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)
    path = str(body.get("path", ""))

    if effective_stage == "BASELINE":
        # Intentionally simulates leaking shadow file contents
        return {
            "status": "read_success",
            "stage": "BASELINE",
            "requested_path": path,
            "content": SYNTHETIC_PASSWD_ENTRY,
        }

    # Protected mode: rejects traversal
    if ".." in path or "/etc" in path or "passwd" in path:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="PathViolation: Path traversal pattern detected. Access outside sandbox directory blocked.",
        )

    return {
        "status": "read_success",
        "stage": "POST_MITIGATION",
        "requested_path": path,
        "content": "Synthetic public documentation content.",
    }


# =====================================================================
# Generic / Fallback Test Endpoint for Other Risks
# =====================================================================

@router.post("/generic/{risk_id}/{scenario_id}", summary="Generic Security Test Target Endpoint")
async def generic_test_endpoint(
    risk_id: str,
    scenario_id: str,
    request: Request,
    x_security_stage: Optional[str] = Header(None),
    stage: Optional[str] = Query(None),
) -> Dict[str, Any]:
    body = await request.json() if (await request.body()) else {}
    effective_stage = get_effective_stage(x_security_stage, stage, body)

    if effective_stage == "BASELINE":
        return {
            "status": "vulnerable",
            "stage": "BASELINE",
            "risk_id": risk_id,
            "scenario_id": scenario_id,
            "message": f"Simulated unmitigated execution for {risk_id} ({scenario_id}).",
        }

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"SecurityViolation: Security policy blocked test request for {risk_id} ({scenario_id}).",
    )
