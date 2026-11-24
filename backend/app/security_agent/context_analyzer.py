"""Application Context Analyzer (Phase D).

Performs controlled reconnaissance and schema discovery on explicitly authorized
applications prior to security assessment, supporting both live local discovery
and manual OpenAPI / Swagger JSON imports.

Strictly enforces target scope: only authorized localhost / approved external targets
are inspected; unrestricted crawling or unauthorized scanning is rejected.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from fastapi import HTTPException, status
import httpx

from app.security_agent.schemas import (
    ApplicationContext,
    DiscoverContextRequest,
    EndpointDiscoverySchema,
    ImportOpenApiRequest,
)
from app.security_agent.scope_validator import ScopeValidator


# Known controlled surfaces for the local reference application
CONTROLLED_LOCAL_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "path": "/api/chat",
        "methods": ["POST"],
        "description": "Multi-model chat interface with knowledge base retrieval",
        "parameters": [],
        "request_body_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "User prompt message"},
                "model": {"type": "string", "enum": ["mock-claude", "mock-gemini", "claude-3-5-sonnet", "gemini-1.5-pro"]},
                "conversation_id": {"type": "string"},
            },
            "required": ["message"],
        },
        "response_schemas": {"200": {"type": "object", "properties": {"response": {"type": "string"}}}},
        "auth_required": False,
        "is_tested_surface": True,
    },
    {
        "path": "/api/agent/run",
        "methods": ["POST"],
        "description": "Autonomous multi-tool agent execution loop with permission engine",
        "parameters": [],
        "request_body_schema": {
            "type": "object",
            "properties": {
                "task": {"type": "string", "description": "Goal/directive for the autonomous agent"},
                "model": {"type": "string"},
            },
            "required": ["task"],
        },
        "response_schemas": {"200": {"type": "object", "properties": {"status": {"type": "string"}}}},
        "auth_required": False,
        "is_tested_surface": True,
    },
    {
        "path": "/api/security-agent/target-app/vulnerable/chat",
        "methods": ["POST"],
        "description": "Baseline vulnerable chatbot endpoint for prompt injection and canary disclosure",
        "parameters": [],
        "request_body_schema": {"type": "object", "properties": {"prompt": {"type": "string"}}, "required": ["prompt"]},
        "response_schemas": {"200": {"type": "object"}, "403": {"type": "object"}},
        "auth_required": False,
        "is_tested_surface": True,
    },
    {
        "path": "/api/security-agent/target-app/protected/chat",
        "methods": ["POST"],
        "description": "Hardened chatbot endpoint with delimiter boundary fences and output token redaction",
        "parameters": [],
        "request_body_schema": {"type": "object", "properties": {"prompt": {"type": "string"}}, "required": ["prompt"]},
        "response_schemas": {"200": {"type": "object"}, "403": {"type": "object"}},
        "auth_required": False,
        "is_tested_surface": True,
    },
    {
        "path": "/api/security-agent/target-app/vulnerable/agent",
        "methods": ["POST"],
        "description": "Baseline vulnerable agent endpoint without tool allowlists or goal immutability",
        "parameters": [],
        "request_body_schema": {"type": "object", "properties": {"directive": {"type": "string"}, "tool": {"type": "string"}}},
        "response_schemas": {"200": {"type": "object"}, "403": {"type": "object"}},
        "auth_required": False,
        "is_tested_surface": True,
    },
    {
        "path": "/api/security-agent/target-app/protected/agent",
        "methods": ["POST"],
        "description": "Hardened agent endpoint with immutable mission objectives and path canonicalization",
        "parameters": [],
        "request_body_schema": {"type": "object", "properties": {"directive": {"type": "string"}, "tool": {"type": "string"}}},
        "response_schemas": {"200": {"type": "object"}, "403": {"type": "object"}},
        "auth_required": False,
        "is_tested_surface": True,
    },
    {
        "path": "/api/health",
        "methods": ["GET"],
        "description": "System health probe",
        "parameters": [],
        "request_body_schema": None,
        "response_schemas": {"200": {"type": "object"}},
        "auth_required": False,
        "is_tested_surface": False,
    },
]


class ApplicationContextAnalyzer:
    """Discovers, parses, and structures application context for authorized targets."""

    @classmethod
    def discover_context(
        cls,
        request: DiscoverContextRequest,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> ApplicationContext:
        """Discovers application context on authorized local target or live endpoint."""
        # 1. Scope & Authorization Validation
        scope = ScopeValidator.resolve_and_validate_target(
            raw_url=request.target_url,
            user_confirmed_authorization=request.user_confirmed_authorization,
        )
        if not scope.is_in_scope:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target URL is out of scope or unauthorized: {scope.reason}",
            )

        target_base = scope.normalized_url
        discovered_endpoints: List[EndpointDiscoverySchema] = []
        identified_components: List[str] = ["Python 3.13", "FastAPI Framework", "Starlette / Uvicorn", "Pydantic V2"]
        security_controls: List[str] = [
            "HMAC-SHA256 Evidence Signing",
            "CORS Restrictive Origin Policy",
            "Localhost Sandbox Execution Boundary",
            "Multi-Turn Execution Budgets",
        ]

        live_openapi = None
        # Attempt to fetch live /openapi.json if reachable
        try:
            client_kwargs: Dict[str, Any] = {"base_url": target_base, "timeout": 2.0}
            if transport:
                client_kwargs["transport"] = transport
            with httpx.Client(**client_kwargs) as client:
                resp = client.get("/openapi.json")
                if resp.status_code == 200:
                    live_openapi = resp.json()
        except Exception:
            live_openapi = None

        if live_openapi and isinstance(live_openapi, dict) and "paths" in live_openapi:
            parsed = cls._parse_openapi_dict(live_openapi, target_base)
            discovered_endpoints = parsed.discovered_endpoints
            identified_components.extend([c for c in parsed.identified_components if c not in identified_components])
            confidence = 1.0
        else:
            # Fall back to controlled local endpoint registry
            for ep_data in CONTROLLED_LOCAL_ENDPOINTS:
                discovered_endpoints.append(
                    EndpointDiscoverySchema(
                        path=ep_data["path"],
                        methods=ep_data["methods"],
                        description=ep_data["description"],
                        parameters=ep_data.get("parameters", []),
                        request_body_schema=ep_data.get("request_body_schema"),
                        response_schemas=ep_data.get("response_schemas", {}),
                        auth_required=ep_data.get("auth_required", False),
                        is_tested_surface=ep_data.get("is_tested_surface", False),
                    )
                )
            confidence = 0.90

        endpoint_methods = {ep.path: ep.methods for ep in discovered_endpoints}
        req_schemas = {ep.path: ep.request_body_schema for ep in discovered_endpoints if ep.request_body_schema}
        resp_schemas = {ep.path: ep.response_schemas for ep in discovered_endpoints if ep.response_schemas}

        return ApplicationContext(
            application_id=f"app_{scope.host}_{scope.port}",
            target_scope=target_base,
            is_local_target=scope.is_local,
            discovered_endpoints=discovered_endpoints,
            endpoint_methods=endpoint_methods,
            authentication_requirements={
                "custom_headers_supported": True,
                "bearer_token_optional": True,
                "api_key_header": "X-API-Key",
            },
            request_schema=req_schemas,
            response_schema=resp_schemas,
            identified_components=identified_components,
            discovered_security_controls=security_controls,
            context_confidence=confidence,
            discovery_timestamp=datetime.now(timezone.utc),
        )

    @classmethod
    def import_openapi_spec(cls, request: ImportOpenApiRequest) -> ApplicationContext:
        """Parses a manually imported OpenAPI 3.0 / Swagger 2.0 schema dictionary."""
        scope = ScopeValidator.resolve_and_validate_target(
            raw_url=request.target_url,
            user_confirmed_authorization=request.user_confirmed_authorization,
        )
        if not scope.is_in_scope:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target URL is out of scope or unauthorized: {scope.reason}",
            )

        spec = request.openapi_spec
        if not isinstance(spec, dict) or "paths" not in spec:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OpenAPI specification: missing 'paths' root object.",
            )

        return cls._parse_openapi_dict(spec, scope.normalized_url)

    @classmethod
    def _parse_openapi_dict(cls, spec: Dict[str, Any], target_url: str) -> ApplicationContext:
        """Internal helper to convert an OpenAPI dictionary into an ApplicationContext."""
        paths = spec.get("paths", {})
        discovered_endpoints: List[EndpointDiscoverySchema] = []
        identified_components: List[str] = []

        # Inspect info object
        info = spec.get("info", {})
        title = info.get("title", "Authorized Application")
        identified_components.append(title)
        if "fastapi" in title.lower():
            identified_components.append("FastAPI")

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            methods = []
            desc = ""
            req_schema = None
            resp_schemas = {}
            auth_req = False

            for m in ["get", "post", "put", "delete", "patch"]:
                if m in path_item:
                    methods.append(m.upper())
                    op = path_item[m]
                    if isinstance(op, dict):
                        desc = desc or op.get("summary") or op.get("description") or ""
                        if "requestBody" in op:
                            content = op["requestBody"].get("content", {})
                            if "application/json" in content:
                                req_schema = content["application/json"].get("schema")
                        if "security" in op and op["security"]:
                            auth_req = True
                        for st_code, st_obj in op.get("responses", {}).items():
                            resp_schemas[str(st_code)] = st_obj

            if methods:
                discovered_endpoints.append(
                    EndpointDiscoverySchema(
                        path=path,
                        methods=methods,
                        description=desc,
                        parameters=[],
                        request_body_schema=req_schema,
                        response_schemas=resp_schemas,
                        auth_required=auth_req,
                        is_tested_surface=any(kw in path for kw in ["chat", "agent", "run", "target-app"]),
                    )
                )

        endpoint_methods = {ep.path: ep.methods for ep in discovered_endpoints}
        req_schemas = {ep.path: ep.request_body_schema for ep in discovered_endpoints if ep.request_body_schema}
        resp_schemas = {ep.path: ep.response_schemas for ep in discovered_endpoints if ep.response_schemas}

        return ApplicationContext(
            application_id=f"app_openapi_{len(discovered_endpoints)}_endpoints",
            target_scope=target_url,
            is_local_target="127.0.0.1" in target_url or "localhost" in target_url,
            discovered_endpoints=discovered_endpoints,
            endpoint_methods=endpoint_methods,
            authentication_requirements={"security_schemes": spec.get("components", {}).get("securitySchemes", {})},
            request_schema=req_schemas,
            response_schema=resp_schemas,
            identified_components=identified_components,
            discovered_security_controls=["OpenAPI Schema Validation", "Typed Endpoint Contract"],
            context_confidence=1.0,
            discovery_timestamp=datetime.now(timezone.utc),
        )
