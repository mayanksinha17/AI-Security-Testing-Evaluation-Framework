"""Dedicated Controlled Test Application package for Security Testing (Phase B).

Provides intentionally vulnerable and protected endpoints for controlled evaluation.
"""

from app.security_agent.target_app.routes import router as target_app_router

__all__ = ["target_app_router"]
