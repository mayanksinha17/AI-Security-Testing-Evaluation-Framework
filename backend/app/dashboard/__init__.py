"""Dashboard module for Phase 8 Unified AI Security Operations Dashboard."""

from app.dashboard.routes import router as dashboard_router
from app.dashboard.service import DashboardService

__all__ = ["dashboard_router", "DashboardService"]

