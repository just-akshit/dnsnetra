"""
FastAPI Application Entry Point
================================
DNS Threat Detection Dashboard API.

Run with:
    uvicorn api.main:app --reload --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes.dashboard import router as dashboard_router
from api.routes.auth import router as auth_router
from api.routes.investigation import router as investigation_router
from api.routes.analytics import router as analytics_router
from api.routes.reports import router as reports_router

app = FastAPI(
    title="DNS Threat Detection Dashboard API",
    description="REST API serving pre-computed dashboard metrics and investigation intelligence from the DNS threat detection pipeline.",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# CORS — allow all origins for development (restrict in production)
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # TODO: Restrict to specific frontend origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Mount routers
# ---------------------------------------------------------------------------
app.include_router(dashboard_router)
app.include_router(auth_router)
app.include_router(investigation_router)
app.include_router(analytics_router)
app.include_router(reports_router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
def health_check():
    """Basic health check endpoint."""
    return {"status": "ok", "service": "dns-threat-dashboard-api"}
