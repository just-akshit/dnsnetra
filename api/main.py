"""
DNSNetra Threat Detection Admin & Operations API
================================================
FastAPI application providing the authoritative HTTP API surface for:
- JWT Authentication (OAuth2 form + JSON alias)
- Unified Overview Dashboard Composition
- Reporting (Summary, Timeseries, Clients, Domains, Queries)
- Domains and Clients Catalog & Deep Investigation Dossiers
- Daily Review Queue Management & Admin Actions
- Authoritative System Status and DNS Analytics
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from api.auth import get_jwt_secret_key
from api.routes.analytics import router as analytics_router
from api.routes.auth import router as auth_router
from api.routes.clients import router as clients_router
from api.routes.daily_review import router as daily_review_router
from api.routes.dashboard import router as dashboard_router
from api.routes.domains import router as domains_router
from api.routes.investigation import router as investigation_router
from api.routes.reports import router as reports_router
from api.routes.status import router as status_router
from investigation.schemas import (
    EntityNotFoundError,
    InvalidEntityError,
    InvariantViolationError,
)
from reporting.schemas import ReportingValidationError
from time_engine.exceptions import InvalidTimeRangeError, TimeEngineValidationError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("api_main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Validate startup environment invariants."""
    # Ensure production configuration fails immediately if secret is insecure
    get_jwt_secret_key()
    logger.info("DNSNetra API initialized successfully.")
    yield


app = FastAPI(
    title="DNSNetra Threat Detection Management API",
    description="Operational and administrative API for DNSNetra threat intelligence, daily review queue, and domain telemetry.",
    version="2.0.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global Exception Handlers
# ---------------------------------------------------------------------------
@app.exception_handler(EntityNotFoundError)
async def entity_not_found_handler(request: Request, exc: EntityNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvalidEntityError)
async def invalid_entity_handler(request: Request, exc: InvalidEntityError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvalidTimeRangeError)
async def invalid_time_range_handler(request: Request, exc: InvalidTimeRangeError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(TimeEngineValidationError)
async def time_engine_validation_handler(request: Request, exc: TimeEngineValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(ReportingValidationError)
async def reporting_validation_handler(request: Request, exc: ReportingValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvariantViolationError)
async def invariant_violation_handler(request: Request, exc: InvariantViolationError):
    logger.error("Internal data invariant violated: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal data integrity invariant was violated."},
    )


# ---------------------------------------------------------------------------
# Routers Registration
# ---------------------------------------------------------------------------
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(reports_router)
app.include_router(domains_router)
app.include_router(clients_router)
app.include_router(investigation_router)
app.include_router(status_router)
app.include_router(analytics_router)
app.include_router(daily_review_router)


# ---------------------------------------------------------------------------
# Health Check (Public)
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


@app.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check():
    """Public health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="dnsnetra-backend-api",
        version="2.0.0",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
