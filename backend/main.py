"""FastAPI application entry point for vuln-scanner."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routers.results import router as results_router
from backend.routers.scans import router as scans_router
from backend.routers.severity_breakdown import router as severity_router
from backend.routers.trend_lines import router as trend_router

app = FastAPI(title="Vuln Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(scans_router)
app.include_router(results_router)
app.include_router(severity_router)
app.include_router(trend_router)


@app.get("/health")
def health_check() -> dict:
    """Health endpoint for monitoring."""
    return {"status": "ok"}