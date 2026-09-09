"""FastAPI application entry point for vuln-scanner."""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.database import init_db
from backend.routers.results import router as results_router
from backend.routers.scans import router as scans_router
from backend.routers.severity_breakdown import router as severity_router
from backend.routers.trend_lines import router as trend_router
from backend.services import scanner
from backend.services.storage import scan_count

logger = logging.getLogger("vuln-scanner")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _seed_first_scan() -> None:
    """On a fresh database, scan this repository so the dashboard is alive."""
    if scan_count() > 0:
        return
    target = os.getenv("VULN_SCAN_ROOT", str(REPO_ROOT))
    try:
        result = scanner.scan_codebase(target)
        from backend.services.storage import persist_scan

        persist_scan(result)
        logger.info(
            "Seeded first scan of %s: %d finding(s)", target, result["vulnerability_count"]
        )
    except Exception:  # seeding must never block startup
        logger.exception("First-run self-scan failed; dashboard starts empty")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    _seed_first_scan()
    yield


app = FastAPI(title="Vuln Scanner", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
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


# Serve the dashboard from the same origin (mounted last so API routes win).
_FRONTEND_DIR = REPO_ROOT / "frontend"
if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
