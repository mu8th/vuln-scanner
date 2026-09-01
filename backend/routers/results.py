"""REST router for returning scan results."""

from fastapi import APIRouter, HTTPException

from backend.services.scanner import (
    get_results,
    get_results_by_category,
    get_results_by_severity,
)

router = APIRouter(prefix="/results")


@router.get("/")
def list_results() -> list[dict]:
    """Return all detected vulnerabilities."""
    try:
        return get_results()
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/category/{category}")
def results_by_category(category: str) -> list[dict]:
    """Filter vulnerabilities by category (sqli, xss, secrets, outdated_deps)."""
    try:
        return get_results_by_category(category)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/severity/{min_severity}")
def results_by_severity(min_severity: float) -> list[dict]:
    """Filter vulnerabilities with severity >= min_severity."""
    try:
        return get_results_by_severity(min_severity)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))