"""REST router for severity breakdown."""

from fastapi import APIRouter

from backend.services.scanner import get_severity_breakdown

router = APIRouter(prefix="/severity_breakdown")


@router.get("/")
def severity_breakdown() -> dict:
    """Return vulnerability distribution by category and severity tier."""
    return get_severity_breakdown()