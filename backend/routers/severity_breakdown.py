"""REST router for severity breakdown."""

from fastapi import APIRouter

from backend.services.storage import get_severity_breakdown

router = APIRouter(prefix="/severity_breakdown")


@router.get("")
def severity_breakdown() -> dict:
    """Return the latest scan's findings grouped by category."""
    return get_severity_breakdown()
