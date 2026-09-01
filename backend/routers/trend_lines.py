"""REST router for trend lines."""

from fastapi import APIRouter

from backend.services.scanner import get_trend_lines

router = APIRouter(prefix="/trend_lines")


@router.get("/")
def trend_lines() -> dict:
    """Return vulnerability counts over time for Chart.js visualization."""
    return get_trend_lines()