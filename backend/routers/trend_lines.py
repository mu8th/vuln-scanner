"""REST router for trend lines."""

from fastapi import APIRouter

from backend.services.storage import get_trend_lines

router = APIRouter(prefix="/trend_lines")


@router.get("")
def trend_lines() -> dict:
    """Return per-day finding counts from scan history (last 7 days)."""
    return get_trend_lines()
