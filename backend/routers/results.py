"""REST router for returning scan results."""

from fastapi import APIRouter

from backend.services.storage import (
    get_results,
    get_results_by_category,
    get_results_by_severity,
)

router = APIRouter(prefix="/results")


@router.get("")
def list_results() -> list[dict]:
    """Return findings from the most recent completed scan."""
    return get_results()


@router.get("/category/{category}")
def results_by_category(category: str) -> list[dict]:
    """Filter the latest scan's findings by category."""
    return get_results_by_category(category)


@router.get("/severity/{min_severity}")
def results_by_severity(min_severity: float) -> list[dict]:
    """Return the latest scan's findings with severity >= min_severity."""
    return get_results_by_severity(min_severity)
