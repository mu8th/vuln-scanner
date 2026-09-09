"""REST router for initiating scans and listing scan history."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.services.scanner import SEVERITY_BY_CATEGORY, scan_codebase
from backend.services.storage import list_scans, persist_scan

router = APIRouter(prefix="/scans")


class ScanRequest(BaseModel):
    """Payload for starting a scan."""

    target_path: str
    categories: list[str] = Field(default=list(SEVERITY_BY_CATEGORY))


@router.post("")
def initiate_scan(req: ScanRequest) -> dict:
    """Run a vulnerability scan on the given target path and persist it."""
    unknown = set(req.categories) - set(SEVERITY_BY_CATEGORY)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown categories: {', '.join(sorted(unknown))}",
        )
    try:
        result = scan_codebase(req.target_path, req.categories)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    scan_id = persist_scan(result)
    return {
        "scan_id": scan_id,
        "status": "completed",
        "target_path": result["target_path"],
        "results_count": result["vulnerability_count"],
        "severity_score": result["severity_score"],
        "duration_ms": result["duration_ms"],
    }


@router.get("")
def scans() -> list[dict]:
    """Return recent completed scans, newest first."""
    return list_scans()
