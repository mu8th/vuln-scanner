"""REST router for initiating scans."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.services.scanner import scan_codebase

router = APIRouter(prefix="/scans")


class ScanRequest(BaseModel):
    """Payload for starting a scan."""
    target_path: str
    categories: list[str] = ["sqli", "xss", "secrets", "outdated_deps"]


@router.post("/")
def initiate_scan(req: ScanRequest) -> dict:
    """Start a vulnerability scan on the given target path."""
    try:
        results = scan_codebase(req.target_path, req.categories)
        return {
            "scan_id": 1,
            "status": "completed",
            "results_count": len(results["vulnerabilities"]),
            "severity_score": results["severity_score"],
        }
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{scan_id}")
def scan_status(scan_id: int) -> dict:
    """Return current status of a scan."""
    return {"scan_id": scan_id, "status": "completed"}