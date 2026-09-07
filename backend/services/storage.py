"""Persistence for scan results and trend history.

Wraps the SQLAlchemy models so routers never touch the ORM directly. Every
completed scan is stored with its findings; the dashboard reads from the most
recent scan, and trend lines aggregate per-day counts from all scans.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import func, select

from ..database import get_session
from ..models import Scan, TrendRecord, Vulnerability


def persist_scan(result: dict) -> int:
    """Store a scan result (from ``scanner.scan_codebase``) and return its id."""
    session = get_session()
    try:
        now = datetime.utcnow()
        scan = Scan(
            target_path=result["target_path"],
            status="completed",
            started_at=now,
            completed_at=now,
        )
        session.add(scan)
        session.flush()

        for finding in result["vulnerabilities"]:
            session.add(
                Vulnerability(
                    scan_id=scan.id,
                    category=finding["category"],
                    severity_score=finding["severity_score"],
                    description=finding["description"],
                    location=finding["location"],
                    remediation_suggestion=finding.get("remediation_suggestion"),
                )
            )

        _upsert_trend_record(session, result)
        session.commit()
        return scan.id
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _upsert_trend_record(session, result: dict) -> None:
    """Record today's finding counts (latest scan of the day wins)."""
    today = date.today()
    counts = {"sqli": 0, "xss": 0, "secrets": 0, "outdated_deps": 0}
    for finding in result["vulnerabilities"]:
        if finding["category"] in counts:
            counts[finding["category"]] += 1

    record = session.scalar(
        select(TrendRecord).where(TrendRecord.date == today)
    )
    if record is None:
        record = TrendRecord(date=today)
        session.add(record)
    record.sqli_count = counts["sqli"]
    record.xss_count = counts["xss"]
    record.secrets_count = counts["secrets"]
    record.outdated_deps_count = counts["outdated_deps"]


def _latest_scan_id() -> int | None:
    session = get_session()
    try:
        return session.scalar(
            select(func.max(Scan.id)).where(Scan.status == "completed")
        )
    finally:
        session.close()


def _finding_rows(session, scan_id: int) -> list[Vulnerability]:
    return list(
        session.scalars(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(
                Vulnerability.severity_score.desc(), Vulnerability.location
            )
        )
    )


def _row_to_dict(row: Vulnerability) -> dict:
    return {
        "id": row.id,
        "category": row.category,
        "severity_score": row.severity_score,
        "description": row.description,
        "location": row.location,
        "remediation_suggestion": row.remediation_suggestion,
    }


def get_results() -> list[dict]:
    """Return findings from the most recent completed scan."""
    scan_id = _latest_scan_id()
    if scan_id is None:
        return []
    session = get_session()
    try:
        return [_row_to_dict(row) for row in _finding_rows(session, scan_id)]
    finally:
        session.close()


def get_results_by_category(category: str) -> list[dict]:
    """Return findings from the latest scan in one category."""
    return [r for r in get_results() if r["category"] == category]


def get_results_by_severity(min_severity: float) -> list[dict]:
    """Return findings from the latest scan at or above a severity score."""
    return [r for r in get_results() if r["severity_score"] >= min_severity]


def get_severity_breakdown() -> dict:
    """Category distribution and average severity for the latest scan."""
    results = get_results()
    categories: dict[str, list[float]] = {}
    for row in results:
        categories.setdefault(row["category"], []).append(row["severity_score"])
    average = (
        round(sum(r["severity_score"] for r in results) / len(results), 3)
        if results
        else 0.0
    )
    return {
        "categories": categories,
        "total_vulnerabilities": len(results),
        "average_severity": average,
    }


def get_trend_lines(days: int = 7) -> dict:
    """Per-day finding counts for the last ``days`` days from scan history."""
    session = get_session()
    try:
        start = date.today() - timedelta(days=days - 1)
        rows = session.scalars(
            select(TrendRecord).where(TrendRecord.date >= start).order_by(TrendRecord.date)
        ).all()
        by_date = {row.date: row for row in rows}
    finally:
        session.close()

    dates: list[str] = []
    sqli_trend: list[int] = []
    xss_trend: list[int] = []
    secrets_trend: list[int] = []
    outdated_deps_trend: list[int] = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        dates.append(day.isoformat())
        row = by_date.get(day)
        sqli_trend.append(row.sqli_count if row else 0)
        xss_trend.append(row.xss_count if row else 0)
        secrets_trend.append(row.secrets_count if row else 0)
        outdated_deps_trend.append(row.outdated_deps_count if row else 0)

    return {
        "dates": dates,
        "sqli_trend": sqli_trend,
        "xss_trend": xss_trend,
        "secrets_trend": secrets_trend,
        "outdated_deps_trend": outdated_deps_trend,
    }


def list_scans(limit: int = 10) -> list[dict]:
    """Return recent completed scans, newest first."""
    session = get_session()
    try:
        rows = session.scalars(
            select(Scan)
            .where(Scan.status == "completed")
            .order_by(Scan.id.desc())
            .limit(limit)
        ).all()
        return [
            {
                "id": row.id,
                "target_path": row.target_path,
                "severity_score": round(
                    session.scalar(
                        select(func.avg(Vulnerability.severity_score)).where(
                            Vulnerability.scan_id == row.id
                        )
                    )
                    or 0.0,
                    3,
                ),
                "started_at": row.started_at.isoformat() if row.started_at else None,
            }
            for row in rows
        ]
    finally:
        session.close()


def scan_count() -> int:
    """Total number of completed scans (used for first-run seeding)."""
    session = get_session()
    try:
        return session.scalar(
            select(func.count()).select_from(Scan).where(Scan.status == "completed")
        ) or 0
    finally:
        session.close()
