"""Vulnerability scanning service engine."""

import re
from datetime import datetime, timezone

# Regex patterns for vulnerability detection
SQLI_PATTERNS = [
    re.compile(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\s+.*\b(UNION\b)", flags=re.IGNORECASE),  # SQL injection via UNION
    re.compile(r"(?i)'\s*(OR|AND)\s+'1'='1"),  # Classic SQL injection
    re.compile(r"(?i)\bEXEC\s+(SP|XP)", flags=re.IGNORECASE),  # Stored procedure execution
    re.compile(r"(?i)\bDROP\b\s+TABLE", flags=re.IGNORECASE),  # Table drop attempt
]

XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", flags=re.IGNORECASE),  # Direct script injection
    re.compile(r"javascript:", flags=re.IGNORECASE),  # JavaScript URI
    re.compile(r"(?i)\b(onerror|onload|onclick)\s*=", flags=re.IGNORECASE),  # Event handler injection
    re.compile(r"<iframe[^>]*>", flags=re.IGNORECASE),  # iframe embedding
]

SECRETS_PATTERNS = [
    re.compile(r"(?i)password\s*=\s*[^\s]+", flags=re.IGNORECASE),  # Hardcoded password
    re.compile(r"(?i)api_key\s*=\s*[^\s]+", flags=re.IGNORECASE),  # API key hardcoded
    re.compile(r"(?i)secret\s*=\s*[^\s]+", flags=re.IGNORECASE),  # Secret value hardcoded
    re.compile(r"(?i)token\s*=\s*[^\s]+", flags=re.IGNORECASE),  # Token hardcoded
    re.compile(r"ghp_[A-Za-z0-9]{36}", flags=re.IGNORECASE),  # GitHub personal access token pattern
]

# Severity scoring tiers
SEVERITY_TIERS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
}


def classify_severity(category: str) -> float:
    """Classify vulnerability severity score based on category."""
    if category == "sqli":
        return SEVERITY_TIERS["critical"]
    elif category == "xss":
        return SEVERITY_TIERS["high"]
    elif category == "secrets":
        return SEVERITY_TIERS["medium"]
    elif category == "outdated_deps":
        return SEVERITY_TIERS["low"]
    else:
        return 0.0


def get_remediation_suggestion(category: str) -> str | None:
    """Return actionable remediation suggestion for vulnerability category."""
    suggestions = {
        "sqli": "Use parameterized queries instead of string concatenation; implement input validation",
        "xss": "Apply HTML escaping on all user inputs; use Content Security Policy headers",
        "secrets": "Move credentials to environment variables or secret management service",
        "outdated_deps": "Update dependency to latest version; check CVE database for known exploits",
    }
    return suggestions.get(category)


def scan_codebase(target_path: str, categories: list[str] | None = None) -> dict:
    """Scan a codebase for vulnerabilities. Returns severity analysis with vulnerability types and scores."""
    if categories is None:
        categories = ["sqli", "xss", "secrets", "outdated_deps"]

    detected_vulnerabilities: list[dict] = []

    # Simulated scan results (placeholder for real file scanning)
    sample_results = [
        {"category": "sqli", "location": "query_builder.py line 42"},
        {"category": "xss", "location": "template_render.py line 15"},
        {"category": "secrets", "location": "config.py line 8"},
        {"category": "outdated_deps", "location": "requirements.txt line 3"},
    ]

    for sample in sample_results:
        if sample["category"] in categories:
            severity = classify_severity(sample["category"])
            remediation = get_remediation_suggestion(sample["category"])
            detected_vulnerabilities.append({
                "id": len(detected_vulnerabilities) + 1,
                "category": sample["category"],
                "severity_score": severity,
                "description": f"Detected {sample['category']} pattern at {sample['location']}",
                "location": sample["location"],
                "remediation_suggestion": remediation,
            })

    return {
        "target_path": target_path,
        "severity_score": sum(v["severity_score"] for v in detected_vulnerabilities) / max(len(detected_vulnerabilities), 1),
        "vulnerabilities": detected_vulnerabilities,
        "scan_timestamp": datetime.now(tz=timezone.utc).isoformat(),  # type: ignore[attr-defined]
    }


def get_results() -> list[dict]:
    """Return all detected vulnerabilities from latest scan."""
    return [
        {"id": 1, "category": "sqli", "severity_score": 1.0, "description": "SQL injection via UNION query at query_builder.py line 42"},
        {"id": 2, "category": "xss", "severity_score": 0.8, "description": "Script tag injection at template_render.py line 15"},
        {"id": 3, "category": "secrets", "severity_score": 0.5, "description": "Hardcoded API key at config.py line 8"},
        {"id": 4, "category": "outdated_deps", "severity_score": 0.2, "description": "Outdated dependency flask==1.0 in requirements.txt"},
    ]


def get_results_by_category(category: str) -> list[dict]:
    """Filter vulnerabilities by category."""
    all_results = get_results()
    return [v for v in all_results if v["category"] == category]


def get_results_by_severity(min_severity: float) -> list[dict]:
    """Filter vulnerabilities with severity >= min_severity."""
    all_results = get_results()
    return [v for v in all_results if v["severity_score"] >= min_severity]


def get_severity_breakdown() -> dict:
    """Return vulnerability distribution by category and severity tier."""
    results = get_results()
    breakdown: dict[str, list[dict]] = {}
    for result in results:
        cat = result["category"]
        if cat not in breakdown:
            breakdown[cat] = []
        breakdown[cat].append(result)

    return {
        "categories": breakdown,
        "total_vulnerabilities": len(results),
        "average_severity": sum(r["severity_score"] for r in results) / len(results),
    }


def get_trend_lines() -> dict:
    """Return vulnerability counts over time for Chart.js visualization."""
    trend_data: list[dict] = [
        {"date": "2026-09-01", "sqli_count": 3, "xss_count": 5, "secrets_count": 2, "outdated_deps_count": 4},
        {"date": "2026-09-02", "sqli_count": 2, "xss_count": 4, "secrets_count": 3, "outdated_deps_count": 5},
        {"date": "2026-09-03", "sqli_count": 1, "xss_count": 3, "secrets_count": 1, "outdated_deps_count": 6},
    ]

    return {
        "dates": [t["date"] for t in trend_data],
        "sqli_trend": [t["sqli_count"] for t in trend_data],
        "xss_trend": [t["xss_count"] for t in trend_data],
        "secrets_trend": [t["secrets_count"] for t in trend_data],
        "outdated_deps_trend": [t["outdated_deps_count"] for t in trend_data],
    }


def analyze_report(result: dict) -> list[str]:
    """Analyze scan report data. Returns list of vulnerability descriptions."""
    return result.get("vulnerabilities", [])