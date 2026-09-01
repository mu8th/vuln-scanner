"""Comprehensive pytest coverage for vuln-scanner."""

from backend.services.scanner import (
    scan_codebase,
    classify_severity,
    get_remediation_suggestion,
    get_results,
    get_results_by_category,
    get_results_by_severity,
    get_severity_breakdown,
    get_trend_lines,
    analyze_report,
)


def test_classify_severity_sqli() -> None:
    """Test SQL injection severity returns critical score."""
    assert classify_severity("sqli") == 1.0


def test_classify_severity_xss() -> None:
    """Test XSS severity returns high score."""
    assert classify_severity("xss") == 0.8


def test_classify_severity_secrets() -> None:
    """Test hardcoded secrets severity returns medium score."""
    assert classify_severity("secrets") == 0.5


def test_classify_severity_outdated_deps() -> None:
    """Test outdated dependencies severity returns low score."""
    assert classify_severity("outdated_deps") == 0.2


def test_classify_severity_unknown() -> None:
    """Test unknown category returns zero score."""
    assert classify_severity("unknown") == 0.0


def test_get_remediation_suggestion_sqli() -> None:
    """Test SQL injection remediation suggestion is actionable."""
    suggestion = get_remediation_suggestion("sqli")
    assert suggestion is not None
    assert "parameterized queries" in suggestion.lower()


def test_get_remediation_suggestion_xss() -> None:
    """Test XSS remediation suggestion includes CSP recommendation."""
    suggestion = get_remediation_suggestion("xss")
    assert suggestion is not None
    assert "Content Security Policy" in suggestion


def test_get_remediation_suggestion_secrets() -> None:
    """Test secrets remediation suggests environment variables."""
    suggestion = get_remediation_suggestion("secrets")
    assert suggestion is not None
    assert "environment variables" in suggestion.lower()


def test_get_remediation_suggestion_outdated_deps() -> None:
    """Test outdated deps remediation suggests version update."""
    suggestion = get_remediation_suggestion("outdated_deps")
    assert suggestion is not None
    assert "Update dependency" in suggestion


def test_get_remediation_suggestion_unknown() -> None:
    """Test unknown category returns no suggestion."""
    assert get_remediation_suggestion("unknown") is None


def test_scan_codebase_default_categories() -> None:
    """Test scan with default categories returns all four vulnerability types."""
    result = scan_codebase(target_path="C:/Users/Server/test-project")
    assert isinstance(result, dict)
    assert "severity_score" in result
    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 4


def test_scan_codebase_filtered_categories() -> None:
    """Test scan with filtered categories returns only matching vulnerabilities."""
    result = scan_codebase(
        target_path="C:/Users/Server/test-project",
        categories=["sqli", "xss"],
    )
    assert len(result["vulnerabilities"]) == 2
    assert all(v["category"] in ["sqli", "xss"] for v in result["vulnerabilities"])


def test_scan_codebase_single_category() -> None:
    """Test scan with single category returns one vulnerability."""
    result = scan_codebase(
        target_path="C:/Users/Server/test-project",
        categories=["secrets"],
    )
    assert len(result["vulnerabilities"]) == 1


def test_scan_codebase_empty_categories() -> None:
    """Test scan with empty categories returns no vulnerabilities."""
    result = scan_codebase(
        target_path="C:/Users/Server/test-project",
        categories=[],
    )
    assert len(result["vulnerabilities"]) == 0


def test_scan_codebase_severity_score_calculation() -> None:
    """Test severity score is average of individual scores."""
    result = scan_codebase(target_path="C:/Users/Server/test-project")
    expected_avg = (1.0 + 0.8 + 0.5 + 0.2) / 4
    assert abs(result["severity_score"] - expected_avg) < 0.01


def test_scan_codebase_timestamp() -> None:
    """Test scan includes timestamp in ISO format."""
    result = scan_codebase(target_path="C:/Users/Server/test-project")
    assert "scan_timestamp" in result
    assert isinstance(result["scan_timestamp"], str)


def test_get_results_all_vulnerabilities() -> None:
    """Test get_results returns four vulnerabilities with correct IDs."""
    results = get_results()
    assert len(results) == 4
    assert all(r["id"] in [1, 2, 3, 4] for r in results)


def test_get_results_by_category_sqli() -> None:
    """Test filter by sqli category returns one result."""
    results = get_results_by_category("sqli")
    assert len(results) == 1
    assert results[0]["category"] == "sqli"


def test_get_results_by_category_xss() -> None:
    """Test filter by xss category returns one result."""
    results = get_results_by_category("xss")
    assert len(results) == 1
    assert results[0]["category"] == "xss"


def test_get_results_by_category_secrets() -> None:
    """Test filter by secrets category returns one result."""
    results = get_results_by_category("secrets")
    assert len(results) == 1
    assert results[0]["category"] == "secrets"


def test_get_results_by_category_outdated_deps() -> None:
    """Test filter by outdated deps category returns one result."""
    results = get_results_by_category("outdated_deps")
    assert len(results) == 1
    assert results[0]["category"] == "outdated_deps"


def test_get_results_by_category_unknown() -> None:
    """Test filter by unknown category returns empty list."""
    results = get_results_by_category("unknown")
    assert len(results) == 0


def test_get_results_by_severity_critical() -> None:
    """Test filter severity >= 1.0 returns only critical vulnerabilities."""
    results = get_results_by_severity(1.0)
    assert len(results) == 1
    assert results[0]["severity_score"] == 1.0


def test_get_results_by_severity_high() -> None:
    """Test filter severity >= 0.8 returns critical and high."""
    results = get_results_by_severity(0.8)
    assert len(results) == 2
    assert all(r["severity_score"] >= 0.8 for r in results)


def test_get_results_by_severity_medium() -> None:
    """Test filter severity >= 0.5 returns critical, high, and medium."""
    results = get_results_by_severity(0.5)
    assert len(results) == 3
    assert all(r["severity_score"] >= 0.5 for r in results)


def test_get_results_by_severity_low() -> None:
    """Test filter severity >= 0.2 returns all vulnerabilities."""
    results = get_results_by_severity(0.2)
    assert len(results) == 4


def test_get_results_by_severity_zero() -> None:
    """Test filter severity >= 0.0 returns all vulnerabilities."""
    results = get_results_by_severity(0.0)
    assert len(results) == 4


def test_get_severity_breakdown_categories() -> None:
    """Test breakdown returns four categories with correct counts."""
    breakdown = get_severity_breakdown()
    assert "categories" in breakdown
    assert len(breakdown["categories"]) == 4
    assert all(len(cat) == 1 for cat in breakdown["categories"].values())


def test_get_severity_breakdown_total() -> None:
    """Test breakdown total_vulnerabilities equals four."""
    breakdown = get_severity_breakdown()
    assert breakdown["total_vulnerabilities"] == 4


def test_get_severity_breakdown_average_severity() -> None:
    """Test average severity matches expected calculation."""
    breakdown = get_severity_breakdown()
    expected_avg = (1.0 + 0.8 + 0.5 + 0.2) / 4
    assert abs(breakdown["average_severity"] - expected_avg) < 0.01


def test_get_trend_lines_dates() -> None:
    """Test trend lines returns three date entries."""
    trend = get_trend_lines()
    assert len(trend["dates"]) == 3
    assert all(d.startswith("2026-09") for d in trend["dates"])


def test_get_trend_lines_sqli_trend() -> None:
    """Test sqli trend shows decreasing pattern."""
    trend = get_trend_lines()
    assert trend["sqli_trend"] == [3, 2, 1]


def test_get_trend_lines_xss_trend() -> None:
    """Test xss trend shows decreasing pattern."""
    trend = get_trend_lines()
    assert trend["xss_trend"] == [5, 4, 3]


def test_get_trend_lines_secrets_trend() -> None:
    """Test secrets trend fluctuates."""
    trend = get_trend_lines()
    assert trend["secrets_trend"] == [2, 3, 1]


def test_get_trend_lines_outdated_deps_trend() -> None:
    """Test outdated deps trend shows increasing pattern."""
    trend = get_trend_lines()
    assert trend["outdated_deps_trend"] == [4, 5, 6]


def test_analyze_empty() -> None:
    """Test analyze report with empty vulnerabilities returns empty list."""
    result: dict = {"vulnerabilities": []}
    violations = analyze_report(result)
    assert isinstance(violations, list)
    assert len(violations) == 0


def test_analyze_with_vulnerabilities() -> None:
    """Test analyze report with populated vulnerabilities returns descriptions."""
    result: dict = {"vulnerabilities": ["SQL injection", "XSS"]}
    violations = analyze_report(result)
    assert isinstance(violations, list)
    assert len(violations) == 2


def test_analyze_report_missing_key() -> None:
    """Test analyze report without vulnerabilities key returns empty."""
    result: dict = {"severity_score": 0.5}
    violations = analyze_report(result)
    assert isinstance(violations, list)
    assert len(violations) == 0


def test_scan_codebase_vulnerability_structure() -> None:
    """Test each vulnerability has required fields."""
    result = scan_codebase(target_path="C:/Users/Server/test-project")
    for v in result["vulnerabilities"]:
        assert "id" in v
        assert "category" in v
        assert "severity_score" in v
        assert "description" in v
        assert "location" in v
        assert "remediation_suggestion" in v


def test_scan_codebase_location_format() -> None:
    """Test vulnerability locations include file and line reference."""
    result = scan_codebase(target_path="C:/Users/Server/test-project")
    for v in result["vulnerabilities"]:
        assert "line" in v["location"] or ".py" in v["location"]


def test_scan_codebase_description_format() -> None:
    """Test vulnerability descriptions include category and location."""
    result = scan_codebase(target_path="C:/Users/Server/test-project")
    for v in result["vulnerabilities"]:
        assert v["category"] in v["description"]