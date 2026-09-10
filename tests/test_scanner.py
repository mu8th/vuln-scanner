"""Tests for the vulnerability scanner engine, storage layer, and API."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.scanner import (
    SEVERITY_BY_CATEGORY,
    _secret_value_is_placeholder,
    _version_tuple,
    classify_severity,
    get_remediation_suggestion,
    scan_codebase,
)

DIRTY_FILE = """\
import sqlite3


def lookup(name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return sqlite3.connect("app.db").execute(query).fetchall()


def render(user_input):
    return "<script>alert(1)</script>" + user_input


password = "hunter2"
api_key = os.getenv("API_KEY")
"""

CLEAN_FILE = """\
def add(a, b):
    return a + b
"""

DIRTY_REQUIREMENTS = """\
flask==1.0.2
requests==2.31.0
"""


@pytest.fixture()
def dirty_dir(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(DIRTY_FILE, encoding="utf-8")
    (tmp_path / "clean.py").write_text(CLEAN_FILE, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def deps_dir(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text(DIRTY_REQUIREMENTS, encoding="utf-8")
    return tmp_path


# ── Pure engine: severity + remediation ───────────────────────────────────


def test_classify_severity_mapping() -> None:
    assert classify_severity("sqli") == 1.0
    assert classify_severity("xss") == 0.8
    assert classify_severity("secrets") == 0.5
    assert classify_severity("outdated_deps") == 0.2
    assert classify_severity("unknown") == 0.0


def test_remediation_suggestions_are_actionable() -> None:
    assert "parameterized" in get_remediation_suggestion("sqli").lower()
    assert "Content Security Policy" in get_remediation_suggestion("xss")
    assert "environment variables" in get_remediation_suggestion("secrets").lower()
    assert "Update" in get_remediation_suggestion("outdated_deps")
    assert get_remediation_suggestion("unknown") is None


def test_version_tuple_parsing() -> None:
    assert _version_tuple("1.0.2") == (1, 0, 2)
    assert _version_tuple("2.0.1rc1") == (2, 0, 1)
    assert _version_tuple("5.4") < _version_tuple("5.4.1")


def test_secret_placeholder_filtering() -> None:
    assert not _secret_value_is_placeholder('password = "hunter2"')
    assert _secret_value_is_placeholder("password = os.getenv('X')")
    assert _secret_value_is_placeholder("api_key = ${ENV_VAR}")
    assert _secret_value_is_placeholder("token = None")


# ── Pure engine: file scanning ────────────────────────────────────────────


def test_scan_finds_sqli_xss_and_literal_secret(dirty_dir: Path) -> None:
    result = scan_codebase(str(dirty_dir))
    categories = {f["category"] for f in result["vulnerabilities"]}
    assert "sqli" in categories
    assert "xss" in categories
    assert "secrets" in categories

    sqli = [f for f in result["vulnerabilities"] if f["category"] == "sqli"]
    assert any("app.py:5" in f["location"] for f in sqli)


def test_scan_skips_env_reference_secrets(dirty_dir: Path) -> None:
    result = scan_codebase(str(dirty_dir))
    vulns = result["vulnerabilities"]
    secret_locations = [f["location"] for f in vulns if f["category"] == "secrets"]
    # `api_key = os.getenv(...)` is wiring, not a credential.
    assert all(not loc.endswith(":14") for loc in secret_locations)
    # The literal password on line 13 is still flagged.
    assert any(loc.endswith(":13") for loc in secret_locations)


def test_scan_clean_dir_reports_no_findings(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text(CLEAN_FILE, encoding="utf-8")
    result = scan_codebase(str(tmp_path))
    assert result["vulnerability_count"] == 0
    assert result["severity_score"] == 0.0


def test_scan_skips_ignored_directories(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.py").write_text(DIRTY_FILE, encoding="utf-8")
    result = scan_codebase(str(tmp_path))
    assert result["vulnerability_count"] == 0


def test_scan_outdated_dependencies(deps_dir: Path) -> None:
    result = scan_codebase(str(deps_dir), categories=["outdated_deps"])
    deps_findings = result["vulnerabilities"]
    assert len(deps_findings) == 1
    assert deps_findings[0]["category"] == "outdated_deps"
    assert "flask==1.0.2" in deps_findings[0]["description"]
    # requests==2.31.0 is above the safe version and must not be flagged.
    assert "requests" not in deps_findings[0]["description"]


def test_scan_missing_path_raises() -> None:
    with pytest.raises(ValueError):
        scan_codebase("/nonexistent/path/xyz")


def test_scan_single_file(dirty_dir: Path) -> None:
    result = scan_codebase(str(dirty_dir / "app.py"))
    assert result["vulnerability_count"] >= 3
    for finding in result["vulnerabilities"]:
        assert finding["location"].startswith("app.py:")


def test_scan_severity_is_mean_of_findings(dirty_dir: Path) -> None:
    result = scan_codebase(str(dirty_dir))
    expected = round(
        sum(f["severity_score"] for f in result["vulnerabilities"])
        / len(result["vulnerabilities"]),
        3,
    )
    assert result["severity_score"] == expected


# ── API (storage-backed) ──────────────────────────────────────────────────


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    with TestClient(app) as test_client:
        yield test_client


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_post_scan_and_results_roundtrip(client: TestClient, dirty_dir: Path) -> None:
    response = client.post(
        "/scans", json={"target_path": str(dirty_dir)}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] is not None
    assert body["results_count"] >= 3

    results = client.get("/results").json()
    assert len(results) == body["results_count"]
    for row in results:
        assert row["id"] is not None
        assert row["category"] in SEVERITY_BY_CATEGORY
        assert row["location"]


def test_severity_breakdown_shape(client: TestClient, dirty_dir: Path) -> None:
    client.post("/scans", json={"target_path": str(dirty_dir)})
    data = client.get("/severity_breakdown").json()
    assert data["total_vulnerabilities"] >= 3
    assert isinstance(data["average_severity"], float)
    total_in_categories = sum(len(v) for v in data["categories"].values())
    assert total_in_categories == data["total_vulnerabilities"]


def test_trend_lines_shape(client: TestClient, dirty_dir: Path) -> None:
    client.post("/scans", json={"target_path": str(dirty_dir)})
    data = client.get("/trend_lines").json()
    assert len(data["dates"]) == 7
    for key in ("sqli_trend", "xss_trend", "secrets_trend", "outdated_deps_trend"):
        assert len(data[key]) == 7
    # Today's counts reflect the scan we just ran.
    assert data["sqli_trend"][-1] >= 1


def test_scans_lists_history(client: TestClient, dirty_dir: Path) -> None:
    client.post("/scans", json={"target_path": str(dirty_dir)})
    scans = client.get("/scans").json()
    assert isinstance(scans, list)
    assert any(s["target_path"] == str(dirty_dir.resolve()) for s in scans)


def test_post_scan_unknown_category_rejected(client: TestClient) -> None:
    response = client.post(
        "/scans", json={"target_path": ".", "categories": ["sqli", "bogus"]}
    )
    assert response.status_code == 422


def test_post_scan_missing_path_404(client: TestClient) -> None:
    response = client.post("/scans", json={"target_path": "/nonexistent/xyz"})
    assert response.status_code == 404
