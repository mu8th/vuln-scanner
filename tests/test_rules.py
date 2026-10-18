"""Precision tests for the line rules: real flaws flagged, safe look-alikes not.

These import only the stdlib engine, so they run without FastAPI installed.
"""

from pathlib import Path

import pytest

from backend.services.scanner import (
    _is_test_path,
    _secret_value_is_placeholder,
    scan_codebase,
    scan_text,
)


def _categories(text: str, filename: str = "app.py") -> list[str]:
    return [f["category"] for f in scan_text(text, filename)["vulnerabilities"]]


# ── SQL injection ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "line",
    [
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"",
        'cur.execute(f"SELECT * FROM orders WHERE id = {order_id}")',
        'sql = "DELETE FROM sessions WHERE token = \'%s\'" % token',
        'db.query("UPDATE accounts SET balance = {}".format(amount))',
        "const q = `SELECT * FROM users WHERE id = ${req.params.id}`;",
        "payload = \"' OR 1=1 --\"",
    ],
)
def test_dynamic_sql_is_flagged(line: str) -> None:
    assert _categories(line) == ["sqli"]


@pytest.mark.parametrize(
    "line",
    [
        'cur.execute("SELECT * FROM users WHERE id = ?", (uid,))',
        'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))',
        "# delete the cached rows from disk before retrying",
        "greeting = 'Hello {}'.format(name)",
        "rows = session.query(User).filter(User.id == uid).all()",
    ],
)
def test_static_or_parameterized_sql_is_not_flagged(line: str) -> None:
    assert _categories(line) == []


def test_markdown_prose_is_not_scanned() -> None:
    prose = "- Hard caps on latency, jitter, and drop rates turn the YAML into a safe spec."
    assert _categories(prose, "README.md") == []


# ── XSS sinks ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "line",
    [
        "el.innerHTML = userInput;",
        "el.innerHTML = '<p>' + comment + '</p>';",
        "el.innerHTML = `<b>${name}</b>`;",
        "box.outerHTML = html;",
        "list.insertAdjacentHTML('beforeend', row);",
        "document.write(location.hash);",
        "eval(request.body)",
    ],
)
def test_dynamic_html_sinks_are_flagged(line: str) -> None:
    assert _categories(line, "app.js") == ["xss"]


@pytest.mark.parametrize(
    "line",
    [
        "el.innerHTML = '';",
        "el.innerHTML = '<p class=\"empty\">No results</p>';",
        "el.innerHTML = `<span class=\"cell\">${escText(txt)}</span>`;",
        "el.innerHTML = `<a href=\"/u/${encodeURIComponent(id)}\">${esc(name)}</a>`;",
        "if (el.innerHTML == expected) { done(); }",
        '<script src="/static/app.js"></script>',
    ],
)
def test_static_or_escaped_html_is_not_flagged(line: str) -> None:
    assert _categories(line, "app.js") == []


def test_partially_escaped_template_is_still_flagged() -> None:
    line = "el.innerHTML = `<b>${esc(name)}</b><i>${bio}</i>`;"
    assert _categories(line, "app.js") == ["xss"]


# ── Secrets ───────────────────────────────────────────────────────────────


def test_literal_secret_flagged_but_comparison_and_reference_are_not() -> None:
    assert _categories('password = "hunter2"') == ["secrets"]
    assert _categories("if password == attempt:") == []
    assert _categories("login(password=form.password.data)") == []
    # In config files an unquoted value is a literal.
    assert _categories("POSTGRES_PASSWORD=postgres", "docker-compose.yml") == ["secrets"]


def test_placeholder_rules_depend_on_file_type() -> None:
    assert _secret_value_is_placeholder("password=form.password", ".py")
    assert not _secret_value_is_placeholder("password=letmein", ".env")


def test_cloud_keys_are_flagged_anywhere() -> None:
    assert _categories("AWS_KEY = AKIAABCDEFGHIJKLMNOP") == ["secrets"]


# ── Context, spans, and the walker ────────────────────────────────────────


def test_test_paths_are_detected() -> None:
    assert _is_test_path("tests/test_api.py")
    assert _is_test_path("src/fixtures/users.json")
    assert _is_test_path("web/app.spec.ts")
    assert not _is_test_path("backend/services/scanner.py")


def test_findings_carry_span_and_halve_in_tests() -> None:
    line = "q = \"SELECT * FROM t WHERE a = '\" + a + \"'\""
    code = scan_text(line, "app.py")["vulnerabilities"][0]
    test = scan_text(line, "tests/test_app.py")["vulnerabilities"][0]
    assert code["line"] == 1 and code["column"] >= 1 and code["end_column"] > code["column"]
    assert code["context"] == "code" and test["context"] == "test"
    assert test["severity_score"] == code["severity_score"] / 2


def test_scan_text_rejects_oversized_input() -> None:
    with pytest.raises(ValueError):
        scan_text("x" * (600 * 1024))


def test_walker_skips_docs_but_scans_code(tmp_path: Path) -> None:
    (tmp_path / "NOTES.md").write_text("select a from b where c = '\" + d", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "q = \"SELECT * FROM t WHERE a = '\" + a + \"'\"\n", encoding="utf-8"
    )
    result = scan_codebase(str(tmp_path))
    assert [f["location"] for f in result["vulnerabilities"]] == ["app.py:1"]
