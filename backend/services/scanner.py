"""Static analysis engine for the vulnerability scanner.

Walks a target directory, applies compiled regex heuristics to every
scannable text file, and checks pinned dependency versions against a small
offline advisory table. This module is deliberately framework-free (stdlib
only) so it can be imported standalone, for example by the portfolio site,
without pulling in FastAPI or SQLAlchemy.

Persistence of scan results lives in :mod:`backend.services.storage`.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

# ── Severity + remediation ────────────────────────────────────────────────

SEVERITY_BY_CATEGORY: dict[str, float] = {
    "sqli": 1.0,
    "xss": 0.8,
    "secrets": 0.5,
    "outdated_deps": 0.2,
}


def classify_severity(category: str) -> float:
    """Return the base severity score for a finding category."""
    return SEVERITY_BY_CATEGORY.get(category, 0.0)


def get_remediation_suggestion(category: str) -> str | None:
    """Return an actionable remediation hint for a finding category."""
    suggestions = {
        "sqli": (
            "Use parameterized queries or an ORM. Never build SQL by "
            "concatenating user input."
        ),
        "xss": (
            "Escape output with the framework's auto-escaping templates and "
            "set a strict Content Security Policy."
        ),
        "secrets": (
            "Move credentials to environment variables or a secrets manager. "
            "Rotate any value that was committed."
        ),
        "outdated_deps": (
            "Update the dependency to the minimum safe version listed in the "
            "finding, then re-run the scan."
        ),
    }
    return suggestions.get(category)


# ── Detection patterns ────────────────────────────────────────────────────
# Heuristic, line-oriented regexes. They catch suspicious literals, not real
# taint flow; see the README limitations section before treating results as a
# substitute for Semgrep or Bandit.

#: A complete SQL statement shape. On its own this is not a finding: a
#: parameterized query contains one too. It counts only on a line that also
#: builds the string dynamically (see ``_DYNAMIC_SQL``).
_SQL_STATEMENT = re.compile(
    r"(?i)\b(?:select\s+[\w*,.\s()]+?\s+from|insert\s+into|update\s+\w+\s+set"
    r"|delete\s+from|drop\s+(?:table|database)|union\s+(?:all\s+)?select)\b"
)

#: String concatenation, %-formatting, ``.format()``, f-strings or JS template
#: interpolation on the same line as a SQL statement.
_DYNAMIC_SQL = re.compile(r"""["']\s*\+|\+\s*["']|["']\s*%\s*[\w(]|\.format\s*\(|\bf["']|\$\{""")

SQLI_PATTERNS: list[re.Pattern[str]] = [
    # Classic tautology payload carried in a literal: ' OR 1=1
    re.compile(r"'\s*OR\s+[0-9]+\s*=\s*[0-9]+"),
    # f-string whose SQL text interpolates a value.
    re.compile(r"f['\"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'\"]*\{", re.IGNORECASE),
    _SQL_STATEMENT,
]

XSS_PATTERNS: list[re.Pattern[str]] = [
    # Static `<script>` tags (external `src=` references or bare inline openers)
    # are the application's own markup, not an injection sink; they are matched
    # here only so `_is_static_script_tag` can suppress them below.
    re.compile(r"<script[^>]*>"),
    re.compile(r"eval\s*\("),
    re.compile(r"document\.write\s*\("),
    re.compile(r"(?:inner|outer)HTML\s*=(?!=)"),
    re.compile(r"insertAdjacentHTML\s*\("),
    re.compile(r"onclick\s*="),
]

#: Calls that escape or sanitize a value before it reaches an HTML sink.
_ESCAPER = re.compile(
    r"^\s*(?:esc\w*|escape\w*|sanitize\w*|DOMPurify\.sanitize|encodeURIComponent)\s*\(",
    re.IGNORECASE,
)

#: File types where an unquoted assignment value is a variable reference
#: (``password=form.password``), not a literal credential.
_CODE_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".java", ".go", ".rb", ".php", ".cs", ".kt", ".swift", ".rs",
}

#: Prose files. Sentences such as "drop rates are bounded into..." look like
#: SQL to a line regex; documentation is not executable, so code patterns are
#: not applied to it.
DOC_EXTENSIONS = {".md", ".markdown", ".rst", ".adoc", ".txt"}

#: Path segments and file names that mark test code or fixtures. Findings there
#: are kept (a leaked key in a fixture is still a leak) but ranked at half
#: severity, because test inputs are often deliberately vulnerable.
_TEST_DIRS = {"tests", "test", "__tests__", "fixtures", "fixture", "testdata", "spec"}
_TEST_FILE = re.compile(r"^(?:test_.*\.py|.*_test\.(?:py|go)|.*\.(?:test|spec)\.[jt]sx?)$")

_COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--")


def _is_test_path(rel_path: str) -> bool:
    """Return True when a relative path points at test code or a fixture."""
    parts = rel_path.replace("\\", "/").split("/")
    return any(p.lower() in _TEST_DIRS for p in parts[:-1]) or bool(_TEST_FILE.match(parts[-1]))


def _sqli_match(line: str) -> re.Match[str] | None:
    """Return the first SQL injection match on a line, or None.

    A bare SQL statement only counts when the same line builds it dynamically;
    ``cursor.execute("SELECT ... WHERE id = ?", (uid,))`` is the safe form and
    is not flagged.
    """
    for pattern in SQLI_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        if pattern is _SQL_STATEMENT and not _DYNAMIC_SQL.search(line):
            continue
        return match
    return None


def _html_sink_is_safe(line: str, match: re.Match[str]) -> bool:
    """Return True when an HTML sink receives only static or escaped content.

    Covers the common safe forms: clearing an element (``el.innerHTML = ''``),
    assigning a fixed string, a template literal with no interpolation, and a
    template literal whose every ``${...}`` passes through an escaping call
    such as ``esc(...)`` or ``DOMPurify.sanitize(...)``.
    """
    sink = match.group(0)
    if "HTML" not in sink:
        if sink.startswith("onclick"):
            # An inline handler in static markup is the app's own code.
            return "${" not in line and "+" not in line
        return False
    rhs = line[match.end():].strip().rstrip(";").strip()
    if not rhs:
        return False
    if re.fullmatch(r"'[^']*'|\"[^\"]*\"", rhs):
        return True
    if rhs.startswith("`") and rhs.endswith("`") and len(rhs) >= 2:
        expressions = re.findall(r"\$\{([^}]*)\}", rhs)
        return all(_ESCAPER.match(expr) for expr in expressions)
    return False


def _is_static_script_tag(line: str, match: re.Match[str]) -> bool:
    """Return True when an XSS match is static markup, not a payload.

    A script tag in HTML markup is not an injection sink: external references
    (``src=...``) load known application code, and bare inline openers are the
    app's own scripts. Real XSS risk lives in dynamic sinks such as
    ``innerHTML`` assignments -- or in a script tag carried inside a string
    literal (a payload), which is still flagged: a quote character before the
    match marks it as data, not markup.
    """
    if not match.group(0).lstrip().startswith("<script"):
        return False
    prefix = line[: match.start()]
    return '"' not in prefix and "'" not in prefix and "`" not in prefix


SECRETS_PATTERNS: list[re.Pattern[str]] = [
    # `(?![=])` keeps comparisons such as `password == attempt` out.
    re.compile(r"(?i)password\s*=(?!=)\s*[^\s]+"),
    re.compile(r"(?i)api[_-]?key\s*=(?!=)\s*[^\s]+"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]

# ── Dependency advisories (offline snapshot) ──────────────────────────────
# name -> (minimum safe version, advisory reference). Only exact `==` pins in
# requirements files are checked. Extend as needed; this is intentionally a
# small, reviewable table rather than a live feed.

KNOWN_VULNERABLE_DEPS: dict[str, tuple[str, str]] = {
    "flask": ("2.0.1", "CVE-2023-30861"),
    "requests": ("2.20.0", "CVE-2018-18074"),
    "urllib3": ("1.26.5", "CVE-2021-33503"),
    "pyyaml": ("5.4", "CVE-2020-1747"),
    "cryptography": ("39.0.1", "CVE-2023-23914, CVE-2023-49083"),
}

# ── Walk configuration ────────────────────────────────────────────────────

SKIP_DIRS = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env",
    "__pycache__", "node_modules",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".idea", ".vscode",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".gz", ".tar", ".whl",
    ".db", ".sqlite", ".sqlite3",
    ".pyc", ".so", ".dll", ".exe", ".bin",
}

MAX_FILE_BYTES = 512 * 1024

# The engine excludes its own source file from scans: the pattern library
# contains literal payloads (e.g. `<script[^>]*>`) that would otherwise match
# themselves on every self-scan.
_SELF_FILE = Path(__file__).resolve()


def _version_tuple(version: str) -> tuple[int, ...]:
    """Parse a dotted version string into comparable ints."""
    parts: list[int] = []
    for chunk in re.split(r"[.\-+]", version.strip()):
        digits = re.match(r"\d+", chunk)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def _secret_value_is_placeholder(match_text: str, suffix: str = "") -> bool:
    """Return True when a secrets match holds no literal credential.

    Skips empty values, None/null, and references such as ``os.getenv(...)``
    or ``${ENV_VAR}`` so the engine does not flag environment wiring. In source
    code (``suffix`` is a code extension such as ``.py``), an unquoted value is
    a variable or attribute reference, not a literal, and is skipped too.
    """
    if "=" not in match_text:
        return False
    raw = match_text.split("=", 1)[1].strip()
    value = raw.strip("'\"")
    if not value or value.lower() in {"none", "null"}:
        return True
    if re.match(r"^(os\.|getenv|\$\{|\{|<|%)", value, re.IGNORECASE):
        return True
    if suffix.lower() in _CODE_EXTENSIONS and raw[:1] not in {"'", '"', "`"}:
        return True
    return False


def _match_line(line: str, category: str, suffix: str) -> re.Match[str] | None:
    """Return the first match for one category on one line, after suppressions."""
    if category == "sqli":
        return _sqli_match(line)
    patterns = {"xss": XSS_PATTERNS, "secrets": SECRETS_PATTERNS}.get(category)
    for pattern in patterns or []:
        match = pattern.search(line)
        if not match:
            continue
        if category == "secrets" and _secret_value_is_placeholder(match.group(0), suffix):
            continue
        if category == "xss" and (
            _is_static_script_tag(line, match) or _html_sink_is_safe(line, match)
        ):
            continue
        return match
    return None


def _scan_lines(text: str, rel_path: str, categories: list[str]) -> list[dict]:
    """Apply the selected category patterns to text. Returns findings.

    Each finding carries the 1-based ``line`` plus the matched ``column`` span
    so a UI can highlight it, and a ``context`` of ``"code"`` or ``"test"``.
    """
    findings: list[dict] = []
    suffix = Path(rel_path).suffix.lower()
    if suffix in DOC_EXTENSIONS:
        return findings
    in_tests = _is_test_path(rel_path)

    for lineno, line in enumerate(text.splitlines(), start=1):
        is_comment = line.lstrip().startswith(_COMMENT_PREFIXES)
        for category in categories:
            if is_comment and category in {"sqli", "xss"}:
                continue
            match = _match_line(line, category, suffix)
            if match is None:
                continue
            severity = classify_severity(category)
            if in_tests:
                severity = round(severity / 2, 3)
            findings.append(
                {
                    "category": category,
                    "severity_score": severity,
                    "location": f"{rel_path}:{lineno}",
                    "line": lineno,
                    "column": match.start() + 1,
                    "end_column": match.end() + 1,
                    "context": "test" if in_tests else "code",
                    "description": (
                        f"Suspicious {category} pattern on line {lineno}: "
                        f"{line.strip()[:120]}"
                    ),
                    "remediation_suggestion": get_remediation_suggestion(category),
                }
            )
    return findings


def _scan_file(path: Path, rel_path: str, categories: list[str]) -> list[dict]:
    """Apply the selected category patterns to one file. Returns findings."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return _scan_lines(text, rel_path, categories)


def scan_text(text: str, filename: str = "snippet.py", categories: list[str] | None = None) -> dict:
    """Scan an in-memory snippet with the same rules as :func:`scan_codebase`.

    ``filename`` only sets the file type (and test context) the rules assume;
    nothing is read from or written to disk. Dependency pins are not checked.
    Text over the 512 KB file cap is rejected with ``ValueError``.
    """
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError("Snippet exceeds the 512 KB scan limit")
    if categories is None:
        categories = list(SEVERITY_BY_CATEGORY)
    started = time.perf_counter()
    findings = _scan_lines(text, filename, [c for c in categories if c != "outdated_deps"])
    findings.sort(key=lambda f: (-f["severity_score"], f["line"]))
    severity = (
        round(sum(f["severity_score"] for f in findings) / len(findings), 3) if findings else 0.0
    )
    return {
        "scan_id": None,
        "target_path": filename,
        "severity_score": severity,
        "vulnerability_count": len(findings),
        "vulnerabilities": findings,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def _check_dependencies(root: Path) -> list[dict]:
    """Check exact `==` pins in requirements files against the advisory table."""
    findings: list[dict] = []
    for req_name in ("requirements.txt", "requirements-dev.txt"):
        req_file = root / req_name
        if not req_file.is_file():
            continue
        try:
            lines = req_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#") or "==" not in line:
                continue
            name, _, version = line.partition("==")
            spec = KNOWN_VULNERABLE_DEPS.get(name.strip().lower())
            if spec and _version_tuple(version) < _version_tuple(spec[0]):
                findings.append(
                    {
                        "category": "outdated_deps",
                        "severity_score": classify_severity("outdated_deps"),
                        "location": f"{req_name}:{lineno}",
                        "description": (
                            f"{name.strip()}=={version.strip()} is below the safe "
                            f"version {spec[0]} ({spec[1]})"
                        ),
                        "remediation_suggestion": get_remediation_suggestion(
                            "outdated_deps"
                        ),
                    }
                )
    return findings


def scan_codebase(target_path: str, categories: list[str] | None = None) -> dict:
    """Scan a directory tree for suspicious patterns.

    Args:
        target_path: Path to the file or directory to scan.
        categories: Subset of ``sqli``, ``xss``, ``secrets``,
            ``outdated_deps``. Defaults to all four.

    Returns:
        A dict with ``scan_id`` (None until persisted), ``target_path``,
        ``severity_score`` (mean of finding scores, 0.0 when clean),
        ``vulnerability_count``, the ordered ``vulnerabilities`` list, and
        ``duration_ms``.

    Raises:
        ValueError: If ``target_path`` does not exist.
    """
    if categories is None:
        categories = list(SEVERITY_BY_CATEGORY)

    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise ValueError(f"Target path does not exist: {target}")

    started = time.perf_counter()
    findings: list[dict] = []

    code_categories = [c for c in categories if c != "outdated_deps"]
    if target.is_file():
        findings.extend(_scan_file(target, target.name, code_categories))
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in sorted(files):
                path = Path(root) / name
                if path.suffix.lower() in SKIP_EXTENSIONS:
                    continue
                if path.resolve() == _SELF_FILE:
                    continue
                rel = os.path.relpath(path, target).replace(os.sep, "/")
                findings.extend(_scan_file(path, rel, code_categories))
        if "outdated_deps" in categories:
            findings.extend(_check_dependencies(target))

    # Most severe first, then stable by location.
    findings.sort(key=lambda f: (-f["severity_score"], f["location"]))
    if findings:
        severity = round(sum(f["severity_score"] for f in findings) / len(findings), 3)
    else:
        severity = 0.0

    return {
        "scan_id": None,
        "target_path": str(target),
        "severity_score": severity,
        "vulnerability_count": len(findings),
        "vulnerabilities": findings,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }
