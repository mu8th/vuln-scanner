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

SQLI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"'\s*OR\s+[0-9]+\s*=\s*[0-9]+"),
    re.compile(
        r"(?i)\b(union|select|insert|update|delete|drop)\b.*\b(from|into|table|database)\b"
    ),
    re.compile(r"\.\s*format\s*\(\s*['\"][^'\"]*\{"),
    re.compile(r"f['\"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b", re.IGNORECASE),
]

XSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<script[^>]*>"),
    re.compile(r"eval\s*\("),
    re.compile(r"document\.write\s*\("),
    re.compile(r"innerHTML\s*="),
    re.compile(r"onclick\s*="),
]

SECRETS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)password\s*=\s*[^\s]+"),
    re.compile(r"(?i)api[_-]?key\s*=\s*[^\s]+"),
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


def _secret_value_is_placeholder(match_text: str) -> bool:
    """Return True when a secrets match holds no literal credential.

    Skips empty values, None/null, and references such as ``os.getenv(...)``
    or ``${ENV_VAR}`` so the engine does not flag environment wiring.
    """
    if "=" not in match_text:
        return False
    value = match_text.split("=", 1)[1].strip().strip("'\"")
    if not value or value.lower() in {"none", "null"}:
        return True
    return re.match(r"^(os\.|getenv|\$\{|\{|<|%)", value, re.IGNORECASE) is not None


def _scan_file(path: Path, rel_path: str, categories: list[str]) -> list[dict]:
    """Apply the selected category patterns to one file. Returns findings."""
    findings: list[dict] = []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return findings
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        for category in categories:
            patterns = {
                "sqli": SQLI_PATTERNS,
                "xss": XSS_PATTERNS,
                "secrets": SECRETS_PATTERNS,
            }.get(category)
            if not patterns:
                continue
            for pattern in patterns:
                match = pattern.search(line)
                if not match:
                    continue
                if category == "secrets" and _secret_value_is_placeholder(
                    match.group(0)
                ):
                    continue
                findings.append(
                    {
                        "category": category,
                        "severity_score": classify_severity(category),
                        "location": f"{rel_path}:{lineno}",
                        "description": (
                            f"Suspicious {category} pattern on line {lineno}: "
                            f"{line.strip()[:120]}"
                        ),
                        "remediation_suggestion": get_remediation_suggestion(category),
                    }
                )
                break  # one finding per category per line
    return findings


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
