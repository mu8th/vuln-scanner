# Vulnerability Scanner

**[Try the live demo →](https://muath.online/#project-scan)** Paste a snippet and see
which lines the rules flag, or scan a deliberately vulnerable sample app.

A local, dependency-light **static vulnerability scanner**. Point it at a
directory and it walks every scannable file, applies regex heuristics for SQL
injection, XSS, hardcoded secrets, and outdated pinned dependencies, then
persists each scan so you can watch findings trend over time. The dashboard is
a FastAPI + Chart.js app that reads straight from the stored results.

The pipeline is three stages:

```
scan                              persist                     visualize
──────                            ─────────                   ───────────
walk the tree, apply patterns     store Scan + findings in    dashboard reads the
and check dependency pins         SQLite / Postgres           latest scan and the
   │                                  │                       per-day trend lines
   └──────────────────────────────────┴──────────────────────►  FastAPI + Chart.js
```

- **Scan**: `backend/services/scanner.py` walks the target, skips VCS and
  cache directories, caps file size at 512 KB, and matches four categories of
  compiled regex patterns line by line. It also checks exact `==` pins in
  `requirements.txt` against a small offline advisory table.
- **Persist**: every completed scan is written with its findings through
  SQLAlchemy. The default store is a local SQLite file; set `DATABASE_URL` to
  point at Postgres instead.
- **Visualize**: the dashboard serves the latest scan's breakdown, the finding
  table, and a 7-day trend line built from real scan history (no canned data).

## Honest scope

This is a regex heuristic scanner, not a taint analyzer. It flags suspicious
literals and known-bad dependency pins. It will miss data that reaches a sink
through several variables, and it can flag a pattern that turns out to be safe.
Treat it as a fast first pass, the way you'd use `grep` for secrets, not as a
replacement for Semgrep or Bandit. The README and code say this plainly because
a reviewer should never have to guess at the limits.

### What keeps the false-positive rate down

Each rule is paired with a suppression for its most common safe look-alike:

| Rule | Flagged | Not flagged |
| --- | --- | --- |
| SQL injection | A SQL statement built on the same line with `+`, `%`, `.format()`, an f-string or `${}` | Parameterized queries (`execute("... WHERE id = ?", (uid,))`), comments, `'Hello {}'.format(x)` |
| XSS | `innerHTML`/`outerHTML` assignments, `insertAdjacentHTML`, `document.write`, `eval` with dynamic input | Clearing an element (`innerHTML = ''`), fixed strings, templates whose every `${}` goes through `esc()`/`escape*()`/`sanitize*()`/`DOMPurify.sanitize()` |
| Secrets | Quoted literals assigned to `password`/`api_key`, AWS and GitHub token shapes | `==` comparisons, `os.getenv(...)`, `${VAR}`, and unquoted variable references in source code |

Documentation files (`.md`, `.rst`, `.txt`, `.adoc`) are not run through the code
rules, and findings under `tests/`, `fixtures/` or in `test_*.py` files are kept
but ranked at half severity with `context: "test"`. `tests/test_rules.py` pins
each of these cases.

## Requirements

- Python 3.11+

Install deps:

```bash
pip install -r requirements.txt
```

## Run the demo server

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000> for the dashboard. On first run against an empty
database, the server scans its own repository so the charts have real data to
show (override the target with `VULN_SCAN_ROOT=/path/to/repo`).

Run a scan on demand:

```bash
curl -s http://127.0.0.1:8000/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_path":"/path/to/scan","categories":["sqli","xss","secrets","outdated_deps"]}'
```

### Configuration (environment)

| Variable         | Default                 | Purpose                                  |
|------------------|-------------------------|------------------------------------------|
| `DATABASE_URL`   | local SQLite file       | SQLAlchemy connection string             |
| `VULN_SCAN_ROOT` | this project's root     | Target for the first-run self-scan       |

### API

| Method | Path                          | Returns                              |
|--------|-------------------------------|--------------------------------------|
| GET    | `/health`                     | Service status                       |
| POST   | `/scans`                      | Run a scan, persist it, return summary |
| GET    | `/scans`                      | Recent completed scans               |
| GET    | `/results`                    | Findings from the latest scan        |
| GET    | `/results/category/{cat}`     | Latest findings in one category      |
| GET    | `/results/severity/{min}`     | Latest findings at/above a severity  |
| GET    | `/severity_breakdown`         | Category distribution + average      |
| GET    | `/trend_lines`                | Per-day counts, last 7 days          |

## Library usage

The scanner is framework-free (stdlib only), so you can import it without
FastAPI or SQLAlchemy:

```python
from backend.services.scanner import scan_codebase

result = scan_codebase("/path/to/repo")
print(result["vulnerability_count"], result["severity_score"])
for finding in result["vulnerabilities"]:
    print(finding["category"], finding["location"], finding["description"])
```

Scan an in-memory snippet with the same rules (the file name only sets the file
type the rules assume; nothing touches disk):

```python
from backend.services.scanner import scan_text

result = scan_text('el.innerHTML = "<b>" + name + "</b>";', "app.js")
finding = result["vulnerabilities"][0]
print(finding["line"], finding["column"], finding["end_column"])  # span to highlight
```

## Docker

```bash
docker compose up --build
```

This runs the app plus a Postgres store. The app binds `0.0.0.0` inside the
container; compose maps the port to the host's loopback only, so the service
stays local.

## Tests

```bash
python -m pytest tests -q
```

The suite covers the pure engine (severity mapping, placeholder filtering,
dependency checks, ignored directories), the storage-backed API through
`TestClient`, and error paths. It uses `tmp_path` fixtures throughout, so no
machine-specific paths are baked in and no live database is required.

## License

MIT, see [LICENSE](LICENSE).
