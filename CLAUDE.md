# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Install in editable mode (requires venv)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest -v

# Run a single test file or test
pytest tests/test_code.py
pytest tests/test_code.py::TestCodeScanner::test_eval_detection

# Run the tool
secaudit scan-code <path>          # secrets + SAST scanners
secaudit scan-url <url>            # headers + TLS scanners
secaudit scan-deps <path>          # dependency vulnerability scanner
secaudit scan-all <path> --url <u> # all scanners
```

## Architecture

SecAudit is a CLI security audit toolkit with a plugin-style scanner architecture.

**Data flow:** CLI (`cli.py`) instantiates scanners → each scanner produces a `ScanResult` containing `Finding` objects → results are rendered by `report.py` (rich tables or JSON).

**Scanner pattern:** All scanners inherit from `BaseScanner` (in `scanners/base.py`) and implement `scan(target: str) -> ScanResult`. The `_timed_scan()` wrapper adds duration tracking. Scanners are registered in `scanners/__init__.py` via the `SCANNERS` dict.

**Scanner types by target:**
- URL-based: `HeaderScanner`, `TLSScanner` — accept URLs/hostnames
- Path-based: `SecretScanner`, `CodeScanner` — walk directories of source files
- File-based: `DependencyScanner` — parses `requirements.txt` or `pyproject.toml`

**Key design decisions:**
- `CodeScanner` uses Python AST analysis (not regex) for SAST checks — the `_SecurityVisitor` class in `code.py` walks the AST tree
- `SecretScanner` combines regex pattern matching with Shannon entropy analysis for detecting high-entropy strings
- `DependencyScanner` queries the OSV.dev API (free, no key) for known vulnerabilities
- Network-dependent scanners (`HeaderScanner`, `DependencyScanner`) accept an injected `requests.Session` for testability
- All tests use mocked HTTP and temp files — no real network calls
