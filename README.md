# SecAudit

Automated security audit toolkit for Python projects. Scans source code for secrets and vulnerabilities, checks HTTP headers and TLS configuration, and identifies known dependency vulnerabilities.

## Scanners

| Scanner | Command | What it checks |
|---------|---------|----------------|
| **SecretScanner** | `scan-code` | Hardcoded secrets via regex + Shannon entropy |
| **CodeScanner** | `scan-code` | SAST checks using Python AST analysis |
| **HeaderScanner** | `scan-url` | Missing/misconfigured HTTP security headers |
| **TLSScanner** | `scan-url` | TLS certificate and protocol issues |
| **DependencyScanner** | `scan-deps` | Known CVEs via the OSV.dev API |

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Usage

```bash
# Scan source code for secrets and SAST issues
secaudit scan-code <path>

# Scan HTTP headers and TLS configuration
secaudit scan-url <url>

# Scan dependencies for known vulnerabilities
secaudit scan-deps <path>

# Run all scanners
secaudit scan-all <path> --url <url>
```

### Options

All commands support:

- `--format table|json` — output format (default: `table`)
- `--severity INFO|LOW|MEDIUM|HIGH|CRITICAL` — minimum severity to display
- `-o, --output <file>` — write JSON report to file
- `--exit-code` — exit with code 1 if findings meet the severity threshold (useful for CI)

## Testing

```bash
pytest -v
```

All tests use mocked HTTP responses and temporary files — no network access required.
