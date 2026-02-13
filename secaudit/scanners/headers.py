"""HTTP security header analysis scanner."""

import requests

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner

EXPECTED_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS header is missing. Browsers may connect over insecure HTTP.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "cwe_id": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP header is missing. The site is more vulnerable to XSS attacks.",
        "remediation": "Implement a Content-Security-Policy header with restrictive directives.",
        "cwe_id": "CWE-79",
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cwe_id": "CWE-16",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "cwe_id": "CWE-1021",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header is missing. Browser features are not restricted.",
        "remediation": "Add a Permissions-Policy header to restrict browser feature access.",
        "cwe_id": None,
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing. Full URLs may leak in Referer headers.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cwe_id": "CWE-200",
    },
}

INSECURE_VALUES = {
    "X-Content-Type-Options": lambda v: v.lower() != "nosniff",
    "X-Frame-Options": lambda v: v.upper() not in ("DENY", "SAMEORIGIN"),
    "Content-Security-Policy": lambda v: "unsafe-inline" in v and "unsafe-eval" in v,
}


class HeaderScanner(BaseScanner):
    name = "headers"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)

        try:
            resp = self.session.get(target, timeout=10, allow_redirects=True)
        except requests.RequestException as exc:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title="Connection failed",
                    description=f"Could not connect to {target}: {exc}",
                    location=target,
                    remediation="Verify the URL is correct and the server is reachable.",
                )
            )
            return result

        headers = resp.headers

        for header_name, info in EXPECTED_HEADERS.items():
            value = headers.get(header_name)
            if value is None:
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        severity=info["severity"],
                        title=f"Missing {header_name} header",
                        description=info["description"],
                        location=target,
                        remediation=info["remediation"],
                        cwe_id=info["cwe_id"],
                    )
                )
            elif header_name in INSECURE_VALUES and INSECURE_VALUES[header_name](value):
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        severity=info["severity"],
                        title=f"Misconfigured {header_name} header",
                        description=f"{header_name} has a weak value: {value}",
                        location=target,
                        remediation=info["remediation"],
                        cwe_id=info["cwe_id"],
                    )
                )

        if "Server" in headers:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="Server header exposes technology",
                    description=f"Server header reveals: {headers['Server']}",
                    location=target,
                    remediation="Remove or obfuscate the Server header.",
                    cwe_id="CWE-200",
                )
            )

        return result
