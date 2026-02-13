"""OWASP Top 10 2021 compliance mapping for CWE IDs."""

from secaudit.models import Finding, ScanResult, Severity

# OWASP Top 10 2021 categories mapped from CWE IDs
OWASP_TOP_10: dict[str, dict] = {
    "A01:2021": {
        "name": "Broken Access Control",
        "cwes": {"CWE-200", "CWE-1021", "CWE-617"},
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "cwes": {"CWE-321", "CWE-326", "CWE-327", "CWE-328", "CWE-798"},
    },
    "A03:2021": {
        "name": "Injection",
        "cwes": {"CWE-78", "CWE-79", "CWE-89", "CWE-95", "CWE-611"},
    },
    "A04:2021": {
        "name": "Insecure Design",
        "cwes": {"CWE-16"},
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "cwes": {"CWE-319", "CWE-489", "CWE-377"},
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "cwes": set(),  # Dependency scanner findings without specific CWEs
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "cwes": {"CWE-295", "CWE-298"},
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "cwes": {"CWE-502"},
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "cwes": set(),
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery",
        "cwes": set(),
    },
}

# Reverse lookup: CWE -> OWASP category
CWE_TO_OWASP: dict[str, str] = {}
for owasp_id, info in OWASP_TOP_10.items():
    for cwe in info["cwes"]:
        CWE_TO_OWASP[cwe] = owasp_id


def map_finding_to_owasp(finding: Finding) -> str | None:
    """Map a finding to its OWASP Top 10 2021 category."""
    if finding.cwe_id:
        return CWE_TO_OWASP.get(finding.cwe_id)
    # Map dependency scanner findings to A06
    if finding.scanner == "dependencies":
        return "A06:2021"
    return None


def group_by_owasp(results: list[ScanResult], min_severity: Severity = Severity.INFO) -> dict[str, list[Finding]]:
    """Group findings by OWASP Top 10 category."""
    groups: dict[str, list[Finding]] = {}

    for r in results:
        for f in r.findings:
            if f.severity < min_severity:
                continue
            owasp = map_finding_to_owasp(f)
            if owasp:
                groups.setdefault(owasp, []).append(f)

    return groups
