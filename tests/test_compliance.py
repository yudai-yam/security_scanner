"""Tests for OWASP Top 10 compliance mapping."""

from secaudit.compliance import CWE_TO_OWASP, group_by_owasp, map_finding_to_owasp
from secaudit.models import Finding, ScanResult, Severity


def _finding(cwe_id="CWE-89", scanner="code", severity=Severity.HIGH):
    return Finding(
        scanner=scanner,
        severity=severity,
        title="Test",
        description="desc",
        location="file.py:1",
        remediation="fix",
        cwe_id=cwe_id,
    )


class TestOWASPMapping:
    def test_sql_injection_maps_to_a03(self):
        assert map_finding_to_owasp(_finding(cwe_id="CWE-89")) == "A03:2021"

    def test_weak_crypto_maps_to_a02(self):
        assert map_finding_to_owasp(_finding(cwe_id="CWE-328")) == "A02:2021"

    def test_hardcoded_secret_maps_to_a02(self):
        assert map_finding_to_owasp(_finding(cwe_id="CWE-798")) == "A02:2021"

    def test_dependency_finding_maps_to_a06(self):
        f = _finding(cwe_id=None, scanner="dependencies")
        assert map_finding_to_owasp(f) == "A06:2021"

    def test_unknown_cwe_returns_none(self):
        f = _finding(cwe_id="CWE-99999")
        assert map_finding_to_owasp(f) is None

    def test_group_by_owasp(self):
        result = ScanResult(scanner_name="code", target=".")
        result.findings = [
            _finding(cwe_id="CWE-89"),
            _finding(cwe_id="CWE-78"),
            _finding(cwe_id="CWE-798"),
        ]
        groups = group_by_owasp([result])
        assert "A03:2021" in groups  # injection (CWE-89, CWE-78)
        assert "A02:2021" in groups  # crypto (CWE-798)
        assert len(groups["A03:2021"]) == 2

    def test_group_respects_severity_filter(self):
        result = ScanResult(scanner_name="code", target=".")
        result.findings = [
            _finding(cwe_id="CWE-89", severity=Severity.LOW),
        ]
        groups = group_by_owasp([result], min_severity=Severity.HIGH)
        assert len(groups) == 0

    def test_all_major_cwes_mapped(self):
        # Verify key CWEs from our scanners are mapped
        mapped_cwes = {"CWE-78", "CWE-79", "CWE-89", "CWE-95", "CWE-200",
                       "CWE-295", "CWE-298", "CWE-321", "CWE-326", "CWE-327",
                       "CWE-328", "CWE-377", "CWE-489", "CWE-502", "CWE-611",
                       "CWE-617", "CWE-798", "CWE-1021"}
        for cwe in mapped_cwes:
            assert cwe in CWE_TO_OWASP, f"{cwe} not mapped to OWASP"
