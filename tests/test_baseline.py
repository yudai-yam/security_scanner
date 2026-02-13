"""Tests for baseline/diff mode."""

import json

import pytest

from secaudit.baseline import _fingerprint, compute_diff, has_new_findings, load_baseline
from secaudit.models import Finding, ScanResult, Severity


def _finding(title="Test finding", location="file.py:1", scanner="code", severity=Severity.HIGH):
    return Finding(
        scanner=scanner,
        severity=severity,
        title=title,
        description="desc",
        location=location,
        remediation="fix",
        cwe_id="CWE-100",
    )


class TestFingerprint:
    def test_stable(self):
        f = _finding()
        assert _fingerprint(f) == _fingerprint(f)

    def test_different_findings(self):
        f1 = _finding(title="A")
        f2 = _finding(title="B")
        assert _fingerprint(f1) != _fingerprint(f2)


class TestComputeDiff:
    def test_new_finding(self):
        result = ScanResult(scanner_name="code", target=".")
        result.findings = [_finding(title="New issue")]
        diff = compute_diff([result], {})
        assert len(diff.new_findings) == 1
        assert len(diff.fixed_findings) == 0

    def test_fixed_finding(self, tmp_path):
        # Baseline had a finding, current scan is clean
        baseline_json = tmp_path / "baseline.json"
        baseline_json.write_text(json.dumps({
            "results": [{
                "findings": [{
                    "scanner": "code",
                    "title": "Old issue",
                    "location": "file.py:1",
                    "severity": "HIGH",
                }]
            }]
        }))
        baseline = load_baseline(str(baseline_json))
        result = ScanResult(scanner_name="code", target=".")
        diff = compute_diff([result], baseline)
        assert len(diff.fixed_findings) == 1
        assert len(diff.new_findings) == 0

    def test_unchanged_finding(self, tmp_path):
        f = _finding(title="Same issue", location="file.py:5")
        baseline_json = tmp_path / "baseline.json"
        baseline_json.write_text(json.dumps({
            "results": [{
                "findings": [{
                    "scanner": "code",
                    "title": "Same issue",
                    "location": "file.py:5",
                    "severity": "HIGH",
                }]
            }]
        }))
        baseline = load_baseline(str(baseline_json))
        result = ScanResult(scanner_name="code", target=".")
        result.findings = [f]
        diff = compute_diff([result], baseline)
        assert len(diff.unchanged_findings) == 1
        assert len(diff.new_findings) == 0
        assert len(diff.fixed_findings) == 0


class TestHasNewFindings:
    def test_has_new_high(self):
        from secaudit.baseline import DiffResult
        diff = DiffResult(
            new_findings=[_finding(severity=Severity.HIGH)],
            fixed_findings=[],
            unchanged_findings=[],
        )
        assert has_new_findings(diff, Severity.HIGH)

    def test_no_new_above_threshold(self):
        from secaudit.baseline import DiffResult
        diff = DiffResult(
            new_findings=[_finding(severity=Severity.LOW)],
            fixed_findings=[],
            unchanged_findings=[],
        )
        assert not has_new_findings(diff, Severity.HIGH)

    def test_empty_diff(self):
        from secaudit.baseline import DiffResult
        diff = DiffResult(new_findings=[], fixed_findings=[], unchanged_findings=[])
        assert not has_new_findings(diff, Severity.INFO)
