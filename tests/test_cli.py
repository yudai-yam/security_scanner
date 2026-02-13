"""Tests for the CLI interface."""

import json
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from secaudit.cli import cli
from secaudit.models import Finding, ScanResult, Severity


def _mock_scan_result(scanner_name="code", findings=None):
    """Create a mock ScanResult."""
    result = ScanResult(scanner_name=scanner_name, target="/tmp/test")
    if findings:
        result.findings = findings
    return result


def _finding(severity=Severity.HIGH, title="Test finding", scanner="code"):
    return Finding(
        scanner=scanner,
        severity=severity,
        title=title,
        description="Test description",
        location="/tmp/test:1",
        remediation="Fix it",
        cwe_id="CWE-100",
    )


class TestCLI:
    def test_scan_code_table_output(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-code", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_code_json_output(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-code", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "$schema" in data
        assert "results" in data

    def test_severity_filter(self, tmp_path):
        (tmp_path / "app.py").write_text("DEBUG = True\n")
        runner = CliRunner()
        # MEDIUM finding should be filtered out at HIGH threshold
        result = runner.invoke(cli, ["scan-code", str(tmp_path), "--format", "json", "--severity", "HIGH"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        for r in data["results"]:
            for f in r["findings"]:
                assert f["severity"] in ("HIGH", "CRITICAL")

    def test_exit_code_with_findings(self, tmp_path):
        (tmp_path / "app.py").write_text("eval(x)\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-code", str(tmp_path), "--exit-code"])
        assert result.exit_code == 1

    def test_exit_code_clean(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-code", str(tmp_path), "--exit-code"])
        assert result.exit_code == 0

    def test_output_file(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        outfile = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-code", str(tmp_path), "-o", str(outfile)])
        assert result.exit_code == 0
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert "results" in data

    def test_scan_deps_command(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==99.0.0\n")
        runner = CliRunner()
        with patch("secaudit.scanners.dependencies.DependencyScanner.scan") as mock_scan:
            mock_scan.return_value = _mock_scan_result("dependencies")
            result = runner.invoke(cli, ["scan-deps", str(req)])
        assert result.exit_code == 0

    def test_scan_all_without_url(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        (tmp_path / "requirements.txt").write_text("")
        runner = CliRunner()
        with patch("secaudit.scanners.dependencies.DependencyScanner.scan") as mock_dep:
            mock_dep.return_value = _mock_scan_result("dependencies")
            result = runner.invoke(cli, ["scan-all", str(tmp_path)])
        assert result.exit_code == 0

    def test_sarif_output(self, tmp_path):
        (tmp_path / "app.py").write_text("eval(x)\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan-code", str(tmp_path), "--format", "sarif"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"][0]["results"]) > 0

    def test_version_option(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help_output(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "SecAudit" in result.output
        assert "scan-code" in result.output
