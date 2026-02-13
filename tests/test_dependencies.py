"""Tests for the dependency vulnerability scanner."""

from unittest.mock import MagicMock

import requests

from secaudit.models import Severity
from secaudit.scanners.dependencies import DependencyScanner, _parse_requirements_txt


def _mock_session(responses: dict | None = None) -> requests.Session:
    """Create a mock session that returns predefined responses for OSV queries."""
    session = MagicMock(spec=requests.Session)

    if responses is None:
        responses = {}

    def post_side_effect(url, json=None, timeout=None):
        resp = MagicMock()
        pkg_name = json.get("package", {}).get("name", "") if json else ""
        data = responses.get(pkg_name, {"vulns": []})
        resp.json.return_value = data
        resp.raise_for_status.return_value = None
        return resp

    session.post.side_effect = post_side_effect
    return session


class TestParseRequirements:
    def test_basic_parse(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\nrequests==2.28.0\n# comment\n-e .\n")
        packages = _parse_requirements_txt(req)
        assert ("flask", "2.3.0") in packages
        assert ("requests", "2.28.0") in packages
        assert len(packages) == 2


class TestDependencyScanner:
    def test_no_vulns(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==3.0.0\n")
        scanner = DependencyScanner(session=_mock_session())
        result = scanner.scan(str(req))
        assert len(result.findings) == 0

    def test_vuln_found(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")

        responses = {
            "flask": {
                "vulns": [
                    {
                        "id": "GHSA-xxxx",
                        "summary": "XSS vulnerability in Flask",
                        "aliases": ["CVE-2023-99999"],
                        "severity": [],
                        "database_specific": {"severity": ["HIGH"]},
                        "affected": [
                            {
                                "ranges": [
                                    {
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.3.3"},
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        }

        scanner = DependencyScanner(session=_mock_session(responses))
        result = scanner.scan(str(req))
        assert len(result.findings) == 1
        assert "flask==2.3.0" in result.findings[0].title
        assert "2.3.3" in result.findings[0].description

    def test_file_not_found(self, tmp_path):
        scanner = DependencyScanner(session=_mock_session())
        result = scanner.scan(str(tmp_path / "nonexistent.txt"))
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.INFO

    def test_api_error_handled(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")

        session = MagicMock(spec=requests.Session)
        session.post.side_effect = requests.ConnectionError("timeout")

        scanner = DependencyScanner(session=session)
        result = scanner.scan(str(req))
        assert len(result.findings) == 0  # gracefully handles error

    def test_multiple_packages(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\ndjango==4.2.0\n")

        responses = {
            "flask": {"vulns": [{"id": "GHSA-1", "summary": "vuln1", "aliases": [], "severity": [], "database_specific": {}, "affected": []}]},
            "django": {"vulns": [{"id": "GHSA-2", "summary": "vuln2", "aliases": [], "severity": [], "database_specific": {}, "affected": []}]},
        }

        scanner = DependencyScanner(session=_mock_session(responses))
        result = scanner.scan(str(req))
        assert len(result.findings) == 2
