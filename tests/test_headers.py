"""Tests for the HTTP security headers scanner."""

from unittest.mock import MagicMock

import pytest
import requests

from secaudit.models import Severity
from secaudit.scanners.headers import HeaderScanner


def _mock_session(headers: dict, status_code: int = 200) -> requests.Session:
    session = MagicMock(spec=requests.Session)
    resp = MagicMock()
    resp.headers = headers
    resp.status_code = status_code
    session.get.return_value = resp
    return session


class TestHeaderScanner:
    def test_all_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "geolocation=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        scanner = HeaderScanner(session=_mock_session(headers))
        result = scanner.scan("https://example.com")
        assert len(result.findings) == 0

    def test_missing_hsts(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "geolocation=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        scanner = HeaderScanner(session=_mock_session(headers))
        result = scanner.scan("https://example.com")
        titles = [f.title for f in result.findings]
        assert "Missing Strict-Transport-Security header" in titles

    def test_all_headers_missing(self):
        scanner = HeaderScanner(session=_mock_session({}))
        result = scanner.scan("https://example.com")
        assert len(result.findings) == 6  # all 6 expected headers missing

    def test_misconfigured_x_content_type(self):
        headers = {
            "X-Content-Type-Options": "wrong-value",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "geolocation=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        scanner = HeaderScanner(session=_mock_session(headers))
        result = scanner.scan("https://example.com")
        misconfig = [f for f in result.findings if "Misconfigured" in f.title]
        assert len(misconfig) == 1
        assert misconfig[0].severity == Severity.MEDIUM

    def test_server_header_info(self):
        headers = {
            "Server": "Apache/2.4.51",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "geolocation=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        scanner = HeaderScanner(session=_mock_session(headers))
        result = scanner.scan("https://example.com")
        assert any(f.severity == Severity.INFO for f in result.findings)

    def test_connection_error(self):
        session = MagicMock(spec=requests.Session)
        session.get.side_effect = requests.ConnectionError("refused")
        scanner = HeaderScanner(session=session)
        result = scanner.scan("https://example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert "Connection failed" in result.findings[0].title
