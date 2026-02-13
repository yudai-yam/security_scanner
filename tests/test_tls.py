"""Tests for the TLS/SSL scanner."""

import ssl
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from secaudit.models import Severity
from secaudit.scanners.tls import TLSScanner


def _make_cert(days_until_expiry: int) -> dict:
    """Create a mock certificate dict with a given expiry."""
    expiry = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
    return {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")}


def _patch_tls(cert, protocol="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)):
    """Context manager that patches ssl/socket for TLSScanner tests."""
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = cert
    mock_ssock.version.return_value = protocol
    mock_ssock.cipher.return_value = cipher
    mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
    mock_ssock.__exit__ = MagicMock(return_value=False)

    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_ssock

    return patch.multiple(
        "secaudit.scanners.tls",
        socket=MagicMock(create_connection=MagicMock(return_value=mock_sock)),
        ssl=MagicMock(create_default_context=MagicMock(return_value=mock_ctx)),
    )


class TestTLSScanner:
    def test_valid_cert(self):
        cert = _make_cert(days_until_expiry=365)
        with _patch_tls(cert):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        assert len(result.findings) == 0

    def test_expired_cert(self):
        cert = _make_cert(days_until_expiry=-10)
        with _patch_tls(cert):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        expired = [f for f in result.findings if "expired" in f.title.lower()]
        assert len(expired) == 1
        assert expired[0].severity == Severity.CRITICAL
        assert expired[0].cwe_id == "CWE-298"

    def test_cert_expiring_soon(self):
        cert = _make_cert(days_until_expiry=15)
        with _patch_tls(cert):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        expiring = [f for f in result.findings if "expiring soon" in f.title.lower()]
        assert len(expiring) == 1
        assert expiring[0].severity == Severity.HIGH

    def test_weak_protocol_tlsv1(self):
        cert = _make_cert(days_until_expiry=365)
        with _patch_tls(cert, protocol="TLSv1"):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        proto = [f for f in result.findings if "Weak TLS protocol" in f.title]
        assert len(proto) == 1
        assert proto[0].cwe_id == "CWE-326"

    def test_weak_protocol_sslv3(self):
        cert = _make_cert(days_until_expiry=365)
        with _patch_tls(cert, protocol="SSLv3"):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        assert any("SSLv3" in f.title for f in result.findings)

    def test_weak_cipher_rc4(self):
        cert = _make_cert(days_until_expiry=365)
        with _patch_tls(cert, cipher=("RC4-SHA", "TLSv1.2", 128)):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        cipher_findings = [f for f in result.findings if "cipher" in f.title.lower()]
        assert len(cipher_findings) == 1
        assert cipher_findings[0].cwe_id == "CWE-327"

    def test_weak_cipher_3des(self):
        cert = _make_cert(days_until_expiry=365)
        with _patch_tls(cert, cipher=("DES-CBC3-SHA", "TLSv1.2", 168)):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        assert any("cipher" in f.title.lower() for f in result.findings)

    def test_cert_verification_failure(self):
        with patch("secaudit.scanners.tls.ssl") as mock_ssl, \
             patch("secaudit.scanners.tls.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_socket.create_connection.return_value = mock_sock

            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("self-signed")
            mock_ssl.create_default_context.return_value = mock_ctx
            mock_ssl.SSLCertVerificationError = ssl.SSLCertVerificationError

            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].cwe_id == "CWE-295"

    def test_connection_timeout(self):
        with patch("secaudit.scanners.tls.socket") as mock_socket:
            mock_socket.create_connection.side_effect = socket.timeout("timed out")
            mock_socket.timeout = socket.timeout
            mock_socket.gaierror = socket.gaierror

            scanner = TLSScanner()
            result = scanner.scan("https://example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert "connection failed" in result.findings[0].title.lower()

    def test_hostname_extraction_with_port(self):
        cert = _make_cert(days_until_expiry=365)
        with _patch_tls(cert):
            scanner = TLSScanner()
            result = scanner.scan("https://example.com:8443")
        assert result.target == "example.com"
