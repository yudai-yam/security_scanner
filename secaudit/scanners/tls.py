"""TLS/SSL certificate and configuration scanner."""

import socket
import ssl
from datetime import datetime, timezone

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner


class TLSScanner(BaseScanner):
    name = "tls"

    def scan(self, target: str) -> ScanResult:
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443
        if ":" in hostname:
            hostname, port_str = hostname.rsplit(":", 1)
            port = int(port_str)

        result = ScanResult(scanner_name=self.name, target=hostname)

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol_version = ssock.version()
                    cipher = ssock.cipher()

            self._check_expiry(cert, hostname, result)
            self._check_protocol(protocol_version, hostname, result)
            self._check_cipher(cipher, hostname, result)

        except ssl.SSLCertVerificationError as exc:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    title="Certificate verification failed",
                    description=f"SSL certificate verification failed: {exc}",
                    location=hostname,
                    remediation="Install a valid certificate from a trusted CA.",
                    cwe_id="CWE-295",
                )
            )
        except (socket.timeout, socket.gaierror, OSError) as exc:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title="TLS connection failed",
                    description=f"Could not establish TLS connection to {hostname}:{port}: {exc}",
                    location=hostname,
                    remediation="Verify the hostname and ensure TLS is enabled on the server.",
                )
            )

        return result

    def _check_expiry(self, cert: dict, hostname: str, result: ScanResult) -> None:
        not_after = cert.get("notAfter")
        if not not_after:
            return
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(timezone.utc)
        days_left = (expiry - now).days

        if days_left < 0:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    title="Certificate expired",
                    description=f"Certificate expired {abs(days_left)} days ago on {not_after}.",
                    location=hostname,
                    remediation="Renew the SSL/TLS certificate immediately.",
                    cwe_id="CWE-298",
                )
            )
        elif days_left < 30:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title="Certificate expiring soon",
                    description=f"Certificate expires in {days_left} days on {not_after}.",
                    location=hostname,
                    remediation="Renew the SSL/TLS certificate before expiration.",
                    cwe_id="CWE-298",
                )
            )

    def _check_protocol(
        self, version: str | None, hostname: str, result: ScanResult
    ) -> None:
        if version and version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title=f"Weak TLS protocol: {version}",
                    description=f"Server negotiated {version}, which is deprecated and insecure.",
                    location=hostname,
                    remediation="Configure the server to use TLS 1.2 or higher.",
                    cwe_id="CWE-326",
                )
            )

    def _check_cipher(
        self, cipher: tuple | None, hostname: str, result: ScanResult
    ) -> None:
        if not cipher:
            return
        cipher_name = cipher[0]
        weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")
        for weak in weak_ciphers:
            if weak in cipher_name.upper():
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title=f"Weak cipher suite: {cipher_name}",
                        description=f"Server uses weak cipher {cipher_name}.",
                        location=hostname,
                        remediation="Disable weak cipher suites and use AES-GCM or ChaCha20.",
                        cwe_id="CWE-327",
                    )
                )
                break
