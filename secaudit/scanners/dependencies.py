"""Dependency vulnerability scanner using OSV.dev API."""

import re
from pathlib import Path

import requests

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner

OSV_API_URL = "https://api.osv.dev/v1/query"

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    packages = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
        if match:
            packages.append((match.group(1).lower(), match.group(2)))
    return packages


def _parse_pyproject_toml(path: Path) -> list[tuple[str, str]]:
    packages = []
    content = path.read_text()
    for match in re.finditer(
        r"""['"]([A-Za-z0-9_.-]+)\s*==\s*([^'";\s]+)['"]""", content
    ):
        packages.append((match.group(1).lower(), match.group(2)))
    return packages


class DependencyScanner(BaseScanner):
    name = "dependencies"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or requests.Session()

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        path = Path(target)

        if not path.exists():
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="File not found",
                    description=f"Dependency file not found: {target}",
                    location=target,
                    remediation="Provide a valid requirements.txt or pyproject.toml path.",
                )
            )
            return result

        if path.name == "requirements.txt":
            packages = _parse_requirements_txt(path)
        elif path.name == "pyproject.toml":
            packages = _parse_pyproject_toml(path)
        else:
            return result

        for pkg_name, pkg_version in packages:
            self._query_osv(pkg_name, pkg_version, target, result)

        return result

    def _query_osv(
        self, name: str, version: str, target: str, result: ScanResult
    ) -> None:
        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": "PyPI"},
        }
        try:
            resp = self.session.post(OSV_API_URL, json=payload, timeout=15)
            resp.raise_for_status()
        except requests.RequestException:
            return

        data = resp.json()
        for vuln in data.get("vulns", []):
            vuln_id = vuln.get("id", "unknown")
            summary = vuln.get("summary", "No description available.")
            aliases = vuln.get("aliases", [])
            cve_ids = [a for a in aliases if a.startswith("CVE-")]

            severity = Severity.MEDIUM
            for s in vuln.get("severity", []):
                score_str = s.get("score", "")
                if ":" in score_str:
                    # CVSS vector; parse base score from database_specific if available
                    pass
            for db in vuln.get("database_specific", {}).get("severity", [None]):
                if db and db.upper() in SEVERITY_MAP:
                    severity = SEVERITY_MAP[db.upper()]
                    break

            fix_versions = []
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fix_versions.append(event["fixed"])

            fix_text = f" Fix available in: {', '.join(fix_versions)}" if fix_versions else ""

            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=severity,
                    title=f"{vuln_id}: {name}=={version}",
                    description=f"{summary}{fix_text}",
                    location=f"{target} ({name}=={version})",
                    remediation=f"Upgrade {name} to a patched version.{fix_text}",
                    cwe_id=cve_ids[0] if cve_ids else None,
                )
            )
