"""Baseline/diff mode — compare current scan against a previous baseline."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity


def _fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint for a finding."""
    raw = f"{finding.scanner}:{finding.title}:{finding.location}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class DiffResult:
    new_findings: list[Finding]
    fixed_findings: list[dict]
    unchanged_findings: list[Finding]


def load_baseline(path: str) -> dict[str, dict]:
    """Load a baseline JSON file and return a dict of fingerprint -> finding dict."""
    data = json.loads(Path(path).read_text())
    baseline = {}
    for result in data.get("results", []):
        for f in result.get("findings", []):
            # Reconstruct a Finding-like dict to compute fingerprint
            fp = hashlib.sha256(
                f"{f['scanner']}:{f['title']}:{f['location']}".encode()
            ).hexdigest()[:16]
            baseline[fp] = f
    return baseline


def compute_diff(results: list[ScanResult], baseline: dict[str, dict]) -> DiffResult:
    """Compare current findings against baseline fingerprints."""
    current_fps: dict[str, Finding] = {}
    for r in results:
        for f in r.findings:
            fp = _fingerprint(f)
            current_fps[fp] = f

    new_findings = [f for fp, f in current_fps.items() if fp not in baseline]
    unchanged = [f for fp, f in current_fps.items() if fp in baseline]
    fixed = [f for fp, f in baseline.items() if fp not in current_fps]

    return DiffResult(
        new_findings=new_findings,
        fixed_findings=fixed,
        unchanged_findings=unchanged,
    )


def has_new_findings(diff: DiffResult, min_severity: Severity) -> bool:
    """Check if there are new findings at or above the given severity."""
    return any(f.severity >= min_severity for f in diff.new_findings)
