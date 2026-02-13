"""SARIF v2.1.0 output formatter for SecAudit findings."""

import json
from datetime import datetime, timezone

from secaudit.models import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# CWE taxonomy reference
CWE_TAXONOMY = {
    "name": "CWE",
    "organization": "MITRE",
    "shortDescription": {"text": "Common Weakness Enumeration"},
    "informationUri": "https://cwe.mitre.org/",
}


def _finding_to_rule_id(finding: Finding) -> str:
    """Generate a stable rule ID from a finding."""
    return f"{finding.scanner}/{finding.title.lower().replace(' ', '-').replace('(', '').replace(')', '')}"


def _parse_location(location: str) -> dict:
    """Parse a location string like 'path/file.py:42' into a SARIF physicalLocation."""
    parts = location.rsplit(":", 1)
    filepath = parts[0]
    line = 1
    if len(parts) == 2:
        try:
            line = int(parts[1])
        except ValueError:
            pass

    return {
        "physicalLocation": {
            "artifactLocation": {"uri": filepath},
            "region": {"startLine": line},
        }
    }


def render_sarif(results: list[ScanResult], min_severity: Severity = Severity.INFO) -> str:
    """Render scan results as SARIF v2.1.0 JSON."""
    all_findings: list[Finding] = []
    for r in results:
        all_findings.extend(f for f in r.findings if f.severity >= min_severity)

    # Collect unique rules
    rules_map: dict[str, dict] = {}
    for f in all_findings:
        rule_id = _finding_to_rule_id(f)
        if rule_id not in rules_map:
            rule = {
                "id": rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL[f.severity]
                },
                "help": {
                    "text": f.remediation,
                    "markdown": f"**Remediation:** {f.remediation}",
                },
            }
            if f.cwe_id:
                cwe_num = f.cwe_id.replace("CWE-", "")
                rule["properties"] = {
                    "tags": ["security", f.cwe_id],
                }
                rule["relationships"] = [
                    {
                        "target": {
                            "id": f.cwe_id,
                            "guid": None,
                            "toolComponent": {"name": "CWE"},
                        },
                        "kinds": ["superset"],
                    }
                ]
            rules_map[rule_id] = rule

    # Build results array
    sarif_results = []
    for f in all_findings:
        rule_id = _finding_to_rule_id(f)
        sarif_result = {
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL[f.severity],
            "message": {"text": f.description},
            "locations": [_parse_location(f.location)],
        }
        if f.cwe_id:
            sarif_result["taxa"] = [
                {
                    "id": f.cwe_id,
                    "toolComponent": {"name": "CWE"},
                }
            ]
        sarif_results.append(sarif_result)

    # Collect CWE taxa
    cwe_taxa = []
    seen_cwes = set()
    for f in all_findings:
        if f.cwe_id and f.cwe_id not in seen_cwes:
            seen_cwes.add(f.cwe_id)
            cwe_taxa.append({
                "id": f.cwe_id,
                "shortDescription": {"text": f.cwe_id},
            })

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecAudit",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/secaudit/secaudit",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": sarif_results,
                "taxonomies": [
                    {
                        **CWE_TAXONOMY,
                        "taxa": cwe_taxa,
                    }
                ] if cwe_taxa else [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2)
