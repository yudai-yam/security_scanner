"""Git history secret scanning — detects secrets in past commits."""

import re
import subprocess
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner
from secaudit.scanners.secrets import SECRET_PATTERNS


class GitHistoryScanner(BaseScanner):
    name = "git-history"

    def __init__(self, max_commits: int = 100):
        self.max_commits = max_commits

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        repo_path = Path(target)

        if not (repo_path / ".git").is_dir():
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="Not a git repository",
                    description=f"{target} is not a git repository.",
                    location=target,
                    remediation="Provide a path to a git repository.",
                )
            )
            return result

        try:
            diff_output = subprocess.run(
                [
                    "git", "log", "-p", "--all", "--diff-filter=A",
                    f"--max-count={self.max_commits}",
                    "--no-color",
                ],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            result.findings.append(
                Finding(
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="Git command failed",
                    description=f"Could not run git log: {exc}",
                    location=target,
                    remediation="Ensure git is installed and the path is a valid repository.",
                )
            )
            return result

        self._parse_diff(diff_output.stdout, result)
        return result

    def _parse_diff(self, output: str, result: ScanResult) -> None:
        current_commit = None
        current_file = None
        line_in_file = 0

        for line in output.splitlines():
            if line.startswith("commit "):
                current_commit = line.split()[1][:8]
                current_file = None
                line_in_file = 0
            elif line.startswith("diff --git"):
                # Extract filename from "diff --git a/path b/path"
                parts = line.split(" b/", 1)
                if len(parts) == 2:
                    current_file = parts[1]
                line_in_file = 0
            elif line.startswith("@@"):
                # Parse hunk header for line numbers
                match = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
                if match:
                    line_in_file = int(match.group(1)) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                line_in_file += 1
                added_line = line[1:]
                for secret in SECRET_PATTERNS:
                    if secret["pattern"].search(added_line):
                        location = f"commit:{current_commit}:{current_file or 'unknown'}:{line_in_file}"
                        result.findings.append(
                            Finding(
                                scanner=self.name,
                                severity=secret["severity"],
                                title=f"{secret['name']} in git history",
                                description=f"Potential {secret['name'].lower()} found in commit {current_commit}.",
                                location=location,
                                remediation="Rotate the credential immediately. Consider using git-filter-repo to remove it from history.",
                                cwe_id=secret["cwe_id"],
                            )
                        )
                        break  # one finding per line
            elif not line.startswith("-"):
                line_in_file += 1
