"""Secret and credential detection scanner."""

import math
import os
import re
from collections import Counter
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner

SECRET_PATTERNS: list[dict] = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"(?:^|[^A-Z0-9])(?:AKIA[0-9A-Z]{16})(?:$|[^A-Z0-9])"),
        "severity": Severity.CRITICAL,
        "cwe_id": "CWE-798",
    },
    {
        "name": "AWS Secret Key",
        "pattern": re.compile(
            r"""(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
        ),
        "severity": Severity.CRITICAL,
        "cwe_id": "CWE-798",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
        "severity": Severity.CRITICAL,
        "cwe_id": "CWE-798",
    },
    {
        "name": "Generic API Key",
        "pattern": re.compile(
            r"""(?:api[_-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]""",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "cwe_id": "CWE-798",
    },
    {
        "name": "Private Key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        "severity": Severity.CRITICAL,
        "cwe_id": "CWE-321",
    },
    {
        "name": "Password in config",
        "pattern": re.compile(
            r"""(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]""",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "cwe_id": "CWE-798",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": Severity.HIGH,
        "cwe_id": "CWE-798",
    },
    {
        "name": "Database Connection String",
        "pattern": re.compile(
            r"""(?:mongodb|postgres|mysql|redis)://[^\s'"]{10,}""",
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "cwe_id": "CWE-798",
    },
]

BINARY_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".zip", ".tar", ".gz",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".pdf", ".woff", ".woff2",
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".eggs"}


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _load_gitignore_patterns(root: Path) -> list[str]:
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return []
    patterns = []
    for line in gitignore.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _is_ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    rel = str(path.relative_to(root))
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if clean in rel or rel.startswith(clean):
            return True
    return False


class SecretScanner(BaseScanner):
    name = "secrets"

    def __init__(self, entropy_threshold: float = 4.5):
        self.entropy_threshold = entropy_threshold

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        root = Path(target)
        if not root.exists():
            return result

        gitignore_patterns = _load_gitignore_patterns(root)

        for filepath in self._walk_files(root, gitignore_patterns):
            self._scan_file(filepath, result)

        return result

    def _walk_files(self, root: Path, gitignore_patterns: list[str]):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                filepath = Path(dirpath) / fname
                if filepath.suffix in BINARY_EXTENSIONS:
                    continue
                if _is_ignored(filepath, root, gitignore_patterns):
                    continue
                yield filepath

    def _scan_file(self, filepath: Path, result: ScanResult) -> None:
        try:
            content = filepath.read_text(errors="ignore")
        except OSError:
            return

        for line_num, line in enumerate(content.splitlines(), start=1):
            for secret in SECRET_PATTERNS:
                if secret["pattern"].search(line):
                    result.findings.append(
                        Finding(
                            scanner=self.name,
                            severity=secret["severity"],
                            title=f"{secret['name']} detected",
                            description=f"Potential {secret['name'].lower()} found in source code.",
                            location=f"{filepath}:{line_num}",
                            remediation="Remove the secret and rotate the credential. Use environment variables or a secrets manager.",
                            cwe_id=secret["cwe_id"],
                        )
                    )

            self._check_entropy(line, line_num, filepath, result)

    def _check_entropy(
        self, line: str, line_num: int, filepath: Path, result: ScanResult
    ) -> None:
        assign_match = re.search(
            r"""(?:secret|token|key|password|api_key)\s*[=:]\s*['"]([^'"]{16,})['"]""",
            line,
            re.IGNORECASE,
        )
        if assign_match:
            value = assign_match.group(1)
            entropy = _shannon_entropy(value)
            if entropy >= self.entropy_threshold:
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        title="High-entropy string in assignment",
                        description=f"High-entropy value (entropy={entropy:.1f}) assigned to sensitive variable.",
                        location=f"{filepath}:{line_num}",
                        remediation="Review this value. If it's a secret, move it to environment variables.",
                        cwe_id="CWE-798",
                    )
                )
