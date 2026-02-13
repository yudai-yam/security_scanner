"""Configuration file support for SecAudit (.secaudit.yml)."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from secaudit.models import Severity

DEFAULT_CONFIG_NAME = ".secaudit.yml"


@dataclass
class Config:
    """SecAudit configuration loaded from .secaudit.yml."""

    enabled_scanners: list[str] = field(default_factory=lambda: [
        "headers", "tls", "secrets", "dependencies", "code", "git-history",
    ])
    severity_threshold: str = "INFO"
    exclude_patterns: list[str] = field(default_factory=list)
    custom_secret_patterns: list[dict] = field(default_factory=list)
    entropy_threshold: float = 4.5
    max_commits: int = 100

    @property
    def min_severity(self) -> Severity:
        return Severity(self.severity_threshold)


def load_config(config_path: str | None = None, project_root: str | None = None) -> Config:
    """Load configuration from a YAML file.

    Priority: explicit --config path > .secaudit.yml in project root > defaults.
    """
    path = None

    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
    elif project_root:
        candidate = Path(project_root) / DEFAULT_CONFIG_NAME
        if candidate.exists():
            path = candidate

    if path is None:
        return Config()

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"Config file {path} must be a YAML mapping, got {type(raw).__name__}")

    return _parse_config(raw)


def _parse_config(raw: dict) -> Config:
    """Parse and validate raw YAML dict into a Config object."""
    config = Config()

    if "enabled_scanners" in raw:
        scanners = raw["enabled_scanners"]
        if not isinstance(scanners, list):
            raise ValueError("enabled_scanners must be a list")
        config.enabled_scanners = scanners

    if "severity_threshold" in raw:
        sev = raw["severity_threshold"]
        valid = {s.value for s in Severity}
        if sev not in valid:
            raise ValueError(f"severity_threshold must be one of {valid}, got '{sev}'")
        config.severity_threshold = sev

    if "exclude_patterns" in raw:
        patterns = raw["exclude_patterns"]
        if not isinstance(patterns, list):
            raise ValueError("exclude_patterns must be a list")
        config.exclude_patterns = patterns

    if "custom_secret_patterns" in raw:
        patterns = raw["custom_secret_patterns"]
        if not isinstance(patterns, list):
            raise ValueError("custom_secret_patterns must be a list")
        config.custom_secret_patterns = patterns

    if "entropy_threshold" in raw:
        val = raw["entropy_threshold"]
        if not isinstance(val, (int, float)):
            raise ValueError("entropy_threshold must be a number")
        config.entropy_threshold = float(val)

    if "max_commits" in raw:
        val = raw["max_commits"]
        if not isinstance(val, int):
            raise ValueError("max_commits must be an integer")
        config.max_commits = val

    return config
