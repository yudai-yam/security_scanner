"""Tests for configuration file support."""

import pytest

from secaudit.config import Config, load_config
from secaudit.models import Severity


class TestConfig:
    def test_default_config(self):
        config = Config()
        assert config.min_severity == Severity.INFO
        assert "code" in config.enabled_scanners
        assert config.entropy_threshold == 4.5

    def test_load_from_file(self, tmp_path):
        cfg_file = tmp_path / ".secaudit.yml"
        cfg_file.write_text("""\
severity_threshold: HIGH
enabled_scanners:
  - code
  - secrets
exclude_patterns:
  - "tests/*"
  - "vendor/*"
entropy_threshold: 5.0
max_commits: 50
""")
        config = load_config(config_path=str(cfg_file))
        assert config.severity_threshold == "HIGH"
        assert config.min_severity == Severity.HIGH
        assert config.enabled_scanners == ["code", "secrets"]
        assert "tests/*" in config.exclude_patterns
        assert config.entropy_threshold == 5.0
        assert config.max_commits == 50

    def test_load_from_project_root(self, tmp_path):
        cfg_file = tmp_path / ".secaudit.yml"
        cfg_file.write_text("severity_threshold: MEDIUM\n")
        config = load_config(project_root=str(tmp_path))
        assert config.severity_threshold == "MEDIUM"

    def test_no_config_file_returns_defaults(self, tmp_path):
        config = load_config(project_root=str(tmp_path))
        assert config.severity_threshold == "INFO"

    def test_explicit_config_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(config_path=str(tmp_path / "missing.yml"))

    def test_invalid_yaml(self, tmp_path):
        cfg_file = tmp_path / ".secaudit.yml"
        cfg_file.write_text(": : invalid: [\n")
        with pytest.raises(ValueError, match="Invalid YAML"):
            load_config(config_path=str(cfg_file))

    def test_invalid_severity(self, tmp_path):
        cfg_file = tmp_path / ".secaudit.yml"
        cfg_file.write_text("severity_threshold: EXTREME\n")
        with pytest.raises(ValueError, match="severity_threshold"):
            load_config(config_path=str(cfg_file))

    def test_invalid_type_for_scanners(self, tmp_path):
        cfg_file = tmp_path / ".secaudit.yml"
        cfg_file.write_text("enabled_scanners: not-a-list\n")
        with pytest.raises(ValueError, match="enabled_scanners must be a list"):
            load_config(config_path=str(cfg_file))

    def test_config_with_custom_secret_patterns(self, tmp_path):
        cfg_file = tmp_path / ".secaudit.yml"
        cfg_file.write_text("""\
custom_secret_patterns:
  - name: "Internal Token"
    pattern: "INT_[A-Z0-9]{32}"
    severity: HIGH
""")
        config = load_config(config_path=str(cfg_file))
        assert len(config.custom_secret_patterns) == 1
        assert config.custom_secret_patterns[0]["name"] == "Internal Token"
