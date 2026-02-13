"""Tests for the git history secret scanner."""

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from secaudit.models import Severity
from secaudit.scanners.git_history import GitHistoryScanner


@pytest.fixture
def git_repo(tmp_path):
    """Create a temporary git repo with a secret in history."""
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)

    # First commit with a secret
    secret_file = tmp_path / "config.py"
    secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "add config"], cwd=str(tmp_path), capture_output=True)

    # Second commit removes the secret
    secret_file.write_text('AWS_KEY = "from-env"\n')
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "remove secret"], cwd=str(tmp_path), capture_output=True)

    return tmp_path


class TestGitHistoryScanner:
    def test_finds_secret_in_history(self, git_repo):
        scanner = GitHistoryScanner()
        result = scanner.scan(str(git_repo))
        assert any("AWS Access Key" in f.title for f in result.findings)
        assert any("git history" in f.title.lower() for f in result.findings)

    def test_location_format(self, git_repo):
        scanner = GitHistoryScanner()
        result = scanner.scan(str(git_repo))
        secret_findings = [f for f in result.findings if "AWS" in f.title]
        assert len(secret_findings) >= 1
        assert secret_findings[0].location.startswith("commit:")

    def test_not_a_git_repo(self, tmp_path):
        scanner = GitHistoryScanner()
        result = scanner.scan(str(tmp_path))
        assert len(result.findings) == 1
        assert "Not a git repository" in result.findings[0].title

    def test_max_commits_limit(self, git_repo):
        scanner = GitHistoryScanner(max_commits=1)
        result = scanner.scan(str(git_repo))
        # Should still work, just limited
        assert result.scanner_name == "git-history"

    def test_clean_repo(self, tmp_path):
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
        clean_file = tmp_path / "app.py"
        clean_file.write_text("x = 42\n")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(["git", "commit", "-m", "clean"], cwd=str(tmp_path), capture_output=True)

        scanner = GitHistoryScanner()
        result = scanner.scan(str(tmp_path))
        assert len(result.findings) == 0

    def test_github_token_in_history(self, tmp_path):
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), capture_output=True)
        f = tmp_path / "deploy.sh"
        f.write_text('TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"\n')
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(["git", "commit", "-m", "deploy"], cwd=str(tmp_path), capture_output=True)

        scanner = GitHistoryScanner()
        result = scanner.scan(str(tmp_path))
        assert any("GitHub Token" in f.title for f in result.findings)

    def test_git_command_failure(self, tmp_path):
        (tmp_path / ".git").mkdir()  # fake .git dir
        with patch("secaudit.scanners.git_history.subprocess.run", side_effect=FileNotFoundError("git not found")):
            scanner = GitHistoryScanner()
            result = scanner.scan(str(tmp_path))
        assert any("Git command failed" in f.title for f in result.findings)

    def test_remediation_mentions_rotate(self, git_repo):
        scanner = GitHistoryScanner()
        result = scanner.scan(str(git_repo))
        secret_findings = [f for f in result.findings if "AWS" in f.title]
        if secret_findings:
            assert "Rotate" in secret_findings[0].remediation or "rotate" in secret_findings[0].remediation
