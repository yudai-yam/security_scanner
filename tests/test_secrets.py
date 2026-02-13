"""Tests for the secret scanner."""

from secaudit.models import Severity
from secaudit.scanners.secrets import SecretScanner


class TestSecretScanner:
    def test_aws_access_key(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert any("AWS Access Key" in f.title for f in result.findings)

    def test_github_token(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "config.py": 'GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"\n',
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert any("GitHub Token" in f.title for f in result.findings)

    def test_private_key(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "key.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert any("Private Key" in f.title for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_password_in_config(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "settings.py": 'DB_PASSWORD = "super_secret_password123"\n',
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert any("Password" in f.title for f in result.findings)

    def test_jwt_token(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "auth.py": 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"\n',
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert any("JWT" in f.title for f in result.findings)

    def test_connection_string(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "db.py": 'DB_URL = "postgres://admin:pass@localhost:5432/mydb"\n',
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert any("Connection String" in f.title for f in result.findings)

    def test_clean_file(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "clean.py": 'x = 42\nname = "hello"\n',
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert len(result.findings) == 0

    def test_skips_binary_files(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "data.pyc": "AKIAIOSFODNN7EXAMPLE",
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert len(result.findings) == 0

    def test_skips_git_dir(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            ".git/config": 'password = "secret12345678"\n',
        })
        scanner = SecretScanner()
        result = scanner.scan(str(root))
        assert len(result.findings) == 0

    def test_high_entropy_detection(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "config.py": 'secret = "aB3$xZ9!kL7@mN2#pQ5&rT8*uW1^yA4"\n',
        })
        scanner = SecretScanner(entropy_threshold=3.5)
        result = scanner.scan(str(root))
        assert any("High-entropy" in f.title for f in result.findings)
