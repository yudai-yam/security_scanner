"""Tests for the SAST code scanner."""

from secaudit.models import Severity
from secaudit.scanners.code import CodeScanner


class TestCodeScanner:
    def test_eval_detection(self, tmp_py_file):
        f = tmp_py_file('eval(user_input)\n')
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("eval()" in finding.title for finding in result.findings)

    def test_exec_detection(self, tmp_py_file):
        f = tmp_py_file('exec(code)\n')
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("exec()" in finding.title for finding in result.findings)

    def test_subprocess_shell_true(self, tmp_py_file):
        f = tmp_py_file("""\
            import subprocess
            subprocess.run("ls -la", shell=True)
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("shell=True" in finding.title for finding in result.findings)
        assert any(finding.cwe_id == "CWE-78" for finding in result.findings)

    def test_subprocess_shell_false_ok(self, tmp_py_file):
        f = tmp_py_file("""\
            import subprocess
            subprocess.run(["ls", "-la"], shell=False)
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert not any("shell=True" in f.title for f in result.findings)

    def test_pickle_loads(self, tmp_py_file):
        f = tmp_py_file("""\
            import pickle
            data = pickle.loads(payload)
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("pickle" in finding.title for finding in result.findings)
        assert any(finding.cwe_id == "CWE-502" for finding in result.findings)

    def test_weak_crypto_md5(self, tmp_py_file):
        f = tmp_py_file("""\
            import hashlib
            h = hashlib.md5(data)
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("md5" in finding.title for finding in result.findings)

    def test_weak_crypto_sha1(self, tmp_py_file):
        f = tmp_py_file("""\
            import hashlib
            h = hashlib.sha1(data)
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("sha1" in finding.title for finding in result.findings)

    def test_sql_injection_fstring(self, tmp_py_file):
        f = tmp_py_file("""\
            def query(cursor, user_id):
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("SQL injection" in finding.title for finding in result.findings)
        assert any(finding.severity == Severity.CRITICAL for finding in result.findings)

    def test_sql_injection_format(self, tmp_py_file):
        f = tmp_py_file("""\
            def query(cursor, user_id):
                cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("SQL injection" in finding.title for finding in result.findings)

    def test_debug_true(self, tmp_py_file):
        f = tmp_py_file('DEBUG = True\n')
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("Debug mode" in finding.title for finding in result.findings)

    def test_debug_false_ok(self, tmp_py_file):
        f = tmp_py_file('DEBUG = False\n')
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert not any("Debug mode" in f.title for f in result.findings)

    def test_hardcoded_password(self, tmp_py_file):
        f = tmp_py_file('db_password = "hunter2"\n')
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert any("Hardcoded secret" in finding.title for finding in result.findings)

    def test_clean_code(self, tmp_py_file):
        f = tmp_py_file("""\
            import os
            name = os.getenv("NAME", "world")
            print(f"Hello, {name}!")
        """)
        scanner = CodeScanner()
        result = scanner.scan(str(f))
        assert len(result.findings) == 0

    def test_directory_scan(self, tmp_dir_with_files):
        root = tmp_dir_with_files({
            "app.py": 'eval(x)\n',
            "utils.py": 'DEBUG = True\n',
        })
        scanner = CodeScanner()
        result = scanner.scan(str(root))
        assert len(result.findings) == 2
