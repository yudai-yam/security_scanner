"""SAST scanner - AST-based Python code analysis."""

import ast
import os
from pathlib import Path

from secaudit.models import Finding, ScanResult, Severity
from secaudit.scanners.base import BaseScanner

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".eggs"}


class CodeScanner(BaseScanner):
    name = "code"

    def scan(self, target: str) -> ScanResult:
        result = ScanResult(scanner_name=self.name, target=target)
        root = Path(target)

        if root.is_file() and root.suffix == ".py":
            self._scan_file(root, result)
        elif root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for fname in filenames:
                    if fname.endswith(".py"):
                        self._scan_file(Path(dirpath) / fname, result)

        return result

    def _scan_file(self, filepath: Path, result: ScanResult) -> None:
        try:
            source = filepath.read_text(errors="ignore")
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError:
            return

        visitor = _SecurityVisitor(str(filepath), result)
        visitor.visit(tree)


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str, result: ScanResult):
        self.filepath = filepath
        self.result = result
        self.imported_modules: set[str] = set()

    def _loc(self, node: ast.AST) -> str:
        return f"{self.filepath}:{node.lineno}"

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imported_modules.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imported_modules.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_eval_exec(node)
        self._check_subprocess_shell(node)
        self._check_pickle_loads(node)
        self._check_weak_crypto(node)
        self._check_sql_injection(node)
        self._check_yaml_load(node)
        self._check_xml_parse(node)
        self._check_os_system(node)
        self._check_flask_debug(node)
        self._check_tempfile_mktemp(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_debug_flag(node)
        self._check_hardcoded_secrets(node)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self._check_assert_security(node)
        self.generic_visit(node)

    def _check_eval_exec(self, node: ast.Call) -> None:
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("eval", "exec"):
            self.result.findings.append(
                Finding(
                    scanner="code",
                    severity=Severity.HIGH,
                    title=f"Use of {func_name}()",
                    description=f"{func_name}() can execute arbitrary code and is a security risk.",
                    location=self._loc(node),
                    remediation=f"Avoid {func_name}(). Use ast.literal_eval() for data parsing or safer alternatives.",
                    cwe_id="CWE-95",
                )
            )

    def _check_subprocess_shell(self, node: ast.Call) -> None:
        func = node.func
        is_subprocess = False
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "subprocess":
                is_subprocess = True
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Attribute):
            pass  # deeper nesting, skip

        if not is_subprocess:
            return

        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.result.findings.append(
                    Finding(
                        scanner="code",
                        severity=Severity.HIGH,
                        title="subprocess with shell=True",
                        description="Using shell=True with subprocess can lead to shell injection.",
                        location=self._loc(node),
                        remediation="Use a list of arguments instead of shell=True.",
                        cwe_id="CWE-78",
                    )
                )

    def _check_pickle_loads(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("loads", "load"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                self.result.findings.append(
                    Finding(
                        scanner="code",
                        severity=Severity.HIGH,
                        title="Insecure deserialization with pickle",
                        description="pickle.loads()/load() can execute arbitrary code from untrusted data.",
                        location=self._loc(node),
                        remediation="Use json or a safe serialization format instead of pickle for untrusted data.",
                        cwe_id="CWE-502",
                    )
                )

    def _check_weak_crypto(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "hashlib" and func.attr in ("md5", "sha1"):
                self.result.findings.append(
                    Finding(
                        scanner="code",
                        severity=Severity.MEDIUM,
                        title=f"Weak hash algorithm: {func.attr}",
                        description=f"hashlib.{func.attr}() is cryptographically weak.",
                        location=self._loc(node),
                        remediation="Use hashlib.sha256() or stronger for security-sensitive hashing.",
                        cwe_id="CWE-328",
                    )
                )

    def _check_sql_injection(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
            return
        if not node.args:
            return
        arg = node.args[0]
        if isinstance(arg, ast.JoinedStr):
            self.result.findings.append(
                Finding(
                    scanner="code",
                    severity=Severity.CRITICAL,
                    title="Potential SQL injection (f-string)",
                    description="SQL query built with f-string may be vulnerable to injection.",
                    location=self._loc(node),
                    remediation="Use parameterized queries instead of string formatting.",
                    cwe_id="CWE-89",
                )
            )
        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add)):
            self.result.findings.append(
                Finding(
                    scanner="code",
                    severity=Severity.CRITICAL,
                    title="Potential SQL injection (string formatting)",
                    description="SQL query built with string concatenation/formatting may be vulnerable.",
                    location=self._loc(node),
                    remediation="Use parameterized queries instead of string formatting.",
                    cwe_id="CWE-89",
                )
            )

    def _check_debug_flag(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    self.result.findings.append(
                        Finding(
                            scanner="code",
                            severity=Severity.MEDIUM,
                            title="Debug mode enabled",
                            description="DEBUG = True found. Debug mode should be disabled in production.",
                            location=self._loc(node),
                            remediation="Set DEBUG = False or use environment variables for configuration.",
                            cwe_id="CWE-489",
                        )
                    )

    def _check_hardcoded_secrets(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_lower = target.id.lower()
                secret_keywords = ("password", "secret", "api_key", "apikey", "token", "private_key")
                if any(kw in name_lower for kw in secret_keywords):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) >= 4:
                            self.result.findings.append(
                                Finding(
                                    scanner="code",
                                    severity=Severity.HIGH,
                                    title=f"Hardcoded secret: {target.id}",
                                    description=f"Variable '{target.id}' appears to contain a hardcoded secret.",
                                    location=self._loc(node),
                                    remediation="Use environment variables or a secrets manager.",
                                    cwe_id="CWE-798",
                                )
                            )

    def _check_yaml_load(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "load"):
            return
        if not (isinstance(func.value, ast.Name) and func.value.id == "yaml"):
            return
        # Check if SafeLoader is used
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr:
                    return
                if isinstance(kw.value, ast.Name) and "Safe" in kw.value.id:
                    return
        self.result.findings.append(
            Finding(
                scanner="code",
                severity=Severity.HIGH,
                title="Unsafe YAML load",
                description="yaml.load() without SafeLoader can execute arbitrary Python code.",
                location=self._loc(node),
                remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                cwe_id="CWE-502",
            )
        )

    def _check_xml_parse(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "parse":
            if isinstance(func.value, ast.Attribute):
                # xml.etree.ElementTree.parse(...)
                if isinstance(func.value.value, ast.Attribute):
                    if (isinstance(func.value.value.value, ast.Name)
                            and func.value.value.value.id == "xml"):
                        self._add_xxe_finding(node)
                        return
                # ET.parse(...) when xml was imported
                if isinstance(func.value, ast.Name) and func.value.id == "ET":
                    if "xml" in self.imported_modules:
                        self._add_xxe_finding(node)
                        return
            if isinstance(func.value, ast.Name) and func.value.id == "ET":
                if "xml" in self.imported_modules:
                    self._add_xxe_finding(node)
        # Also check for ElementTree.fromstring / iterparse
        if isinstance(func, ast.Attribute) and func.attr in ("fromstring", "iterparse", "parse"):
            if isinstance(func.value, ast.Name) and func.value.id in ("ET", "ElementTree"):
                if "xml" in self.imported_modules:
                    self._add_xxe_finding(node)

    def _add_xxe_finding(self, node: ast.Call) -> None:
        self.result.findings.append(
            Finding(
                scanner="code",
                severity=Severity.HIGH,
                title="Potential XXE vulnerability",
                description="xml.etree is vulnerable to XXE attacks. Use defusedxml instead.",
                location=self._loc(node),
                remediation="Replace xml.etree with defusedxml.ElementTree.",
                cwe_id="CWE-611",
            )
        )

    def _check_os_system(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("system", "popen"):
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                self.result.findings.append(
                    Finding(
                        scanner="code",
                        severity=Severity.HIGH,
                        title=f"Use of os.{func.attr}()",
                        description=f"os.{func.attr}() executes commands via the shell and is vulnerable to injection.",
                        location=self._loc(node),
                        remediation="Use subprocess.run() with a list of arguments instead.",
                        cwe_id="CWE-78",
                    )
                )

    def _check_assert_security(self, node: ast.Assert) -> None:
        # Check if the assert test references security-related names
        source = ast.dump(node.test)
        security_keywords = ("auth", "permission", "role", "admin", "token",
                             "password", "session", "login", "access", "allowed")
        source_lower = source.lower()
        if any(kw in source_lower for kw in security_keywords):
            self.result.findings.append(
                Finding(
                    scanner="code",
                    severity=Severity.MEDIUM,
                    title="Assert used for security check",
                    description="assert statements are removed when Python runs with -O flag.",
                    location=self._loc(node),
                    remediation="Use if/raise instead of assert for security checks.",
                    cwe_id="CWE-617",
                )
            )

    def _check_flask_debug(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "run"):
            return
        if not (isinstance(func.value, ast.Name) and func.value.id == "app"):
            return
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.result.findings.append(
                    Finding(
                        scanner="code",
                        severity=Severity.HIGH,
                        title="Flask debug mode enabled",
                        description="app.run(debug=True) enables the Werkzeug debugger, which allows RCE.",
                        location=self._loc(node),
                        remediation="Never use debug=True in production. Use environment variables.",
                        cwe_id="CWE-489",
                    )
                )

    def _check_tempfile_mktemp(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "mktemp":
            if isinstance(func.value, ast.Name) and func.value.id == "tempfile":
                self.result.findings.append(
                    Finding(
                        scanner="code",
                        severity=Severity.MEDIUM,
                        title="Use of tempfile.mktemp()",
                        description="tempfile.mktemp() is vulnerable to race conditions (TOCTOU).",
                        location=self._loc(node),
                        remediation="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
                        cwe_id="CWE-377",
                    )
                )
