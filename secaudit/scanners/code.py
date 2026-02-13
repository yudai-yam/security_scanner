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

    def _loc(self, node: ast.AST) -> str:
        return f"{self.filepath}:{node.lineno}"

    def visit_Call(self, node: ast.Call) -> None:
        self._check_eval_exec(node)
        self._check_subprocess_shell(node)
        self._check_pickle_loads(node)
        self._check_weak_crypto(node)
        self._check_sql_injection(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_debug_flag(node)
        self._check_hardcoded_secrets(node)
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
