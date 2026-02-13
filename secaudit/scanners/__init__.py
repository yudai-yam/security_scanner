"""Scanner registry for SecAudit."""

from secaudit.scanners.base import BaseScanner
from secaudit.scanners.code import CodeScanner
from secaudit.scanners.dependencies import DependencyScanner
from secaudit.scanners.headers import HeaderScanner
from secaudit.scanners.secrets import SecretScanner
from secaudit.scanners.tls import TLSScanner

SCANNERS: dict[str, type[BaseScanner]] = {
    "headers": HeaderScanner,
    "tls": TLSScanner,
    "secrets": SecretScanner,
    "dependencies": DependencyScanner,
    "code": CodeScanner,
}

__all__ = [
    "BaseScanner",
    "HeaderScanner",
    "TLSScanner",
    "SecretScanner",
    "DependencyScanner",
    "CodeScanner",
    "SCANNERS",
]
