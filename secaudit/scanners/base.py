"""Abstract base scanner."""

import time
from abc import ABC, abstractmethod

from secaudit.models import ScanResult


class BaseScanner(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, target: str) -> ScanResult:
        ...

    def _timed_scan(self, target: str) -> ScanResult:
        start = time.monotonic()
        result = self.scan(target)
        result.duration_seconds = round(time.monotonic() - start, 3)
        return result
