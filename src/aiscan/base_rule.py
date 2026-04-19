"""Base class for all aiscan detection rules."""

from __future__ import annotations

from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, Severity


class BaseRule:
    """Abstract base class for all aiscan detection rules."""

    rule_id: str = ""
    rule_name: str = ""
    severity: Severity | None = None
    cwe_ids: list[str] = []
    languages: list[str] = []
    detection_method: DetectionMethod | None = None

    def check(self, parsed: ParsedFile) -> list[Finding]:
        raise NotImplementedError(f"{self.__class__.__name__}.check() must be implemented")
