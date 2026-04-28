"""Pydantic models for aiscan findings and scan results."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectionMethod(str, Enum):
    AST = "AST"
    LLM = "LLM"
    HYBRID = "HYBRID"


SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class Finding(BaseModel):
    """A single security finding produced by aiscan."""

    rule_id: str = Field(..., description="Rule identifier, e.g. 'AI-SEC-001'")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0
    message: str = Field(..., description="Clear explanation of the vulnerability")
    cwe_ids: list[str] = Field(default_factory=list, description="e.g. ['CWE-259', 'CWE-321']")
    detection_method: DetectionMethod
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0–1.0")
    remediation: str = Field(..., description="Specific fix instructions")
    code_snippet: str = ""
    suppressed: bool = False
    suppression_reason: str = ""


class ScanResult(BaseModel):
    """Top-level result returned by a full aiscan run."""

    scan_id: str
    target_path: str
    timestamp: str
    total_files_scanned: int
    findings: list[Finding]
    duration_seconds: float
    llm_enabled: bool
    llm_provider: str | None = None
    llm_model: str | None = None
    # Number of files/rules/LLM calls that errored during the scan. SARIF
    # surfaces this through invocations[].executionSuccessful so CI consumers
    # can distinguish a clean run from a partial-failure run.
    scan_errors: int = 0

    @property
    def finding_count(self) -> int:
        return len([f for f in self.findings if not f.suppressed])

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            if not f.suppressed:
                result[f.severity.value].append(f)
        return result
