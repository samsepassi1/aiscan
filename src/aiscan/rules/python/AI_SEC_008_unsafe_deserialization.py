"""AI-SEC-008: Unsafe Deserialization.

AI-generated code routinely uses pickle.loads() or yaml.load() on untrusted data,
which allows arbitrary code execution. These patterns appear in AI-generated
data-pipeline and configuration-loading code.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, Severity


class UnsafeDeserializationRule:
    rule_id = "AI-SEC-008"
    rule_name = "Unsafe Deserialization"
    severity = Severity.CRITICAL
    cwe_ids = ["CWE-502"]
    languages = ["python"]
    detection_method = DetectionMethod.AST

    PATTERNS: list[tuple[re.Pattern, str, str, float]] = [
        (
            re.compile(r"\bpickle\.loads\s*\("),
            "pickle.loads() deserializes arbitrary Python objects and executes embedded code. "
            "Never deserialize untrusted data with pickle.",
            "Use json.loads() or a safe serialization library. If pickle is required, "
            "cryptographically sign and verify the payload before deserializing.",
            0.95,
        ),
        (
            re.compile(r"\bpickle\.load\s*\("),
            "pickle.load() deserializes arbitrary Python objects from a file-like object. "
            "Ensure the source is trusted and cryptographically verified.",
            "Use json.load() instead. If pickle is required, verify the payload integrity first.",
            0.9,
        ),
        (
            # yaml.load() without an explicit SafeLoader/BaseLoader on the same line.
            # Note: multiline calls (Loader= on the next line) may still trigger; prefer yaml.safe_load().
            re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)(?![^)]*Loader\s*=\s*yaml\.BaseLoader)"),
            "yaml.load() without an explicit safe Loader can execute arbitrary Python. "
            "This is a critical RCE vulnerability when loading untrusted YAML.",
            "Replace yaml.load(data) with yaml.safe_load(data), or explicitly pass "
            "Loader=yaml.SafeLoader.",
            0.92,
        ),
        (
            re.compile(r"\bmarshal\.loads\s*\("),
            "marshal.loads() can execute arbitrary code embedded in Python bytecode. "
            "Never use marshal for untrusted data.",
            "Use json.loads() or msgpack for serialization of untrusted data.",
            0.95,
        ),
        (
            re.compile(r"\bshelve\.open\s*\("),
            "shelve.open() uses pickle internally and is vulnerable to the same RCE risks. "
            "Opening attacker-controlled shelve files can execute arbitrary code.",
            "Use a database (sqlite3, SQLAlchemy) or a safe serialization format (JSON) "
            "for storing user-controlled data.",
            0.7,
        ),
    ]

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(parsed.lines, start=1):
            for pattern, message, remediation, confidence in self.PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        file_path=str(parsed.path),
                        line_start=i,
                        line_end=i,
                        message=message,
                        cwe_ids=self.cwe_ids,
                        detection_method=self.detection_method,
                        confidence=confidence,
                        remediation=remediation,
                        code_snippet=line.rstrip(),
                    ))
        return findings
