"""AI-SEC-011: Path Traversal.

AI-generated file-serving code frequently concatenates user input into file paths
without sanitization, enabling directory traversal (../../etc/passwd).
Applies to Python, JavaScript, TypeScript, Go, and Java.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, Severity


# Python patterns
PY_PATTERNS = [
    re.compile(r"""open\s*\(\s*(?:os\.path\.join\s*\([^)]*\)|f?['"]{1,3}[^'"]*['"]{1,3}\s*\+|[a-z_]+\s*\+)"""),
    re.compile(r"""Path\s*\([^)]*(?:request|user|input|param|query|body)[^)]*\)""", re.IGNORECASE),
    re.compile(r"""os\.path\.join\s*\([^)]*(?:request|user|input|param|query)[^)]*\)""", re.IGNORECASE),
]

# JS/TS patterns
JS_PATTERNS = [
    re.compile(r"""(?:fs\.readFile|fs\.writeFile|fs\.readFileSync|fs\.writeFileSync)\s*\([^)]*(?:req\.|params\.|query\.|body\.)[^)]*"""),
    re.compile(r"""path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)[^)]*\)"""),
]

LANGUAGE_PATTERNS: dict[str, list[re.Pattern]] = {
    "python": PY_PATTERNS,
    "javascript": JS_PATTERNS,
    "typescript": JS_PATTERNS,
}


class PathTraversalRule:
    rule_id = "AI-SEC-011"
    rule_name = "Path Traversal"
    severity = Severity.HIGH
    cwe_ids = ["CWE-22", "CWE-23", "CWE-36"]
    languages = ["python", "javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        patterns = LANGUAGE_PATTERNS.get(parsed.language, [])
        for i, line in enumerate(parsed.lines, start=1):
            for pattern in patterns:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        file_path=str(parsed.path),
                        line_start=i,
                        line_end=i,
                        message=(
                            "Potential path traversal: user-controlled input appears to be "
                            "used in a file path operation without sanitization. "
                            "An attacker may supply '../' sequences to read arbitrary files."
                        ),
                        cwe_ids=self.cwe_ids,
                        detection_method=self.detection_method,
                        confidence=0.75,
                        remediation=(
                            "Validate and canonicalize paths before use. "
                            "In Python: use pathlib.Path.resolve() and assert the resolved path "
                            "starts with your intended base directory. "
                            "Never concatenate user input directly into file paths."
                        ),
                        code_snippet=line.rstrip(),
                    ))
                    break
        return findings
