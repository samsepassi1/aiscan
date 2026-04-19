"""AI-SEC-012: Permissive CORS Configuration.

AI-generated Express/Node.js code frequently uses cors({ origin: '*' }) or
sets Access-Control-Allow-Origin: * on sensitive endpoints, allowing credential
theft from any origin.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


WILDCARD_CORS_PATTERNS = [
    re.compile(r"""cors\(\s*\{\s*origin\s*:\s*['"`]\*['"`]"""),
    re.compile(r"""['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]"""),
    re.compile(r"""res\.header\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]"""),
    re.compile(r"""res\.set\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]"""),
]


class PermissiveCORSRule(BaseRule):
    rule_id = "AI-SEC-012"
    rule_name = "Permissive CORS Configuration"
    severity = Severity.HIGH
    cwe_ids = ["CWE-942", "CWE-346"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(parsed.lines, start=1):
            for pattern in WILDCARD_CORS_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        file_path=str(parsed.path),
                        line_start=i,
                        line_end=i,
                        message=(
                            "Wildcard CORS origin ('*') allows any website to make "
                            "credentialed cross-origin requests to this API. This can "
                            "lead to credential theft and cross-site request forgery."
                        ),
                        cwe_ids=self.cwe_ids,
                        detection_method=self.detection_method,
                        confidence=0.9,
                        remediation=(
                            "Replace '*' with an explicit allowlist of trusted origins. "
                            "Example: cors({ origin: ['https://app.example.com'] }). "
                            "Never combine credentials:true with origin:'*'."
                        ),
                        code_snippet=line.rstrip(),
                    ))
                    break
        return findings
