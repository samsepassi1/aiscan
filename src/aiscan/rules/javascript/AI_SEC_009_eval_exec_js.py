"""AI-SEC-009 (JavaScript): Dynamic Code Execution via eval / new Function."""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, Severity


EVAL_PATTERN = re.compile(r"\beval\s*\(")
NEW_FUNCTION_PATTERN = re.compile(r"\bnew\s+Function\s*\(")
STRING_LITERAL_ONLY = re.compile(r"""\beval\s*\(\s*["'`][^"'`]*["'`]\s*\)""")


class JSEvalExecRule:
    rule_id = "AI-SEC-009"
    rule_name = "Dynamic Code Execution (JavaScript)"
    severity = Severity.CRITICAL
    cwe_ids = ["CWE-79", "CWE-94", "CWE-95"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(parsed.lines, start=1):
            if EVAL_PATTERN.search(line) and not STRING_LITERAL_ONLY.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    file_path=str(parsed.path),
                    line_start=i,
                    line_end=i,
                    message=(
                        "eval() with a non-literal argument. In JavaScript, eval() executes "
                        "arbitrary code in the current scope. If the argument is user-controlled, "
                        "this is an XSS / RCE vulnerability."
                    ),
                    cwe_ids=self.cwe_ids,
                    detection_method=self.detection_method,
                    confidence=0.88,
                    remediation=(
                        "Remove eval(). Use JSON.parse() for data, or restructure logic to "
                        "avoid dynamic code execution."
                    ),
                    code_snippet=line.rstrip(),
                ))
            if NEW_FUNCTION_PATTERN.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    file_path=str(parsed.path),
                    line_start=i,
                    line_end=i,
                    message=(
                        "new Function() constructs a function from a string, equivalent to eval(). "
                        "Treat this as a code injection risk."
                    ),
                    cwe_ids=self.cwe_ids,
                    detection_method=self.detection_method,
                    confidence=0.85,
                    remediation="Replace new Function() with a statically defined function.",
                    code_snippet=line.rstrip(),
                ))
        return findings
