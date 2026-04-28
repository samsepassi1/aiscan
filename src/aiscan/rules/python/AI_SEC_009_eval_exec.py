"""AI-SEC-009: Dynamic Code Execution via eval/exec.

AI-generated code frequently generates eval()/exec() patterns, especially in
code that processes user input, template engines, or admin consoles. These are
trivial RCE vectors when the argument is attacker-controlled.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# Matches eval() or exec() with a non-literal argument.
# STRING_LITERAL_ONLY anchors with ^...$ so a trailing comment or assignment
# (e.g. `x = eval('1+1')  # comment`) falls through and fires. That's
# intentional: literal-string eval is still an anti-pattern, and most
# ergonomic uses live on a bare line. A tree-sitter argument-type check
# would be more precise but the regex covers the common AI-generated shapes.
EVAL_EXEC_PATTERN = re.compile(r"\b(eval|exec)\s*\(")
STRING_LITERAL_ONLY = re.compile(r"""^\s*(eval|exec)\s*\(\s*["'][^"']*["']\s*\)\s*$""")

IMPORT_VAR_PATTERN = re.compile(r"\b__import__\s*\((?!\s*[\"'])")


class EvalExecRule(BaseRule):
    rule_id = "AI-SEC-009"
    rule_name = "Dynamic Code Execution"
    severity = Severity.CRITICAL
    cwe_ids = ["CWE-78", "CWE-94", "CWE-95"]
    languages = ["python"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(parsed.lines, start=1):
            # eval() / exec() with non-literal arguments
            if EVAL_EXEC_PATTERN.search(line) and not STRING_LITERAL_ONLY.match(line):
                m = EVAL_EXEC_PATTERN.search(line)
                func = m.group(1) if m else "eval/exec"
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    file_path=str(parsed.path),
                    line_start=i,
                    line_end=i,
                    message=(
                        f"{func}() called with a non-literal argument. "
                        "If the argument derives from user input, this is a Remote Code Execution vulnerability."
                    ),
                    cwe_ids=self.cwe_ids,
                    detection_method=self.detection_method,
                    confidence=0.88,
                    remediation=(
                        "Avoid eval/exec entirely. Use ast.literal_eval() for safe literal parsing, "
                        "or redesign the feature to avoid dynamic code execution."
                    ),
                    code_snippet=line.rstrip(),
                ))

            # __import__ with variable argument
            if IMPORT_VAR_PATTERN.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    file_path=str(parsed.path),
                    line_start=i,
                    line_end=i,
                    message=(
                        "__import__() called with a variable argument. "
                        "This allows an attacker to load arbitrary modules."
                    ),
                    cwe_ids=self.cwe_ids,
                    detection_method=self.detection_method,
                    confidence=0.85,
                    remediation=(
                        "Use importlib.import_module() with a strict allowlist of module names. "
                        "Never import based on user-controlled strings."
                    ),
                    code_snippet=line.rstrip(),
                ))

        return findings
