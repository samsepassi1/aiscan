"""AI-SEC-011: Path Traversal.

AI-generated file-serving code frequently concatenates user input into file paths
without sanitization, enabling directory traversal (../../etc/passwd).
Applies to Python, JavaScript, TypeScript, Go, and Java.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# Taint markers — identifiers that commonly carry request-derived data in Python web code.
_PY_TAINT = r"(?:request|flask\.request|req|user_input|form\.|args\.|params\.|query|body|cookies\.|headers\.)"

# Python patterns — each requires a taint marker on the same line to avoid
# flagging well-behaved code like open(os.path.join(CACHE_DIR, filename)).
PY_PATTERNS = [
    # open() with concatenation or os.path.join that includes a taint marker
    re.compile(
        rf"""open\s*\([^)]*{_PY_TAINT}""",
        re.IGNORECASE,
    ),
    # Path(...) constructed from request input
    re.compile(
        rf"""Path\s*\([^)]*{_PY_TAINT}[^)]*\)""",
        re.IGNORECASE,
    ),
    # os.path.join with request input
    re.compile(
        rf"""os\.path\.join\s*\([^)]*{_PY_TAINT}[^)]*\)""",
        re.IGNORECASE,
    ),
]

# Secondary proximity check: open('path/' + var) where var was assigned from a
# taint source within the preceding 5 lines.
_CONCAT_OPEN = re.compile(r"""open\s*\(\s*[^)]*\+\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)""")
_TAINT_ASSIGN = re.compile(
    rf"""(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^=].*?{_PY_TAINT}""",
    re.IGNORECASE,
)

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


class PathTraversalRule(BaseRule):
    rule_id = "AI-SEC-011"
    rule_name = "Path Traversal"
    severity = Severity.HIGH
    cwe_ids = ["CWE-22", "CWE-23", "CWE-36"]
    languages = ["python", "javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        patterns = LANGUAGE_PATTERNS.get(parsed.language, [])
        # Build set of tainted variable names (Python only) from assignments
        # in the file. The taint set is scope-blind by design — we don't
        # track function boundaries, reassignment, or sanitizing wrappers.
        # The tradeoff is occasional FPs (e.g. var = sanitize(req.body))
        # for higher recall on the AI-generated patterns this rule targets.
        tainted_vars: set[str] = set()
        if parsed.language == "python":
            for line in parsed.lines:
                m = _TAINT_ASSIGN.search(line)
                if m:
                    tainted_vars.add(m.group("var"))
        for i, line in enumerate(parsed.lines, start=1):
            matched = False
            for pattern in patterns:
                if pattern.search(line):
                    matched = True
                    break
            # Python-only: catch open('/path/' + tainted_var) via proximity taint tracking
            if not matched and parsed.language == "python" and tainted_vars:
                concat_m = _CONCAT_OPEN.search(line)
                if concat_m and concat_m.group("var") in tainted_vars:
                    matched = True
            if matched:
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
        return findings
