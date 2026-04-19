"""AI-SEC-004: Insecure Random Number Generator in Security Context.

AI-generated code almost universally uses the `random` module for token/session
generation because it is simpler to demo. The `random` module is a Mersenne Twister
and is entirely predictable given 624 consecutive outputs.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# Identifiers that indicate a security context
SECURITY_CONTEXT_PATTERN = re.compile(
    r"(token|password|passwd|pwd|session|nonce|salt|key|secret|auth|csrf|otp|pin|code)",
    re.IGNORECASE,
)

# random.* calls to flag
RANDOM_CALL_PATTERN = re.compile(
    r"\brandom\.(random|randint|randrange|choice|choices|sample|uniform|shuffle)\s*\("
)


class InsecureRandomRule(BaseRule):
    rule_id = "AI-SEC-004"
    rule_name = "Insecure Random Number Generator"
    severity = Severity.HIGH
    cwe_ids = ["CWE-330", "CWE-338"]
    languages = ["python"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        lines = parsed.lines

        # Two-pass: detect lines with random.* calls, then check surrounding context
        for i, line in enumerate(lines, start=1):
            if not RANDOM_CALL_PATTERN.search(line):
                continue

            # Check the current line + preceding 5 lines for a security-context identifier.
            # lines is 0-indexed; line i corresponds to lines[i-1].
            context_window = "\n".join(lines[max(0, i - 6) : i])
            if not SECURITY_CONTEXT_PATTERN.search(context_window):
                continue

            match = RANDOM_CALL_PATTERN.search(line)
            func_name = match.group(1) if match else "random"

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                file_path=str(parsed.path),
                line_start=i,
                line_end=i,
                message=(
                    f"random.{func_name}() used in a security-sensitive context. "
                    "The random module uses a Mersenne Twister PRNG which is not "
                    "cryptographically secure and can be predicted after ~624 outputs."
                ),
                cwe_ids=self.cwe_ids,
                detection_method=self.detection_method,
                confidence=0.85,
                remediation=(
                    "Use the `secrets` module for all security-sensitive randomness: "
                    "secrets.token_hex(32), secrets.token_urlsafe(32), or secrets.randbelow(n)."
                ),
                code_snippet=line.rstrip(),
            ))
        return findings
