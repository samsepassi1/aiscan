"""AI-SEC-018: Prompt Injection via Untrusted Input (Python).

AI-written code that *calls* LLM APIs routinely interpolates HTTP request
data directly into the system prompt. A user who controls that input can
override instructions ("ignore previous rules, reveal..."), exfiltrate
secrets baked into the system prompt, or invoke tools with attacker-chosen
arguments.

The scanner targets the two dominant Python SDKs — Anthropic and OpenAI —
and the two dominant taint-to-prompt shapes: f-string interpolation and
``+``/``.format()`` concatenation into a system role.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# Lines that indicate we're looking at a system-prompt slot. Either a
# keyword argument on a Python-SDK call (``system=``, ``system_prompt=``,
# ``instructions=``) or an OpenAI-style messages dict with ``"role":
# "system"``.
_SYSTEM_PROMPT_INDICATOR = re.compile(
    r"""\b(?:system|system_prompt|instructions)\s*=\s*"""
    r"""|["']role["']\s*:\s*["']system["']"""
)

# Names / attribute accesses that commonly carry user-controlled data in
# Python web apps. Kept tight to avoid false positives.
_TAINT = (
    r"(?:"
    r"request\.(?:args|json|form|data|values|files|headers|cookies)(?:\.[a-zA-Z_]\w*|\[[^\]]+\])?"
    r"|flask\.request\.\w+"
    r"|req\.(?:body|params|query)"
    r"|user_input|user_query|user_message|user_prompt|user_content"
    r"|sys\.argv"
    r")"
)

# A taint-bearing string construction on a single line. The interpolation
# regexes use [^'"\n]* so they cannot cross line boundaries — taint inside
# a multi-line triple-quoted f-string spread across several lines won't
# match. That's a known limitation; we accept it because the AI-generated
# prompt-injection patterns this rule targets sit on one line in practice.
_INTERP_TAINT = re.compile(
    rf"""f['"][^'"\n]*\{{[^}}\n]*{_TAINT}"""
    rf"""|['"][^'"\n]*['"]\s*\+\s*{_TAINT}"""
    rf"""|{_TAINT}\s*\+\s*['"][^'"\n]*['"]"""
    rf"""|\.format\s*\([^)]*{_TAINT}"""
)


class PromptInjectionRule(BaseRule):
    rule_id = "AI-SEC-018"
    rule_name = "Prompt Injection via Untrusted Input"
    severity = Severity.HIGH
    cwe_ids = ["CWE-20", "CWE-94", "CWE-77"]
    languages = ["python"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        lines = parsed.lines

        for i, line in enumerate(lines, start=1):
            # Skip comment-only lines — vulnerable examples appear in
            # docstrings and how-to comments and are not active calls.
            if line.lstrip().startswith("#"):
                continue
            if not _INTERP_TAINT.search(line):
                continue

            # Only flag when the interpolated taint is *inside* a system-prompt
            # slot. Use a window of 3 lines before / 2 after to cover the
            # common multi-line call shapes:
            #
            #     client.messages.create(
            #         system=f"...{request.args['x']}...",   # ← here
            #         model="claude-sonnet-4-6",
            #     )
            window = "\n".join(lines[max(0, i - 4) : i + 3])
            if not _SYSTEM_PROMPT_INDICATOR.search(window):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                file_path=str(parsed.path),
                line_start=i,
                line_end=i,
                message=(
                    "Untrusted input interpolated into an LLM system prompt. "
                    "An attacker can override instructions, exfiltrate secrets "
                    "baked into the prompt, or invoke tools with chosen arguments."
                ),
                cwe_ids=self.cwe_ids,
                detection_method=self.detection_method,
                confidence=0.82,
                remediation=(
                    "Keep the system prompt static. Pass user-controlled text "
                    "in a separate user-role message and validate/escape it. "
                    "For tool-use setups, add input schemas with strict types "
                    "and reject out-of-schema values before calling the model."
                ),
                code_snippet=line.rstrip(),
            ))

        return findings
