"""AI-SEC-018 (JavaScript/TypeScript): Prompt Injection via Untrusted Input.

Detects untrusted HTTP input flowing into LLM system prompts via the
Anthropic and OpenAI JS SDKs — the JavaScript analog of
``python/AI_SEC_018_prompt_injection.py``.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# Object-literal shapes that identify a system-prompt slot:
#   system: ...     (top-level Anthropic SDK option)
#   role: "system"  (OpenAI-style messages array entry)
_SYSTEM_PROMPT_INDICATOR = re.compile(
    r"""\bsystem\s*:\s*"""
    r"""|\brole\s*:\s*["']system["']"""
)

# Taint sources in Node/Edge web frameworks (Express, Fastify, Koa,
# Next.js API routes, Hono).
_TAINT = (
    r"(?:"
    r"(?:req|request|ctx)\.(?:body|params|query|headers|cookies|url)"
    r"(?:\.[a-zA-Z_$][\w$]*|\[[^\]]+\])*"
    r"|userInput|userQuery|userMessage|userPrompt|userContent"
    r")"
)

# Template literal with ${taint}, or "..." + taint / taint + "..."
# concatenation on a single line.
_INTERP_TAINT = re.compile(
    rf"""`[^`]*\$\{{[^}}]*{_TAINT}"""
    rf"""|['"][^'"\n]*['"]\s*\+\s*{_TAINT}"""
    rf"""|{_TAINT}\s*\+\s*['"][^'"\n]*['"]"""
)


class PromptInjectionJSRule(BaseRule):
    rule_id = "AI-SEC-018"
    rule_name = "Prompt Injection via Untrusted Input (JavaScript)"
    severity = Severity.HIGH
    cwe_ids = ["CWE-20", "CWE-94", "CWE-77"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        lines = parsed.lines

        for i, line in enumerate(lines, start=1):
            # Skip single-line comments — vulnerable examples in docs
            # and how-to comments are not active calls.
            if line.lstrip().startswith("//"):
                continue
            if not _INTERP_TAINT.search(line):
                continue
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
                    "Keep the system prompt static (a constant string). Pass "
                    "user input in a separate {role: 'user', content: ...} "
                    "message, and validate/escape it. For tool-use, add "
                    "input schemas and reject out-of-schema arguments."
                ),
                code_snippet=line.rstrip(),
            ))

        return findings
