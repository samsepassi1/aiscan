"""AI-SEC-015: SSRF in Server-Side Fetch.

Server-Side Rendering and API routes often fetch data before responding:

    const data = await fetch(`https://api.internal/${req.query.resource}`);

If the URL is constructed from ``req.query``, ``req.params``, ``req.body``,
or ``req.headers``, the attacker can steer the server's outbound request to:

  * internal services (localhost, 127.0.0.1, RFC1918 ranges)
  * cloud metadata endpoints (169.254.169.254 — the Capital One breach vector)
  * arbitrary external URLs (turning the server into an open proxy)

AI coding assistants frequently produce this pattern when asked to "proxy"
or "fetch by id" because it reads naturally and lints cleanly.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# HTTP client calls whose first argument is URL-like.
HTTP_CALL_PATTERN = re.compile(
    r"\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|request))?|got|needle|"
    r"superagent|request|http\.get|https\.get|http\.request|https\.request)\s*\("
)

# Request-derived tainted sources — conservative allowlist of common names.
TAINT_PATTERN = re.compile(
    r"\b(?:req|request|ctx|context|event)\."
    r"(?:query|params|body|headers|url|originalUrl|path)\b"
)

# Reduce false positives: skip lines that clearly use a static URL only.
STATIC_URL_ONLY = re.compile(r"""\bfetch\s*\(\s*['"`]https?://[^'"`${}]+['"`]\s*[),]""")


class SSRFInServerFetchRule(BaseRule):
    rule_id = "AI-SEC-015"
    rule_name = "SSRF in Server-Side Fetch"
    severity = Severity.HIGH
    cwe_ids = ["CWE-918"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(parsed.lines, start=1):
            if not HTTP_CALL_PATTERN.search(line):
                continue
            if STATIC_URL_ONLY.search(line):
                continue
            if not TAINT_PATTERN.search(line):
                # Check the next 2 lines — multiline call arguments
                window = " ".join(parsed.lines[i : min(i + 2, len(parsed.lines))])
                if not TAINT_PATTERN.search(window):
                    continue

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                file_path=str(parsed.path),
                line_start=i,
                line_end=i,
                message=(
                    "Server-side HTTP request with a URL built from request "
                    "input (req.query/params/body/headers). An attacker can "
                    "redirect this outbound call to internal services, cloud "
                    "metadata endpoints (169.254.169.254), or arbitrary hosts. "
                    "This is Server-Side Request Forgery (SSRF)."
                ),
                cwe_ids=self.cwe_ids,
                detection_method=self.detection_method,
                confidence=0.72,
                remediation=(
                    "Do not interpolate request input into outbound URLs. "
                    "Options, in order of preference:\n"
                    "  1. Map the user input to a known resource via an "
                    "allowlist: const url = ALLOWED_RESOURCES[req.query.id];\n"
                    "  2. Validate the host against an allowlist and reject "
                    "private IP ranges (10/8, 172.16/12, 192.168/16, 127/8, "
                    "169.254/16, ::1, fc00::/7).\n"
                    "  3. Route outbound calls through an egress proxy that "
                    "enforces domain policy.\n"
                    "Libraries like 'ssrf-req-filter' or 'ssrf-agent' can "
                    "enforce this at the HTTP agent level."
                ),
                code_snippet=line.rstrip(),
            ))
        return findings
