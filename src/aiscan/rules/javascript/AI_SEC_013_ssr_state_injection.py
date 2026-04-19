"""AI-SEC-013: SSR State Hydration Injection.

Server-Side Rendering frameworks (Electrode, Next.js, custom Node/React SSR)
serialize a state object into the initial HTML so the client can "hydrate":

    <script>window.__INITIAL_STATE__ = ${JSON.stringify(state)};</script>

If ``state`` contains attacker-controlled data, ``JSON.stringify`` does NOT
escape ``</script>`` because that sequence is legal inside a JSON string.
The browser's HTML parser, however, terminates the <script> tag early —
turning user input into executable JavaScript (stored XSS with full cookie
access).

The fix is ``serialize-javascript``, which escapes ``<``, ``>``, ``/``, and
U+2028/U+2029 line separators.

AI coding assistants routinely generate the unsafe ``JSON.stringify`` pattern
because it's the "obvious" answer when asked to inline state for SSR.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# State-injection patterns. Each matches an unsafe JSON.stringify usage that
# lands inside an inline <script> tag or a window.__STATE__ assignment.
SSR_INJECTION_PATTERNS = [
    # <script>...${JSON.stringify(x)}...</script> in a template literal
    re.compile(r"<script\b[^>]*>[^<]*\$\{\s*JSON\.stringify\s*\("),
    # window.__INITIAL_STATE__ = ${JSON.stringify(...)} (template literal form)
    re.compile(r"window\.__\w+__\s*=\s*\$\{\s*JSON\.stringify\s*\("),
    # window.__INITIAL_STATE__ = JSON.stringify(...) (direct assignment)
    re.compile(r"window\.__\w+__\s*=\s*JSON\.stringify\s*\("),
    # Common named state globals, regardless of window. prefix
    re.compile(
        r"(__INITIAL_STATE__|__PRELOADED_STATE__|__APP_STATE__|__REDUX_STATE__)"
        r"\s*=\s*\$?\{?\s*JSON\.stringify\s*\("
    ),
    # res.send(`<script>window.X = ${JSON.stringify(y)}</script>`)
    re.compile(r"res\.(send|write|end)\s*\([^)]*<script[^)]*JSON\.stringify"),
]

# Markers that indicate the developer already uses a safe serializer —
# if any of these appear in the file, we lower confidence substantially.
SAFE_SERIALIZER_MARKERS = [
    re.compile(r"""['"`]serialize-javascript['"`]"""),
    re.compile(r"\bserialize\s*\(\s*\w+\s*(?:,|\))"),  # serialize(state) / serialize(state, opts)
]


class SSRStateInjectionRule(BaseRule):
    rule_id = "AI-SEC-013"
    rule_name = "SSR State Hydration Injection"
    severity = Severity.CRITICAL
    cwe_ids = ["CWE-79", "CWE-116"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []

        # File-level check: does the developer already import serialize-javascript?
        source_text = parsed.source.decode("utf-8", errors="replace")
        uses_safe_serializer = any(m.search(source_text) for m in SAFE_SERIALIZER_MARKERS)

        for i, line in enumerate(parsed.lines, start=1):
            matched = False
            for pattern in SSR_INJECTION_PATTERNS:
                if pattern.search(line):
                    matched = True
                    break
            if not matched:
                continue
            confidence = 0.75 if uses_safe_serializer else 0.92
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                file_path=str(parsed.path),
                line_start=i,
                line_end=i,
                message=(
                    "SSR state is serialized with JSON.stringify and embedded "
                    "inline in a <script> tag. JSON.stringify does not escape "
                    "'</script>' inside string values, so attacker-controlled "
                    "state can break out of the script tag and execute arbitrary "
                    "JavaScript in the victim's browser (stored XSS with session "
                    "access)."
                ),
                cwe_ids=self.cwe_ids,
                detection_method=self.detection_method,
                confidence=confidence,
                remediation=(
                    "Replace JSON.stringify with the 'serialize-javascript' "
                    "package, which escapes '<', '>', '/', and U+2028/U+2029. "
                    "Example:\n"
                    "  const serialize = require('serialize-javascript');\n"
                    "  html += `<script>window.__INITIAL_STATE__ = "
                    "${serialize(state, { isJSON: true })};</script>`;\n"
                    "Also verify any CSP nonce is applied to this inline script."
                ),
                code_snippet=line.rstrip(),
            ))
        return findings
