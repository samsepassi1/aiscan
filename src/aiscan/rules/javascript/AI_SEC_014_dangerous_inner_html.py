"""AI-SEC-014: Dangerous Inner HTML.

React's ``dangerouslySetInnerHTML`` is the framework's single explicit escape
hatch from automatic output encoding. Passing unsanitized input to it is a
direct XSS sink. AI coding assistants reach for it when asked to render "rich
text", CMS content, markdown, or email bodies — almost always without a
sanitizer in front of it.

This rule flags all usage and downgrades confidence when a recognised
sanitizer (DOMPurify, sanitize-html, xss, isomorphic-dompurify) is imported
in the same file.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, Severity


DANGEROUS_HTML_PATTERN = re.compile(
    r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"
)

SANITIZER_MARKERS = [
    re.compile(r"""['"`](?:isomorphic-)?dompurify['"`]""", re.IGNORECASE),
    re.compile(r"""['"`]sanitize-html['"`]"""),
    re.compile(r"""\brequire\s*\(\s*['"`]xss['"`]\s*\)"""),
    re.compile(r"""\bfrom\s+['"`]xss['"`]"""),
    re.compile(r"\bDOMPurify\.sanitize\s*\("),
    re.compile(r"\bsanitizeHtml\s*\("),
]


class DangerousInnerHTMLRule:
    rule_id = "AI-SEC-014"
    rule_name = "Dangerous Inner HTML"
    severity = Severity.HIGH
    cwe_ids = ["CWE-79", "CWE-80"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []

        source_text = parsed.source.decode("utf-8", errors="replace")
        has_sanitizer = any(m.search(source_text) for m in SANITIZER_MARKERS)

        for i, line in enumerate(parsed.lines, start=1):
            if not DANGEROUS_HTML_PATTERN.search(line):
                continue

            # Even with a sanitizer in the file, the specific call site may
            # not pass through it — report, but at reduced confidence.
            if has_sanitizer:
                confidence = 0.55
                message = (
                    "dangerouslySetInnerHTML disables React's automatic escaping. "
                    "A sanitizer (DOMPurify/sanitize-html/xss) appears to be "
                    "available in this file — confirm the value passed here "
                    "is actually routed through it before rendering."
                )
            else:
                confidence = 0.85
                message = (
                    "dangerouslySetInnerHTML disables React's automatic escaping "
                    "and no HTML sanitizer (DOMPurify, sanitize-html, xss) is "
                    "imported in this file. If the __html value contains any "
                    "user-controlled data, this is a direct XSS sink."
                )

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                file_path=str(parsed.path),
                line_start=i,
                line_end=i,
                message=message,
                cwe_ids=self.cwe_ids,
                detection_method=self.detection_method,
                confidence=confidence,
                remediation=(
                    "Prefer rendering as text: <div>{value}</div>. If raw HTML "
                    "is required, sanitize first with DOMPurify:\n"
                    "  import DOMPurify from 'isomorphic-dompurify';\n"
                    "  <div dangerouslySetInnerHTML={{ __html: "
                    "DOMPurify.sanitize(value) }} />\n"
                    "For markdown, prefer react-markdown with default-safe "
                    "rendering over manual HTML injection."
                ),
                code_snippet=line.rstrip(),
            ))
        return findings
