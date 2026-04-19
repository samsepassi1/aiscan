"""AI-SEC-017: Weak Content Security Policy.

Content Security Policy is the defense-in-depth layer that limits damage
when an XSS slips through. The common failure modes are:

  * ``'unsafe-inline'`` in script-src — allows any inline <script>, which
    is exactly what an XSS payload injects. Effectively disables CSP's XSS
    protection.
  * ``'unsafe-eval'`` — allows eval() and new Function().
  * Wildcard ``*`` source in script-src/default-src — trivially bypassable.

SSR frameworks like Electrode make strict CSP harder (the inline state
hydration script needs a nonce), so developers and AI assistants take the
shortcut of ``'unsafe-inline'``. This rule catches that shortcut.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# CSP string literal containing an unsafe directive value.
CSP_UNSAFE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"""['"`]Content-Security-Policy['"`]\s*[,:]\s*['"`][^'"`]*unsafe-inline""",
            re.IGNORECASE,
        ),
        "'unsafe-inline'",
    ),
    (
        re.compile(
            r"""['"`]Content-Security-Policy['"`]\s*[,:]\s*['"`][^'"`]*unsafe-eval""",
            re.IGNORECASE,
        ),
        "'unsafe-eval'",
    ),
    # Any line containing a CSP directive keyword AND an unsafe value.
    # This catches the common multi-line form where the header name and
    # the policy string are on separate lines, and handles CSP strings
    # that contain embedded quotes like 'self'.
    (
        re.compile(
            r"""(?:default-src|script-src|style-src|img-src|"""
            r"""connect-src|object-src|base-uri|frame-src)[^;]*unsafe-inline""",
            re.IGNORECASE,
        ),
        "'unsafe-inline' (in CSP directive)",
    ),
    (
        re.compile(
            r"""(?:default-src|script-src|style-src|img-src|"""
            r"""connect-src|object-src|base-uri|frame-src)[^;]*unsafe-eval""",
            re.IGNORECASE,
        ),
        "'unsafe-eval' (in CSP directive)",
    ),
    # HTML meta tag form
    (
        re.compile(
            r"""<meta\s+http-equiv\s*=\s*['"`]Content-Security-Policy['"`][^>]*unsafe-inline""",
            re.IGNORECASE,
        ),
        "'unsafe-inline' (meta tag)",
    ),
    (
        re.compile(
            r"""<meta\s+http-equiv\s*=\s*['"`]Content-Security-Policy['"`][^>]*unsafe-eval""",
            re.IGNORECASE,
        ),
        "'unsafe-eval' (meta tag)",
    ),
    # helmet({ contentSecurityPolicy: { directives: { scriptSrc: [..., "'unsafe-inline'"] }}})
    (
        re.compile(r"""scriptSrc\s*:\s*\[[^\]]*['"`]'?unsafe-inline'?['"`]"""),
        "'unsafe-inline' in scriptSrc",
    ),
    (
        re.compile(r"""scriptSrc\s*:\s*\[[^\]]*['"`]'?unsafe-eval'?['"`]"""),
        "'unsafe-eval' in scriptSrc",
    ),
    # Wildcard source in script-src
    (
        re.compile(r"""script-src\s+[^;'"`]*\*"""),
        "wildcard '*' in script-src",
    ),
]


class WeakCSPRule(BaseRule):
    rule_id = "AI-SEC-017"
    rule_name = "Weak Content Security Policy"
    severity = Severity.MEDIUM
    cwe_ids = ["CWE-693", "CWE-1021"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(parsed.lines, start=1):
            seen_labels: set[str] = set()
            for pattern, label in CSP_UNSAFE_PATTERNS:
                # Normalise label for dedup: strip parenthetical qualifiers so
                # "'unsafe-inline'" and "'unsafe-inline' (in CSP directive)"
                # are treated as the same issue on the same line.
                base_label = label.split(" (")[0]
                if base_label in seen_labels:
                    continue
                if pattern.search(line):
                    seen_labels.add(base_label)
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        file_path=str(parsed.path),
                        line_start=i,
                        line_end=i,
                        message=(
                            f"Content Security Policy contains {label}, which "
                            f"negates CSP's XSS protection. In an SSR app the "
                            f"inline hydration script must be authorized some "
                            f"other way (nonce or hash), not by blanket-allowing "
                            f"all inline scripts."
                        ),
                        cwe_ids=self.cwe_ids,
                        detection_method=self.detection_method,
                        confidence=0.9,
                        remediation=(
                            "Use a per-request nonce or a script hash instead of "
                            "'unsafe-inline':\n"
                            "  const nonce = crypto.randomBytes(16).toString('base64');\n"
                            "  res.setHeader('Content-Security-Policy',\n"
                            "    `default-src 'self'; "
                            "script-src 'self' 'nonce-${nonce}'; "
                            "object-src 'none'; base-uri 'self'`);\n"
                            "  html += `<script nonce=\"${nonce}\">window.__INITIAL_STATE__ "
                            "= ...</script>`;\n"
                            "Remove 'unsafe-eval' entirely — it exists to support "
                            "eval() and new Function(), which should not be in "
                            "production code."
                        ),
                        code_snippet=line.rstrip(),
                    ))
        return findings
