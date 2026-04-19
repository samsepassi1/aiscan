"""AI-SEC-016: Insecure Cookie Flags.

Session and auth cookies must carry ``httpOnly``, ``secure``, and a
restrictive ``sameSite`` to be safe in a modern browser:

  * ``httpOnly``   — blocks JavaScript access (defeats XSS cookie theft)
  * ``secure``     — forces HTTPS transport
  * ``sameSite``   — ``Lax`` or ``Strict`` defeats most CSRF

AI coding assistants often generate ``res.cookie('session', token)`` with
no options at all, or with ``httpOnly: false`` / ``secure: false`` copied
from a development snippet. This rule flags both.

Supports Express (``res.cookie``), Fastify (``reply.setCookie``), and Hapi
(``h.state``). Electrode apps on Fastify are the primary target.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.models import DetectionMethod, Finding, Severity


# Call signatures we care about.
COOKIE_CALL_PATTERN = re.compile(
    r"\b(?:res|reply|response|ctx|h)\.(?:cookie|setCookie|state)\s*\("
)

# Explicit disabling — these are always unsafe.
EXPLICIT_BAD_FLAGS = [
    (re.compile(r"httpOnly\s*:\s*false"), "httpOnly: false"),
    (re.compile(r"secure\s*:\s*false"), "secure: false"),
    (re.compile(r"""sameSite\s*:\s*['"`]?[Nn]one['"`]?"""), "sameSite: 'none'"),
]


def _line_plus_window(parsed: ParsedFile, i: int, span: int = 4) -> str:
    """Join the current line with the next ``span`` lines to catch multiline option objects."""
    end = min(len(parsed.lines), i + span)
    return " ".join(parsed.lines[i - 1 : end])


class InsecureCookieRule:
    rule_id = "AI-SEC-016"
    rule_name = "Insecure Cookie Flags"
    severity = Severity.HIGH
    cwe_ids = ["CWE-614", "CWE-1004", "CWE-1275"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(parsed.lines, start=1):
            # Skip single-line comments — the literal text of unsafe flags
            # often appears in developer notes and docs.
            stripped = line.lstrip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            # Case 1: explicit bad flags anywhere in code — report every occurrence
            explicit_fired = False
            for pattern, label in EXPLICIT_BAD_FLAGS:
                if pattern.search(line):
                    explicit_fired = True
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        file_path=str(parsed.path),
                        line_start=i,
                        line_end=i,
                        message=(
                            f"Explicit unsafe cookie option ({label}). Session "
                            f"cookies must set httpOnly: true, secure: true, and "
                            f"sameSite: 'lax' or 'strict' in production."
                        ),
                        cwe_ids=self.cwe_ids,
                        detection_method=self.detection_method,
                        confidence=0.95,
                        remediation=(
                            "Set all three protective flags:\n"
                            "  res.cookie('session', token, {\n"
                            "    httpOnly: true,\n"
                            "    secure: true,        // HTTPS only\n"
                            "    sameSite: 'lax',     // or 'strict' for auth cookies\n"
                            "    maxAge: 60 * 60 * 1000\n"
                            "  });\n"
                            "If sameSite: 'none' is genuinely required (e.g. "
                            "cross-site embeds), it MUST be paired with secure: true."
                        ),
                        code_snippet=line.rstrip(),
                    ))

            # Case 2: cookie call whose (multi-line) options object is missing httpOnly.
            # Skip if Case 1 already fired — the explicit-flag finding is more precise.
            if not explicit_fired and COOKIE_CALL_PATTERN.search(line):
                window = _line_plus_window(parsed, i, span=4)
                has_http_only = "httpOnly" in window and not re.search(
                    r"httpOnly\s*:\s*false", window
                )
                # Only flag if there's no httpOnly AND it's not a delete/clear call
                if not has_http_only and "clearCookie" not in line:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        file_path=str(parsed.path),
                        line_start=i,
                        line_end=i,
                        message=(
                            "Cookie is set without an httpOnly flag. JavaScript "
                            "in the page (including any XSS payload) will be able "
                            "to read this cookie via document.cookie. For auth or "
                            "session cookies this defeats most XSS mitigations."
                        ),
                        cwe_ids=self.cwe_ids,
                        detection_method=self.detection_method,
                        confidence=0.78,
                        remediation=(
                            "Add httpOnly, secure, and sameSite to the options:\n"
                            "  res.cookie('name', value, {\n"
                            "    httpOnly: true,\n"
                            "    secure: true,\n"
                            "    sameSite: 'lax'\n"
                            "  });\n"
                            "For Fastify use reply.setCookie with the same options."
                        ),
                        code_snippet=line.rstrip(),
                    ))
        return findings
