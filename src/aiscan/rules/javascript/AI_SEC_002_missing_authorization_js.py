"""AI-SEC-002: Missing Authorization Checks (JavaScript/TypeScript).

Detects Express, Fastify, and Next.js API route handlers that handle
sensitive or mutating operations without any authentication/authorization guard.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# ── Route/endpoint detection ──────────────────────────────────────────────────

ROUTE_REGISTRATION_JS = re.compile(
    r"""(?P<obj>app|router|server|fastify|instance)\."""
    r"""(?P<method>get|post|put|patch|delete|head|options|all)\s*"""
    r"""\(\s*['"`](?P<path>[^'"`]+)['"`]""",
    re.IGNORECASE,
)

# app.get('/path', namedMiddleware, handler) — named identifier in slot 2 means auth present
INLINE_MIDDLEWARE_JS = re.compile(
    r"""(?:app|router|server)\.\w+\s*\(\s*['"`][^'"`]+['"`]\s*,\s*([A-Za-z_]\w*)\s*,"""
)

# ── Auth markers ──────────────────────────────────────────────────────────────

_AUTH_PATTERNS_JS: list[re.Pattern[str]] = [
    re.compile(r"\brequireAuth\b"),
    re.compile(r"\bauthenticate\b"),
    re.compile(r"\bauthorize\b"),
    re.compile(r"\bisAuthenticated\b"),
    re.compile(r"\bverifyToken\b"),
    re.compile(r"\bjwtMiddleware\b"),
    re.compile(r"\bauthMiddleware\b"),
    re.compile(r"\bpassport\.authenticate\b"),
    re.compile(r"\bcheckAuth\b"),
    re.compile(r"\bensureLoggedIn\b"),
    re.compile(r"\bensureAuthenticated\b"),
    re.compile(r"\bverifyJWT\b"),
    re.compile(r"\bcheckJwt\b"),
    re.compile(r"\bwithAuth\b"),
    re.compile(r"\bwithSession\b"),
    re.compile(r"\bgetServerSession\b"),
    re.compile(r"\bgetSession\b"),
    re.compile(r"\bclerkMiddleware\b"),
    re.compile(r"\bauth\s*\(\s*\)"),
    re.compile(r"\bpreHandler\b"),
    re.compile(r"\bonRequest\b"),
    re.compile(r"if\s*\(\s*!req\.user"),
    re.compile(r"if\s*\(\s*!request\.user"),
    re.compile(r"if\s*\(\s*!session"),
    re.compile(r"res\.status\s*\(\s*401"),
    re.compile(r"res\.sendStatus\s*\(\s*401"),
    re.compile(r"reply\.status\s*\(\s*401"),
    re.compile(r"return\s+res\.status\s*\(\s*401"),
    re.compile(r"req\.isAuthenticated\s*\("),
    re.compile(r"req\.session\.(?:user|userId|account|identity)\b"),
    re.compile(r"\bjwt\.verify\b", re.IGNORECASE),
]

# ── Sensitivity classifier ────────────────────────────────────────────────────

SENSITIVE_PATH_JS = re.compile(
    r"/(?:admin|staff|manage|management|dashboard|panel|"
    r"users?|accounts?|profile|settings?|config|configuration|"
    r"delete|remove|update|edit|create|add|upload|"
    r"payment|billing|invoice|orders?|checkout|"
    r"api/(?:v\d+/)?(?!(?:public|health|status|ping|docs|swagger|favicon)(?:/|$)))",
    re.IGNORECASE,
)

URL_PARAM_JS = re.compile(r":[\w]+|\[[\w]+\]")

MUTATION_METHODS_JS: frozenset[str] = frozenset({"post", "put", "patch", "delete"})

MUTATION_OPS_JS = re.compile(
    r"\b(?:\.save\(\)|\.deleteOne\(|\.deleteMany\(|\.findByIdAndDelete\(|"
    r"\.findOneAndDelete\(|\.updateOne\(|\.updateMany\(|\.findByIdAndUpdate\(|"
    r"\.insertOne\(|\.insertMany\(|\.create\(|db\.query\b|"
    r"prisma\.\w+\.(?:create|update|delete|upsert))\b"
)

FILE_AUTH_IMPORT_JS = re.compile(
    r"""require\s*\(\s*['"`](?:passport|jsonwebtoken|express-jwt|"""
    r"""jose|@auth0|next-auth|clerk|supertokens|firebase-admin|"""
    r"""@clerk|@supabase)['"`]\s*\)|"""
    r"""import\s+.+\s+from\s+['"`](?:passport|jsonwebtoken|express-jwt|"""
    r"""jose|@auth0|next-auth|clerk|supertokens|firebase-admin|"""
    r"""@clerk/nextjs|@supabase/auth-helpers)['"`]""",
    re.IGNORECASE,
)

_CONTEXT_BACK = 2
_CONTEXT_FORWARD = 20

_ADMIN_PATH_JS = re.compile(r"/admin|/staff|/manage", re.IGNORECASE)


class MissingAuthorizationJSRule(BaseRule):
    rule_id = "AI-SEC-002"
    rule_name = "Missing Authorization Check"
    severity = Severity.CRITICAL
    cwe_ids = ["CWE-862", "CWE-306"]
    languages = ["javascript", "typescript"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        source_text = parsed.source.decode("utf-8", errors="replace")
        has_auth_infrastructure = bool(FILE_AUTH_IMPORT_JS.search(source_text))

        lines = parsed.lines
        n = len(lines)

        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            route_m = ROUTE_REGISTRATION_JS.search(line)
            if not route_m:
                continue

            url_path = route_m.group("path")
            http_method = route_m.group("method").lower()

            is_sensitive = bool(SENSITIVE_PATH_JS.search(url_path))
            has_url_param = bool(URL_PARAM_JS.search(url_path))
            is_mutation = http_method in MUTATION_METHODS_JS

            if not (is_sensitive or is_mutation or has_url_param):
                continue

            if INLINE_MIDDLEWARE_JS.search(line):
                continue

            ctx_start = max(0, i - _CONTEXT_BACK)
            # Cap forward window at next route registration to avoid bleeding across handlers
            raw_end = min(n, i + _CONTEXT_FORWARD + 1)
            ctx_end = raw_end
            for j in range(i + 1, raw_end):
                if ROUTE_REGISTRATION_JS.search(lines[j]):
                    ctx_end = j
                    break
            context_text = "\n".join(lines[ctx_start:ctx_end])

            if any(pat.search(context_text) for pat in _AUTH_PATTERNS_JS):
                continue

            is_admin = bool(_ADMIN_PATH_JS.search(url_path))
            if is_mutation or is_admin:
                severity = Severity.CRITICAL
                base_confidence = 0.82 if is_admin else 0.80
            else:
                severity = Severity.HIGH
                base_confidence = 0.70 if is_sensitive else 0.62

            body_text = "\n".join(lines[i:ctx_end])
            if MUTATION_OPS_JS.search(body_text):
                base_confidence = min(base_confidence + 0.08, 0.90)

            if has_auth_infrastructure:
                base_confidence = max(base_confidence - 0.10, 0.50)

            method_label = http_method.upper()
            if is_mutation or is_admin:
                msg = (
                    f"{method_label} {url_path!r} performs a privileged or mutating operation "
                    f"without any authentication or authorization middleware. Any caller can "
                    f"invoke this endpoint."
                )
            else:
                msg = (
                    f"{method_label} {url_path!r} exposes user-specific data with no visible "
                    f"authentication check. Unauthenticated callers may access this data."
                )
            if has_auth_infrastructure:
                msg += (
                    " (Auth library is imported in this file but no guard was detected "
                    "on this specific route.)"
                )

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=severity,
                file_path=str(parsed.path),
                line_start=i + 1,
                line_end=i + 1,
                message=msg,
                cwe_ids=self.cwe_ids,
                detection_method=self.detection_method,
                confidence=round(base_confidence, 2),
                remediation=(
                    "Add authentication/authorization before the route handler:\n"
                    "  Express:  app.delete('/path', requireAuth, handler)\n"
                    "  Fastify:  add a preHandler hook with your auth logic\n"
                    "  Next.js:  use getServerSession() or auth() at the top of the handler\n"
                    "  Manual:   if (!req.user) return res.status(401).json({ error: 'Unauthorized' });"
                ),
                code_snippet=line.rstrip(),
            ))

        return findings
