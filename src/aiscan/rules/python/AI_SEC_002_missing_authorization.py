"""AI-SEC-002: Missing Authorization Checks (Python).

AI tools generate route handlers and API endpoints without any
authorization/authentication guard at a 322% higher rate than human developers.
This rule detects Flask, FastAPI, and Django routes that handle sensitive
operations with no apparent auth check.
"""

from __future__ import annotations

import re

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# ── Route/endpoint detection ──────────────────────────────────────────────────

ROUTE_DECORATOR_PY = re.compile(
    r"""^\s*@(?:app|router|blueprint|bp|api)\."""
    r"""(?P<method>route|get|post|put|patch|delete|head|options)\s*\(\s*['"`](?P<path>[^'"`]+)['"`]""",
    re.IGNORECASE,
)

# ── Auth markers ──────────────────────────────────────────────────────────────

_AUTH_PATTERNS_PY: list[re.Pattern[str]] = [
    re.compile(r"@login_required"),
    re.compile(r"@permission_required"),
    re.compile(r"@jwt_required"),
    re.compile(r"@token_required"),
    re.compile(r"@requires_auth"),
    re.compile(r"@admin_required"),
    re.compile(r"@staff_member_required"),
    re.compile(r"@superuser_required"),
    re.compile(r"@auth\.login_required"),
    re.compile(r"@roles_required"),
    re.compile(r"current_user\s*[:=]"),
    re.compile(r"\bDepends\s*\(\s*get_current_user"),
    re.compile(r"\bDepends\s*\(\s*require_auth"),
    re.compile(r"\bDepends\s*\(\s*get_current_active"),
    re.compile(r"\bDepends\s*\(\s*oauth2_scheme"),
    re.compile(r"\bDepends\s*\(\s*security"),
    re.compile(r"request\.user\.is_authenticated"),
    re.compile(r"request\.user\.is_staff"),
    re.compile(r"request\.user\.is_superuser"),
    re.compile(r"if\s+not\s+(?:current_user|request\.user)"),
    re.compile(r"\bget_current_user\b"),
    re.compile(r"\bverify_token\b"),
    re.compile(r"\braise\s+HTTPException.*status_code\s*=\s*40[13]"),
    re.compile(r"\braise\s+HTTPException.*4(?:01|03)"),
    re.compile(r"\babort\s*\(\s*40[13]"),
    re.compile(r"\bPermissionDenied\b"),
    re.compile(r"\bIsAuthenticated\b"),
    re.compile(r"\bIsAdminUser\b"),
    re.compile(r"\bpermission_classes\b"),
    re.compile(r"\bauthentication_classes\b"),
    re.compile(r"\bTokenAuthentication\b"),
    re.compile(r"\bSessionAuthentication\b"),
    re.compile(r"\bJSONWebTokenAuthentication\b"),
    re.compile(r"@csrf_protect"),
]

# ── Sensitivity classifier ────────────────────────────────────────────────────

SENSITIVE_PATH_PY = re.compile(
    r"/(?:admin|staff|superuser|manage|management|dashboard|panel|"
    r"users?|accounts?|profile|settings?|config|configuration|"
    r"delete|remove|destroy|edit|update|create|add|upload|"
    r"payment|billing|invoice|orders?|checkout|"
    r"api/(?:v\d+/)?(?!public|health|status|ping|docs|openapi|redoc|favicon))",
    re.IGNORECASE,
)

URL_PARAM_PY = re.compile(r"<[^>]+>|\{[^}]+\}")

MUTATION_METHODS_PY: frozenset[str] = frozenset({"post", "put", "patch", "delete"})

MUTATION_OPS_PY = re.compile(
    r"\b(?:\.save\(\)|\.delete\(\)|\.commit\(\)|\.update\(|\.insert\(|"
    r"\.create\(|db\.session\.add|db\.session\.commit|"
    r"\.filter_by.*\.delete|\.bulk_create|\.bulk_update|"
    r"cursor\.execute\b|\.execute\b)",
    re.IGNORECASE,
)

# ── File-level auth infrastructure signal ────────────────────────────────────

FILE_AUTH_IMPORT_PY = re.compile(
    r"(?:from|import)\s+(?:flask_login|flask_jwt|flask_security|"
    r"fastapi_users|fastapi_jwt_auth|jose|authlib|"
    r"django\.contrib\.auth|rest_framework\.authentication|"
    r"rest_framework\.permissions|itsdangerous)",
    re.IGNORECASE,
)

_CONTEXT_BACK = 2       # lines before route decorator (stacked decorators)
_CONTEXT_FORWARD = 20   # lines into handler body

# Extracts explicit methods from methods=['DELETE', 'POST'] style arguments
METHODS_ARG_PY = re.compile(r"methods\s*=\s*\[([^\]]+)\]", re.IGNORECASE)


class MissingAuthorizationRule(BaseRule):
    rule_id = "AI-SEC-002"
    rule_name = "Missing Authorization Check"
    severity = Severity.CRITICAL
    cwe_ids = ["CWE-862", "CWE-306"]
    languages = ["python"]
    detection_method = DetectionMethod.AST

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        source_text = parsed.source.decode("utf-8", errors="replace")
        has_auth_infrastructure = bool(FILE_AUTH_IMPORT_PY.search(source_text))

        lines = parsed.lines
        n = len(lines)

        for i, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue

            route_m = ROUTE_DECORATOR_PY.search(line)
            if not route_m:
                continue

            url_path = route_m.group("path")
            raw_method = route_m.group("method").lower()

            # For @app.route(..., methods=['DELETE']), extract the explicit method
            if raw_method == "route":
                methods_m = METHODS_ARG_PY.search(line)
                if methods_m:
                    explicit = [m.strip().strip("'\"").lower() for m in methods_m.group(1).split(",")]
                    explicit = [m for m in explicit if m]
                    http_method = explicit[0] if explicit else "get"
                else:
                    http_method = "get"
            else:
                http_method = raw_method

            is_sensitive = bool(SENSITIVE_PATH_PY.search(url_path))
            has_url_param = bool(URL_PARAM_PY.search(url_path))
            is_mutation = http_method in MUTATION_METHODS_PY

            if not (is_sensitive or is_mutation or has_url_param):
                continue

            ctx_start = max(0, i - _CONTEXT_BACK)
            # Cap forward window at next route decorator to avoid bleeding across functions
            raw_end = min(n, i + _CONTEXT_FORWARD + 1)
            ctx_end = raw_end
            for j in range(i + 1, raw_end):
                if ROUTE_DECORATOR_PY.search(lines[j]):
                    ctx_end = j
                    break
            context_text = "\n".join(lines[ctx_start:ctx_end])

            if any(pat.search(context_text) for pat in _AUTH_PATTERNS_PY):
                continue

            is_admin = bool(re.search(r"/admin|/staff|/superuser|/manage", url_path, re.IGNORECASE))
            if is_mutation or is_admin:
                severity = Severity.CRITICAL
                base_confidence = 0.85 if is_admin else 0.82
            else:
                severity = Severity.HIGH
                base_confidence = 0.72 if is_sensitive else 0.65

            body_text = "\n".join(lines[i:ctx_end])
            if MUTATION_OPS_PY.search(body_text):
                base_confidence = min(base_confidence + 0.08, 0.92)

            if has_auth_infrastructure:
                base_confidence = max(base_confidence - 0.10, 0.50)

            method_label = http_method.upper()
            if is_mutation or is_admin:
                msg = (
                    f"{method_label} {url_path!r} performs a privileged or mutating operation "
                    f"but has no authorization check. Any caller — authenticated or not — "
                    f"can invoke this endpoint."
                )
            else:
                msg = (
                    f"{method_label} {url_path!r} exposes user-specific data without an "
                    f"authorization check. An unauthenticated or unprivileged caller can "
                    f"access this data."
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
                    "Add an authorization guard to this route:\n"
                    "  Flask:   @login_required decorator, or abort(401) at top of handler\n"
                    "  FastAPI: add current_user: User = Depends(get_current_user) parameter\n"
                    "  Django:  set permission_classes = [IsAuthenticated] or [IsAdminUser]\n"
                    "Ensure the check cannot be bypassed by HTTP method overrides."
                ),
                code_snippet=line.rstrip(),
            ))

        return findings
