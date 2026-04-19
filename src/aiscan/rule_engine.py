"""Rule engine: loads all built-in rules and runs them against parsed files."""

from __future__ import annotations

import warnings

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import Finding


class RuleEngine:
    """Loads all built-in rules and dispatches them against ParsedFile objects."""

    def __init__(self) -> None:
        self.rules: list[BaseRule] = []
        self._load_builtin_rules()

    def _load_builtin_rules(self) -> None:
        from aiscan.rules.python.AI_SEC_002_missing_authorization import MissingAuthorizationRule
        from aiscan.rules.javascript.AI_SEC_002_missing_authorization_js import MissingAuthorizationJSRule
        from aiscan.rules.python.AI_SEC_001_hardcoded_secrets import HardcodedSecretsRule
        from aiscan.rules.python.AI_SEC_003_weak_crypto import WeakCryptoRule
        from aiscan.rules.python.AI_SEC_004_insecure_random import InsecureRandomRule
        from aiscan.rules.python.AI_SEC_008_unsafe_deserialization import UnsafeDeserializationRule
        from aiscan.rules.python.AI_SEC_009_eval_exec import EvalExecRule
        from aiscan.rules.javascript.AI_SEC_009_eval_exec_js import JSEvalExecRule
        from aiscan.rules.javascript.AI_SEC_012_permissive_cors_js import PermissiveCORSRule
        from aiscan.rules.javascript.AI_SEC_013_ssr_state_injection import SSRStateInjectionRule
        from aiscan.rules.javascript.AI_SEC_014_dangerous_inner_html import DangerousInnerHTMLRule
        from aiscan.rules.javascript.AI_SEC_015_ssrf_ssr_fetch import SSRFInServerFetchRule
        from aiscan.rules.javascript.AI_SEC_016_insecure_cookie import InsecureCookieRule
        from aiscan.rules.javascript.AI_SEC_017_weak_csp import WeakCSPRule
        from aiscan.rules.common.AI_SEC_011_path_traversal import PathTraversalRule

        self.rules = [
            MissingAuthorizationRule(),
            MissingAuthorizationJSRule(),
            HardcodedSecretsRule(),
            WeakCryptoRule(),
            InsecureRandomRule(),
            UnsafeDeserializationRule(),
            EvalExecRule(),
            JSEvalExecRule(),
            PermissiveCORSRule(),
            SSRStateInjectionRule(),
            DangerousInnerHTMLRule(),
            SSRFInServerFetchRule(),
            InsecureCookieRule(),
            WeakCSPRule(),
            PathTraversalRule(),
        ]

    def run(self, parsed: ParsedFile) -> list[Finding]:
        """Run all applicable rules against a parsed file. Never raises — rule failures emit a warning."""
        findings: list[Finding] = []
        for rule in self.rules:
            if parsed.language not in rule.languages:
                continue
            try:
                new_findings = rule.check(parsed)
                findings.extend(new_findings)
            except Exception as exc:
                warnings.warn(
                    f"aiscan: rule {rule.rule_id} failed on {parsed.path} ({exc}); skipping rule.",
                    stacklevel=2,
                )
        return findings

    def list_rules(self) -> list[dict]:
        """Return rule metadata for display."""
        return [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": r.severity.value if r.severity else "UNKNOWN",
                "languages": r.languages,
                "cwe_ids": r.cwe_ids,
            }
            for r in self.rules
        ]
