"""AI-SEC-001: Hardcoded Secrets Detection.

Detects variables with secret-like names assigned string literals with high entropy,
which is a hallmark of AI-generated code that embeds credentials inline.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from aiscan.ast_layer import ParsedFile
from aiscan.base_rule import BaseRule
from aiscan.models import DetectionMethod, Finding, Severity


# Variable/attribute names that commonly hold secrets
SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|token|auth_token|"
    r"access_token|refresh_token|auth|credential|private_key|signing_key|"
    r"encryption_key|database_url|db_url|db_pass|connection_string)",
    re.IGNORECASE,
)

# Patterns that look like real secrets (not placeholder text)
PLACEHOLDER_PATTERN = re.compile(
    r"^(your[_\-]|<.*>|\[.*\]|example|placeholder|changeme|change_me|"
    r"xxx+|yyy+|zzz+|todo|fixme|test|fake|dummy|mock|sample|insert_here)$",
    re.IGNORECASE,
)

# Minimum string length to consider entropy calculation worthwhile
MIN_SECRET_LENGTH = 8

# Shannon entropy threshold above which a string is likely a real secret
ENTROPY_THRESHOLD = 3.5


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_string_value(raw: str) -> str:
    """Strip quotes from a tree-sitter string node text."""
    if raw.startswith('"""') or raw.startswith("'''"):
        return raw[3:-3] if len(raw) >= 6 else ""
    if raw.startswith('"') or raw.startswith("'"):
        return raw[1:-1] if len(raw) >= 2 else ""
    return raw.strip("\"'`")


def looks_like_real_secret(value: str) -> bool:
    """Return True if the string value looks like a real secret (high entropy, non-placeholder)."""
    if len(value) < MIN_SECRET_LENGTH:
        return False
    stripped = value.strip()
    if PLACEHOLDER_PATTERN.match(stripped):
        return False
    # Common fake secrets used in docs — skip them
    if stripped.lower() in {"password", "secret", "token", "api_key", "your_api_key"}:
        return False
    return shannon_entropy(stripped) >= ENTROPY_THRESHOLD


class HardcodedSecretsRule(BaseRule):
    rule_id = "AI-SEC-001"
    rule_name = "Hardcoded Secret"
    severity = Severity.CRITICAL
    cwe_ids = ["CWE-259", "CWE-321", "CWE-798"]
    languages = ["python"]
    detection_method = DetectionMethod.AST

    # tree-sitter query: match assignments where the left side is an identifier
    # and the right side is a string literal
    _QUERY_SRC = """
    (assignment
      left: (identifier) @name
      right: (string) @value
    )
    (assignment
      left: (pattern_list
        (identifier) @name
      )
      right: (string) @value
    )
    """

    def check(self, parsed: ParsedFile) -> list[Finding]:
        findings: list[Finding] = []
        try:
            from tree_sitter_language_pack import get_language
            lang = get_language(parsed.language)  # type: ignore[arg-type]
            query = lang.query(self._QUERY_SRC)  # type: ignore[attr-defined]
            captures = query.captures(parsed.tree.root_node)  # type: ignore[attr-defined]

            # captures is a dict {capture_name: [nodes]} or list of (node, name) tuples
            # Normalize to list of (node, capture_name)
            if isinstance(captures, dict):
                pairs: list[tuple] = []
                for cap_name, nodes in captures.items():
                    for node in nodes:
                        pairs.append((node, cap_name))
            else:
                pairs = list(captures)
        except Exception:
            # Fallback: manual traversal if query API unavailable
            return self._manual_check(parsed)

        # Group by row, collecting all name nodes and value nodes per row
        by_row: dict[int, dict[str, list[object]]] = {}
        for node, cap_name in pairs:
            row = node.start_point[0]  # type: ignore[attr-defined]
            if row not in by_row:
                by_row[row] = {}
            by_row[row].setdefault(cap_name, []).append(node)

        for row, captures_by_name in by_row.items():
            name_nodes = captures_by_name.get("name", [])
            value_nodes = captures_by_name.get("value", [])
            if not name_nodes or not value_nodes:
                continue
            value_node = value_nodes[0]
            raw_value = parsed.get_node_text(value_node)
            string_value = _extract_string_value(raw_value)
            if not looks_like_real_secret(string_value):
                continue
            for name_node in name_nodes:
                var_name = parsed.get_node_text(name_node)
                if not SECRET_NAME_PATTERN.search(var_name):
                    continue
                line = row + 1
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    file_path=str(parsed.path),
                    line_start=line,
                    line_end=line,
                    column_start=name_node.start_point[1],  # type: ignore[attr-defined]
                    column_end=value_node.end_point[1],  # type: ignore[attr-defined]
                    message=(
                        f"Hardcoded secret detected in variable '{var_name}'. "
                        "Embedding credentials in source code exposes them to version control and logs."
                    ),
                    cwe_ids=self.cwe_ids,
                    detection_method=self.detection_method,
                    confidence=0.85,
                    remediation=(
                        "Move this secret to an environment variable or a secrets manager "
                        "(e.g., AWS Secrets Manager, HashiCorp Vault). "
                        f"Replace the literal with: {var_name} = os.environ['{var_name.upper()}']"
                    ),
                    code_snippet=parsed.get_line(line),
                ))
        return findings

    def _manual_check(self, parsed: ParsedFile) -> list[Finding]:
        """Line-based fallback when the tree-sitter query API is unavailable."""
        findings: list[Finding] = []
        assign_re = re.compile(
            r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>[\"'])(?P<value>.*?)(?P=quote)\s*(?:#.*)?$"
        )
        for i, line in enumerate(parsed.lines, start=1):
            m = assign_re.match(line)
            if not m:
                continue
            var_name = m.group("name")
            string_value = m.group("value")
            if not SECRET_NAME_PATTERN.search(var_name):
                continue
            if not looks_like_real_secret(string_value):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                file_path=str(parsed.path),
                line_start=i,
                line_end=i,
                message=(
                    f"Hardcoded secret detected in variable '{var_name}'. "
                    "Embedding credentials in source code exposes them to version control."
                ),
                cwe_ids=self.cwe_ids,
                detection_method=self.detection_method,
                confidence=0.75,
                remediation=(
                    f"Replace with: {var_name} = os.environ['{var_name.upper()}']"
                ),
                code_snippet=line.rstrip(),
            ))
        return findings
