"""Tests for detection rules via the rule engine."""

from __future__ import annotations

from pathlib import Path


from aiscan.ast_layer import ASTLayer
from aiscan.rule_engine import RuleEngine
from aiscan.models import Severity


class TestRuleEngine:
    def _scan(self, rule_engine: RuleEngine, ast_layer: ASTLayer, path: Path):
        parsed = ast_layer.parse_file(path)
        assert parsed is not None, f"Failed to parse {path}"
        return rule_engine.run(parsed)

    def test_detects_hardcoded_secrets(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "secrets_test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-001" in rule_ids

    def test_detects_weak_crypto(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "crypto_test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-003" in rule_ids

    def test_detects_insecure_random(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "random_test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-004" in rule_ids

    def test_detects_unsafe_deserialization(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "deserialization_test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-008" in rule_ids

    def test_detects_eval_exec(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "eval_test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-009" in rule_ids

    def test_no_false_positives_secrets_safe(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, safe_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, safe_dir / "secrets_safe.py")
        sec001 = [f for f in findings if f.rule_id == "AI-SEC-001"]
        assert len(sec001) == 0, f"False positive in secrets_safe.py: {sec001}"

    def test_no_false_positives_crypto_safe(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, safe_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, safe_dir / "crypto_safe.py")
        sec003 = [f for f in findings if f.rule_id == "AI-SEC-003"]
        assert len(sec003) == 0, f"False positive in crypto_safe.py: {sec003}"

    def test_finding_has_required_fields(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "secrets_test.py")
        assert len(findings) > 0
        f = findings[0]
        assert f.rule_id
        assert f.rule_name
        assert f.severity in list(Severity)
        assert f.line_start >= 1
        assert f.message
        assert f.remediation
        assert 0.0 <= f.confidence <= 1.0

    def test_rule_failures_do_not_crash_engine(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        # A valid but unusual Python file should not cause the engine to crash
        f = tmp_path / "edge_case.py"
        f.write_text("def f(): pass\n" * 100)
        parsed = ast_layer.parse_file(f)
        assert parsed is not None
        findings = rule_engine.run(parsed)
        assert isinstance(findings, list)
