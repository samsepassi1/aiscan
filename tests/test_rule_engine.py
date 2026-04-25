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

    def test_no_false_positives_random_safe(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, safe_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, safe_dir / "random_safe.py")
        sec004 = [f for f in findings if f.rule_id == "AI-SEC-004"]
        assert len(sec004) == 0, f"False positive in random_safe.py: {sec004}"

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

    # ── AI-SEC-002: Missing Authorization (Python) ────────────────────────────

    def test_detects_missing_auth_flask_admin(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "authorization_test.py")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        assert len(sec002) >= 3, f"Expected >=3 AI-SEC-002 findings, got {len(sec002)}: {sec002}"

    def test_missing_auth_admin_route_is_critical(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "authorization_test.py")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        admin_findings = [f for f in sec002 if "/admin" in f.code_snippet]
        assert len(admin_findings) >= 1
        assert all(f.severity == Severity.CRITICAL for f in admin_findings)

    def test_missing_auth_mutation_is_critical(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "authorization_test.py")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        mutation_findings = [
            f for f in sec002
            if f.message.startswith(("DELETE", "POST", "PUT", "PATCH"))
        ]
        assert len(mutation_findings) >= 1
        assert all(f.severity == Severity.CRITICAL for f in mutation_findings)

    def test_no_false_positive_auth_safe_python(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, safe_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, safe_dir / "authorization_safe.py")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        assert len(sec002) == 0, f"False positives in authorization_safe.py: {sec002}"

    def test_missing_auth_cwe_ids(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "authorization_test.py")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        assert len(sec002) > 0
        for f in sec002:
            assert "CWE-862" in f.cwe_ids
            assert "CWE-306" in f.cwe_ids

    def test_auth_on_one_route_does_not_suppress_adjacent_unprotected_route(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "two_routes.py"
        f.write_text(
            "@app.route('/admin/config')\n"
            "@login_required\n"
            "def config():\n"
            "    return 'ok'\n"
            "\n"
            "@app.route('/admin/delete', methods=['DELETE'])\n"
            "def delete_thing():\n"
            "    return 'deleted'\n"
        )
        parsed = ast_layer.parse_file(f)
        assert parsed is not None
        findings = rule_engine.run(parsed)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) >= 1
        assert any("delete" in fi.code_snippet.lower() for fi in sec002)

    def test_public_health_endpoint_not_flagged(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "public.py"
        f.write_text(
            "@app.get('/health')\n"
            "def health():\n"
            "    return {'status': 'ok'}\n"
        )
        parsed = ast_layer.parse_file(f)
        assert parsed is not None
        findings = rule_engine.run(parsed)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 0, f"Health endpoint falsely flagged: {sec002}"

    def test_multi_method_route_picks_most_dangerous_method(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "multi_method.py"
        f.write_text(
            "@app.route('/api/posts/<int:id>', methods=['GET', 'DELETE'])\n"
            "def post_detail(id):\n"
            "    return 'ok'\n"
        )
        parsed = ast_layer.parse_file(f)
        assert parsed is not None
        findings = rule_engine.run(parsed)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 1
        assert sec002[0].severity == Severity.CRITICAL
        assert sec002[0].message.startswith("DELETE")

    def test_auth_lib_import_reduces_confidence(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "auth_import.py"
        f.write_text(
            "from flask_login import login_manager\n"
            "\n"
            "@app.route('/admin/users')\n"
            "def admin_users():\n"
            "    return 'ok'\n"
        )
        parsed = ast_layer.parse_file(f)
        assert parsed is not None
        findings = rule_engine.run(parsed)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 1
        assert sec002[0].confidence < 0.80
        assert "Auth library" in sec002[0].message
