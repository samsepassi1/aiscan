"""Tests for JavaScript/TypeScript detection rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from aiscan.ast_layer import ASTLayer
from aiscan.rule_engine import RuleEngine
from aiscan.models import Severity


class TestJSRules:
    def _scan(self, rule_engine: RuleEngine, ast_layer: ASTLayer, path: Path):
        parsed = ast_layer.parse_file(path)
        assert parsed is not None, f"Failed to parse {path}"
        return rule_engine.run(parsed)

    def test_detects_eval_js(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "eval_test.js")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-009" in rule_ids

    def test_detects_new_function_js(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "eval_test.js")
        new_fn_findings = [f for f in findings if "new Function" in f.message]
        assert len(new_fn_findings) >= 1

    def test_detects_permissive_cors(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "cors_test.js")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-012" in rule_ids

    def test_cors_finding_severity(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "cors_test.js")
        cors_findings = [f for f in findings if f.rule_id == "AI-SEC-012"]
        assert all(f.severity == Severity.HIGH for f in cors_findings)

    def test_detects_path_traversal_python(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "path_traversal_test.py")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-011" in rule_ids

    def test_eval_literal_string_no_finding(self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path):
        f = tmp_path / "safe.js"
        f.write_text("const x = eval('1 + 1');\n")
        findings = self._scan(rule_engine, ast_layer, f)
        eval_findings = [fi for fi in findings if fi.rule_id == "AI-SEC-009"]
        assert len(eval_findings) == 0
