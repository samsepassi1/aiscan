"""Tests for the LLM analysis engine."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aiscan.ast_layer import ParsedFile
from aiscan.llm_engine import LLMEngine
from aiscan.models import DetectionMethod, Finding, Severity


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parsed(tmp_path: Path, code: str, lang: str = "python") -> ParsedFile:
    f = tmp_path / "sample.py"
    f.write_text(code)
    mock_tree = MagicMock()
    lines = code.splitlines()
    return ParsedFile(
        path=f,
        language=lang,
        source=code.encode(),
        tree=mock_tree,
        lines=lines,
    )


def _engine(tmp_path: Path, provider: str = "anthropic") -> LLMEngine:
    return LLMEngine(provider=provider, model="test-model", cache_dir=str(tmp_path / "cache"))


def _finding(line: int = 1) -> Finding:
    return Finding(
        rule_id="AI-SEC-001",
        rule_name="Hardcoded Secret",
        severity=Severity.CRITICAL,
        file_path="sample.py",
        line_start=line,
        line_end=line,
        message="Hardcoded secret on this line.",
        cwe_ids=["CWE-259"],
        detection_method=DetectionMethod.AST,
        confidence=0.9,
        remediation="Use env var.",
    )


# ── _parse_response ───────────────────────────────────────────────────────────

class TestParseResponse:
    def test_valid_json_array(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        raw = json.dumps([{
            "rule_id": "AI-LLM-001",
            "rule_name": "Race condition",
            "severity": "HIGH",
            "line_start": 1,
            "line_end": 1,
            "message": "Possible TOCTOU.",
            "cwe_ids": ["CWE-367"],
            "confidence": 0.8,
            "remediation": "Use a lock.",
        }])
        findings = engine._parse_response(raw, pf)
        assert len(findings) == 1
        assert findings[0].rule_id == "AI-LLM-001"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].detection_method == DetectionMethod.LLM

    def test_markdown_fenced_json(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        raw = '```json\n[{"rule_id":"AI-LLM-001","rule_name":"X","severity":"LOW","line_start":1,"line_end":1,"message":"m","cwe_ids":[],"confidence":0.5,"remediation":"r"}]\n```'
        findings = engine._parse_response(raw, pf)
        assert len(findings) == 1

    def test_empty_array(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        assert engine._parse_response("[]", pf) == []

    def test_invalid_json_returns_empty(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        assert engine._parse_response("not json at all", pf) == []

    def test_missing_optional_fields_use_defaults(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        raw = json.dumps([{"line_start": 1}])
        findings = engine._parse_response(raw, pf)
        assert len(findings) == 1
        assert findings[0].rule_id == "AI-LLM-001"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].confidence == 0.7

    def test_line_numbers_clamped_to_positive(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        raw = json.dumps([{"line_start": -5, "line_end": -1}])
        findings = engine._parse_response(raw, pf)
        assert findings[0].line_start >= 1
        assert findings[0].line_end >= findings[0].line_start


# ── Caching ───────────────────────────────────────────────────────────────────

class TestCaching:
    def test_second_call_uses_cache(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "password = 'abc'\n")

        with patch.object(engine, "_call_llm", return_value="[]") as mock_call:
            engine.analyze(pf)
            engine.analyze(pf)
            assert mock_call.call_count == 1

    def test_different_context_bypasses_cache(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "password = 'abc'\n")

        with patch.object(engine, "_call_llm", return_value="[]") as mock_call:
            engine.analyze(pf)
            engine.analyze(pf, context_findings=[_finding(line=1)])
            assert mock_call.call_count == 2


# ── Context-aware prompt ──────────────────────────────────────────────────────

class TestContextFindings:
    def test_context_findings_appear_in_prompt(self, tmp_path: Path):
        engine = _engine(tmp_path)
        captured: list[str] = []

        def fake_call(source: str, language: str, context_findings=None) -> str:
            if context_findings:
                captured.append(
                    "\n".join(f"  - Line {f.line_start}: [{f.rule_id}] {f.message}"
                               for f in context_findings)
                )
            return "[]"

        with patch.object(engine, "_call_llm", side_effect=fake_call):
            engine.analyze(_parsed(tmp_path, "x=1\n"), context_findings=[_finding(1)])

        assert len(captured) == 1
        assert "AI-SEC-001" in captured[0]
        assert "Hardcoded secret" in captured[0]

    def test_no_context_sends_plain_prompt(self, tmp_path: Path):
        engine = _engine(tmp_path)

        def fake_call(source: str, language: str, context_findings=None) -> str:
            assert context_findings is None or len(context_findings) == 0
            return "[]"

        with patch.object(engine, "_call_llm", side_effect=fake_call):
            engine.analyze(_parsed(tmp_path, "x=1\n"))


# ── Provider wiring ───────────────────────────────────────────────────────────

class TestProviderWiring:
    def test_anthropic_client_created(self, tmp_path: Path):
        engine = _engine(tmp_path, provider="anthropic")
        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            engine._client = None
            client = engine._get_client()
            assert client is mock_client

    def test_openai_client_created(self, tmp_path: Path):
        engine = _engine(tmp_path, provider="openai")
        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            engine._client = None
            client = engine._get_client()
            assert client is mock_client

    def test_local_provider_sets_ollama_base_url(self, tmp_path: Path):
        engine = LLMEngine(provider="local", model="codellama", cache_dir=str(tmp_path / "cache"))
        mock_openai = MagicMock()
        mock_openai.OpenAI.return_value = MagicMock()

        with patch.dict("sys.modules", {"openai": mock_openai}):
            engine._client = None
            engine._get_client()
            call_kwargs = mock_openai.OpenAI.call_args[1]
            assert "localhost:11434" in call_kwargs["base_url"]

    def test_local_provider_rejects_api_key(self, tmp_path: Path):
        with pytest.raises(ValueError, match="zero-egress"):
            LLMEngine(
                provider="local",
                api_key="sk-secret",
                cache_dir=str(tmp_path / "cache"),
            )

    def test_unknown_provider_raises(self, tmp_path: Path):
        engine = LLMEngine(provider="unknown", cache_dir=str(tmp_path / "cache"))
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            engine._get_client()
