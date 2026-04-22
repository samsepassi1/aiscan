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
        with pytest.warns(UserWarning, match="no JSON array"):
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

    def test_none_input_returns_empty(self, tmp_path: Path):
        """Handle empty content from OpenAI/Anthropic gracefully (now warns)."""
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        with pytest.warns(UserWarning, match="empty response"):
            assert engine._parse_response("", pf) == []

    def test_non_array_json_returns_empty(self, tmp_path: Path):
        """Top-level JSON object (not array) should not crash, and MUST warn."""
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        with pytest.warns(UserWarning, match="not a list"):
            assert engine._parse_response('{"rule_id": "X"}', pf) == []

    def test_empty_raw_warns_and_returns_empty(self, tmp_path: Path):
        """Empty LLM response now emits a warning so failures are visible."""
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        with pytest.warns(UserWarning, match="empty response"):
            assert engine._parse_response("", pf) == []

    def test_bad_severity_skipped_not_crashed(self, tmp_path: Path):
        """One malformed item should not abort the whole response."""
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\n")
        raw = json.dumps([
            {"rule_id": "AI-LLM-001", "severity": "NONSENSE", "line_start": 1},
            {"rule_id": "AI-LLM-002", "severity": "HIGH", "line_start": 1},
        ])
        with pytest.warns(UserWarning, match="malformed LLM finding"):
            findings = engine._parse_response(raw, pf)
        assert len(findings) == 1
        assert findings[0].rule_id == "AI-LLM-002"


# ── Truncation warning ────────────────────────────────────────────────────────

class TestTruncationWarning:
    def test_warns_when_file_exceeds_max_lines(self, tmp_path: Path):
        engine = _engine(tmp_path)
        big = "\n".join(f"x{i} = {i}" for i in range(600))
        pf = _parsed(tmp_path, big)
        with patch.object(engine, "_call_llm", return_value="[]"):
            with pytest.warns(UserWarning, match="first 500"):
                engine.analyze(pf, max_lines=500)

    def test_no_warning_for_small_files(self, tmp_path: Path):
        engine = _engine(tmp_path)
        pf = _parsed(tmp_path, "x = 1\ny = 2\n")
        with patch.object(engine, "_call_llm", return_value="[]"):
            import warnings as w
            with w.catch_warnings(record=True) as recorded:
                w.simplefilter("always")
                engine.analyze(pf, max_lines=500)
            truncation_warnings = [x for x in recorded if "first 500" in str(x.message)]
            assert truncation_warnings == []


# ── Anthropic response handling ───────────────────────────────────────────────

class TestAnthropicResponseBlocks:
    def test_iterates_past_non_text_blocks(self, tmp_path: Path):
        """First block may be tool_use or thinking; skip to first text block."""
        engine = _engine(tmp_path, provider="anthropic")
        fake_response = MagicMock()
        tool_block = MagicMock()
        tool_block.type = "tool_use"
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "[]"
        fake_response.content = [tool_block, text_block]

        engine._client = MagicMock()
        engine._client.messages.create.return_value = fake_response
        result = engine._call_llm("code", "python")
        assert result == "[]"

    def test_empty_content_returns_empty_string(self, tmp_path: Path):
        engine = _engine(tmp_path, provider="anthropic")
        fake_response = MagicMock()
        fake_response.content = []
        engine._client = MagicMock()
        engine._client.messages.create.return_value = fake_response
        result = engine._call_llm("code", "python")
        assert result == ""


# ── OpenAI JSON mode gated by provider ────────────────────────────────────────

class TestOpenAIJsonMode:
    def test_json_mode_enabled_for_openai(self, tmp_path: Path):
        engine = _engine(tmp_path, provider="openai")
        fake_response = MagicMock()
        fake_response.choices = [MagicMock()]
        fake_response.choices[0].message.content = "[]"
        engine._client = MagicMock()
        engine._client.chat.completions.create.return_value = fake_response
        engine._call_llm("code", "python")
        kwargs = engine._client.chat.completions.create.call_args[1]
        assert kwargs.get("response_format") == {"type": "json_object"}

    def test_json_mode_not_sent_to_local(self, tmp_path: Path):
        """Ollama doesn't understand response_format — don't send it for local."""
        engine = LLMEngine(provider="local", model="gpt-oss-custom", cache_dir=str(tmp_path / "cache"))
        fake_response = MagicMock()
        fake_response.choices = [MagicMock()]
        fake_response.choices[0].message.content = "[]"
        engine._client = MagicMock()
        engine._client.chat.completions.create.return_value = fake_response
        engine._call_llm("code", "python")
        kwargs = engine._client.chat.completions.create.call_args[1]
        assert "response_format" not in kwargs

    def test_openai_none_content_handled(self, tmp_path: Path):
        """Filtered responses can return content=None; engine must return ''."""
        engine = _engine(tmp_path, provider="openai")
        fake_response = MagicMock()
        fake_response.choices = [MagicMock()]
        fake_response.choices[0].message.content = None
        engine._client = MagicMock()
        engine._client.chat.completions.create.return_value = fake_response
        result = engine._call_llm("code", "python")
        assert result == ""

    def test_openai_empty_choices_handled(self, tmp_path: Path):
        """Some providers return response.choices=[] under filtering/errors."""
        engine = _engine(tmp_path, provider="openai")
        fake_response = MagicMock()
        fake_response.choices = []
        engine._client = MagicMock()
        engine._client.chat.completions.create.return_value = fake_response
        result = engine._call_llm("code", "python")
        assert result == ""


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
