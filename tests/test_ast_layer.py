"""Tests for the AST parsing layer."""

from __future__ import annotations

from pathlib import Path


from aiscan.ast_layer import ASTLayer, LANGUAGE_MAP


class TestASTLayer:
    def test_parse_python_file(self, ast_layer: ASTLayer, vulnerable_dir: Path):
        parsed = ast_layer.parse_file(vulnerable_dir / "secrets_test.py")
        assert parsed is not None
        assert parsed.language == "python"
        assert len(parsed.lines) > 0
        assert parsed.tree is not None

    def test_unsupported_extension_returns_none(self, ast_layer: ASTLayer, tmp_path: Path):
        f = tmp_path / "test.xyz"
        f.write_text("hello")
        assert ast_layer.parse_file(f) is None

    def test_collect_files_from_directory(self, ast_layer: ASTLayer, vulnerable_dir: Path):
        files = ast_layer.collect_files(vulnerable_dir)
        assert len(files) > 0
        for f in files:
            assert f.suffix in LANGUAGE_MAP

    def test_collect_skips_pycache(self, ast_layer: ASTLayer, tmp_path: Path):
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "test.py").write_text("x = 1")
        (tmp_path / "real.py").write_text("x = 1")
        files = ast_layer.collect_files(tmp_path)
        assert all("__pycache__" not in str(f) for f in files)

    def test_collect_single_file(self, ast_layer: ASTLayer, vulnerable_dir: Path):
        target = vulnerable_dir / "secrets_test.py"
        files = ast_layer.collect_files(target)
        assert files == [target]

    def test_get_snippet(self, ast_layer: ASTLayer, vulnerable_dir: Path):
        parsed = ast_layer.parse_file(vulnerable_dir / "secrets_test.py")
        assert parsed is not None
        snippet = parsed.get_snippet(1, 3)
        assert isinstance(snippet, str)
        assert len(snippet) > 0
