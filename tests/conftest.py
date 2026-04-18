"""pytest configuration and shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

# Absolute path to the fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_DIR = FIXTURES_DIR / "vulnerable"
SAFE_DIR = FIXTURES_DIR / "safe"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def vulnerable_dir() -> Path:
    return VULNERABLE_DIR


@pytest.fixture
def safe_dir() -> Path:
    return SAFE_DIR


@pytest.fixture
def ast_layer():
    from aiscan.ast_layer import ASTLayer
    return ASTLayer()


@pytest.fixture
def rule_engine():
    from aiscan.rule_engine import RuleEngine
    return RuleEngine()
