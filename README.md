# aiscan — AI Code Security Scanner

**Author:** Sam Sepassi, Staff AppSec Engineer, Walmart Global Tech

A hybrid AST + LLM security scanner purpose-built for the vulnerability patterns that AI coding assistants (GitHub Copilot, Cursor, ChatGPT, Claude) are statistically known to introduce.

## Why aiscan?

Research shows AI-generated code has:
- **322% higher rate** of missing authorization checks (CWE-639)
- **88% failure rate** on log injection / output neutralization (CWE-117)
- **86% failure rate** on XSS / improper output encoding (CWE-79)
- High prevalence of hardcoded secrets, weak crypto, and unsafe deserialization

Traditional SAST tools are not tuned for these patterns. aiscan is.

## Installation

```bash
pip install aiscan
```

## Quick Start

```bash
# Scan current directory (AST rules only)
aiscan scan .

# Scan with LLM analysis tier (Anthropic)
export ANTHROPIC_API_KEY="your-key"
aiscan scan . --llm

# Scan with OpenAI
export OPENAI_API_KEY="your-key"
aiscan scan . --llm --llm-provider openai --llm-model gpt-4o

# Zero-egress mode with local Ollama
aiscan scan . --llm --llm-provider local --llm-model codellama

# Enterprise Ollama endpoint
aiscan scan . --llm --llm-provider local \
  --llm-base-url http://internal-ollama.walmart.net:11434/v1 \
  --llm-model codellama

# Output SARIF for GitHub Security tab
aiscan scan . --format sarif --output results.sarif

# Exit code 1 if HIGH+ findings (CI/CD use)
aiscan scan . --severity HIGH --exit-code

# Scan only git-changed files (pre-commit hook)
aiscan scan . --diff-only --exit-code
```

## Inline Suppression

Add `# aiscan: suppress` to a line to suppress all findings on that line:

```python
API_KEY = os.environ["API_KEY"]  # aiscan: suppress not a real secret
```

## Detection Rules

| Rule ID | Name | Severity | CWE |
|---------|------|----------|-----|
| AI-SEC-001 | Hardcoded Secret | CRITICAL | CWE-259, CWE-321, CWE-798 |
| AI-SEC-003 | Weak Cryptographic Algorithm | HIGH | CWE-327, CWE-328 |
| AI-SEC-004 | Insecure Random Number Generator | HIGH | CWE-330, CWE-338 |
| AI-SEC-008 | Unsafe Deserialization | CRITICAL | CWE-502 |
| AI-SEC-009 | Dynamic Code Execution | CRITICAL | CWE-78, CWE-94 |
| AI-SEC-011 | Path Traversal | HIGH | CWE-22 |
| AI-SEC-012 | Permissive CORS | HIGH | CWE-942 |

List all rules:

```bash
aiscan rules
```

## GitHub Actions

```yaml
- uses: walmartlabs/aiscan@v1
  with:
    target: "src/"
    severity: "HIGH"
    llm: "false"
```

## VS Code Extension

Install the extension, then findings appear inline in the Problems panel. Supports:
- Scan on save (automatic)
- `aiscan: Scan Current File` command
- `aiscan: Scan Workspace` command
- Quick Fix: View remediation
- Quick Fix: Suppress finding (inserts `# aiscan: suppress`)

## LLM Providers

| Provider | Flag | Notes |
|----------|------|-------|
| Anthropic (default) | `--llm-provider anthropic` | Requires `ANTHROPIC_API_KEY` |
| OpenAI | `--llm-provider openai` | Requires `OPENAI_API_KEY` |
| Ollama (local) | `--llm-provider local` | Zero-egress; no external API calls |

## Development

```bash
git clone https://github.com/walmartlabs/aiscan
cd aiscan
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT. Copyright © 2024 Walmart Global Tech.
