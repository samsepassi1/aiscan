# aiscan — AI Code Security Scanner

**Author:** Sam Sepassi

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

# Self-hosted Ollama endpoint
aiscan scan . --llm --llm-provider local \
  --llm-base-url http://localhost:11434/v1 \
  --llm-model codellama

# Output SARIF for GitHub Security tab
aiscan scan . --format sarif --output results.sarif

# Exit code 1 if HIGH+ findings (CI/CD use)
aiscan scan . --severity HIGH --exit-code

# Scan only git-changed files (pre-commit hook)
aiscan scan . --diff-only --exit-code
```

## Inline Suppression

Add an `aiscan: suppress` comment to a line to suppress all findings on
that line. The comment syntax matches the file's language:

```python
# Python
API_KEY = os.environ["API_KEY"]  # aiscan: suppress not a real secret
```

```javascript
// JavaScript / TypeScript
const token = process.env.TOKEN; // aiscan: suppress already env-sourced

/* C-style block comments also work */
const key = process.env.KEY; /* aiscan: suppress */
```

An optional reason after `suppress` is recorded in the finding's
`suppression_reason` and surfaced in SARIF and JSON output.

## Detection Rules

| Rule ID | Name | Severity | CWE |
|---------|------|----------|-----|
| AI-SEC-001 | Hardcoded Secret | CRITICAL | CWE-259, CWE-321, CWE-798 |
| AI-SEC-002 | Missing Authorization Check | CRITICAL | CWE-862, CWE-306 |
| AI-SEC-003 | Weak Cryptographic Algorithm | HIGH | CWE-327, CWE-328 |
| AI-SEC-004 | Insecure Random Number Generator | HIGH | CWE-330, CWE-338 |
| AI-SEC-008 | Unsafe Deserialization | CRITICAL | CWE-502 |
| AI-SEC-009 | Dynamic Code Execution | CRITICAL | CWE-78, CWE-94 |
| AI-SEC-011 | Path Traversal | HIGH | CWE-22 |
| AI-SEC-012 | Permissive CORS | HIGH | CWE-942 |
| AI-SEC-013 | SSR State Hydration Injection | CRITICAL | CWE-79, CWE-116 |
| AI-SEC-014 | Dangerous Inner HTML | HIGH | CWE-79, CWE-80 |
| AI-SEC-015 | SSRF in Server-Side Fetch | HIGH | CWE-918 |
| AI-SEC-016 | Insecure Cookie Flags | HIGH | CWE-614, CWE-1004, CWE-1275 |
| AI-SEC-017 | Weak Content Security Policy | HIGH | CWE-693, CWE-1021 |

### SSR / Electrode Coverage

Rules **AI-SEC-013 through AI-SEC-017** target vulnerability patterns common
in Server-Side-Rendering codebases (Electrode, Next.js, custom Node/React SSR)
that AI coding assistants routinely introduce:

- **AI-SEC-013** catches the single most dangerous SSR-specific XSS: using
  `JSON.stringify` to inline state into a `<script>` tag. Fix: `serialize-javascript`.
- **AI-SEC-014** catches `dangerouslySetInnerHTML` without a sanitizer like DOMPurify.
- **AI-SEC-015** catches SSRF via `fetch`/`axios`/`got` calls whose URL is built
  from `req.query`/`req.params`/`req.body`.
- **AI-SEC-016** catches Express/Fastify/Hapi cookie calls missing `httpOnly`,
  `secure`, or `sameSite`, and explicit `httpOnly: false`.
- **AI-SEC-017** catches `'unsafe-inline'`/`'unsafe-eval'` in Content Security Policy.

All five rules run on `.js`, `.jsx`, `.ts`, and `.tsx` files.

List all rules:

```bash
aiscan rules
```

## GitHub Actions

```yaml
- uses: samsepassi1/aiscan@v1
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
git clone https://github.com/samsepassi1/aiscan
cd aiscan
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT. Copyright © 2025 Sam Sepassi.
