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

The `aiscan` name on PyPI is taken by an unrelated project, so install
from this repository directly:

```bash
pip install git+https://github.com/samsepassi1/aiscan@v0.2.2
```

Or pin a specific commit / branch by replacing `@v0.2.2`. Local
development install:

```bash
git clone https://github.com/samsepassi1/aiscan && cd aiscan
pip install -e ".[dev]"
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

# LLM reviews every file, not just those with AST findings (deeper, costlier)
aiscan scan . --llm --llm-scan-all

# Configure LLM request timeout and per-file line budget
aiscan scan . --llm --llm-timeout 90 --llm-max-lines 800

# Override the LLM response cache location (default: platform user cache dir)
aiscan scan . --llm --cache-dir ./.aiscan_cache
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

Suppression is **language-aware**: `#` is recognized only in Python, and
`//`/`/* */` are recognized in JavaScript, TypeScript, Go, and Java. A
`//` in a Python file is integer division, not a comment, and will not
suppress anything — and the same applies to `#` in a JS/TS file.

## Path-level Exclusion

Drop a `.aiscanignore` file at the scan target root to exclude paths
declaratively (the same prefix semantics as `--exclude`, one entry per
line). Lines starting with `#` are comments.

```
# .aiscanignore
tests/fixtures
vendor
generated
```

Entries from `.aiscanignore` and any `--exclude` flags are merged.

## Metrics — AI vs. human defect rates

`aiscan metrics` runs a scan, uses `git blame` to map each finding to the
commit that last touched it, and classifies that commit as AI-generated
or human based on `Co-Authored-By` trailers, commit-message markers
(e.g. `Generated with [Claude Code]`), and author email domains. Findings
are aggregated into `ai` / `human` / `unknown` buckets with severity and
rule breakdowns.

```bash
# Terminal report on the whole repo
aiscan metrics . --severity HIGH

# JSON output for dashboards / CI
aiscan metrics . --format json --output metrics.json

# Only attribute findings in currently-changed files
aiscan metrics . --diff-only
```

Recognized AI agents: Claude, Copilot, Cursor, ChatGPT, Gemini, Devin,
aider. The LLM tier is disabled for `metrics` so it's free to run in CI.
Suppressed findings are excluded from buckets. Lines that are uncommitted
(staged or modified) are attributed to `unknown` with reason `uncommitted`.

Sample output:

```
                           Findings by origin
╭────────────┬────────┬────────┬───────┬───────┬───────┬───────┬───────╮
│ Origin     │  Count │      % │  Crit │  High │  Medi │   Low │  Info │
├────────────┼────────┼────────┼───────┼───────┼───────┼───────┼───────┤
│ AI         │     30 │    60% │    18 │    12 │     0 │     0 │     0 │
│ HUMAN      │     20 │    40% │     7 │    13 │     0 │     0 │     0 │
│ UNKNOWN    │      0 │     0% │     0 │     0 │     0 │     0 │     0 │
╰────────────┴────────┴────────┴───────┴───────┴───────┴───────┴───────╯
```

### Detection coverage and what it means for your repo

Attribution fires only when a commit carries an AI marker that aiscan
can recognize: a `Co-Authored-By:` trailer naming a known agent, a body
marker like `Generated with [Claude Code]`, or an author email matching
an AI vendor domain (e.g. `noreply@anthropic.com`,
`@copilot.github.com`, `@cursor.sh`). What that means in practice:

- **Claude Code** adds `Co-Authored-By: Claude` to commits automatically
  and works out of the box.
- **GitHub Copilot, Cursor, ChatGPT, aider, and most other tools** do
  *not* tag commits by default. On a repo where the team uses these
  without trailers, AI-authored code will mostly land in the `human`
  bucket because there's no signal to distinguish it.

If you want meaningful coverage on a repo where AI tools aren't already
tagging commits, the simplest fix is a one-line shared commit template
or git hook that appends a `Co-Authored-By:` trailer when AI was used.
Once your team adopts that, `aiscan metrics` becomes a real trend line
of human vs. AI defect rates over time.

Heuristic detection without explicit markers (commit-message linguistic
patterns, PR-author analysis, etc.) is on the roadmap but not in v0.2.2
— that approach trades higher coverage for higher false-positive rates,
so the v1 implementation prefers the high-precision marker-based path.

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
| AI-SEC-018 | Prompt Injection via Untrusted Input | HIGH | CWE-20, CWE-94, CWE-77 |

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
- uses: samsepassi1/aiscan@v0.2.2
  with:
    target: "src/"
    severity: "HIGH"
    llm: "false"
```

To enable the LLM tier, expose your provider key at the job or step
level — the action reads `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` from
the workflow environment, so the secret must be wired explicitly:

```yaml
- uses: samsepassi1/aiscan@v0.2.2
  with:
    target: "src/"
    severity: "HIGH"
    llm: "true"
    llm-provider: "anthropic"
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    # OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}   # for --llm-provider openai
```

## Pre-commit

Add aiscan to any repo as a [pre-commit](https://pre-commit.com/) hook —
one entry in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/samsepassi1/aiscan
    rev: v0.2.1   # or any tagged release
    hooks:
      - id: aiscan
```

By default the hook runs `aiscan scan --diff-only --severity HIGH --exit-code`,
blocking commits that introduce new HIGH+ findings in changed files.
Override any argument via pre-commit's standard `args:` override:

```yaml
hooks:
  - id: aiscan
    args: ['--diff-only', '--severity', 'CRITICAL', '--exit-code']
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

MIT. Copyright © 2026 Sam Sepassi.
