# Changelog

All notable changes to aiscan are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `//` and `/* */` suppression comment syntax for JavaScript/TypeScript
  (`// aiscan: suppress <reason>`). Previously only `# aiscan: suppress`
  worked, which meant JS/TS files could not suppress findings.
- `--exclude PATH` (repeatable) to skip subdirectories from scanning.
- Context-aware LLM analysis: the LLM tier now receives AST findings for
  the same file as context and is instructed to find *additional* issues
  rather than re-report what AST already caught. LLM runs are skipped on
  files with no AST findings.
- `LICENSE` file (MIT).
- `CHANGELOG.md`.

### Changed
- `AI-SEC-017` (Weak Content Security Policy) severity bumped from MEDIUM
  to HIGH. `'unsafe-inline'` in `script-src` effectively disables CSP's
  XSS protection; HIGH matches CodeQL and industry consensus.
- `AI-SEC-011` (Path Traversal) Python patterns now require taint markers
  (`request`, `args`, `query`, `body`, etc.) on the same line OR via a
  proximity check for `open('/path/' + var)` where `var` was assigned
  from a taint source. Previously the Python patterns fired on any
  `open(os.path.join(...))` regardless of whether args were user-controlled.
- Aggregator `merge()` only marks a finding as `HYBRID` when the two
  deduplicated findings came from different detection tiers (AST vs LLM).
  Previously, duplicate findings from the same tier were incorrectly
  marked `HYBRID`.
- LLM engine `max_tokens` raised from 4096 to 8192 to prevent mid-JSON
  truncation on complex files.
- LLM engine now gates OpenAI JSON-mode on `provider == "openai"` instead
  of substring `"gpt" in model` — prevents Ollama models with "gpt" in
  their alias from being sent an unsupported `response_format` parameter.
- LLM engine emits a warning when a file exceeds `max_lines` (default
  500) and is truncated for analysis.
- LLM engine `_parse_response` narrows exception handling, warns on
  malformed responses, and handles `None` content from OpenAI/Anthropic
  gracefully (previously silent `[]`).

### Fixed
- LLM engine Anthropic response handling iterates content blocks to find
  the first `text` block; previously assumed `response.content[0].text`
  which broke on `tool_use`-first or empty-content responses.
- LLM engine OpenAI `message.content` can legitimately be `None`
  (filtered/refused); engine now returns `""` instead of crashing.
- `AI-SEC-001` (Hardcoded Secrets) `_manual_check` regex accepts trailing
  inline comments (e.g. `api_key = '...'  # aiscan: suppress`). Previously
  the `\s*$` anchor rejected such lines, causing suppressed secrets to be
  silently missed on Python 3.11+ Linux where the tree-sitter path fell
  back to `_manual_check`.
- Scanner `--exclude` support wired through `action.yml` for CI self-scan
  to skip `src/aiscan/rules` (regex pattern strings in rule files were
  triggering the very rules they define).
- `SEC-002` (Missing Authorization) context window is capped at the next
  route declaration, preventing auth markers from one handler from
  suppressing findings on an adjacent unprotected handler.

## [0.1.0] — Initial release

Initial rule set:

- `AI-SEC-001` Hardcoded Secrets (Python)
- `AI-SEC-002` Missing Authorization (Python + JavaScript/TypeScript)
- `AI-SEC-003` Weak Cryptographic Algorithm (Python)
- `AI-SEC-004` Insecure Random in Security Context (Python)
- `AI-SEC-008` Unsafe Deserialization (Python)
- `AI-SEC-009` Dynamic Code Execution (Python + JavaScript/TypeScript)
- `AI-SEC-011` Path Traversal (Python + JavaScript/TypeScript)
- `AI-SEC-012` Permissive CORS (JavaScript/TypeScript)
- `AI-SEC-013` SSR State Hydration Injection (JavaScript/TypeScript)
- `AI-SEC-014` Dangerous Inner HTML (JavaScript/TypeScript)
- `AI-SEC-015` SSRF in Server-Side Fetch (JavaScript/TypeScript)
- `AI-SEC-016` Insecure Cookie Flags (JavaScript/TypeScript)
- `AI-SEC-017` Weak Content Security Policy (JavaScript/TypeScript)

Other features: SARIF 2.1.0, JSON, and Rich terminal output; LLM analysis
tier (Anthropic/OpenAI/Ollama); disk-cached LLM responses; inline
suppression; `--diff-only` for pre-commit hooks; GitHub Action.
