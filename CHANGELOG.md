# Changelog

All notable changes to aiscan are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `AI-SEC-018` Prompt Injection via Untrusted Input (Python +
  JavaScript/TypeScript). Detects HTTP request data interpolated into LLM
  system prompts via the Anthropic and OpenAI SDKs — f-string / template-
  literal interpolation, `+` concatenation, and `.format()` injection into
  `system=`, `system_prompt=`, `instructions=`, or an OpenAI messages-
  array entry with `{"role": "system", ...}`. Taint sources include
  `request.args`/`request.json`/`request.form` (Flask/Django),
  `req.body`/`req.params`/`req.query` (Express/Fastify/Koa/Hono), and
  common `userInput`/`userQuery` names. HIGH severity; CWE-20, CWE-94,
  CWE-77. Fires only when the taint interpolation is within a ±3-line
  window of a system-prompt indicator, so user-role messages with request
  data are not flagged.
- `aiscan metrics` subcommand: runs a scan, then uses `git blame` to map
  each finding to the commit that last touched its line and classifies
  that commit as AI-generated or human via `Co-Authored-By` trailers,
  commit-message markers (`Generated with [Claude Code]`, robot-emoji
  generation markers, Cursor/Copilot attribution lines), and author
  email domains. Aggregates findings into `ai`/`human`/`unknown` buckets
  with severity and per-rule breakdowns. Terminal (Rich) and JSON
  output. Recognizes Claude, Copilot, Cursor, ChatGPT, Gemini, Devin,
  and aider. LLM tier is disabled for this command so it runs free in
  CI. Suppressed findings are excluded from buckets; uncommitted lines
  are attributed to `unknown` with reason `uncommitted`.
- `//` and `/* */` suppression comment syntax for JavaScript/TypeScript
  (`// aiscan: suppress <reason>`). Previously only `# aiscan: suppress`
  worked, which meant JS/TS files could not suppress findings.
- Language-aware suppression comments: `#` is now recognized only in
  Python; `//`/`/* */` are recognized only in JS/TS/Go/Java. A `//` in a
  Python file (integer division, not a comment) no longer suppresses
  findings; a `#` in a JS/TS file (typically inside a string literal)
  no longer suppresses findings.
- `--llm-scan-all` flag: run LLM analysis on every file, not just those
  with AST findings. Higher coverage, higher cost. Useful for small
  repos or exploratory review.
- `--llm-max-lines N` flag: configure the per-file line budget sent to
  the LLM (default 500). Larger files are truncated and a warning is
  emitted.
- `--llm-timeout SECONDS` flag: per-request timeout for LLM calls
  (default 60s). Prevents hung requests from blocking a scan forever.
  Passed through to both the Anthropic and OpenAI SDK clients.
- `--cache-dir PATH` flag: override the LLM response cache location.
  Default is now a platform-appropriate user cache dir (via
  `platformdirs.user_cache_dir("aiscan")`) — `~/Library/Caches/aiscan`
  on macOS, `~/.cache/aiscan` on Linux, `%LOCALAPPDATA%\aiscan\Cache`
  on Windows. Previously defaulted to `.aiscan_cache/` in the current
  working directory, which littered user repos.
- `--exclude PATH` (repeatable) to skip subdirectories from scanning.
- Context-aware LLM analysis: the LLM tier now receives AST findings for
  the same file as context and is instructed to find *additional* issues
  rather than re-report what AST already caught. LLM runs are skipped on
  files with no AST findings unless `--llm-scan-all` is set.
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
- LLM engine now warns on empty responses and on top-level JSON that is
  not a list, rather than silently returning `[]`. Makes diagnosing
  flaky providers much easier.
- Migrated `AI-SEC-001` from deprecated `lang.query()` to `Query(lang,
  src)` constructor. Eliminates the `DeprecationWarning: query() is
  deprecated. Use the Query() constructor instead.` on every scan.
- `Scanner._get_diff_files` handles fresh repos (no HEAD commit yet)
  gracefully instead of falling back to a full scan with a confusing
  warning.
- `ast_layer.py` is properly typed via `TYPE_CHECKING: from tree_sitter
  import Tree, Node, Parser`. Removed redundant
  `# type: ignore[attr-defined]` comments from `ParsedFile.get_node_text`,
  `ASTLayer._get_parser`, `ASTLayer.parse_file`, and the capture-pair
  handling in `AI-SEC-001`.

### Dependencies
- Added `platformdirs>=4.0` for platform-appropriate user cache
  directory resolution.
- Excluded `tree-sitter-language-pack==1.6.3` via `!=1.6.3` constraint.
  This release publishes a wheel that installs dist-info metadata but
  omits the `tree_sitter_language_pack/` module directory, so `pip show`
  reports "installed" while `import tree_sitter_language_pack` raises
  `ModuleNotFoundError`. Affected Python 3.12 in CI (3.11's resolver
  picked 1.6.2 which is fine).

### Fixed
- `AI-SEC-004` (Insecure Random) false positive when safe `secrets.*` calls
  appeared on lines preceding unrelated `random.*` calls. The security-
  context heuristic now filters out lines that themselves call `secrets.*`
  before looking for security-context keywords, so the safe `secrets`
  API doesn't pull its own variable names (`token`, `session_key`, `otp`)
  into the context window of a nearby `random.randint(1, 6)` etc.
- VS Code extension default LLM model aligned with the CLI / GitHub
  Action default (`claude-sonnet-4-6`). Was previously `claude-sonnet-4-5`
  in both `package.json` and the language server default, which drifted
  from the rest of the toolchain.
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
