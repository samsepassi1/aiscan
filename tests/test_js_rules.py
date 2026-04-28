"""Tests for JavaScript/TypeScript detection rules."""

from __future__ import annotations

from pathlib import Path


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

    def test_path_traversal_no_false_positive_on_benign_join(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        """open(os.path.join(INTERNAL_DIR, filename)) with no taint source must not fire."""
        f = tmp_path / "benign.py"
        f.write_text(
            "import os\n"
            "CACHE_DIR = '/var/cache/app'\n"
            "def read_cached(filename):\n"
            "    with open(os.path.join(CACHE_DIR, filename)) as fh:\n"
            "        return fh.read()\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        pt = [fi for fi in findings if fi.rule_id == "AI-SEC-011"]
        assert pt == [], f"False positive on benign path join: {pt}"

    def test_eval_literal_string_no_finding(self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path):
        f = tmp_path / "safe.js"
        f.write_text("const x = eval('1 + 1');\n")
        findings = self._scan(rule_engine, ast_layer, f)
        eval_findings = [fi for fi in findings if fi.rule_id == "AI-SEC-009"]
        assert len(eval_findings) == 0

    # --- AI-SEC-013: SSR State Hydration Injection -----------------------------

    def test_detects_ssr_state_injection(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "ssr_state_test.js")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-013" in rule_ids

    def test_ssr_state_injection_severity_critical(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "ssr_state_test.js")
        ssr_findings = [f for f in findings if f.rule_id == "AI-SEC-013"]
        assert all(f.severity == Severity.CRITICAL for f in ssr_findings)
        assert len(ssr_findings) >= 2  # fixture has multiple unsafe patterns

    def test_ssr_state_safe_serializer_lowers_confidence(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "serialized.js"
        f.write_text(
            "const serialize = require('serialize-javascript');\n"
            "const html = `<script>window.__INITIAL_STATE__ "
            "= ${JSON.stringify(state)};</script>`;\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        ssr_findings = [fi for fi in findings if fi.rule_id == "AI-SEC-013"]
        assert len(ssr_findings) == 1
        assert ssr_findings[0].confidence < 0.9  # still reported, but downgraded

    # --- AI-SEC-014: Dangerous Inner HTML --------------------------------------

    def test_detects_dangerous_inner_html(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "dangerous_html_test.js")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-014" in rule_ids

    def test_dangerous_inner_html_sanitizer_lowers_confidence(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "with_sanitizer.js"
        f.write_text(
            "import DOMPurify from 'isomorphic-dompurify';\n"
            "export const Bio = ({ v }) => "
            "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(v) }} />;\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        html_findings = [fi for fi in findings if fi.rule_id == "AI-SEC-014"]
        assert len(html_findings) == 1
        assert html_findings[0].confidence < 0.7

    # --- AI-SEC-015: SSRF in Server-Side Fetch ---------------------------------

    def test_detects_ssrf_in_server_fetch(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "ssrf_test.js")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-015" in rule_ids

    def test_ssrf_static_url_not_flagged(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "static_fetch.js"
        f.write_text(
            "async function ping() {\n"
            "  const r = await fetch('https://api.internal/health');\n"
            "  return r.json();\n"
            "}\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        ssrf_findings = [fi for fi in findings if fi.rule_id == "AI-SEC-015"]
        assert len(ssrf_findings) == 0

    def test_ssrf_multiline_call_with_taint_below(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        """Regression: the multiline-window slice was off-by-one and missed
        taint on the line(s) immediately below an HTTP call."""
        f = tmp_path / "multiline_ssrf.js"
        f.write_text(
            "async function proxy(req, res) {\n"
            "  const r = await axios.post(\n"
            "    req.body.callback_url,\n"
            "    { ok: true }\n"
            "  );\n"
            "  res.json(r.data);\n"
            "}\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        ssrf = [fi for fi in findings if fi.rule_id == "AI-SEC-015"]
        assert len(ssrf) >= 1, "multiline SSRF call should still be flagged"

    # --- AI-SEC-016: Insecure Cookie Flags -------------------------------------

    def test_detects_insecure_cookie(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "cookie_test.js")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-016" in rule_ids

    def test_safe_cookie_not_flagged(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "safe_cookie.js"
        f.write_text(
            "app.post('/login', (req, res) => {\n"
            "  res.cookie('session', token, {\n"
            "    httpOnly: true,\n"
            "    secure: true,\n"
            "    sameSite: 'lax',\n"
            "  });\n"
            "  res.sendStatus(200);\n"
            "});\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        cookie_findings = [fi for fi in findings if fi.rule_id == "AI-SEC-016"]
        assert len(cookie_findings) == 0

    # --- AI-SEC-017: Weak CSP --------------------------------------------------

    def test_detects_weak_csp(self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "csp_test.js")
        rule_ids = [f.rule_id for f in findings]
        assert "AI-SEC-017" in rule_ids

    def test_strict_csp_not_flagged(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "strict_csp.js"
        f.write_text(
            "res.setHeader('Content-Security-Policy',\n"
            "  `default-src 'self'; script-src 'self' 'nonce-${nonce}'; "
            "object-src 'none'; base-uri 'self'`);\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        csp_findings = [fi for fi in findings if fi.rule_id == "AI-SEC-017"]
        assert len(csp_findings) == 0

    # ── AI-SEC-002: Missing Authorization (JavaScript) ────────────────────────

    def test_detects_missing_auth_express_admin(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "authorization_test.js")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        assert len(sec002) >= 3, f"Expected >=3 AI-SEC-002 findings, got {len(sec002)}: {sec002}"

    def test_missing_auth_js_admin_is_critical(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "authorization_test.js")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        admin_findings = [f for f in sec002 if "/admin" in f.code_snippet]
        assert len(admin_findings) >= 1
        assert all(f.severity == Severity.CRITICAL for f in admin_findings)

    def test_no_false_positive_auth_safe_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, safe_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, safe_dir / "authorization_safe.js")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        assert len(sec002) == 0, f"False positives in authorization_safe.js: {sec002}"

    def test_inline_middleware_arg_not_flagged_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "mw_safe.js"
        f.write_text(
            "app.delete('/api/user/:id', requireAuth, async (req, res) => {\n"
            "  await User.findByIdAndDelete(req.params.id);\n"
            "  res.json({ deleted: req.params.id });\n"
            "});\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 0, f"Middleware-guarded route falsely flagged: {sec002}"

    def test_manual_req_user_check_not_flagged_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "manual_check.js"
        f.write_text(
            "app.delete('/api/posts/:id', async (req, res) => {\n"
            "  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });\n"
            "  res.json({ ok: true });\n"
            "});\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 0, f"Manual-check route falsely flagged: {sec002}"

    def test_public_get_not_flagged_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "public.js"
        f.write_text(
            "app.get('/api/public/articles', (req, res) => {\n"
            "  res.json([]);\n"
            "});\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 0, f"Public route falsely flagged: {sec002}"

    def test_delete_route_without_auth_is_critical_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "vuln_delete.js"
        f.write_text(
            "router.delete('/api/user/:id', async (req, res) => {\n"
            "  await User.findByIdAndDelete(req.params.id);\n"
            "  res.json({ deleted: req.params.id });\n"
            "});\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 1
        assert sec002[0].severity == Severity.CRITICAL

    def test_missing_auth_js_cwe_ids(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "authorization_test.js")
        sec002 = [f for f in findings if f.rule_id == "AI-SEC-002"]
        assert len(sec002) > 0
        for f in sec002:
            assert "CWE-862" in f.cwe_ids
            assert "CWE-306" in f.cwe_ids

    def test_auth_lib_import_reduces_confidence_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "auth_import.js"
        f.write_text(
            "const jwt = require('jsonwebtoken');\n"
            "\n"
            "app.delete('/api/user/:id', async (req, res) => {\n"
            "  await User.findByIdAndDelete(req.params.id);\n"
            "  res.json({ deleted: req.params.id });\n"
            "});\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 1
        assert sec002[0].confidence < 0.80
        assert "Auth library" in sec002[0].message

    def test_detects_prompt_injection_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, vulnerable_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, vulnerable_dir / "prompt_injection_test.js")
        sec018 = [f for f in findings if f.rule_id == "AI-SEC-018"]
        # Template literal, concatenation, and OpenAI system-role entry.
        assert len(sec018) >= 3, f"expected 3+ AI-SEC-018 findings, got {len(sec018)}"
        for f in sec018:
            assert f.severity == Severity.HIGH
            assert "CWE-94" in f.cwe_ids

    def test_no_false_positives_prompt_injection_safe_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, safe_dir: Path
    ):
        findings = self._scan(rule_engine, ast_layer, safe_dir / "prompt_injection_safe.js")
        sec018 = [f for f in findings if f.rule_id == "AI-SEC-018"]
        assert len(sec018) == 0, f"False positive in prompt_injection_safe.js: {sec018}"

    def test_req_session_non_auth_not_suppressed_js(
        self, rule_engine: RuleEngine, ast_layer: ASTLayer, tmp_path: Path
    ):
        f = tmp_path / "session_cart.js"
        f.write_text(
            "app.post('/api/orders', async (req, res) => {\n"
            "  const cart = req.session.cart;\n"
            "  const order = await Order.create({ items: cart });\n"
            "  res.json(order);\n"
            "});\n"
        )
        findings = self._scan(rule_engine, ast_layer, f)
        sec002 = [fi for fi in findings if fi.rule_id == "AI-SEC-002"]
        assert len(sec002) == 1, "Non-auth session access must not suppress the finding"
