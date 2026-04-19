// aiscan test fixture — should trigger AI-SEC-015 (SSRF in Server-Side Fetch)
// DO NOT USE IN PRODUCTION

const express = require('express');
const axios = require('axios');
const app = express();

// Unsafe: attacker controls the URL path segment.
app.get('/proxy', async (req, res) => {
  const data = await fetch(`https://api.internal/${req.query.resource}`);
  res.json(await data.json());
});

// Unsafe: attacker controls the full URL.
app.get('/proxy2', async (req, res) => {
  const response = await axios.get(req.query.url);
  res.json(response.data);
});

// Unsafe: attacker controls host via req.body.
app.post('/webhook', async (req, res) => {
  await axios.post(
    req.body.callback_url,
    { status: 'ok' }
  );
  res.sendStatus(204);
});

// Safe (control): static URL, should NOT be flagged.
app.get('/health', async (_req, res) => {
  const data = await fetch('https://api.internal/health');
  res.json(await data.json());
});
