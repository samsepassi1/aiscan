// aiscan test fixture — should trigger AI-SEC-012 (Permissive CORS)
// DO NOT USE IN PRODUCTION

const express = require('express');
const cors = require('cors');
const app = express();

// Unsafe: wildcard CORS
app.use(cors({ origin: '*' }));

// Also unsafe: manual header
app.get('/api/data', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.json({ data: 'sensitive' });
});
