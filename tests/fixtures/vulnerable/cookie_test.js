// aiscan test fixture — should trigger AI-SEC-016 (Insecure Cookie Flags)
// DO NOT USE IN PRODUCTION

const express = require('express');
const app = express();

// Unsafe: no options at all — cookie readable by JS, sent over HTTP.
app.post('/login-v1', (req, res) => {
  res.cookie('session', 'abc123');
  res.sendStatus(200);
});

// Unsafe: explicit httpOnly:false.
app.post('/login-v2', (req, res) => {
  res.cookie('session', 'abc123', {
    httpOnly: false,
    maxAge: 3600000,
  });
  res.sendStatus(200);
});

// Unsafe: secure:false.
app.post('/login-v3', (req, res) => {
  res.cookie('session', 'abc123', {
    httpOnly: true,
    secure: false,
  });
  res.sendStatus(200);
});

// Unsafe: sameSite:'none' (needs secure:true even then).
app.post('/login-v4', (req, res) => {
  res.cookie('session', 'abc123', {
    httpOnly: true,
    sameSite: 'none',
  });
  res.sendStatus(200);
});

// Fastify variant (reply.setCookie) — same problem.
async function fastifyLogin(request, reply) {
  reply.setCookie('session', 'abc123', {
    path: '/',
  });
  return { ok: true };
}

module.exports = { fastifyLogin };
