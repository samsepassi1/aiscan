// aiscan test fixture — should trigger AI-SEC-017 (Weak Content Security Policy)
// DO NOT USE IN PRODUCTION

const express = require('express');
const helmet = require('helmet');
const app = express();

// Unsafe: raw header with 'unsafe-inline'.
app.use((_req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'",
  );
  next();
});

// Unsafe: 'unsafe-eval' in scriptSrc (helmet form).
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        scriptSrc: ["'self'", "'unsafe-eval'"],
      },
    },
  }),
);

// Unsafe: meta tag injection path.
const metaHtml =
  '<meta http-equiv="Content-Security-Policy" content="script-src * \'unsafe-inline\'">';

module.exports = { metaHtml };
