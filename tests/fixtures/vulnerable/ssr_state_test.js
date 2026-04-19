// aiscan test fixture — should trigger AI-SEC-013 (SSR State Hydration Injection)
// DO NOT USE IN PRODUCTION

const express = require('express');
const { renderToString } = require('react-dom/server');
const App = require('./App');

const app = express();

app.get('/', (req, res) => {
  const state = {
    user: req.query.user,        // attacker-controlled
    bio: req.query.bio,
  };
  const appHtml = renderToString(App(state));

  // Unsafe: JSON.stringify inside a <script> tag via template literal.
  // If state contains "</script><script>evil()</script>", it breaks out.
  const html = `
    <!doctype html>
    <html>
      <body>
        <div id="app">${appHtml}</div>
        <script>window.__INITIAL_STATE__ = ${JSON.stringify(state)};</script>
      </body>
    </html>
  `;
  res.send(html);
});

// Also unsafe: direct assignment form
app.get('/v2', (req, res) => {
  const state = { search: req.query.q };
  let out = '<script>';
  out += `window.__PRELOADED_STATE__ = ${JSON.stringify(state)};`;
  out += '</script>';
  res.send(out);
});
