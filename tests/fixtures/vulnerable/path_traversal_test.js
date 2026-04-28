// aiscan test fixture — should trigger AI-SEC-011 (Path Traversal, JS/TS)
// DO NOT USE IN PRODUCTION

const fs = require("fs");
const path = require("path");

// Unsafe: fs read with HTTP request body data
app.post("/upload", (req, res) => {
  fs.readFileSync(req.body.path);
});

// Unsafe: path.join with request query parameter
app.get("/file", (req, res) => {
  const full = path.join("/var/data", req.query.name);
  fs.readFileSync(full);
});

// Unsafe: path.resolve with route param
app.get("/asset/:name", (req, res) => {
  const full = path.resolve("/var/assets", req.params.name);
  res.sendFile(full);
});
