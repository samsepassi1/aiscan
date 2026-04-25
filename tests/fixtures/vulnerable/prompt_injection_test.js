// aiscan test fixture — should trigger AI-SEC-018 (Prompt Injection, JS)
// DO NOT USE IN PRODUCTION

const Anthropic = require("@anthropic-ai/sdk");
const OpenAI = require("openai");

const anthropic = new Anthropic();
const openai = new OpenAI();

app.post("/chat", async (req, res) => {
  // Vulnerable: template literal interpolation into Anthropic system prompt
  const r1 = await anthropic.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 1024,
    system: `You are an assistant. User name: ${req.body.name}`,
    messages: [{ role: "user", content: "hi" }],
  });

  // Vulnerable: string concatenation into system prompt
  const r2 = await anthropic.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 1024,
    system: "You are a bot. " + req.query.instructions,
    messages: [{ role: "user", content: "hi" }],
  });

  // Vulnerable: OpenAI system role content built from request body
  const r3 = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: `Policy: ${req.body.policy}` },
      { role: "user", content: "hi" },
    ],
  });

  res.json({ r1, r2, r3 });
});
