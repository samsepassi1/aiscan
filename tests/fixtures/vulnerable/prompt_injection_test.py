# aiscan test fixture — should trigger AI-SEC-018 (Prompt Injection)
# DO NOT USE IN PRODUCTION

import anthropic
import openai
from flask import request


client = anthropic.Anthropic()

# Vulnerable: f-string interpolation of request data into Anthropic system prompt
resp = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system=f"You are a helpful assistant. User name: {request.args['name']}",
    messages=[{"role": "user", "content": "hi"}],
)

# Vulnerable: string concatenation into system prompt
system_prompt = "You are a bot. " + request.json["instructions"]
client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system=system_prompt,
    messages=[{"role": "user", "content": "hi"}],
)

# Vulnerable: .format() injection into system prompt
client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system="You are a helpful {} agent".format(request.args.get("persona")),
    messages=[{"role": "user", "content": "hi"}],
)

# Vulnerable: OpenAI messages array with tainted system content
openai_client = openai.OpenAI()
openai_client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": f"System rules: {request.form['policy']}"},
        {"role": "user", "content": "hi"},
    ],
)
