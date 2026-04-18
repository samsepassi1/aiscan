# aiscan test fixture — should NOT trigger AI-SEC-001
# Demonstrates safe secret handling

import os
import secrets

# Safe: read from environment variable
API_KEY = os.environ["API_KEY"]
password = os.environ.get("DB_PASSWORD", "")

# Safe: generate a cryptographic secret at runtime (not hardcoded)
session_token = secrets.token_hex(32)
