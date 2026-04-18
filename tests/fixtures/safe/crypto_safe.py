# aiscan test fixture — should NOT trigger AI-SEC-003
# Demonstrates safe cryptographic usage

import hashlib
import hmac
import os

data = b"sensitive data"

# Safe: SHA-256
hash_value = hashlib.sha256(data).hexdigest()

# Safe: SHA-3
sha3_hash = hashlib.sha3_256(data).hexdigest()

# Safe: HMAC with SHA-256
key = os.urandom(32)
mac = hmac.new(key, data, hashlib.sha256).hexdigest()
