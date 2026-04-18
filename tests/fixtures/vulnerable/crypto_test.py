# aiscan test fixture — should trigger AI-SEC-003 (Weak Crypto)
# DO NOT USE IN PRODUCTION

import hashlib

data = b"sensitive data"
password = b"user_password"

# Weak: MD5
hash_value = hashlib.md5(data).hexdigest()

# Weak: SHA-1
sha = hashlib.sha1(password).hexdigest()
