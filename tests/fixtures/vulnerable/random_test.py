# aiscan test fixture — should trigger AI-SEC-004 (Insecure Random)
# DO NOT USE IN PRODUCTION

import random
import string

# Insecure: using random for token generation
token = random.randint(100000, 999999)
session_key = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
password = random.randint(10000000, 99999999)
