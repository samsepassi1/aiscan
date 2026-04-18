# aiscan test fixture — should NOT trigger AI-SEC-004
# Demonstrates safe randomness for security contexts

import secrets
import random  # imported but only used for non-security purposes

# Safe: secrets module for security-sensitive values
token = secrets.token_hex(32)
session_key = secrets.token_urlsafe(32)
otp = secrets.randbelow(1000000)

# Safe: random module for non-security use (game, simulation)
dice_roll = random.randint(1, 6)
shuffled_list = list(range(10))
random.shuffle(shuffled_list)
