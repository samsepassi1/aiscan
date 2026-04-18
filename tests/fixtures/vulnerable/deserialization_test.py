# aiscan test fixture — should trigger AI-SEC-008 (Unsafe Deserialization)
# DO NOT USE IN PRODUCTION

import pickle
import yaml

user_data = b""  # imagine this comes from a request body
user_input = ""  # imagine this is user-supplied YAML

# Unsafe: pickle.loads on untrusted data
obj = pickle.loads(user_data)

# Unsafe: yaml.load without SafeLoader
config = yaml.load(user_input)
