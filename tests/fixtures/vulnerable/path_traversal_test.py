# aiscan test fixture — should trigger AI-SEC-011 (Path Traversal)
# DO NOT USE IN PRODUCTION

import os
from pathlib import Path
from flask import request

# Unsafe: user input directly in open()
filename = request.args.get('file')
with open('/var/data/' + filename) as f:
    content = f.read()

# Unsafe: Path() with user-controlled input
user_path = request.query_string
data = Path(user_path).read_text()

# Unsafe: os.path.join with request param
safe_base = '/var/www/static'
full_path = os.path.join(safe_base, request.args.get('path'))
