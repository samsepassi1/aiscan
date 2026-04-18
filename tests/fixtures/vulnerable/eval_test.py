# aiscan test fixture — should trigger AI-SEC-009 (Eval/Exec)
# DO NOT USE IN PRODUCTION

user_input = ""  # imagine this comes from a web request

# Unsafe: eval on user input
result = eval(user_input)

# Unsafe: exec on user input
exec(user_input)
