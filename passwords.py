
# Storing tokens and passwords in string literals is bad
password = "NODFGODFG"
token = "ASDFSFGDG"
secret = "SDHGFHFDG"

# Comparing with EQ is bad for timing attacks
if password == "SUPER_SECRET": 
  proceed()

# Likewise for simple hashes
if password == hash:
  proceed()