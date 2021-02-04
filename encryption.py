import hashlib

# Use of weak hashers is bad (discouraged!)
hashlib.new('md5')
hashlib.md4()
hashlib.md5()
hashlib.new('sha1')
hashlib.sha1()

# These are all vulnerable to length-extension (or similar issues)
hashlib.new('sha256')
hashlib.sha256()
hashlib.new('sha512')
hashlib.sha512()
hashlib.new('whirlpool')
hashlib.new('ripemd160')
