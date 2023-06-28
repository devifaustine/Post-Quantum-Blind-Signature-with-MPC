# This is the main file, where the post quantum blind signature scheme is implemented and benchmarked.

import pyspx.shake_128f
import random
import string

x = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(48))

print("seed = %s" %x)
seed = bytes(x, 'ascii')

print(seed)

message = b"Hello World!"

public_key, secret_key = pyspx.shake_128f.generate_keypair(seed)
signature = pyspx.shake_128f.sign(message, secret_key)
ver = pyspx.shake_128f.verify(message, signature, public_key)
print(ver)
