# This is the main file, where the post quantum blind signature scheme is implemented and benchmarked.

import pyspx.shake256_128f

seed = 99
public_key, secret_key = pyspx.shake256_128f.generate_keypair(seed)
signature = pyspx.shake256_128f.sign(message, secret_key)
ver = pyspx.shake256_128f.verify(message, signature, public_key)
print(ver)
