# test collision in SPHINCS+ first using SHA256

import pyspx.shake_256f
import string
import random

# generate seed
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))
seed_bytes = seed.encode('utf-8')

# generate key pair
public_key, secret_key = pyspx.shake_256f.generate_keypair(seed_bytes)

message = b'1'
# list of signatures produced
signatures = []
# counter i
i = 0

# sign message in a while loop until collision is found
while True:
    signature = pyspx.shake_256f.sign(message, secret_key)
    assert pyspx.shake_256f.verify(message, signature, public_key)
    i += 1
    print(i)
    if signature in signatures:
        print("collision found in %d iterations" %i)
        break