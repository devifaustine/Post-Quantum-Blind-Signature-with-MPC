# test key generation process of pyspx

import pyspx.shake_256f as pyspx
import random
import string

# expected sizes of (pk ,sk, sig): [64, 128, 49856]
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

for i in range(100):
    pk, sk = pyspx.generate_keypair(bytes(seed, 'utf-8'))
    assert len(pk) == 64
    assert len(sk) == 128
    print("pk: ", pk)
    print("sk: ", sk)
    print()
