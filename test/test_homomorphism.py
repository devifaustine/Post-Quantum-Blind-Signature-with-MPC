# this program tests the homomorphism of SPHINCS+

import pyspx.shake_256f
import random
import string

# seed for SPHINCS+ with SHA-256 has to be 96 bytes long
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))
seed_bytes = seed.encode('utf-8')

# generate public and private key pair
public_key, secret_key = pyspx.shake_256f.generate_keypair(seed_bytes)

print("here's the public key: ", public_key)
print()
print("here's the secret key: ", secret_key)
print()

# sign a message using the key pair
s1 = pyspx.shake_256f.sign(b'2', secret_key)
print("here's the signature: ", s1)
print()
if pyspx.shake_256f.verify(b'2', s1, public_key):
    print("signature verified")
else:
    print("signature not verified")
print()


# sign another message
s2 = pyspx.shake_256f.sign(b'3', secret_key)
print("here's the signature: ", s2)
print()
if pyspx.shake_256f.verify(b'3', s2, public_key):
    print("signature verified")
else:
    print("signature not verified")
print()

# test additional homomorphism
s3 = pyspx.shake_256f.sign(b'5', secret_key)
print()
if pyspx.shake_256f.verify(b'5', s3, public_key):
    print("signature verified")
else:
    print("signature not verified")
print()

if s1 + s2 == s3:
    print("homomorphism verified")
else:
    print("SPHINCS+ is not homomorphic with respect to addition")

'''
# cannot multiply bytes
# test multipliccation homomorphic property
s4 = pyspx.shake_256f.sign(b'6', secret_key)
print()
if pyspx.shake_256f.verify(b'6', s4, public_key):
    print("signature verified")
else:
    print("signature not verified")
print()
if s1 * s2 == s4:
    print("homomorphism verified")
else:
    print("SPHINCS+ is not homomorphic with respect to multiplication")

'''

# test randomizer
s5 = pyspx.shake_256f.sign(b'2', secret_key)
print()
if pyspx.shake_256f.verify(b'2', s5, public_key):
    print("signature verified")
else:
    print("signature not verified")
print()
if s1 == s5:
    print("randomizer is not active in SPHINCS+")
else:
    print("SPHINCS+ randomizer is active")