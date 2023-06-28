# This is the main file, where the post quantum blind signature scheme is implemented and benchmarked.

import pyspx.shake_256f
import pyspx.shake_128f
import random
import string
import time

x = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(48))
y = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

list_seeds = [x, y]
seeds = []

for i in range(len(list_seeds)):
    print(i)
    print("seed (string)= %s" %list_seeds[i])
    seeds.append(bytes(list_seeds[i], 'ascii'))
    print(seeds[i])

message = b"Hello World!"

start = time.time()
public_key, secret_key = pyspx.shake_128f.generate_keypair(seeds[0])
signature = pyspx.shake_128f.sign(message, secret_key)
ver = pyspx.shake_128f.verify(message, signature, public_key)
end = time.time()
elapsed = end - start
print(ver)
print("time =", elapsed)

start = time.time()
public_key, secret_key = pyspx.shake_256f.generate_keypair(seeds[1])
signature = pyspx.shake_256f.sign(message, secret_key)
ver = pyspx.shake_256f.verify(message, signature, public_key)
end = time.time()
elapsed = end - start
print(ver)
print("time =", elapsed)