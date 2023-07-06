# This is the main file, where the post quantum blind signature scheme is implemented and benchmarked.

import pyspx.shake_256f
import pyspx.shake_128f
import random
import string
import time
from statistics import mean

# Create 2 seeds randomly, one for SHA128 the other for SHA256
x = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(48))
y = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

list_seeds = [x, y]
seeds = []

# print out the seeds
for i in range(len(list_seeds)):
    if i == 1:
        print("seed SHA-128 = %s" %list_seeds[i])
    else:
        print("seed SHA-256 = %s" % list_seeds[i])
    seeds.append(bytes(list_seeds[i], 'ascii'))

# Randomly generate 100 messages of random length (1-70) to be signed later on
messages = []

print("Messages: ")
for i in range(100):
    length = random.randint(1, 70)
    message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
    messages.append(bytes(message, 'ascii'))
    print("\t %s" %message)

time_128 = []
time_256 = []

# Signing using SHA-128
for i in range(len(messages)):
    start = time.time()
    public_key, secret_key = pyspx.shake_128f.generate_keypair(seeds[0])
    signature = pyspx.shake_128f.sign(messages[i], secret_key)
    ver = pyspx.shake_128f.verify(messages[i], signature, public_key)
    end = time.time()
    elapsed = end - start
    time_128.append(elapsed)
    if not ver:
        print(ver)
    #print(ver)
    #print("time =", elapsed)

    # Signing using SHA-256
    start = time.time()
    public_key, secret_key = pyspx.shake_256f.generate_keypair(seeds[1])
    signature = pyspx.shake_256f.sign(messages[i], secret_key)
    ver = pyspx.shake_256f.verify(messages[i], signature, public_key)
    end = time.time()
    elapsed = end - start
    time_256.append(elapsed)
    if not ver:
        print(ver)
    #print(ver)
    #print("time =", elapsed)

print(time_128)
print(time_256)
print()
#print("Average time to sign messages using SHA-128 = %d" %(mean(time_128)))
#print("Average time to sign messages using SHA-256 = %d" %(mean(time_256)))

elapsed_128 = 0
elapsed_256 = 0
for i in range(len(time_128)):
    elapsed_128 += time_128[i]
for i in range(len(time_256)):
    elapsed_256 += time_256[i]
print(elapsed_128)
print(elapsed_256)
print("SHA128 is %d times faster than SHA256" %(elapsed_128/elapsed_256))

"""

# Average Time
elapsed_128 = 0
elapsed_256 = 0
for i in range(len(time_128)):
    elapsed_128 += time_128[i]
print("Average time to sign messages using SHA-128 = %d" %(elapsed_128/len(messages)))
for i in range(len(time_256)):
    elapsed_256 += time_256[i]
print("Average time to sign messages using SHA-256 = %d" %(elapsed_256/len(messages)))


"""