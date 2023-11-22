# This executes a benchmark for the signing function of the official SPHINCS Library/Implementation,
# the PySPX library over different inputs

import pyspx.shake_256f
import pyspx.shake_128f
import random
import string
import time

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

# print("Messages: ")
# generating messages to be signed / payload
for i in range(100):
    length = random.randint(1, 70)
    message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
    messages.append(bytes(message, 'ascii'))
    # prints out generated messages
    #print("\t %s" %message)

# list of elapsed time for SPHINCS using SHA128
time_128 = []
# list of elapsed time for SPHINCS using SHA256
time_256 = []
# list of elapsed time for keygen SPHINCS using SHA128
time_key_128 = []
# list of elapsed time for keygen SPHINCS using SHA256
time_key_256 = []
# list of elapsed time for verify SPHINCS using SHA128
time_ver_128 = []
# list of elapsed time for verify SPHINCS using SHA256
time_ver_256 = []

# benchmark the keygen(), sign() and verify()
for i in range(len(messages)):
    # Signing using SHA-128
    # generate public and private key pair
    start_key = time.time()
    public_key, secret_key = pyspx.shake_128f.generate_keypair(seeds[0])
    end_key = time.time()
    time_key_128.append(end_key - start_key)
    #print("secret key of SHA-128 is: ", secret_key)

    # sign the message
    start = time.time()
    signature = pyspx.shake_128f.sign(messages[i], secret_key)
    end = time.time()
    time_128.append(end - start)


    # verify the signature
    start_ver = time.time()
    ver = pyspx.shake_128f.verify(messages[i], signature, public_key)
    end_ver = time.time()
    time_ver_128.append(end_ver - start_ver)

    if not ver:
        print(ver)
    #print(ver)
    #print("time =", elapsed)

    # Signing using SHA-256
    # keygen using SHA256
    start_key_2 = time.time()
    public_key, secret_key = pyspx.shake_256f.generate_keypair(seeds[1])
    end_key_2 = time.time()
    time_key_256.append(end_key_2 - start_key_2)
    #print("secret key of SHA-256 is: ", secret_key)

    # sign the message using SHA256
    start = time.time()
    signature = pyspx.shake_256f.sign(messages[i], secret_key)
    end = time.time()
    time_256.append(end - start)

    # verify the signature using SHA256
    start_ver_2 = time.time()
    ver = pyspx.shake_256f.verify(messages[i], signature, public_key)
    end_ver_2 = time.time()
    time_ver_256.append(end_ver_2 - start_ver_2)

    if not ver:
        print(ver)
    #print(ver)
    #print("time =", elapsed)

#print("Average time to sign messages using SHA-128 = %d" %(mean(time_128)))
#print("Average time to sign messages using SHA-256 = %d" %(mean(time_256)))
#print(time_128)
#print(time_256)

elapsed_128 = 0
elapsed_256 = 0

for i in range(len(time_128)):
    elapsed_128 += time_128[i]
for i in range(len(time_256)):
    elapsed_256 += time_256[i]

# prints out the average time results - needs to be divided by 100, since it is
# the sum of time it takes to sign 100 messages
print("Time required for sign() using SHA128 is %d seconds." %elapsed_128)
print("Time required for sign() using SHA256 is %d seconds." %elapsed_256)
print("SHA128 is %d times faster than SHA256" %(elapsed_128/elapsed_256))
print()

print("here's the time for keygen() using SHA128: ", time_key_128)
print()
print("here's the time for keygen() using SHA256: ", time_key_256)
print()

print("here's the time for verify() using SHA128: ", time_ver_128)
print()
print("here's the time for verify() using SHA256: ", time_ver_256)
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