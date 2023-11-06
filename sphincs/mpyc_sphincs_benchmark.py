# This file executes the benchmark for SPHINCS build from MPC using the help of MPyC library
from signmpyc import SPHINCS
import time

sphincs = SPHINCS()

# generate public and private key pair
start = time.time()
key = sphincs.keygen()
end = time.time()

elapsed = end - start
print("time taken to generate the key: %d seconds" % elapsed)

for i in range(len(key)):
    print(type(key[i]))
