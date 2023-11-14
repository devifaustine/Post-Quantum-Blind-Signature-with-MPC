# This file executes the benchmark for SPHINCS build from MPC using the help of MPyC library
from signmpyc import SPHINCS
import time
from mpyc.runtime import mpc


sphincs = SPHINCS()

# generate public and private key pair
start = time.time()
key = sphincs.keygen()
end = time.time()

elapsed = end - start
print("time taken to generate the key: %d seconds" % elapsed)

for i in range(len(key)):
    print(type(key[i]))

# runs the sign() function using MPC
# TODO: does the benchmark and mpc.run(sign()) needs to be separated?
# TODO: signing process needs to be done in file mpyc_sphincs_benchmark.py
mpc.run(sphincs.sign())

# TODO: verifies if the signature is correct and legit
