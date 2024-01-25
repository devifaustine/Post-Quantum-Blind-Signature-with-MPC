# Generates key-pairs for the benchmark

from signmpyc import SPHINCS
import time
import random
import string

# set log variable to true for logging
log = False

def xprint(string):
    if log:
        print(string)

sphincs = SPHINCS()

# _________________________________________________________________________________________________

# seed for SPHINCS+ with SHA-256 has to be 96 bytes long
seed1 = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

def gen_key(n=1, seed=seed1):
    """
    generate a key pair (pk, sk) n times
    :param n: the number of key pairs generated
    :param seed: seed for KeyGen
    :return: key(s) (printed out)
    """

    # seed has to be 96 bytes long
    assert len(seed) == 96

    # Convert the string to bytes
    seed_bytes = seed.encode('utf-8')

    keys = []
    elapsed = []

    # generate public and private key pair
    for i in range(n):
        start = time.time()
        key = sphincs.keygen(seed_bytes)
        end = time.time()
        keys.append(key)
        elapsed.append(end-start)

    # keys need to be printed out as a tuple - for bash variable
    print(tuple(keys))

    average = sum(elapsed) / len(elapsed)
    xprint("time taken to generate the key: %d seconds" % average)

# _________________________________________________________________________________________________

if __name__ == '__main__':
    n = input("How many keys do you want generated?")
    gen_key(n)