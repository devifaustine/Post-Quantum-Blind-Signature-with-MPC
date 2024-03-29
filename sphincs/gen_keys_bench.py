# Generates key-pairs for the benchmark
import argparse
from signmpyc import SPHINCS
import time
import random
import string

# set log variable to true for logging
log = False

def digest(list):
    """
    prints out the list to be used as a bash array
    :param list: list of objects
    :return: none
    """
    for i in list:
        # (pk, sk)
        if isinstance(i, tuple):
            print(i)


def xprint(string):
    if log:
        print(string)

sphincs = SPHINCS()

# _________________________________________________________________________________________________

def gen_key(n=1):
    """
    generate a key pair (pk, sk) n times
    :param n: the number of key pairs generated
    :param seed: seed for KeyGen
    :return: key(s) (printed out)
    """

    keys = []
    elapsed = []

    # generate public and private key pair
    for i in range(n):
        # seed for SPHINCS+ with SHA-256 has to be 96 bytes long
        seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))


        # seed has to be 96 bytes long
        assert len(seed) == 96

        # Convert the string to bytes
        seed_bytes = seed.encode('utf-8')
        start = time.time()
        key = sphincs.keygen(seed_bytes)
        end = time.time()
        keys.append(key)
        elapsed.append(end-start)

    # keys need to be printed out as a tuple - for bash variable
    digest(keys)

    average = sum(elapsed) / len(elapsed)
    xprint("time taken to generate the key: %d seconds" % average)

# _________________________________________________________________________________________________

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=int, metavar='N',
                        help='number of times N (default 1) to create the key pairs')
    parser.set_defaults(n=1)
    args = parser.parse_args()
    gen_key(args.n)