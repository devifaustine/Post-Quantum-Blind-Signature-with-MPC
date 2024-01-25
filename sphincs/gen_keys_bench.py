# Generates key-pairs for the benchmark
import argparse
from signmpyc import SPHINCS
import time
import random
import string

# set log variable to true for logging
log = False

def digest(list):
    res = ''
    # TODO: reform this s.t. the output is accepted by bash script as an array of (pk, sk) for each element
    for i in list:
        # (pk, sk)
        if isinstance(i, tuple):
            res += '"('
            res += str(i[0])
            res += ','
            res += str(i[1])
            res += ')"'
        res += ' '
    return res


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
    print(keys)
    print(digest(keys))

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