from mpyc.runtime import mpc
import os
from math import ceil, log

# here are the list of variables needed
n = 256
m = 512
h = 60
d = 12
w = 16
tau = 16
k = 32

l = 1 # TODO: change this value

def keygen(seed):
    """
    generate a public and private key pair based on the seed
    :param seed: seed (typically 32 bytes / 256 bits long)
    :return: public key, private key
    """
    # TODO: make the key generation function based on the seed
    secret_seed = os.urandom(seed)
    secret_prf = os.urandom(seed)
    public_seed = os.urandom(seed)

    # TODO: l is supposedly self.wots.l, find out what this is in SPHINCS-256-py
    p = max(w - 1, 2 * (h + ceil(log(l, 2))), 2 * tau)
    public_root = [os.urandom(seed // 8) for _ in range(p)]
    pk = [public_seed, public_root]
    sk = [secret_seed, secret_prf, public_seed, public_root]
    return pk, sk

def verify(s, m, pk):
    """
    verifies the signature s accordingly, which is a signature of m with public key pk
    :param s: signature
    :param m: message
    :param pk: public key
    :return: true/false
    """
    # TODO: finish the verification process/function
    return True

def check_type(x):
    """
    checks the type of x and returns the object as the secure type of itself
    :return: secure x
    """
    return mpc.SecInt(32)

async def sign():
    """
    signing function of SPHINCS+
    :return: nothing
    """

    # TODO: finish this function
    secint = mpc.SecInt(16)

    # wait until all parties (user and signer) starts the mpc
    await mpc.start()

    # accept input from all parties
    payload = input('Give your input here: ')

    # TODO: check the type of input (message or sk) and use check_type() to determine the secure object
    payloads = mpc.input(secint(payload))

    # TODO: process both inputs from parties and sign the message with the sk
    for i in range(len(payloads)):
        print(payloads[i])
    print("There's the payload")

    # TODO: outputs the blind signature before shutting down
    await mpc.shutdown()

# runs the sign() function using MPC
mpc.run(sign())

# TODO: verifies if the signature is correct and legit
