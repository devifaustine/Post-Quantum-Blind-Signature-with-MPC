from mpyc.runtime import mpc
import os
from math import ceil, log
import pyspx.shake_256f
import random
import string
from sphincs_params import *

# seed for SPHINCS+ with SHA-256 has to be 96 bytes long
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

# this can be set to 1 if you want the signature to be randomized (for security)
RANDOMIZE = 0

class SPHINCS(object):
    # TODO: make the variables accessible and changable from main() in mpyc_sphincs_benchmark.py
    def __init__(self, n=32, m=512, h=68, d=17, w=16, tau=16, k=35):
        """Initializes SPHINCS+-256f

        n -- length of hash in WOTS / HORST (in bits)
        m -- length of message hash (in bits)
        h -- height of the hyper-tree
        d -- number of layers in the hyper-tree
        w -- Winternitz parameter used for WOTS signature
        tau -- layers in the HORST tree (2^tau is no. of secret-key elements)
        k -- number of trees in FORS
        #TODO: add t to the constructor argument and fix the code
        t -- number of leaves of FORS tree

        resulting signature would be 49856 bytes long
        """
        self.n = n  # security parameter in bytes
        self.m = m
        self.h = h
        self.d = d
        self.w = w
        self.tau = tau
        self.t = 1 << tau
        self.k = k
        SPX_N = 32
        SPX_FULL_HEIGHT = 68
        SPX_FORS_HEIGHT = 9
        SPX_FORS_TREES = 35
        SPX_WOTS_W = 16
        SPX_SHA512 = 1

        # Derived parameters
        SPX_ADDR_BYTES = 32
        SPX_WOTS_LOGW = 8 if SPX_WOTS_W == 256 else 4
        SPX_WOTS_LEN1 = 8 * SPX_N // SPX_WOTS_LOGW

        # ... Other derived parameters ...

        SPX_WOTS_LEN2 = 2 if SPX_WOTS_W == 256 else 4  # Adjust based on your precomputation

        SPX_WOTS_LEN = SPX_WOTS_LEN1 + SPX_WOTS_LEN2
        SPX_WOTS_BYTES = SPX_WOTS_LEN * SPX_N
        SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES

        # ... Define other parameters ...

        # Subtree size
        SPX_TREE_HEIGHT = SPX_FULL_HEIGHT // SPX_D

        if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT:
            raise ValueError("SPX_D should always divide SPX_FULL_HEIGHT")

# key generation is the same as the original SPHINCS+ implementation
    def keygen(self, seed):
        """
        generate a public and private key pair according to pyspx library
        :return: public key, private key
        """
        pk, sk = pyspx.shake_256f.generate_keypair(seed)
        return pk, sk

    async def toByte(self, x, y):
        """
        returns a y-byte string containing binary representation of x in big endian order
        :param x: non-negative integer
        :param y: non-negative integer
        :return: bytestring of length y
        """
        res = bytearray(y)
        for i in range(y):
            res[i] = x % 256
            x //= 256
        return res

    async def sign(self, M, SK):
        """
        sign the message M using secret key SK (All done using MPyC functions)
        :param M: message (secure object)
        :param SK: tuple of (SK.seed, SK.prf, PK.seed, PK.root) all of type secure objects
        :return: signature sign(M, SK) - still secure object
        """
        # TODO: determine which type of secure object M and SK have to be
        # TODO: implement the method from SPHINCS+!
        # s is the signature for message M
        s = 0

        # initialization
        ADRS = self.toByte(0, 32)

        # SK = (SK.seed, SK.prf, PK.seed, PK.root)
        skseed, skprf, pkseed, pkroot = SK

        # generate randomizer
        opt = pkseed
        if RANDOMIZE:
            opt = random.randint(0, 2**SPX_N)

        raise NotImplementedError("Signing function not implemented yet!")

        # signature is a tuple of (Sig, Auth.Path)
        sig = (s, M)
        return tuple(sig)