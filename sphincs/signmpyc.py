from mpyc.runtime import mpc
import os
from math import ceil, log
import pyspx.shake_256f
import random
import string
from sphincs_params import *

# seed for SPHINCS+ with SHA-256 has to be 96 bytes long
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

class SPHINCS(object):

    def __init__(self, n=32, m=512, h=9, d=17, w=16, tau=16, k=32):
        """Initializes SPHINCS (default to SPHINCS-256)

        Currently other parameters than SPHINCS-256 can be buggy
        n -- length of hash in WOTS / HORST (in bits)
        m -- length of message hash (in bits)
        h -- height of the hyper-tree
        d -- layers of the hyper-tree
        w -- Winternitz parameter used for WOTS signature
        tau -- layers in the HORST tree (2^tau is no. of secret-key elements)
        k -- number of revealed secret-key elements per HORST signature
        """
        self.n = n
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


    def keygen(self, seed):
        """
        generate a public and private key pair
        :return: public key, private key
        """
        pk, sk = pyspx.shake_256f.generate_keypair(seed)
        return pk, sk

    def sign(self, M, SK):
        """
        sign the message M using secret key SK
        :param M: message
        :param SK: secret key
        :return: signature sign(M, SK)
        """
        # TODO: implement the method from SPHINCS+!
        # s is the signature for message M
        s = 0
        sig = (s, M)
        return tuple(sig)