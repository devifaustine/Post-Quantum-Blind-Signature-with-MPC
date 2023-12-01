from mpyc.runtime import mpc
import os
from math import ceil, log
import pyspx.shake_256f
import random
import string

# seed for SPHINCS+ with SHA-256
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

class SPHINCS(object):

    def __init__(self, n=256, m=512, h=60, d=12, w=16, tau=16, k=32):
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


    def keygen(self):
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