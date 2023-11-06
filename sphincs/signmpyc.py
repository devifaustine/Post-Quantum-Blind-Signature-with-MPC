from mpyc.runtime import mpc
import os
from math import ceil, log
from blake import BLAKE
from ChaCha import ChaCha
from WOTS import WOTS
from HORST import HORST
from bytes_utils import xor, chunkbytes, ints_to_4bytes, ints_from_4bytes
from trees import root, hash_tree, l_tree

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

        self.Hdigest = lambda r, m: BLAKE(512).digest(r + m)
        self.Fa = lambda a, k: BLAKE(256).digest(k + a)
        self.Frand = lambda m, k: BLAKE(512).digest(k + m)

        C = bytes("expand 32-byte to 64-byte state!", 'latin-1')
        perm = ChaCha().permuted
        self.Glambda = lambda seed, n: ChaCha(key=seed).keystream(n)
        self.F = lambda m: perm(m + C)[:32]
        self.H = lambda m1, m2: perm(xor(perm(m1 + C), m2 + bytes(32)))[:32]

        self.wots = WOTS(n=n, w=w, F=self.F, Gl=self.Glambda)
        self.horst = HORST(n=n, m=m, k=k, tau=tau,
                           F=self.F, H=self.H, Gt=self.Glambda)

    @classmethod
    def address(self, level, subtree, leaf):
        """
        combine level, subtree and leaf with bitwise or into bytes
        :param level: level of the tree
        :param subtree: the subtree
        :param leaf: the leaf
        :return: byte representation of t / the address of the leaf
        """
        t = level | (subtree << 4) | (leaf << 59)
        return int.to_bytes(t, length=8, byteorder='little')

    def keygen_pub(self, sk1, q):
        addresses = [self.address(self.d - 1, 0, i)
                     for i in range(1 << (self.h//self.d))]
        leafs = [self.wots_leaf(a, sk1, q) for a in addresses]
        Qtree = q[2 * ceil(log(self.wots.l, 2)):]
        H = lambda x, y, i: self.H(xor(x, Qtree[2*i]), xor(y, Qtree[2*i+1]))
        pk1 = root(hash_tree(H, leafs))
        return pk1

    def keygen(self):
        """
        generate a public and private key pair
        :return: public key, private key
        """
        sk1 = os.urandom(self.n // 8)
        sk2 = os.urandom(self.n // 8)
        p = max(self.w - 1, 2 * (self.h + ceil(log(self.wots.l, 2))), 2 * self.tau)
        q = [os.urandom(self.n // 8) for _ in range(p)]
        pk1 = self.keygen_pub(sk1, q)

        sk = (sk1, sk2, q)
        pk = (pk1, q)

        return pk, sk

    def wots_leaf(self, address, SK1, masks):
        seed = self.Fa(address, SK1)
        pk_A = self.wots.keygen(seed, masks)
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        return root(l_tree(H, pk_A))

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

    async def sign(self):
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
        payloads = mpc.input(secint(int(payload)))

        # TODO: process both inputs from parties and sign the message with the sk
        for i in range(len(payloads)):
            print(payloads[i])
        print("There's the payload")

        # TODO: outputs the blind signature before shutting down
        await mpc.shutdown()

