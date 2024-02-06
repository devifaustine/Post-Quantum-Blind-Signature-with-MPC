from mpyc.runtime import mpc
from math import ceil, log, floor
import pyspx.shake_256f
import random
import string
from sphincs_params import *

# seed for SPHINCS+ with SHA-256 has to be 96 bytes long
seed = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(96))

# this can be set to 1 if you want the signature to be randomized (for security)
RANDOMIZE = 0

def q_split(q):
    """
    function to parse q in form of string
    :param q: Q in SK
    :return: Q in its original form a list of bytestring
    """
    #TODO: fix this function!
    res = []
    for i in range(len(q)):
        if i == 0:  # [ present at the first char
            res.append(eval(q[i][1:]))
            print(res[i])
        elif i == len(q) - 1:
            res.append(eval(q[i][:-1]))
        else:
            res.append(eval(q[i]))
    return res


def split_sk(sk):
    """
    sk includes pk and the real secret key SK = (PK, (SK1, SK2, Q))
    :param sk: secret key
    :return: (pk, (sk1, sk2, q))
    """
    #TODO: fix this function!
    pk, sk_eval = eval(sk)

    sk1 = eval(sk_eval[0])  # Using eval to convert the string back to bytes
    sk2 = eval(sk_eval[1])
    q_str = sk_eval[2:]
    q = q_split(q_str)

    return pk, (sk1, sk2, q)

class SPHINCS(object):
    # TODO: make the variables accessible and changable from main() in mpyc_sphincs_benchmark.py
    def __init__(self, n=32, m=512, h=68, d=17, w=16, tau=16, k=35):
        """Initializes SPHINCS+-256f according to docs

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
        self.a = log(self.t)
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

    # key generation is the same as the original SPHINCS+ implementation - pyspx library
    def keygen(self, seed):
        """
        generate a public and private key pair according to pyspx library
        :return: public key, private key
        """
        pk, sk = pyspx.shake_256f.generate_keypair(seed)
        return pk, sk

    # verify should function the same as described in pyspx library
    def verify(self, pk, sig, msg):
        """
        verify the signature of the message
        :param pk: public key
        :param sig: signature
        :param msg: message
        :return: True/False
        """
        return pyspx.shake_256f.verify(sig, msg, pk)

    def toByte(self, x, y):
        """
        returns a y-byte string containing binary representation of x in big endian order
        :param x: non-negative integer
        :param y: non-negative integer
        :return: bytestring of length y
        """
        return x.to_bytes(y, byteorder='big')

    async def PRF_msg(self, sk, opt, msg):
        """
        pseudorandom function to generate randomness for the message compression
        :param sk: SK.prf
        :param opt: randomizer
        :param msg: message in Secure Object type
        :return: SHAKE256(sk || opt || msg, 8n)
        """
        # TODO: Implement the function using SHA2 or SHAKE256
        raise NotImplementedError("PRF_msg function not implemented yet!")

    async def H_msg(self, R, pkseed, pkroot, msg):
        """
        hash function to generate the message digest and index
        :param R: randomness from PRF_msg
        :param pkseed: PK.seed
        :param pkroot: PK.root
        :param msg: message in Secure Object type
        :return: digest and index
        """
        # TODO: implement hash message to digest the message
        raise NotImplementedError("H_msg function not implemented yet!")

    async def sign(self, M, SK):
        """
        sign the message M using secret key SK (All done using MPyC functions)
        :param M: message (secure object)
        :param SK: tuple of (SK.seed, SK.prf, PK.seed, PK.root) all of type secure objects
        :return: signature sign(M, SK) - still of secure object
        """
        # TODO: determine which type of secure object M and SK have to be
        # TODO: implement the method from SPHINCS+!
        # s is the signature for message M
        s = 0

        # initialization
        ADRS = self.toByte(0, 32)

        # SK = (SK.seed, SK.prf, PK.seed, PK.root)
        # TODO: since SK is of type secure object, need to use np_split() from mpc library
        skseed, skprf, pkseed, pkroot = SK

        # generate randomizer - default to pkseed and not randomized
        opt = pkseed
        if RANDOMIZE:
            opt = random.randint(0, 2**SPX_N)

        R = self.PRF_msg(skprf, opt, M)

        # TODO: R has to be of type array so concatenate works?
        s = mpc.np_concatenate((s, R))

        # compute message digest and index
        digest = self.H_msg(R, pkseed, pkroot, M)

        tmp_md = mpc.np_split(digest, floor((self.k * self.a + 7) / 8))
        tmp_idx_tree = mpc.np_split(digest, floor((self.h - (self.h / self.d) + 7) / 8))
        tmp_idx_leaf = mpc.np_split(digest, floor(((self.h / self.d) + 7) / 8))

        md = tmp_md[self.k * self.a]  # first ka bits of tmp_md
        idx_tree = tmp_idx_tree[self.h - (self.h / self.d)]  # first h - h/d bits of tmp_idx_tree
        idx_leaf = tmp_idx_leaf[self.h / self.d]  # first h/d bits of tmp_idx_leaf

        # FORS sign
        # TODO: implement ADRS and its functions!
        ADRS.setLayerAddress(0)
        ADRS.setTreeAddress(idx_tree)
        ADRS.setType(FORS_TREE)
        ADRS.setKeyPairAddress(idx_leaf)

        SIG_FORS = fors_sign(md, skseed, pkseed, ADRS)
        # TODO: pay attention to type of SIG_FORS and make sure concat works!
        s = mpc.np_concatenate((s, SIG_FORS))

        # get FORS public key
        PK_FORS = fors_pkFromSig(SIG_FORS, md, pkseed, ADRS)

        # sign FORS public key with HT
        ADRS.setType(TREE)
        SIG_HT = ht_sign(PK_FORS, skseed, pkseed, idx_tree, idx_leaf)
        s = mpc.np_concatenate((s, SIG_HT))

        raise NotImplementedError("Signing function not implemented yet!")

        # signature consists of R, SIG_FORS, SIG_HT - all of type secure object
        sig = (s, M)
        return sig